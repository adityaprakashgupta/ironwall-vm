#!/usr/bin/env bash
# Bring up the enclave topology: three Firecracker MicroVMs, one vsock each.
#
#   CID 3  red-team    the adversary; no network, no host mount, one shot
#   CID 4  blue-team   the defence stages; answers only the Referee
#   CID 5  llm-engine  the model; answers only the Referee, reset per turn
#
# The VMs have *no* network device at all. The only way in or out is AF_VSOCK,
# and the only peer any of them can reach is the host -- where the Referee
# listens. That is the "Isolated" pillar in concrete terms: there is no route
# to the signer, to the evidence log, or to each other.
#
# The Referee itself runs on the host (it is the TCB) and is started
# separately, so this script stays open in the foreground holding the VMs up:
#
#   sudo microvm/boot_enclave.sh --kernel artifacts/vmlinux --task /tmp/red-task.json
#   # ... in another shell, with the enclave still up:
#   cargo run -p bayora-referee -- \
#       --policy config/policy.yaml --images config/images.json \
#       --signer unix:/run/bayora/signer.sock --transport vsock \
#       --blue-cid 4 --blue-port 9001 --llm-cid 5 --llm-port 9002 \
#       --vsock-port 5000 --evidence-log evidence/evidence_log.ndjson
#
# Prerequisites: root, /dev/kvm, firecracker, images from
# build_immutable_images.sh, and a Linux host whose kernel provides
# `vsock_loopback` for the host-side guest CIDs (4/5 are guest CIDs; the host
# reaches them through the vsock backend).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MICROVM="$ROOT/microvm"
IMAGES="$MICROVM/images"
RUNTIME="${BAYORA_RUNTIME:-/run/bayora}"
FIRECRACKER="${FIRECRACKER:-firecracker}"

KERNEL=""
TASK=""
KEEP_TASK=0
MEM_MIB=256
VCPUS=1

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//; $d'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --kernel)     KERNEL="$2"; shift 2 ;;
    --task)       TASK="$2"; shift 2 ;;
    --runtime)    RUNTIME="$2"; shift 2 ;;
    --mem)        MEM_MIB="$2"; shift 2 ;;
    --vcpus)      VCPUS="$2"; shift 2 ;;
    --keep-task)  KEEP_TASK=1; shift ;;
    -h|--help)    usage 0 ;;
    *)            echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

die() { echo "boot_enclave: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (creates TAP-less vsock sockets in $RUNTIME)"
[ -e /dev/kvm ] || die "/dev/kvm is missing: this host cannot run Firecracker"
command -v "$FIRECRACKER" >/dev/null || die "firecracker not found (set FIRECRACKER=...)"
[ -n "$KERNEL" ] || die "--kernel <vmlinux> is required"
[ -f "$KERNEL" ] || die "kernel image not found: $KERNEL"
for role in red blue llm; do
  [ -f "$IMAGES/$role.ext4" ] || \
    die "$IMAGES/$role.ext4 is missing; run microvm/build_immutable_images.sh first"
done

mkdir -p "$RUNTIME"
PIDS=()

cleanup() {
  echo
  echo "==> shutting the enclave down"
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
  rm -f "$RUNTIME"/*.vsock "$RUNTIME"/fc-*.sock
  if [ "$KEEP_TASK" = 0 ]; then
    rm -f "$RUNTIME/red-task.ext4"
  fi
}
trap cleanup EXIT INT TERM

wait_for_socket() {
  local sock="$1" name="$2"
  for _ in $(seq 1 100); do
    [ -S "$sock" ] && return 0
    sleep 0.1
  done
  die "$name never opened $sock"
}

boot() {
  local role="$1" cid="$2" port="$3"; shift 3
  local config="$RUNTIME/fc-$role.json"
  local api_sock="$RUNTIME/fc-$role.sock"
  local vsock_uds="$RUNTIME/$role.vsock"
  local log="$RUNTIME/$role.log"

  rm -f "$api_sock" "$vsock_uds"

  # One drive for the read-only rootfs, plus optional extra drives (red gets
  # its provisioning disk as /dev/vdb, which init mounts and then deletes).
  local drives
  drives="{\"drive_id\":\"rootfs\",\"path_on_host\":\"$IMAGES/$role.ext4\",\"is_root_device\":true,\"is_read_only\":true}"
  for extra in "$@"; do
    drives="$drives,{\"drive_id\":\"$(basename "$extra" .ext4)\",\"path_on_host\":\"$extra\",\"is_root_device\":false,\"is_read_only\":true}"
  done

  cat > "$config" <<JSON
{
  "boot-source": {
    "kernel_image_path": "$KERNEL",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/opt/bayora/init.sh bayora.role=$role bayora.port=$port"
  },
  "drives": [$drives],
  "machine-config": { "vcpu_count": $VCPUS, "mem_size_mib": $MEM_MIB, "smt": false },
  "vsock": { "guest_cid": $cid, "uds_path": "$vsock_uds" },
  "logger": { "log_path": "$log", "level": "Warning" }
}
JSON

  "$FIRECRACKER" --api-sock "$api_sock" --config-file "$config" >/dev/null 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  wait_for_socket "$api_sock" "$role"
  echo "    cid $cid  $role  pid $pid  $IMAGES/$role.ext4"
}

# Red's provisioning disk: exactly one evaluation, one capability, one prompt.
# It is a small ext4 image the guest mounts read-only and never writes to; the
# host never has to talk to Red after boot.
prepare_task_disk() {
  local stage
  stage="$(mktemp -d)"
  mkdir -p "$stage/run/bayora"
  cp "$TASK" "$stage/run/bayora/task.json"
  chmod 0400 "$stage/run/bayora/task.json"
  dd if=/dev/zero of="$RUNTIME/red-task.ext4" bs=1M count=4 status=none
  mke2fs -q -t ext4 -F -b 1024 -I 128 -L bayora-task -d "$stage" "$RUNTIME/red-task.ext4"
  rm -rf "$stage"
}

echo "==> booting the enclave (no network devices anywhere)"
boot blue 4 9001
boot llm  5 9002

if [ -n "$TASK" ]; then
  [ -f "$TASK" ] || die "task file not found: $TASK"
  prepare_task_disk
  boot red 3 9000 "$RUNTIME/red-task.ext4"
else
  echo "    (no --task given: red is not booted; provision one evaluation first)"
fi

echo
echo "==> waiting for the guests to answer over VSOCK"
python3 - "$RUNTIME" <<'PY'
import json, os, socket, struct, sys, time

runtime = sys.argv[1]

def call(cid, port, message, timeout=2.0):
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((cid, port))
        body = json.dumps(message).encode()
        sock.sendall(struct.pack("<I", len(body)) + body)
        (length,) = struct.unpack("<I", sock.recv(4))
        chunks, remaining = [], length
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise OSError("short read")
            chunks.append(chunk)
            remaining -= len(chunk)
        return json.loads(b"".join(chunks).decode())

def wait(cid, port, message, predicate, label, timeout=20.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            reply = call(cid, port, message)
            if predicate(reply):
                print(f"    [ok] {label}")
                return reply
            last = reply
        except OSError as exc:
            last = exc
        time.sleep(0.2)
    raise SystemExit(f"    [FAILED] {label}: last response was {last!r}")

wait(4, 9001, {"eval_id": "probe", "prompt": "hello"},
     lambda r: r.get("decision") == "allow", "blue answered a verdict")
wait(5, 9002, {"eval_id": "probe", "prompt": "hello", "max_tokens": 8},
     lambda r: "output" in r, "llm answered a completion")
PY

cat <<EOF

==> the enclave is up. In another shell, start the Referee on the host:

    cargo run -p bayora-referee -- \\
        --policy config/policy.yaml \\
        --images config/images.json \\
        --signer unix:$RUNTIME/signer.sock \\
        --transport vsock \\
        --blue-cid 4 --blue-port 9001 \\
        --llm-cid 5 --llm-port 9002 \\
        --vsock-port 5000 \\
        --evidence-log evidence/evidence_log.ndjson \\
        --reset snapshot

  then drive it with a capability per evaluation, and let Red speak:

    python3 workloads/red-team/agent.py --host-cid 2 --vsock-port 5000

  Ctrl-C here tears the VMs down. Guest logs: $RUNTIME/*.log
EOF

echo
echo "==> holding the enclave open (Ctrl-C to stop)"
while :; do sleep 3600; done
