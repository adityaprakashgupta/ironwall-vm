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
# Same overrides as build_immutable_images.sh: the images must be booted from
# wherever they were built, and on WSL that is not /mnt/c.
IMAGES="${BAYORA_IMAGES_DIR:-$MICROVM/images}"
RUNTIME="${BAYORA_RUNTIME:-/run/bayora}"
FIRECRACKER="${FIRECRACKER:-firecracker}"

KERNEL=""
TASK=""
KEEP_TASK=0
MEM_MIB=2048
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

# cgroups v2 containment — each MicroVM runs in its own slice with hard
# resource limits so a compromised or malicious guest cannot starve the host
# or its siblings. Limits match config/policy.yaml resources.
# Fails gracefully if cgroup v2 is not mounted or writable (e.g. some WSL
# hosts), since the vsock/AF_UNIX mediation still provides isolation.
CGROUP_ROOT="/sys/fs/cgroup/bayora"
if mkdir -p "$CGROUP_ROOT" 2>/dev/null; then
  for role in red blue llm; do
    mkdir -p "$CGROUP_ROOT/$role" 2>/dev/null || true
  done
  # Per-role resource limits (cpu.max: "max 100000" means 100% of one CPU;
  # memory.max in bytes; pids.max is a count).
  # Run in a subshell so set -e does not kill the script if cgroup writes
  # are denied by the host kernel.
  bash -c '
    echo "100000" > /sys/fs/cgroup/bayora/red/cpu.max 2>/dev/null || true
    echo "268435456" > /sys/fs/cgroup/bayora/red/memory.max 2>/dev/null || true
    echo "64" > /sys/fs/cgroup/bayora/red/pids.max 2>/dev/null || true
    echo "200000" > /sys/fs/cgroup/bayora/blue/cpu.max 2>/dev/null || true
    echo "1073741824" > /sys/fs/cgroup/bayora/blue/memory.max 2>/dev/null || true
    echo "64" > /sys/fs/cgroup/bayora/blue/pids.max 2>/dev/null || true
    echo "300000" > /sys/fs/cgroup/bayora/llm/cpu.max 2>/dev/null || true
    echo "2147483648" > /sys/fs/cgroup/bayora/llm/memory.max 2>/dev/null || true
    echo "64" > /sys/fs/cgroup/bayora/llm/pids.max 2>/dev/null || true
  ' 2>/dev/null || true
else
  echo "note: cannot create cgroup hierarchy at $CGROUP_ROOT; running without cgroup isolation" >&2
fi

# The llm guest refuses to serve unless the weights on its disk hash to the
# digest the deployment published. Read that digest out of config/images.json
# (what build_immutable_images.sh measured) and put it on the kernel command
# line; booting llm without it would freeze the guest in its fail-closed loop.
MODEL_SHA=""
if [ -f "$ROOT/config/images.json" ]; then
  MODEL_SHA="$(python3 -c '
import json, sys
value = json.load(open(sys.argv[1])).get("model_digest", "")
print(value.removeprefix("sha256:"))' "$ROOT/config/images.json" 2>/dev/null || true)"
fi

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
  # Release cgroups
  for role in red blue llm; do
    rmdir "$CGROUP_ROOT/$role" 2>/dev/null || true
  done
  rmdir "$CGROUP_ROOT" 2>/dev/null || true
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

  # Referee owns the llm Firecracker process (via --reset snapshot with
  # with_process()). boot_enclave.sh only boots blue and red; Referee
  # spawns llm firecracker, loads golden snapshot, and brings it up.
  if [ "$role" = llm ]; then
    echo "    cid $cid  llm  skipped (Referee owns llm Firecracker process)"
    return 0
  fi

  rm -f "$api_sock" "$vsock_uds"

  # One drive for the read-only rootfs, plus optional extra drives (red gets
  # its provisioning disk as /dev/vdb, which init mounts and then deletes).
  local drives
  drives="{\"drive_id\":\"rootfs\",\"path_on_host\":\"$IMAGES/$role.ext4\",\"is_root_device\":true,\"is_read_only\":true}"
  for extra in "$@"; do
    drives="$drives,{\"drive_id\":\"$(basename "$extra" .ext4)\",\"path_on_host\":\"$extra\",\"is_root_device\":false,\"is_read_only\":true}"
  done

  # Only the llm role carries weights, so only it is told which ones to expect.
  local boot_args="console=ttyS0 reboot=k panic=1 pci=off init=/opt/bayora/init.sh bayora.role=$role bayora.port=$port"
  if [ "$role" = llm ]; then
    [ -n "$MODEL_SHA" ] || die "config/images.json has no model_digest; the llm guest refuses to boot unverified weights"
    boot_args="$boot_args bayora.model_sha256=$MODEL_SHA"
  fi

  cat > "$config" <<JSON
{
  "boot-source": {
    "kernel_image_path": "$KERNEL",
    "boot_args": "$boot_args"
  },
  "drives": [$drives],
  "machine-config": { "vcpu_count": $VCPUS, "mem_size_mib": $MEM_MIB, "smt": false },
  "vsock": { "guest_cid": $cid, "uds_path": "$vsock_uds" },
  "serial": { "path": "$RUNTIME/$role.serial" },
  "logger": { "log_path": "$log", "level": "Warning" }
}
JSON

  "$FIRECRACKER" --api-sock "$api_sock" --config-file "$config" >"$RUNTIME/$role.fcout" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  wait_for_socket "$api_sock" "$role"
  # `--config-file` configures the microVM; start it explicitly so the vsock
  # device (and the host-side $role.vsock socket) is actually activated.
  curl -s -f -X PUT "http://localhost/actions" --unix-socket "$api_sock" \
    -H 'Content-Type: application/json' -d '{"action_type":"InstanceStart"}' >/dev/null 2>&1 || true
  # Wait for the vsock socket to appear, then make it world-readable so the
  # Referee (which may run as a different user) can connect to it.
  for _ in $(seq 1 100); do [ -S "$vsock_uds" ] && break; sleep 0.1; done
  if [ -S "$vsock_uds" ]; then
    chmod 0666 "$vsock_uds" 2>/dev/null || true
  fi
  echo "$pid" > "$RUNTIME/fc-$role.pid"
  echo "    cid $cid  $role  pid $pid  $IMAGES/$role.ext4"
}

# Red's provisioning disk: exactly one evaluation, one capability, one prompt.
# It is a small ext4 image the guest mounts read-only and never writes to; the
# host never has to talk to Red after boot.
prepare_task_disk() {
  local stage
  stage="$(mktemp -d)"
  mkdir -p "$stage"
  cp "$TASK" "$stage/task.json"
  chmod 0400 "$stage/task.json"
  dd if=/dev/zero of="$RUNTIME/red-task.ext4" bs=1M count=4 status=none
  mke2fs -q -t ext4 -F -b 1024 -I 128 -L bayora-task -d "$stage" "$RUNTIME/red-task.ext4"
  rm -rf "$stage"
}

echo "==> booting the enclave (no network devices anywhere)"
boot blue 4 9001
boot llm  5 9002

echo
echo "==> waiting for the guests to answer over AF_UNIX vsock mediation"
python3 - "$RUNTIME" <<'PY'
import json, os, socket, struct, sys, time

runtime = sys.argv[1]

def call(sock_path, port, message, timeout=2.0):
    # Firecracker mediates the guest vsock over AF_UNIX: connect the host-side
    # uds socket, ask for the guest port with "CONNECT <port>\n", require the
    # exact "OK <port>\n" ack, then speak the length-prefixed JSON frame.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(sock_path)
        sock.sendall(f"CONNECT {port}\n".encode())
        ack = sock.makefile("rb").readline()
        # Firecracker acknowledges with "OK <host-side-assigned-port>", not
        # "OK <guest-port>"; a guest that is not listening terminates the
        # connection instead.
        if not ack.strip().startswith(b"OK "):
            raise OSError(f"vsock handshake failed: {ack!r}")
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

def wait(sock_path, port, message, predicate, label, timeout=20.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            reply = call(sock_path, port, message)
            if predicate(reply):
                print(f"    [ok] {label}")
                return reply
            last = reply
        except OSError as exc:
            last = exc
        time.sleep(0.2)
    raise SystemExit(f"    [FAILED] {label}: last response was {last!r}")

wait(os.path.join(runtime, "blue.vsock"), 9001,
     {"eval_id": "probe", "prompt": "hello"},
     lambda r: r.get("decision") == "allow", "blue answered a verdict")
PY

if [ -n "$TASK" ]; then
  [ -f "$TASK" ] || die "task file not found: $TASK"
  # Red dials CID 2:5000 from inside its VM; Firecracker forwards that to the
  # Referee's AF_UNIX listener at $RUNTIME/red.vsock_5000. The Referee must be
  # up and listening before Red boots, or Red's one-shot connect fails and
  # the evaluation cannot run.
  echo "==> waiting for the Referee's red listener ($RUNTIME/red.vsock_5000)"
  for _ in $(seq 1 300); do
    [ -S "$RUNTIME/red.vsock_5000" ] && break
    sleep 0.1
  done
  [ -S "$RUNTIME/red.vsock_5000" ] || \
    die "Referee is not listening on $RUNTIME/red.vsock_5000: start bayora-referee (--transport firecracker) before booting red"
  prepare_task_disk
  boot red 3 9000 "$RUNTIME/red-task.ext4"
else
  echo "    (no --task given: red is not booted; provision one evaluation first)"
fi

cat <<EOF

==> the enclave is up. In another shell, start the Referee on the host:

    cargo run -p bayora-referee -- \\
        --policy config/policy.yaml \\
        --images config/images.json \\
        --signer unix:$RUNTIME/signer.sock \\
        --runtime-dir $RUNTIME \\
        --firecracker-api $RUNTIME/fc-llm.sock \\
        --llm-port 9002 \\
        --transport firecracker \\
        --vsock-port 5000 \\
        --evidence-log evidence/evidence_log.ndjson \\
        --reset snapshot

  then drive it with a capability per evaluation, and let Red speak:

    python3 workloads/red-team/agent.py --vsock-port 5000

  (--host-cid is irrelevant under --transport firecracker: Firecracker maps
  the guest's CID 2 to the Referee's AF_UNIX listener at $RUNTIME/red.vsock_5000.)

  The Referee owns the llm Firecracker process: on each reset it kills the
  pidfile instance, respawns firecracker, loads the golden snapshot and waits
  for the restored llm to answer the CONNECT handshake before the turn runs.

  Ctrl-C here tears the VMs down. Guest logs: $RUNTIME/*.log
EOF

echo
echo "==> holding the enclave open (Ctrl-C to stop)"
while :; do sleep 3600; done
