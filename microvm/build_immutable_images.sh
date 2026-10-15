#!/usr/bin/env bash
# Build the three immutable guest images and publish their content addresses.
#
# This is an offline, privileged, one-shot operation on the enclave host. It is
# the only place image bytes are ever produced; from here on, images are
# identified by digest and never rebuilt in place.
#
# For each role (red, blue, llm) it:
#   1. stages the guest payload (the Python agent + workloads/common) in a
#      scratch directory,
#   2. packs it into a fixed-size ext4 image with a deterministic label/UUID,
#   3. seals the image read-only (mode 0444),
#   4. and then rewrites config/images.json with the fresh sha256 digests.
#
# Finally, unless --skip-golden, it boots the llm image once and asks
# Firecracker for the golden snapshot the Referee restores on every reset
# (`bayora-referee --reset snapshot --snapshot-path microvm/snapshots/llm-golden.snap`).
#
# Prerequisites (bare-metal or nested-virt Linux host):
#   * root, /dev/kvm, firecracker on PATH
#   * e2fsprogs (mke2fs), coreutils
#   * an uncompressed kernel image: --kernel microvm/artifacts/vmlinux
#   * the model weights for the llm image: --model microvm/artifacts/model.gguf
#
# Usage:
#   sudo microvm/build_immutable_images.sh --kernel artifacts/vmlinux --model artifacts/model.gguf

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MICROVM="$ROOT/microvm"
ARTIFACTS="$MICROVM/artifacts"
IMAGES="$MICROVM/images"
SNAPSHOTS="$MICROVM/snapshots"
IMAGES_JSON="$ROOT/config/images.json"

KERNEL=""
MODEL=""
IMAGE_SIZE_MB=64
SKIP_GOLDEN=0
FIRECRACKER="${FIRECRACKER:-firecracker}"

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//; $d'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --kernel)       KERNEL="$2"; shift 2 ;;
    --model)        MODEL="$2"; shift 2 ;;
    --image-size)   IMAGE_SIZE_MB="$2"; shift 2 ;;
    --skip-golden)  SKIP_GOLDEN=1; shift ;;
    -h|--help)      usage 0 ;;
    *)              echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

die() { echo "build_immutable_images: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (mke2fs -d needs to set guest ownership)"
[ -e /dev/kvm ] || die "/dev/kvm is missing: this host cannot run Firecracker"
command -v mke2fs >/dev/null || die "mke2fs not found (install e2fsprogs)"
command -v "$FIRECRACKER" >/dev/null || die "firecracker not found (set FIRECRACKER=...)"
[ -n "$KERNEL" ] || die "--kernel <vmlinux> is required"
[ -f "$KERNEL" ] || die "kernel image not found: $KERNEL"

if [ -z "$MODEL" ]; then
  MODEL="$ARTIFACTS/model.gguf"
  echo "note: no --model given, defaulting to $MODEL"
fi

# The model digest is what the manifest pins, so it has to be the real thing.
if [ ! -f "$MODEL" ]; then
  die "model weights not found: $MODEL
       Supply the weights with --model <path>. A deployment that cannot prove
       which weights it ran cannot prove anything else about its answers."
fi

KERNEL_DIGEST="sha256:$(sha256sum "$KERNEL" | cut -d' ' -f1)"
MODEL_DIGEST="sha256:$(sha256sum "$MODEL" | cut -d' ' -f1)"
FIRECRACKER_VERSION="$("$FIRECRACKER" --version | awk '{print $2}')"
# The defence policy is guest-side code, so its digest is over policy.py: an
# auditor can rebuild the image and check that this file -- and nothing else --
# decides blue's verdicts.
BLUE_POLICY_DIGEST="sha256:$(sha256sum "$ROOT/workloads/common/policy.py" | cut -d' ' -f1)"

mkdir -p "$IMAGES" "$SNAPSHOTS"

stage_guest() {
  local role="$1" stage="$2"
  rm -rf "$stage"
  mkdir -p "$stage/opt/bayora" "$stage/run/bayora" "$stage/var/log/bayora" \
           "$stage/proc" "$stage/sys" "$stage/tmp" "$stage/dev"

  # The guest payload: one agent plus the shared guest library. Anything not
  # copied here simply does not exist inside the VM.
  cp -r "$ROOT/workloads/common" "$stage/opt/bayora/common"
  cp -r "$ROOT/workloads/$role" "$stage/opt/bayora/$role"
  cp "$MICROVM/guest/init.sh" "$stage/opt/bayora/init.sh"
  chmod 0755 "$stage/opt/bayora/init.sh"

  find "$stage/opt" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "$stage/opt" -name '*.pyc' -delete 2>/dev/null || true
}

build_image() {
  local role="$1" out="$2" stage="$3"
  local label="bayora-${role}"

  echo "==> building $label ($IMAGE_SIZE_MB MiB)"
  # A fixed UUID keeps the digest a function of *content*, not of when it was
  # built, so two builds of the same tree produce the same image.
  local uuid
  case "$role" in
    blue) uuid="b1a0e0a1-0000-4000-8000-000000000004" ;;
    llm)  uuid="b1a0e0a1-0000-4000-8000-000000000005" ;;
    red)  uuid="b1a0e0a1-0000-4000-8000-000000000003" ;;
  esac

  dd if=/dev/zero of="$out" bs=1M count="$IMAGE_SIZE_MB" status=none
  # Run as root so `-d` copies the payload with root:root ownership, which is
  # all the guest needs (init mounts it read-only and never writes to it).
  mke2fs -q -t ext4 -F -b 1024 -I 128 -L "$label" -U "$uuid" -d "$stage" "$out"
  # Shrink to the minimum that still holds the content, then re-check.
  e2fsck -f -y "$out" >/dev/null 2>&1 || true
  resize2fs -M "$out" >/dev/null 2>&1 || true
  e2fsck -f -y "$out" >/dev/null 2>&1 || true

  chmod 0444 "$out"
  echo "    $(sha256sum "$out" | cut -d' ' -f1)  $(basename "$out")"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for role in red blue llm; do
  stage="$WORK/$role"
  out="$IMAGES/$role.ext4"
  [ -e "$out" ] && die "$out already exists.
       Images are content-addressed and immutable: build into a fresh
       microvm/images/ directory rather than overwriting one in place."
  stage_guest "$role" "$stage"
  build_image "$role" "$out" "$stage"
done

RED_DIGEST="sha256:$(sha256sum "$IMAGES/red.ext4" | cut -d' ' -f1)"
BLUE_DIGEST="sha256:$(sha256sum "$IMAGES/blue.ext4" | cut -d' ' -f1)"
LLM_DIGEST="sha256:$(sha256sum "$IMAGES/llm.ext4" | cut -d' ' -f1)"

# --- golden snapshot -------------------------------------------------------
# The Referee restores this on every reset, so the snapshot has to be taken
# from a booted, idle llm VM (a snapshot of a VM that had already served a
# prompt would carry that prompt's state into every later evaluation).
create_golden_snapshot() {
  local api_sock="$WORK/fc-llm.sock" config="$WORK/fc-llm.json"
  local snapshot="$SNAPSHOTS/llm-golden.snap" mem="$SNAPSHOTS/llm-golden.mem"
  rm -f "$snapshot" "$mem"

  cat > "$config" <<JSON
{
  "boot-source": {
    "kernel_image_path": "$KERNEL",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/opt/bayora/init.sh bayora.role=llm bayora.port=9002"
  },
  "drives": [
    { "drive_id": "rootfs", "path_on_host": "$IMAGES/llm.ext4",
      "is_root_device": true, "is_read_only": true }
  ],
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 256, "smt": false },
  "vsock": { "guest_cid": 5, "uds_path": "$WORK/llm.vsock" },
  "logger": { "log_path": "$WORK/fc-llm.log", "level": "Warning" }
}
JSON

  "$FIRECRACKER" --api-sock "$api_sock" --config-file "$config" >/dev/null 2>&1 &
  local fc_pid=$!
  trap 'kill $fc_pid 2>/dev/null || true; rm -rf "$WORK"' EXIT

  for _ in $(seq 1 100); do [ -S "$api_sock" ] && break; sleep 0.1; done
  [ -S "$api_sock" ] || { echo "firecracker did not open $api_sock" >&2; exit 1; }
  sleep 2   # let the guest finish booting before freezing it

  curl -s -f -X PATCH "http://localhost/vm" --unix-socket "$api_sock" \
    -H 'Content-Type: application/json' -d '{"state":"Paused"}' >/dev/null
  curl -s -f -X PUT "http://localhost/snapshot/create" --unix-socket "$api_sock" \
    -H 'Content-Type: application/json' \
    -d "{\"snapshot_type\":\"Full\",\"snapshot_path\":\"$snapshot\",\"mem_file_path\":\"$mem\"}" \
    >/dev/null
  kill "$fc_pid" 2>/dev/null || true
  wait "$fc_pid" 2>/dev/null || true
  chmod 0444 "$snapshot" "$mem"
  echo "==> golden snapshot: $snapshot"
}

if [ "$SKIP_GOLDEN" = 0 ]; then
  if command -v curl >/dev/null; then
    create_golden_snapshot
  else
    echo "note: curl not found, skipping the golden snapshot (--skip-golden)" >&2
  fi
fi

# --- publish the content addresses ----------------------------------------
cat > "$IMAGES_JSON" <<JSON
{
  "kernel_digest": "$KERNEL_DIGEST",
  "red_image_digest": "$RED_DIGEST",
  "blue_image_digest": "$BLUE_DIGEST",
  "llm_image_digest": "$LLM_DIGEST",
  "model_digest": "$MODEL_DIGEST",
  "blue_policy_digest": "$BLUE_POLICY_DIGEST",
  "firecracker_version": "$FIRECRACKER_VERSION"
}
JSON

echo
echo "==> config/images.json rewritten from the bytes just produced"
echo "    kernel      $KERNEL_DIGEST"
echo "    red         $RED_DIGEST"
echo "    blue        $BLUE_DIGEST"
echo "    llm         $LLM_DIGEST"
echo "    model       $MODEL_DIGEST"
echo "    blue policy $BLUE_POLICY_DIGEST"
echo
echo "Every digit above is what the Referee will pin into each evaluation's"
echo "signed manifest. Change one byte of any input and the next evaluation"
echo "will not verify against the old manifests."
