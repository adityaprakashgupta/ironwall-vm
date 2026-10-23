#!/usr/bin/env bash
# Build the three immutable guest images and publish their content addresses.
#
# This is an offline, privileged, one-shot operation on the enclave host. It is
# the only place image bytes are ever produced; from here on, images are
# identified by digest and never rebuilt in place.
#
# For each role (red, blue, llm) it:
#   1. stages the guest payload (the Python agent + workloads/common) on top
#      of a minimal userspace -- busybox for /bin/sh and the applets init.sh
#      uses, plus a stripped Python 3 with only the libraries it links,
#   2. for the llm role, stages the model weights the manifest will pin,
#   3. packs it into an ext4 image sized to its content, with a deterministic
#      label/UUID,
#   4. mounts the image read-only and chroots into it, so an image that cannot
#      even import its own agent is never published,
#   5. seals the image read-only (mode 0444),
#   6. and then rewrites config/images.json with the fresh sha256 digests.
#
# Finally, unless --skip-golden, it boots the llm image once and asks
# Firecracker for the golden snapshot the Referee restores on every reset
# (`bayora-referee --reset snapshot --snapshot-path microvm/snapshots/llm-golden.snap`).
#
# Prerequisites (bare-metal or nested-virt Linux host):
#   * root, /dev/kvm, firecracker on PATH (see microvm/fetch_artifacts.sh)
#   * e2fsprogs (mke2fs), coreutils, util-linux (mount/chroot), binutils
#   * a static busybox (dnf install busybox ships one)
#   * python3 on the build host: its interpreter and stdlib are staged into
#     the guests (so the image digests cover them); their own digests are
#     echoed at build time as provenance
#   * an uncompressed kernel image: --kernel microvm/artifacts/vmlinux
#     (raw vmlinux ELF, not bzImage -- Firecracker does not decompress)
#   * the model weights the llm guest will carry: --model <file.gguf>
#
# The images are content-addressed: the label and UUID are fixed, so the only
# thing that varies between builds of the same tree is filesystem metadata
# that mke2fs stamps with the wall clock. Two builds are therefore *not*
# bit-identical, and the workflow does not pretend otherwise -- each build
# publishes its own digests, and a manifest pins the artifact that actually
# ran, not the one that would have been built.
#
# Usage:
#   sudo microvm/build_immutable_images.sh \
#       --kernel microvm/artifacts/vmlinux --model microvm/artifacts/model.gguf
#
#   Optional:
#     --image-size <MiB>   override the computed size for every role
#     --llama-wheel <whl>  prebuilt llama-cpp-python wheel for LLM guest
#                          (guests have no pip/network; must be staged at build)
#     --skip-golden        do not boot the llm image / take the golden snapshot
#     --golden-only        skip building the images; regenerate the golden
#                          snapshot from the already-built llm image and
#                          republish config/images.json only
#     --firecracker <path> firecracker binary if not on PATH
#
# Environment:
#   FIRECRACKER              same as --firecracker
#   BAYORA_IMAGES_DIR        where to publish images (default: microvm/images)
#   BAYORA_SNAPSHOTS_DIR     where to publish the golden snapshot
#                            (default: microvm/snapshots)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MICROVM="$ROOT/microvm"
ARTIFACTS="$MICROVM/artifacts"
# Guest images are large binary artifacts (gitignored anyway). On WSL the repo
# sits on /mnt/c behind 9p, which is a poor place for a VM to page its rootfs
# and its 491 MB of weights from; BAYORA_IMAGES_DIR moves them onto the native
# Linux filesystem. Same content-addressed contract either way -- only the
# location of the bytes changes, never the digests published below.
IMAGES="${BAYORA_IMAGES_DIR:-$MICROVM/images}"
SNAPSHOTS="${BAYORA_SNAPSHOTS_DIR:-$MICROVM/snapshots}"
IMAGES_JSON="$ROOT/config/images.json"

KERNEL=""
MODEL=""
IMAGE_SIZE_MB=""   # empty = compute per role from the staged content
SKIP_GOLDEN=0
GOLDEN_ONLY=0
FIRECRACKER="${FIRECRACKER:-firecracker}"
LLAMA_WHEEL=""     # path to prebuilt llama-cpp-python wheel for the LLM guest

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
    --golden-only)  GOLDEN_ONLY=1; shift ;;
    --firecracker)  FIRECRACKER="$2"; shift 2 ;;
    --llama-wheel)  LLAMA_WHEEL="$2"; shift 2 ;;
    -h|--help)      usage 0 ;;
    *)              echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

die() { echo "build_immutable_images: $*" >&2; exit 1; }

# Firecracker exposes each guest vsock on the host as a Unix socket at
# <uds_path>; the host asks for a guest port with "CONNECT <port>\n" and the
# device answers "OK <port>\n". Probe until the guest's agent answers, so the
# golden snapshot is frozen from an idle, listening VM rather than mid-boot.
fc_connect_ok() {
  local sock="$1" port="$2"
  python3 - "$sock" "$port" <<'PY'
import socket, sys
sock, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_UNIX)
s.settimeout(2.0)
try:
    s.connect(sock)
    s.sendall(f"CONNECT {port}\n".encode())
    line = s.makefile("rb").readline()
    # Firecracker acknowledges with "OK <host-side-assigned-port>" (e.g.
    # "OK 1073741824"), not "OK <guest-port>". A guest that is not listening
    # on `port` causes the connection to be terminated instead.
    sys.exit(0 if line.strip().startswith(b"OK ") else 1)
finally:
    s.close()
PY
}

[ "$(id -u)" = 0 ] || die "must run as root (mke2fs -d needs to set guest ownership)"
[ -e /dev/kvm ] || die "/dev/kvm is missing: this host cannot run Firecracker"
command -v mke2fs >/dev/null || die "mke2fs not found (install e2fsprogs)"
command -v "$FIRECRACKER" >/dev/null || die "firecracker not found (set FIRECRACKER=...)"
command -v python3 >/dev/null || die "python3 not found: its interpreter and stdlib are staged into the guests"
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

# The llama-cpp-python wheel provides real inference inside the LLM guest.
# It must be prebuilt for the guest's Python version and architecture; guests
# have no package index and no network, so it must be staged at build time.
if [ -n "$LLAMA_WHEEL" ]; then
  [ -f "$LLAMA_WHEEL" ] || die "llama-cpp-python wheel not found: $LLAMA_WHEEL"
  case "$LLAMA_WHEEL" in
    *.whl) ;;
    *) die "--llama-wheel must be a .whl file, got: $LLAMA_WHEEL" ;;
  esac
else
  echo "note: no --llama-wheel given; LLM guest will use hash-based fallback inference"
fi

BUSYBOX="$(command -v busybox || true)"
[ -n "$BUSYBOX" ] || die "busybox not found: the guests need it for /bin/sh.
       Install a static build (e.g. 'dnf install busybox') and re-run."
# The guest has no shared-library loader beyond what Python already needs, so
# the busybox staged into it must resolve nothing at runtime.
if ldd "$BUSYBOX" >/dev/null 2>&1; then
  die "busybox at $BUSYBOX is dynamically linked; the guest cannot resolve its
       libraries. Install a static build (on Fedora, 'dnf install busybox'
       ships one)."
fi

KERNEL_DIGEST="sha256:$(sha256sum "$KERNEL" | cut -d' ' -f1)"
MODEL_DIGEST="sha256:$(sha256sum "$MODEL" | cut -d' ' -f1)"
FIRECRACKER_VERSION="$("$FIRECRACKER" --version | head -1 | awk '{print $2}')"
case "$FIRECRACKER_VERSION" in
  v[0-9]*) ;;
  *) die "could not parse a version out of '$FIRECRACKER --version' (got: $FIRECRACKER_VERSION).
       Refusing to publish an unparseable firecracker_version into images.json." ;;
esac
# The defence policy is guest-side code, so its digest is over policy.py: an
# auditor can rebuild the image and check that this file -- and nothing else --
# decides blue's verdicts.
BLUE_POLICY_DIGEST="sha256:$(sha256sum "$ROOT/workloads/common/policy.py" | cut -d' ' -f1)"
BUSYBOX_DIGEST="sha256:$(sha256sum "$BUSYBOX" | cut -d' ' -f1)"

# The interpreter and its stdlib are guest-side code too, so their digests are
# recorded: the manifest pins not only which policy and which weights ran, but
# which Python decided the bytes it was handed.
PYTHON_BIN="$(readlink -f "$(command -v python3)")"
PYTHON_STDLIB="$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')"
PYTHON_DIGEST="sha256:$(sha256sum "$PYTHON_BIN" | cut -d' ' -f1)"
STDLIB_DIGEST="sha256:$(tar -C "$(dirname "$PYTHON_STDLIB")" -cf - \
      --exclude='__pycache__' --exclude='test' --exclude='tests' \
      --exclude='idlelib' --exclude='tkinter' --exclude='turtledemo' \
      "$(basename "$PYTHON_STDLIB")" | sha256sum | cut -d' ' -f1)"

mkdir -p "$IMAGES" "$SNAPSHOTS"

# --- staging ---------------------------------------------------------------

# Copy a shared object and everything it links to, preserving absolute paths,
# so the guest's dynamic loader finds each library where it expects it.
stage_libs_for() {
  local binary="$1" stage="$2" lib
  ldd "$binary" 2>/dev/null | awk '/=>/ {print $3} /^\// {print $NF}' | while read -r lib; do
    [ -n "$lib" ] && [ -e "$lib" ] || continue
    mkdir -p "$stage$(dirname "$lib")"
    cp -L "$lib" "$stage$lib" 2>/dev/null || true
  done
}

# The minimal userspace every guest gets: a static busybox providing /bin/sh
# and the applets init.sh uses, plus a stripped Python 3 with only the
# libraries its interpreter and extension modules actually link against.
stage_base() {
  local stage="$1"

  mkdir -p "$stage/bin" "$stage/usr/bin" "$stage/usr/lib64" "$stage/lib64" \
           "$stage/etc" "$stage/proc" "$stage/sys" "$stage/dev" \
           "$stage/tmp" "$stage/run" "$stage/var/log" "$stage/root"

  # busybox: one static binary; the applets init.sh and the agents touch are
  # symlinked in. /bin/sh is busybox's ash.
  cp "$BUSYBOX" "$stage/bin/busybox"
  chmod 0755 "$stage/bin/busybox"
  local applet
  for applet in sh ash mount umount mkdir sed sleep seq echo cat ls grep \
                sha256sum cut head basename dirname env test true false; do
    ln -sf busybox "$stage/bin/$applet"
  done

  # /etc/passwd and /etc/group: the interpreter looks up the current user, and
  # an image with no root entry at all is a surprise at runtime.
  printf 'root:x:0:0:root:/root:/bin/sh\n' > "$stage/etc/passwd"
  printf 'root:x:0:\n' > "$stage/etc/group"

  # Python: the interpreter, its stdlib (minus tests and byte-code caches the
  # interpreter would want to rewrite), and every shared object the
  # interpreter and its extension modules link against.
  local pyver site_packages so loader
  pyver="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  mkdir -p "$stage/usr/lib64/python$pyver"
  cp -a "$PYTHON_STDLIB/." "$stage/usr/lib64/python$pyver/"
  find "$stage/usr/lib64/python$pyver" -type d \( -name '__pycache__' -o -name 'test' \
       -o -name 'tests' -o -name 'idlelib' -o -name 'tkinter' -o -name 'turtledemo' \) \
       -prune -exec rm -rf {} + 2>/dev/null || true

  if [ -d "$PYTHON_STDLIB/lib-dynload" ]; then
    for so in "$PYTHON_STDLIB"/lib-dynload/*.so; do
      [ -e "$so" ] || continue
      stage_libs_for "$so" "$stage"
    done
  fi

  cp -L "$PYTHON_BIN" "$stage/usr/bin/python3"
  chmod 0755 "$stage/usr/bin/python3"
  stage_libs_for "$PYTHON_BIN" "$stage"

  # site-packages, in case the payload imports something from the host env.
  site_packages="$(python3 -c 'import sysconfig; print(sysconfig.get_path("platlib"))' 2>/dev/null || true)"
  if [ -n "$site_packages" ] && [ -d "$site_packages" ]; then
    mkdir -p "$stage$site_packages"
    cp -a "$site_packages/." "$stage$site_packages/" 2>/dev/null || true
    find "$stage$site_packages" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
  fi

  # The dynamic loader itself; the interpreter's DT_INTERP points at it.
  loader="$(readelf -l "$PYTHON_BIN" 2>/dev/null \
            | awk '/Requesting program interpreter/ {gsub(/[][]/,""); print $NF}')"
  if [ -n "$loader" ] && [ -e "$loader" ]; then
    mkdir -p "$stage$(dirname "$loader")"
    cp -L "$loader" "$stage$loader"
  fi
}

stage_guest() {
  local role="$1" stage="$2"
  # Role name (red/blue/llm, used for image name and boot cmdline) vs payload
  # directory (the agent's own name, which is what init.sh execs).
  local dir
  case "$role" in
    red)  dir=red-team ;;
    blue) dir=blue-team ;;
    llm)  dir=llm-engine ;;
    *)    die "unknown role $role" ;;
  esac
  rm -rf "$stage"
  mkdir -p "$stage/opt/bayora" "$stage/run/bayora" "$stage/var/log/bayora"

  # The base userspace first, then the payload on top of it.
  stage_base "$stage"

  # The guest payload: one agent plus the shared guest library. Anything not
  # copied here simply does not exist inside the VM.
  cp -r "$ROOT/workloads/common" "$stage/opt/bayora/common"
  cp -r "$ROOT/workloads/$dir" "$stage/opt/bayora/$dir"
  cp "$MICROVM/guest/init.sh" "$stage/opt/bayora/init.sh"
  chmod 0755 "$stage/opt/bayora/init.sh"

  find "$stage/opt" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "$stage/opt" -name '*.pyc' -delete 2>/dev/null || true

  # The llm guest carries the model weights; init.sh verifies their digest
  # against the kernel command line before the agent binds its socket.
  if [ "$role" = llm ]; then
    cp "$MODEL" "$stage/opt/bayora/model.gguf"
    chmod 0444 "$stage/opt/bayora/model.gguf"

    # Stage llama-cpp-python wheel and ALL its dependency wheels so the LLM
    # guest can run real inference without a package index or network.
    if [ -n "$LLAMA_WHEEL" ]; then
      local llama_stage="$stage/usr/local/lib64/python3.14/site-packages"
      mkdir -p "$llama_stage"
      # Unpack the main wheel (it's a zip) directly into site-packages.
      python3 -c "
import zipfile, sys
with zipfile.ZipFile('$LLAMA_WHEEL') as z:
    z.extractall('$llama_stage')
"
      # Also unpack any sibling wheels in the same directory (dependencies
      # such as typing_extensions, numpy, jinja2, markupsafe, diskcache).
      local wheel_dir
      wheel_dir="$(dirname "$LLAMA_WHEEL")"
      for dep_wheel in "$wheel_dir"/*.whl; do
        [ -f "$dep_wheel" ] || continue
        [ "$dep_wheel" = "$LLAMA_WHEEL" ] && continue
        python3 -c "
import zipfile, sys
with zipfile.ZipFile('$dep_wheel') as z:
    z.extractall('$llama_stage')
"
      done
      # Stage shared library dependencies of the compiled llama backend.
      stage_libs_for "$llama_stage/llama_cpp/libllama.so" "$stage" 2>/dev/null || true
      stage_libs_for "$llama_stage/llama_cpp/_llama.so" "$stage" 2>/dev/null || true

      # Explicitly copy key system libraries needed by libllama.so that
      # stage_libs_for may miss (e.g. libstdc++.so.6, libgcc_s.so.1).
      local sys_lib_dir="$stage/usr/lib64"
      mkdir -p "$sys_lib_dir"
      for sys_lib in libstdc++.so.6 libgcc_s.so.1 libgomp.so.1 libpthread.so.0; do
        local sys_lib_path
        # Find the library on the host system (follow symlinks)
        sys_lib_path="$(find -L /usr/lib64 /usr/lib -name "$sys_lib" -type f 2>/dev/null | head -1)"
        if [ -n "$sys_lib_path" ] && [ -e "$sys_lib_path" ]; then
          cp -L "$sys_lib_path" "$sys_lib_dir/" 2>/dev/null || true
        fi
      done
    fi
  fi
}

# Size each image to its staged content, with headroom for the filesystem's
# own bookkeeping. A fixed 64 MiB would not hold a 491 MiB model, and a fixed
# size large enough for the model would waste it on the other two roles.
compute_size_mb() {
  local stage="$1" content_mb
  content_mb="$(du -sm "$stage" | cut -f1)"
  # content + 20% + 8 MiB for inode tables and journals.
  echo $(( content_mb + content_mb / 5 + 8 ))
}

build_image() {
  local role="$1" out="$2" stage="$3"
  local label="bayora-${role}"
  local size_mb="${IMAGE_SIZE_MB:-$(compute_size_mb "$stage")}"

  echo "==> building $label ($size_mb MiB)"
  # A fixed UUID keeps the digest a function of *content*, not of when it was
  # built, so two builds of the same tree produce the same image.
  local uuid
  case "$role" in
    blue) uuid="b1a0e0a1-0000-4000-8000-000000000004" ;;
    llm)  uuid="b1a0e0a1-0000-4000-8000-000000000005" ;;
    red)  uuid="b1a0e0a1-0000-4000-8000-000000000003" ;;
  esac

  dd if=/dev/zero of="$out" bs=1M count="$size_mb" status=none
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

# Run the staged payload's own imports inside the exact bytes that were just
# hashed: loop-mount the image read-only and chroot into it. An image that
# cannot start its agent here must never reach config/images.json.
self_test_image() {
  local role="$1" image="$2" mnt ok=0
  # Same role -> payload directory mapping as stage_guest.
  local dir
  case "$role" in
    red)  dir=red-team ;;
    blue) dir=blue-team ;;
    llm)  dir=llm-engine ;;
  esac
  mnt="$(mktemp -d)"

  if ! mount -o loop,ro "$image" "$mnt" 2>/dev/null; then
    echo "    [warn] could not loop-mount $image for the self-test; skipping" >&2
    rmdir "$mnt" 2>/dev/null || true
    return 0
  fi

  local err="$WORK/selftest-$role.err"
  if chroot "$mnt" /usr/bin/python3 - "$dir" 2>"$err" <<'PY'; then
import importlib.util, sys
dir = sys.argv[1]
spec = importlib.util.spec_from_file_location("agent", f"/opt/bayora/{dir}/agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)   # raises if any import fails inside the image
# Entry points differ by role: red drives itself from main(), blue and llm
# bind a listener from serve(). Either is fine -- what must hold is that the
# module loads and has the entry point its own __main__ block calls.
assert hasattr(agent, "main") or hasattr(agent, "serve"), \
    f"{dir} agent defines neither main() nor serve()"
sys.path.insert(0, "/opt/bayora")
import common.wire, common.policy  # noqa: F401
print(f"{dir} payload ok")
PY
    ok=1
  fi

  umount "$mnt" 2>/dev/null || true
  rmdir "$mnt" 2>/dev/null || true

  if [ "$ok" = 1 ]; then
    echo "    [ok] $role payload imports and starts inside the image"
  else
    echo "    chroot stderr follows:" >&2
    sed 's/^/      /' "$err" >&2 || true
    die "$role image failed its in-image self-test.
       The image was built but will not be published: an image that cannot
       run its agent is not a deployable artifact. Check the chroot error
       above (usually a shared library the staged python needs but does not
       link, or a missing applet)."
  fi
}

WORK="$(mktemp -d)"
# Set when the snapshot helper launches a Firecracker, so the main trap can
# reap it if the build dies mid-snapshot. (A trap inside the helper would
# reference a `local` that has already gone out of scope.)
SNAP_FC_PID=""
cleanup() {
  [ -n "$SNAP_FC_PID" ] && kill "$SNAP_FC_PID" 2>/dev/null || true
  # NOTE: $WORK is intentionally preserved so the golden-snapshot debug logs
  # (fc-llm.log, serial) can be inspected after a failure.
}
trap cleanup EXIT

if [ "$GOLDEN_ONLY" = 0 ]; then
  for role in red blue llm; do
    stage="$WORK/$role"
    out="$IMAGES/$role.ext4"
    [ -e "$out" ] && die "$out already exists.
         Images are content-addressed and immutable: build into a fresh
         microvm/images/ directory rather than overwriting one in place."
    stage_guest "$role" "$stage"
    build_image "$role" "$out" "$stage"
    self_test_image "$role" "$out"
  done
else
  for role in red blue llm; do
    [ -f "$IMAGES/$role.ext4" ] || \
      die "$IMAGES/$role.ext4 is missing: build the images first (drop --golden-only)"
  done
fi

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
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/opt/bayora/init.sh bayora.role=llm bayora.port=9002 bayora.model_sha256=${MODEL_DIGEST#sha256:}"
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
  SNAP_FC_PID=$!
  local fc_pid="$SNAP_FC_PID"

  for _ in $(seq 1 100); do [ -S "$api_sock" ] && break; sleep 0.1; done
  [ -S "$api_sock" ] || { echo "firecracker did not open $api_sock" >&2; exit 1; }

  # `--config-file` configures the microVM but does not necessarily start it;
  # the vsock device (and therefore the host-side $WORK/llm.vsock socket) is
  # only created once the guest is running. Start it explicitly; a second
  # start is a no-op that Firecracker reports as an error we ignore.
  curl -s -f -X PUT "http://localhost/actions" --unix-socket "$api_sock" \
    -H 'Content-Type: application/json' -d '{"action_type":"InstanceStart"}' >/dev/null 2>&1 || true

  # Freeze the image from an idle, listening guest: probe the mediated vsock
  # until the llm agent answers the CONNECT handshake (guest port 9002). A
  # snapshot frozen mid-boot would make every restored instance pay ~1.2 s of
  # boot latency before it can answer its first turn.
  for _ in $(seq 1 600); do
    fc_connect_ok "$WORK/llm.vsock" 9002 && break
    sleep 0.1
  done
  fc_connect_ok "$WORK/llm.vsock" 9002 || {
    echo "golden snapshot: llm agent never answered on $WORK/llm.vsock (CONNECT 9002)" >&2
    exit 1
  }

  # The guest refuses to serve on a digest mismatch; if init is stuck in its
  # fail-closed loop, the serial log says so and a snapshot of that state
  # would be useless. Read the log before freezing anything.
  if grep -q "model digest mismatch" "$WORK/fc-llm.log" 2>/dev/null; then
    echo "golden snapshot: the llm guest refused its own model digest:" >&2
    grep "bayora-init" "$WORK/fc-llm.log" >&2 || true
    exit 1
  fi

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
# Note what is deliberately *not* written here: the python, stdlib and busybox
# digests are echoed above but stay out of this file, because ImageRegistry
# (crates/bayora-common/src/manifest.rs) denies unknown fields and the Referee
# must load this file verbatim. Their bytes are already pinned transitively --
# they live inside the three images, whose digests are below -- so a manifest
# that pins the images pins them.
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
echo "    python      $PYTHON_DIGEST   (inside the images)"
echo "    stdlib      $STDLIB_DIGEST   (inside the images)"
echo "    busybox     $BUSYBOX_DIGEST  (inside the images)"
echo
echo "Every digest above is measured from the bytes just produced; the seven"
echo "in images.json are what the Referee pins into each evaluation's signed"
echo "manifest. Rebuilding later yields fresh digests, which is the point:"
echo "a manifest must describe the artifact that actually ran, not the one"
echo "that would have been built."
