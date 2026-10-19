#!/bin/sh
# PID 1 inside every Bayora MicroVM.
#
# The kernel mounts the root filesystem read-only (Firecracker config sets
# `is_read_only: true`), so this init cannot change the guest image even if the
# agent it launches is compromised. The only writable paths are tmpfs mounts,
# which live and die with the VM -- that is what makes a state reset both
# meaningful and cheap: there is nothing persistent to clean up.
#
# The role arrives on the kernel command line and nowhere else, because the
# guest has no configuration channel to attack.
#
# Everything this script needs is inside the image: /bin/sh and the small set
# of applets below are busybox, python3 is staged by the image build. There is
# no package manager, no shell profile, no libc other than what the interpreter
# was linked against.

set -eu

# The image ships busybox applets in /bin and python3 in /usr/bin; nothing
# else. PATH must be set before the first external command.
PATH=/usr/bin:/bin
export PATH

# /proc must be mounted before /proc/cmdline can be read -- the original
# ordering read it first and would have died under `set -e` on a real boot.
mount -t proc  proc  /proc 2>/dev/null || true
mount -t sysfs sys   /sys  2>/dev/null || true
# devtmpfs gives the guest its device nodes (/dev/null, /dev/kmsg, and for the
# red role the provisioning disk /dev/vdb). Without it Red's task disk would
# not exist.
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /tmp       2>/dev/null || true
mount -t tmpfs tmpfs /run       2>/dev/null || true
mount -t tmpfs tmpfs /var/log   2>/dev/null || true

mkdir -p /run/bayora /var/log/bayora

ROLE=$(sed -n 's/.*bayora\.role=\([a-z]*\).*/\1/p' /proc/cmdline)
PORT=$(sed -n 's/.*bayora\.port=\([0-9]*\).*/\1/p' /proc/cmdline)
MODEL_SHA=$(sed -n 's/.*bayora\.model_sha256=\([0-9a-f]\{64\}\).*/\1/p' /proc/cmdline)

echo "bayora-init: role=$ROLE port=${PORT:-default} $(uname -r)" > /dev/kmsg 2>/dev/null || true

case "$ROLE" in
  red)
    # Red's one provisioning disk: mount it read-only, and once the agent has
    # read the task out of it, make it disappear. Red cannot be asked to
    # re-run, cannot recover a consumed prompt, and cannot keep evidence of
    # what it was told to try.
    if [ -b /dev/vdb ]; then
      mkdir -p /run/bayora
      mount -t ext4 -o ro /dev/vdb /run/bayora 2>/dev/null || true
    fi
    # Red is a *client*: it connects out to the host's Referee listener
    # (--vsock-port) with the task it just mounted, so there is no port for it
    # to bind and no positional argument. All its inputs are flags.
    ls -l /dev/vdb > /dev/kmsg 2>&1 || true
    ls -l /run/bayora > /dev/kmsg 2>&1 || true
    echo "exec python3 /opt/bayora/red-team/agent.py" > /dev/kmsg 2>/dev/null || true
    exec python3 /opt/bayora/red-team/agent.py
    ;;
  blue)
    echo "exec python3 /opt/bayora/blue-team/agent.py ${PORT:-9001}" > /dev/kmsg 2>/dev/null || true
    exec python3 /opt/bayora/blue-team/agent.py "${PORT:-9001}"
    ;;
  llm)
    # The llm guest carries the model weights, and must be told which weights
    # to expect: without a digest on the command line it refuses to serve at
    # all, so there is no path to running unverified weights. The digest comes
    # from config/images.json (what the build measured) via boot_enclave.sh.
    if [ -z "$MODEL_SHA" ]; then
      echo "bayora-init: llm role requires bayora.model_sha256, refusing to serve" > /dev/kmsg 2>/dev/null || true
      while :; do sleep 3600; done
    fi
    if [ ! -f /opt/bayora/model.gguf ]; then
      echo "bayora-init: model file missing, refusing to serve" > /dev/kmsg 2>/dev/null || true
      while :; do sleep 3600; done
    fi
    # This check runs before the agent binds its socket, so a failed check
    # means the Referee sees a deadline abort -- fail closed.
    if ! echo "$MODEL_SHA  /opt/bayora/model.gguf" | sha256sum -c - >/dev/null 2>&1; then
      echo "bayora-init: model digest mismatch, refusing to serve" > /dev/kmsg 2>/dev/null || true
      echo "bayora-init: wanted $MODEL_SHA" > /dev/kmsg 2>/dev/null || true
      echo "bayora-init: got    $(sha256sum /opt/bayora/model.gguf | cut -d' ' -f1)" > /dev/kmsg 2>/dev/null || true
      while :; do sleep 3600; done
    fi
    echo "bayora-init: model sha256 verified" > /dev/kmsg 2>/dev/null || true
    echo "exec python3 /opt/bayora/llm-engine/agent.py ${PORT:-9002}" > /dev/kmsg 2>/dev/null || true
    exec python3 /opt/bayora/llm-engine/agent.py "${PORT:-9002}"
    ;;
  *)
    echo "bayora-init: no or unknown bayora.role ('$ROLE'); debug shell" > /dev/kmsg 2>/dev/null || true
    exec sh
    ;;
esac
