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

set -eu

ROLE=$(sed -n 's/.*bayora\.role=\([a-z]*\).*/\1/p' /proc/cmdline)
PORT=$(sed -n 's/.*bayora\.port=\([0-9]*\).*/\1/p' /proc/cmdline)

mount -t proc  proc  /proc 2>/dev/null || true
mount -t sysfs sys   /sys  2>/dev/null || true
mount -t tmpfs tmpfs /tmp       2>/dev/null || true
mount -t tmpfs tmpfs /run       2>/dev/null || true
mount -t tmpfs tmpfs /var/log   2>/dev/null || true

mkdir -p /run/bayora /var/log/bayora

echo "bayora-init: role=$ROLE port=${PORT:-default} $(uname -r)" > /dev/kmsg 2>/dev/null || true

case "$ROLE" in
  blue)
    exec python3 /opt/bayora/blue-team/agent.py "${PORT:-9001}"
    ;;
  llm)
    exec python3 /opt/bayora/llm-engine/agent.py "${PORT:-9002}"
    ;;
  red)
    # Red's provisioning disk (/dev/vdb, prepared by microvm/boot_enclave.sh)
    # carries exactly one evaluation, one capability and one prompt. Red mounts
    # it, reads its orders, and the disk is gone when the VM dies.
    if [ -b /dev/vdb ]; then
      mkdir -p /run/bayora
      mount -t ext4 -o ro /dev/vdb /run/bayora 2>/dev/null || \
        echo "bayora-init: could not mount /dev/vdb" >&2
    fi
    for _ in $(seq 1 300); do
      [ -s /run/bayora/task.json ] && break
      sleep 0.1
    done
    exec python3 /opt/bayora/red-team/agent.py \
      --task /run/bayora/task.json \
      --transcript /var/log/bayora/red-transcript.ndjson
    ;;
  *)
    echo "bayora-init: unknown bayora.role '$ROLE' on the kernel command line" >&2
    exec sh
    ;;
esac
