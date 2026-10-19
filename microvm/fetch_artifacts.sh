#!/usr/bin/env bash
# Fetch the three external artifacts the enclave build needs, once, pinned.
#
#   microvm/artifacts/firecracker   the VMM binary (verified against the release
#                                   sha256 published by the Firecracker project)
#   microvm/artifacts/vmlinux       an uncompressed guest kernel (verified to be
#                                   an ELF image; sourced from Firecracker's CI)
#   microvm/artifacts/model.gguf    the model weights the llm guest carries
#                                   (verified against Hugging Face's LFS sha256)
#
# This script is idempotent: an artifact that is already present and passes its
# check is left alone. Everything lands under microvm/artifacts/, which is
# gitignored -- these are third-party bytes, not ours, and the digests that
# matter are the ones build_immutable_images.sh publishes into
# config/images.json after it has measured the bytes it actually used.
#
# Usage:
#   microvm/fetch_artifacts.sh
#   FIRECRACKER_VERSION=v1.17.0 microvm/fetch_artifacts.sh   # pin another FC
#   ARCH=x86_64 microvm/fetch_artifacts.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS="$ROOT/microvm/artifacts"

ARCH="${ARCH:-$(uname -m)}"
FC_VERSION="${FIRECRACKER_VERSION:-v1.17.0}"
S3="${FIRECRACKER_CI_S3:-https://s3.amazonaws.com/spec.ccfc.min}"
MODEL_URL="${BAYORA_MODEL_URL:-https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf}"

# The task cards promise only bytes we can prove; die loudly instead of
# downloading something we cannot check.
die() { echo "fetch_artifacts: $*" >&2; exit 1; }
note() { echo "    $*"; }
have() { [ -s "$1" ]; }

command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required (kernel discovery + digests)"
mkdir -p "$ARTIFACTS"

# ---------------------------------------------------------------------------
# 1. Firecracker -- release tarball + the sha256 the project published for it.
# ---------------------------------------------------------------------------
fc_bin="$ARTIFACTS/firecracker"
# ELF magic, compared as raw hex: `od -c` spellings of 0x7f differ between
# od builds (\177 vs 177), and a check that can't decide is worse than none.
is_elf() { [ "$(head -c 4 "$1" | od -An -t x1 | tr -d ' \n')" = "7f454c46" ]; }
if have "$fc_bin" && "$fc_bin" --version >/dev/null 2>&1; then
  note "firecracker: already present ($("$fc_bin" --version | head -1))"
else
  echo "==> firecracker $FC_VERSION ($ARCH)"
  base="https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION"
  tarball="firecracker-$FC_VERSION-$ARCH.tgz"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  curl -fsSL --retry 3 -o "$work/$tarball" "$base/$tarball"
  curl -fsSL --retry 3 -o "$work/$tarball.sha256.txt" "$base/$tarball.sha256.txt"

  want="$(awk '{print $1}' "$work/$tarball.sha256.txt" | head -1)"
  got="$(sha256sum "$work/$tarball" | cut -d' ' -f1)"
  [ "$want" = "$got" ] || die "firecracker tarball sha256 mismatch:
       published $want
       downloaded $got"

  tar -xzf "$work/$tarball" -C "$work"
  extracted="$(find "$work" -type f -name "firecracker-$FC_VERSION-$ARCH" | head -1)"
  [ -n "$extracted" ] || die "tarball did not contain the expected binary"
  install -m 0755 "$extracted" "$fc_bin"
  rm -rf "$work"
  trap - EXIT
  note "verified sha256 $got"
fi

# ---------------------------------------------------------------------------
# 2. Guest kernel -- newest vmlinux in Firecracker's CI bucket, must be ELF.
# ---------------------------------------------------------------------------
kern="$ARTIFACTS/vmlinux"
if have "$kern" && is_elf "$kern"; then
  note "kernel: already present ($(du -h "$kern" | cut -f1))"
else
  echo "==> guest kernel (newest vmlinux in $S3 firecracker-ci/)"
  key="$(python3 - "$S3" "$ARCH" <<'PY'
import re
import sys
import urllib.request

s3, arch = sys.argv[1], sys.argv[2]


def get(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as reply:
        return reply.read().decode("utf-8", "replace")


listing = get(f"{s3}?list-type=2&prefix=firecracker-ci/&delimiter=/")
prefixes = sorted(set(re.findall(r"<Prefix>(firecracker-ci/\d{8}-[^/]+)/</Prefix>", listing)))
if not prefixes:
    sys.exit("no firecracker-ci/ prefixes in the bucket listing")

# Newest bucket first; a bucket without an $ARCH kernel just moves on.
for prefix in reversed(prefixes):
    page = get(f"{s3}?list-type=2&prefix={prefix}/{arch}/vmlinux-")
    versions = re.findall(
        rf"<Key>{re.escape(prefix)}/{arch}/(vmlinux-(\d+)\.(\d+)\.(\d+))</Key>", page
    )
    if versions:
        versions.sort(key=lambda item: tuple(int(g) for g in item[1:]))
        print(f"{prefix}/{arch}/{versions[-1][0]}", end="")
        break
else:
    sys.exit("no vmlinux for this architecture in any CI bucket")
PY
)"
  [ -n "$key" ] || die "kernel discovery failed"
  note "key: $key"
  curl -fsSL --retry 3 -o "$kern.part" "$S3/$key"
  is_elf "$kern.part" || {
    rm -f "$kern.part"
    die "downloaded kernel is not an ELF image"
  }
  mv "$kern.part" "$kern"
  note "verified ELF, $(du -h "$kern" | cut -f1)"
fi

# ---------------------------------------------------------------------------
# 3. Model weights -- Hugging Face LFS ships the file's sha256 as its ETag,
#    so we can prove the download is the exact object the repo published.
# ---------------------------------------------------------------------------
model="$ARTIFACTS/model.gguf"
if have "$model" && [ "$(head -c 4 "$model")" = "GGUF" ]; then
  note "model: already present ($(du -h "$model" | cut -f1))"
else
  echo "==> model weights ($(basename "$MODEL_URL"))"
  etag="$(curl -fsSLI "$MODEL_URL" | tr -d '"\r' \
          | awk -F': ' 'tolower($1) == "x-linked-etag" {v = $2} END {print v}')"
  # Resume loop: a 350 MB object over a flaky stream restarts from where it
  # stopped, and "downloaded" means "matches the published sha256", not
  # "curl exited 0". `-C -` needs the file to exist to compute an offset.
  [ -f "$model.part" ] || : > "$model.part"
  for attempt in 1 2 3 4 5; do
    if [ -s "$model.part" ] \
       && [ -n "$etag" ] \
       && [ "$(sha256sum "$model.part" | cut -d' ' -f1)" = "$etag" ]; then
      break
    fi
    [ "$attempt" -eq 5 ] && die "model download did not reach the published sha256 after 5 attempts"
    # A partial whose magic is wrong can only be a corrupt base; resuming
    # onto garbage would never converge, so start it over.
    if [ -s "$model.part" ] && [ "$(head -c 4 "$model.part")" != "GGUF" ]; then
      note "partial file is not a GGUF; restarting from byte 0"
      : > "$model.part"
    fi
    if curl -fSL --http1.1 -C - -o "$model.part" "$MODEL_URL" >/dev/null 2>&1; then
      # Transfer claimed complete. If the digest still differs, the base we
      # resumed from was bad; clear it so the next attempt starts clean.
      if [ -n "$etag" ] && [ "$(sha256sum "$model.part" | cut -d' ' -f1)" != "$etag" ]; then
        note "completed transfer failed the digest; restarting from byte 0"
        : > "$model.part"
      fi
    fi
    sleep 1
  done
  [ "$(head -c 4 "$model.part")" = "GGUF" ] || {
    rm -f "$model.part"
    die "downloaded file does not start with the GGUF magic"
  }
  if [ -n "$etag" ]; then
    got="$(sha256sum "$model.part" | cut -d' ' -f1)"
    [ "$got" = "$etag" ] || {
      rm -f "$model.part"
      die "model sha256 mismatch:
       Hugging Face published $etag
       downloaded            $got"
    }
    note "verified sha256 $got"
  else
    note "no sha256 published by the host; recorded $(sha256sum "$model.part" | cut -d' ' -f1)"
  fi
  mv "$model.part" "$model"
fi

echo
echo "==> artifacts ready in microvm/artifacts/"
ls -la "$ARTIFACTS"
echo
echo "Next: sudo microvm/build_immutable_images.sh --kernel microvm/artifacts/vmlinux --model microvm/artifacts/model.gguf"
