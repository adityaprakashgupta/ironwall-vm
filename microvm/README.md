# MicroVM enclave

Three Firecracker MicroVMs, one vsock each, no network anywhere. This directory
is the *deployment* layer: it turns the crate code into an actual enclave.

| CID | Role | Image | Reaches | Cannot reach |
|-----|------|-------|---------|--------------|
| 3 | red-team | `images/red.ext4` | the Referee's vsock listener | everything else |
| 4 | blue-team | `images/blue.ext4` | the Referee | Red, the LLM VM, the signer, the log |
| 5 | llm-engine | `images/llm.ext4` | the Referee | Red, Blue, the signer, the log |

The Referee runs on the host, not in a VM: it is the TCB, and it is the only
component with a socket to the signer. The guests have no network device in
their Firecracker config at all, so "Isolated" is a property of the topology
rather than of any policy inside the guest.

## What the scripts do

`build_immutable_images.sh` (offline, run as root, once per image revision)

1. stages each guest's payload — one agent plus `workloads/common/` — into a
   scratch tree,
2. packs it into a fixed-size ext4 image with a deterministic label and UUID,
   so two builds of the same tree produce byte-identical images,
3. seals the image `0444`,
4. boots the llm image once and asks Firecracker for the golden snapshot the
   Referee restores on every reset,
5. rewrites `config/images.json` with the fresh digests.

Those digests are exactly what the Referee pins into each evaluation's signed
manifest, so an auditor can rebuild the images and check that the evidence was
produced by this code. The script refuses to overwrite an existing image: the
images are content-addressed, and rebuilding in place would silently invalidate
every manifest that referenced the old bytes.

`boot_enclave.sh` (privileged, on the enclave host)

1. boots blue and llm with their read-only rootfs images,
2. optionally boots red with a small read-only "orders" disk that carries one
   evaluation id, one capability and one prompt,
3. probes blue and llm over AF_VSOCK until each answers a real request,
4. prints the exact `bayora-referee` command line for the host shell, then
   holds the VMs open until Ctrl-C.

`guest/init.sh` is PID 1 inside every VM. It mounts `/proc`, `/sys` and tmpfs
over `/tmp`, `/run` and `/var/log`, reads its role from the **kernel command
line only** (the guest has no configuration channel to attack), and `exec`s the
agent. Because the rootfs is mounted read-only and everything writable is
tmpfs, a reset only has to throw the VM's memory away — there is no persistent
guest state that could carry one evaluation into the next.

## Prerequisites

* a Linux host with `/dev/kvm` (bare metal, or a VM with nested
  virtualisation); `firecracker` on `PATH` (the images were built against
  `v1.7.0`),
* `e2fsprogs`, `coreutils`, and `curl` for the snapshot step,
* an uncompressed kernel image (`artifacts/vmlinux`),
* the model weights for the llm image (`artifacts/model.gguf`); a deployment
  that cannot prove which weights it ran cannot prove anything about its
  answers,
* `root` for both scripts.

## Running it

```bash
sudo microvm/build_immutable_images.sh \
    --kernel microvm/artifacts/vmlinux \
    --model  microvm/artifacts/model.gguf

sudo microvm/boot_enclave.sh --kernel microvm/artifacts/vmlinux
# in another shell:
cargo run -p bayora-referee -- \
    --policy config/policy.yaml --images config/images.json \
    --signer unix:/run/bayora/signer.sock --transport vsock \
    --blue-cid 4 --blue-port 9001 --llm-cid 5 --llm-port 9002 \
    --vsock-port 5000 --evidence-log evidence/evidence_log.ndjson \
    --reset snapshot
```

## On a host without Firecracker

`scripts/demo-vsock.py` runs the same guest agents as ordinary processes on one
Linux kernel, connected over `VMADDR_CID_LOCAL` (CID 1) instead of to real
MicroVMs. The frame protocol, strict parser, capability gate, bounded release,
constant-size egress, evidence chain, Merkle seal and independent verification
are all the production code path; only the VM boundary is simulated. That is
the variant you can run in WSL or CI.

`scripts/demo.ps1` (Windows) does the same with the Referee's deterministic
stub transport, so no Linux is needed at all.

## Status

`scripts/demo-vsock.py` is exercised in CI/WSL on every change and asserts the
four pillars from Red's own transcript and from the evidence log. The two
scripts in this directory are deployment artefacts that need a KVM host; they
are written to fail loudly rather than to limp along without the prerequisites
they check for.
