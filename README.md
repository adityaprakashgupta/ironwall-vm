# IronWall VM

**Isolated. Mediated. Resettable. Verifiable.**

A production-shaped AI red-team/blue-team evaluation harness in which an adversary **cannot tell which defense stage stopped it**, **cannot observe timing**, and **cannot make the operator lie about what happened** — because every evaluation is committed to a hash-chained, Merkle-sealed, append-only evidence log that a standalone verifier re-derives byte for byte.

Built for **Hack in Hills '26 — PS 04**.

```
        ┌──────────────────────────────────────────────────────────────┐
        │  L5 · Trust Anchor + Independent Verifier                    │
        │      Ed25519 key custody (isolated daemon) · SIGN(digest)     │
        │      ironwall-verifier recomputes the whole log — trusts nothing│
        └──────────────────────────────────────────────────────────────┘
                     ▲ pinned pubkey                    ▲ re-derivation
        ┌────────────┴───────────────────────────────┴────────────────┐
        │  L2 · Blind Referee (TCB)                                    │
        │      policy · capability · bounded timing · manifest · chain  │
        └───┬──────────────────┬──────────────────────┬────────────────┘
            │ VSOCK            │ VSOCK                │ VSOCK
     ┌──────┴─────┐     ┌──────┴─────┐        ┌───────┴──────┐
     │ Red  VM    │     │ Blue  VM   │        │  LLM  VM     │
     │ untrusted  │     │ untrusted  │        │  untrusted   │
     └────────────┘     └────────────┘        └──────────────┘
        ┌──────────────────────────────────────────────────────────────┐
        │  L1 · Control Plane (axum HTTP)   │  L4 · Evidence Plane      │
        │  create/turn/seal/posture         │  NDJSON + PostgreSQL sink │
        └──────────────────────────────────────────────────────────────┘
```

## The four pillars

| Pillar | Mechanism | Where |
|---|---|---|
| **Isolated** | Red/Blue/LLM guests share no network namespace; the Referee is the only meeting point. | `microvm/` |
| **Mediated** | Every flow is checked against `config/policy.yaml`; `DENIED` is an auditable refusal, never a silent drop. | `bayora-referee` policy engine |
| **Resettable** | Every evaluation starts from a golden Firecracker snapshot or a logical KV erase. | `bayora-referee` snapshot manager |
| **Verifiable** | Manifest signed *before* the prompt; timing bounded; every turn chained into a dual-sink log. | `bayora-signer`, `bayora-verifier` |

## Branding note

This README and the `docs/` directory refer to the project as **IronWall VM**. The Rust crate/package names in source code (e.g. `bayora-common`, `bayora-referee`, `bayora-verifier`, `bayora-orchestrator`) are intentionally left unchanged — no code files were modified as part of this documentation.

## Workspace layout

```
Cargo.toml                     workspace (stable Rust toolchain, Rust 2021)
config/
  policy.yaml                  declarative policy (digest recorded in every manifest)
  images.json                  content-addressed image/model inventory
crates/
  bayora-common/               shared types: JCS, digest, chain, records, manifest,
                                events, capability, frame, telemetry, signature,
                                signer-proto, timeutil, error, policy
  bayora-signer/               L5 isolated key custody (trust anchor + capability issuer)
  bayora-referee/              L2 Blind Referee TCB + L1 control plane + VSOCK ingress
  bayora-verifier/             L5 standalone Independent Verifier (CLI + library)
  bayora-llm-engine/           llama-cpp-4 inference engine for the LLM guest role
  bayora-orchestrator/         full-lifecycle harness: artifact download, image build,
                                MicroVM boot, evaluate, seal, verify (+ optional TUI)
fuzz/
  fuzz_targets/vsock_frame_parser.rs   cargo-fuzz target for the ingress parser (nightly)
workloads/
  common/                      shared guest codec, policy, deterministic engine
  red-team|blue-team|llm-engine/   the three guest agents
  tests/                       guest tests (no AF_VSOCK needed)
microvm/
  guest/init.sh                PID 1 inside every VM (reads role from kernel cmdline)
  build artifacts: vmlinux, model.gguf, firecracker binary
dashboard/
  serve.py                     read-only static page + API proxy (listed for completeness)
migrations/
  0001_evidence_records.sql    the PostgreSQL evidence sink (append-only role)
```

## Quickstart — development host (no KVM required)

The Referee runs against a real signer daemon and a **stub** downstream transport, so the entire security architecture is exercisable on any OS without virtualization, Firecracker, or KVM.

### Prerequisites

* A Rust toolchain (stable), e.g. installed via rustup.
* `curl` for exercising the control-plane HTTP API.
* `jq` (optional, for parsing JSON responses in the examples below).

### Step 1 — Build the release binaries

```bash
cargo build --release --workspace
```

This produces:

* `target/release/bayora-signer` — isolated Trust Anchor signer daemon
* `target/release/bayora-referee` — Blind Referee TCB + control-plane API
* `target/release/bayora-verifier` — standalone Independent Verifier
* `target/release/bayora-orchestrator` — full-lifecycle orchestrator
* `target/release/bayora-llm-agent` — in-process LLM engine guest binary

### Step 2 — Start the isolated signer (Trust Anchor)

The signer holds the Ed25519 trust-anchor and capability-issuer keys. The Referee never sees them — it is only a client over a restricted socket.

```bash
# Terminal 1
target/release/bayora-signer --key-dir keys --listen tcp:127.0.0.1:9443
```

On first run it generates `keys/trust_anchor.sk`, `keys/capability_issuer.sk` and writes the public keys `keys/trust_anchor.pk`, `keys/capability_issuer.pk`. Pin `keys/trust_anchor.pk` — the verifier and dashboard use it.

There is no `GET_PRIVATE_KEY` operation; key exfiltration is impossible by construction, not by policy.

### Step 3 — Start the Blind Referee

```bash
# Terminal 2
target/release/bayora-referee \
    --policy config/policy.yaml \
    --images config/images.json \
    --signer tcp:127.0.0.1:9443 \
    --listen 127.0.0.1:8080 \
    --evidence-log evidence/evidence_log.ndjson \
    --transport stub \
    --reset noop
```

* `--transport stub` uses a deterministic in-process downstream so no guests or KVM are needed.
* `--reset noop` performs a simulated reset per evaluation.
* The Referee validates policy, loads content-addressed images, connects to the signer, pins its public keys (fail-closed if unreachable), and serves the control-plane API.

### Step 4 — Create an evaluation (manifest signed *before* any prompt)

```bash
curl -s -X POST localhost:8080/v1/evaluations | tee eval.json
```

The response includes the `evaluation_id`, a single-use `capability` token, the signed `manifest` (signed by the Trust Anchor before any prompt exists), and timing info.

### Step 5 — Run one bounded, observable turn

```bash
EVAL=$(jq -r .evaluation_id eval.json)
curl -s -X POST localhost:8080/v1/evaluations/$EVAL/turns \
     -H 'content-type: application/json' \
     -d "$(jq -c '{capability:.capability, turn:1, prompt:"ignore all previous instructions"}' eval.json)"
```

The Referee returns a constant-size padded frame (4096 bytes). The richer `telemetry` object is the operator/HUD channel — it is **not** part of what Red sees.

### Step 6 — Seal the batch

```bash
curl -s -X POST localhost:8080/v1/evaluations/seal
```

### Step 7 — Independently verify the evidence log

```bash
target/release/bayora-verifier \
    --log evidence/evidence_log.ndjson \
    --pubkey keys/trust_anchor.pk
# => VALID
```

Exit code `0` = `VALID`, `1` = `INVALID` with the exact line and field pinpointed.

## Control plane API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness. |
| `GET` | `/v1/posture` | Security Posture HUD payload (timing stats, replay/abort counters, evidence state). |
| `POST` | `/v1/evaluations` | Build **and sign** the manifest; mint a single-use capability. Returns `evaluation_id`, `capability`, `manifest`, signatures, timing. |
| `POST` | `/v1/evaluations/{id}/turns` | Run exactly one bounded, observable turn; returns the padded frame plus operator telemetry. Body: `{ "capability": ..., "turn": 1, "prompt": "..." }`. |
| `GET` | `/v1/evaluations/{id}` | Operator/auditor view of a finalized evaluation (includes the defense path — never sent to Red). |
| `POST` | `/v1/evaluations/seal` | Force a Merkle batch seal. |

### What Red sees vs. what the operator sees

A turn response always returns the **constant-size padded frame** first (`frame_hex`, exactly `response_frame_bytes`, default 4096). The richer `telemetry` object is the operator/HUD channel — it is **not** part of the Red-visible envelope.

The Referee runs exactly one turn per evaluation; a frame claiming otherwise is refused with `ERR_TURN_MISMATCH` **before** the capability gate, so a malformed frame can never burn a legitimate single-use nonce. The same check runs on both ingress paths — HTTP and VSOCK — because Red speaks VSOCK in production.

Red-visible response bytes are byte-identical for a regex block, a semantic block, and any other terminating stage:

```json
{"status":"rejected","data":"I can't assist with that request."}
```
…padded with ASCII spaces to exactly 4096 bytes.

## Bounded Observable Execution

The Referee measures only *bucketed* elapsed time. Under `EVAL_1000` (the shipped policy):

* `T_bucket = 1000 ms`, `abort_margin = 15 ms` (deadline at 985 ms);
* work finishing before `T_bucket − margin` is held until the bucket boundary; work crossing it is cancelled and answered with the same observable shape;
* because the response is released at the boundary, all three defense stages are **indistinguishable by latency** (`held_us` is constant).

Baseline (`NORMAL`) releases as soon as work completes, exposing three clean timing bands (regex ~2 ms, semantic ~160 ms, LLM ~340 ms) — inference accuracy ≈ 1.0. `EVAL_1000` collapses to one band → accuracy ≈ 0.33 (chance). The verifier reproduces this measurement from the evidence log alone.

Two honest caveats, both enforced in code:

* Accuracy is only reported when it means something — fewer than nine samples, or fewer than two distinct stage labels, yields `not measurable`; `--strict-timing` treats that as *inconclusive*, not a pass.
* `bounded` is a structural claim: every released frame must sit inside the declared bucket window (`bucket − 2 ms .. bucket + 30 ms`) and the observed latencies must form a single band (relative spread < 5 %).

Timing modes: `NORMAL`, `EVAL_500`, `EVAL_1000`, `EVAL_2000` (set via `timing_mode` in `config/policy.yaml`).

## Security Posture HUD

A read-only dashboard exposes the live posture at `http://127.0.0.1:8090` (`dashboard/serve.py`). It proxies `GET /healthz`, `GET /v1/posture`, and `GET /v1/evaluations/{id}` and refuses everything else, so a monitoring surface can never spend a capability or create an evaluation. It shows the pinned trust anchor, chain length and head, sink list, replay/abort/frame-rejection counters, and per-mode timing statistics, refreshing every two seconds.

> The dashboard (`dashboard/serve.py`) is a read-only monitoring surface. It is listed for completeness; this guide does not advise executing it directly.

## The evidence plane

```text
EventHash_i  = sha256( JCS(events_i) )
ManifestHash = sha256( JCS(manifest) )
ChainHash_i  = sha256( ChainHash_{i-1} || ManifestHash_i || EventHash_i )
ChainHash_-1 = 32 zero bytes            (genesis)
```

* Every record is written in **RFC 8785 JCS** form, so the NDJSON line, the PostgreSQL row, and the verifier's re-derivation are the same bytes.
* Merkle batch seals commit to the chain hashes; an odd node is promoted unchanged (no duplication).
* The Trust Anchor signs the raw 32-byte `ManifestHash` and the raw 32-byte Merkle root — never a string.

See [`docs/EVIDENCE.md`](docs/EVIDENCE.md) for the full record spec.

### Dual sink

| Sink | Purpose | Failure policy |
|---|---|---|
| `NDJsonSink` | append-only `evidence_log.ndjson` — the audit-trusted copy | always on |
| `PostgresSink` | fast query path for the dashboard | opt-in (`--features postgres`) |

Both receive the identical canonical bytes. If the two ever diverge, `bayora-verifier --postgres-url …` compares them record for record (`SinkDivergence`) and names the first differing index.

## The Independent Verifier

```bash
target/release/bayora-verifier --log <ndjson> --pubkey <hex|file> [options]
```

It trusts only the pinned Trust Anchor public key and re-derives every canonical byte, chain link, Merkle root and signature. It refuses the log unless all of the following hold:

1. every line is the canonical JCS form of its record (reordered keys, injected fields, reformatted whitespace rejected);
2. `ManifestHash` recomputes and the Trust Anchor signature over it verifies under the pinned key;
3. `EventHash` recomputes, events are bound to their manifest, and pinned environment digests do not drift mid-log;
4. every chain link recomputes and `seq` is strictly sequential;
5. every seal's Merkle root recomputes, each leaf equals the chain hash at that `seq`, no seal overlaps another, and the root signature verifies;
6. observable timings are consistent with the declared timing policy (reported always; enforced with `--strict-timing`).

Any failure pinpoints the exact line and field:

```text
INVALID
line 7: chain link broken at seq 6 (eval_0195f2a4): recorded prev 9c1f…, expected 4ab2…
```

A healthy log:

```text
VALID
  evaluations   : 3
  batch seals   : 1
  unsealed      : 0
  chain head    : 3f9a1c8e2b47d0a5…
  trust anchor  : daae177d0f9d9f2048d47463b4dea1e5059609392f1d6b8339eeb31913dbc0e9
  timing        : EVAL_1000 - 3 sample(s), held 1001233..1003011us, stddev 812us (0.1612% of mean), inference accuracy not measurable (3 samples across 3 stage(s); need 9+ over 2+) (bounded)
```

| Option | Effect |
|---|---|
| `--expect-evaluations N` | Fail unless exactly `N` evaluation records are present (truncation detection). |
| `--expect-seals N` | Fail unless exactly `N` batch seals are present. |
| `--expect-chain-head HEX` | Pin the published chain head. |
| `--require-all-sealed` | Fail if any evaluation is not covered by a seal. |
| `--strict-timing` | Fail if a bounded run still leaks the defense stage. |
| `--postgres-url URL` | Compare the append log against the PostgreSQL copy byte for byte (requires `--features postgres`). |
| `--json` | Emit the full report as JSON. |

## Error codes

Refusals are auditable constants:

```text
Capability   ERR_CAPABILITY_REPLAY_DENIED   ERR_CROSS_EVAL_MISMATCH
              ERR_CAPABILITY_EXPIRED         ERR_CAPABILITY_BAD_SIGNATURE
              ERR_CAPABILITY_MALFORMED
Frame        ERR_FRAME_TOO_LARGE            ERR_FRAME_INVALID_UTF8
              ERR_FRAME_MALFORMED_JSON       ERR_FRAME_UNKNOWN_FIELD
              ERR_FRAME_BAD_TYPE
Flow/State   ERR_FLOW_DENIED                ERR_UNKNOWN_EVALUATION
              ERR_EVALUATION_FINALIZED       ERR_DEADLINE_ABORT
              ERR_TURN_MISMATCH
Trust        ERR_POLICY_INVALID             ERR_SIGNER_UNAVAILABLE
              ERR_EVIDENCE_FAILURE           ERR_INTERNAL
```

## Testing

```bash
cargo test --workspace                 # full suite, no KVM / no network
cargo test -p bayora-common            # canonicalizer, chain, Merkle, frame, telemetry
cargo test -p bayora-referee           # policy, capability, bounded timing, evidence, API
cargo test -p bayora-verifier          # tamper matrix: every mutation pinpointed
cargo test -p bayora-signer            # key custody, SIGN(digest) round trips
cargo test -p bayora-llm-engine        # token ceiling, load/reset lifecycle
cargo test -p bayora-orchestrator      # orchestrator unit tests
```

Guest unit tests live in `workloads/tests/` and exercise the codec, policy, and engine without needing AF_VSOCK.

Fuzzing the ingress parser (needs a nightly toolchain):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run vsock_frame_parser
```

## The orchestrator — `bayora-orchestrator`

`bayora-orchestrator` is a single Rust binary that replaces the legacy shell and Python lifecycle scripts (`fetch_artifacts.sh`, `build_immutable_images.sh`, `boot_enclave.sh`, `full_e2e_microvm.py`). It drives the full lifecycle: artifact download and sha256 verification, immutable ext4 image building, golden Firecracker snapshot creation, MicroVM boot, evaluation creation, turn execution, batch sealing, and independent verification.

### CLI

```bash
target/release/bayora-orchestrator [--root <project-root>] [--headless] [-v|-vv] <subcommand>
```

| Subcommand | Purpose |
|---|---|
| `download` | Download and verify artifacts (firecracker, vmlinux, model.gguf) with sha256 pinning. |
| `build` | Build immutable guest images (red, blue, llm) and the golden Firecracker snapshot; publish `config/images.json`. |
| `boot` | Boot Firecracker MicroVMs (blue + red) directly. |
| `evaluate` | Create evaluations, run turns, seal the batch, run the verifier. |
| `full` | Run the complete lifecycle (download → build → boot → evaluate → seal → verify). |
| `dashboard` | Launch the optional ratatui TUI dashboard (requires `--features tui`). |
| `trace` | Show the structured trace log (`evidence/orchestrator.trace.jsonl`). |
| `config` | Print the resolved orchestrator configuration as JSON. |

### Example: full lifecycle

```bash
target/release/bayora-orchestrator full
```

This builds release binaries, downloads/verifies artifacts, builds guest images, boots Firecracker MicroVMs, creates five evaluations through the Referee API, runs turns, seals the evidence batch, and runs the independent verifier — reporting `VALID` when the four pillars hold.

The orchestrator runs Firecracker as root for KVM/vsock access; review `crates/bayora-orchestrator/src/` before running it on a host. The default build is headless and safe for CI.

## Running the real MicroVMs (Linux / KVM)

The `microvm/` directory is the deployment layer for real Firecracker MicroVMs (Red CID 3, Blue CID 4, LLM CID 5), each with no network device and a read-only rootfs. The Referee runs on the host and is the only component with a socket to the signer.

**No-KVM host (recommended):** the default `--transport stub --reset noop` configuration runs the complete architecture without KVM, Firecracker, or virtualization — this is the development and CI path.

**Linux with KVM:** `--transport vsock` (native AF_VSOCK) and `--transport firecracker` / `--reset snapshot` (Firecracker-mediated guests) are available. These paths are `cfg`-gated to Linux/unix; on other platforms they fail closed with a clear message. Real-MicroVM deployment uses the artifacts in `microvm/artifacts/` (kernel, Firecracker binary, GGUF model) and builds content-addressed guest images whose digests are pinned into `config/images.json` and recorded in every signed manifest.

The `microvm/` directory contains privileged shell scripts for image build, golden-snapshot creation, and enclave boot. They are documented in [`microvm/README.md`](microvm/README.md) for completeness; this guide does not advise executing shell scripts directly.

## Threat model (what the design defends)

| Adversary | Attack | Defense |
|---|---|---|
| Red (in-VM) | replay a captured capability | single-use nonce guard → `ERR_CAPABILITY_REPLAY_DENIED` |
| Red | present a token for another evaluation | `eval_id` binding → `ERR_CROSS_EVAL_MISMATCH` |
| Red | infer the defense stage from latency | Bounded Observable Execution (constant bucket release) |
| Red | infer the stage from response length | constant-size padded envelope |
| Red | smuggle a payload past the parser | strict length prefix + `deny_unknown_fields` + fuzzed parser |
| Blue/LLM (compromised) | exfiltrate to Red | `blue_to_red: DENIED`, no shared network namespace |
| Referee (compromised) | forge/alter the record | append-only NDJSON + PostgreSQL divergence check; signatures pinned to the Trust Anchor |
| Referee | leak private keys | keys live only in the signer daemon; no `GET_PRIVATE_KEY` exists |
| Operator | truncate the log | `--expect-evaluations` / `--expect-seals` / `--expect-chain-head` |
| Operator | rewrite history | hash chain + Merkle seals + pinned chain head |
| Red (cross-run) | carry state between evaluations | snapshot / logical-KV reset each evaluation |

## Further reading

* [`docs/TRUST_ANCHOR.md`](docs/TRUST_ANCHOR.md) — the `SIGN(digest)` boundary and isolated key custody (software, TPM 2.0, PKCS#11 HSM).
* [`docs/EVIDENCE.md`](docs/EVIDENCE.md) — byte-for-byte evidence plane specification (JCS, hash chain, Merkle batches, dual sink).
* [`docs/GUEST_WORKLOAD_AUDIT.md`](docs/GUEST_WORKLOAD_AUDIT.md) — audit of the Red/Blue/LLM guest agents against the v3.0 design.
* [`docs/DEMO.md`](docs/DEMO.md) — demo narrative and reviewer talking points.
* [`microvm/README.md`](microvm/README.md) — Firecracker MicroVM deployment layer.

## License

Apache-2.0.
