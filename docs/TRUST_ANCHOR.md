# The Trust Anchor boundary

The Trust Anchor is the **only** party in the Bayora Enclave that holds private
key material. Everything else — the Referee, the control plane, the workloads,
the verifier — holds at most a *public* key. This document defines the
boundary and how the reference implementation enforces it.

## The interface: `SIGN(digest) -> signature`

Two keys live in the signer daemon:

| Key | Purpose | Signs |
|---|---|---|
| **Trust Anchor** | Attests manifests and batch seals. | the raw 32-byte `ManifestHash` and the raw 32-byte Merkle root |
| **Capability Issuer** | Mints single-use capability tokens. | `JCS(CapabilityClaims)` |

The wire protocol is deliberately tiny (`bayora_common::signer_proto`):

```text
SignerRequest::GetPubkeys
SignerRequest::SignManifestDigest { digest: sha256:<hex> }   -> SignerResponse::Signature { .. }
SignerRequest::SignTrustAnchorDigest { digest: sha256:<hex> } -> SignerResponse::Signature { .. }
SignerRequest::SignMerkleRoot { root: sha256:<hex> }          -> SignerResponse::Signature { .. }
SignerRequest::IssueCapability { eval_id, ttl_ms }            -> SignerResponse::Capability { .. }
```

There is **no `GET_PRIVATE_KEY` operation**, no key-export request, and no
request variant that returns a seed. The private key type is not reachable from
the Referee at all: the Referee's dependency graph does not link a signer
that owns a key — it links a *client* (`IsolatedSocketSigner`).

> **Invariant.** If the Referee process is fully compromised, the attacker gains
> the ability to *request signatures* (rate-limited by the socket), never the
> ability to *read* the key. Key exfiltration is impossible by construction,
> not by policy.

## The boundary in code

```rust
// crates/bayora-referee/src/trust_anchor.rs
pub trait TrustAnchorSigner: Send + Sync {
    async fn sign_digest(&self, digest: &Digest) -> Result<[u8; 64], SignerError>;
    fn public_key_hex(&self) -> String;
}

pub trait CapabilityIssuer: Send + Sync {
    async fn issue_capability(&self, eval_id: &str, ttl_ms: u64)
        -> Result<CapabilityToken, SignerError>;
    fn issuer_public_key_hex(&self) -> String;
}
```

`IsolatedSocketSigner` implements both traits by speaking the protocol over:

* **production PoC** — a UNIX domain socket (`unix:/run/bayora/signer.sock`)
  owned by the signer's UID with mode `0600`;
* **development** — loopback TCP (`tcp:127.0.0.1:9443`).

The socket handle is opaque and excluded from `Debug`; there is no field,
method or accessor anywhere in the Referee that yields private bytes. The
signer's own `SignerKeys` type exposes only public-key accessors.

## Key custody and lifecycle

* Keys are generated on first run with a 32-byte random seed (64 hex chars) and
  persisted under `--key-dir` (`trust_anchor.sk`, `capability_issuer.sk`).
* Public keys are written alongside as `trust_anchor.pk` /
  `capability_issuer.pk` for parties that must **pin** them (the Verifier, the
  dashboard).
* The Referee pins the Trust Anchor public key at startup by asking the daemon
  (`GetPubkeys`) and checking the answer; a mismatch or an unreachable daemon is
  a **fail-closed** boot error (`ERR_SIGNER_UNAVAILABLE`). The enclave never
  starts without a live Trust Anchor.
* Restrict the key directory to the signer's user: `chmod 700 keys` and
  `chown signer:signer keys`.

## What gets signed, and why it is a raw digest

Signatures are always over the **raw 32 bytes** of a SHA-256 digest, never over
a hex string or a JSON document:

```text
ManifestSignature = Ed25519_sign( sk, sha256(JCS(manifest)) )
SealSignature     = Ed25519_sign( sk, merkle_root(leaf_1 … leaf_n) )
```

This removes an entire class of ambiguity: there is no JSON canonicalization on
the signing path, so a verifier cannot disagree with the signer about *what was
signed*. It also means the same digest can be attested without any parser
differences between implementations.

The key property for the audit is **ordering**: the manifest is built and signed
at `POST /v1/evaluations`, *before* the prompt is sent. The evidence record for
the evaluation is only written at finalize, binding that pre-committed manifest
to the events that actually occurred. A compromised Referee cannot choose the
manifest after seeing the outcome.

## Production path: TPM 2.0 / HSM

`IsolatedSocketSigner` is a software signer for the PoC. `Tpm2HsmSigner` in the
same module is the fail-closed seam for hardware custody:

* **TPM 2.0** via `/dev/tpmrm0` — create a non-exportable Ed25519 (or ECDSA P-256)
  key under an owner-hierarchy primary; sign by submitting the digest to
  `TPM2_Sign` through the resource manager. The key's `TPMA_OBJECT_NODA` (no
  DA), `TPMA_OBJECT_NODA` and `TPMA_OBJECT_USERWITHAUTH` attributes prevent
  dictionary attacks and unauthorized use.
* **PKCS#11 HSM** — a `CKA_SIGN`-only, `CKA_EXTRACTABLE=false` key; the token
  refuses key export at the firmware level.

Both implement the *same two traits*, so the Referee is unchanged: swap the
`Arc<dyn TrustAnchorSigner>` at construction. `Tpm2HsmSigner` currently returns
`SignerError::Unavailable` rather than silently falling back to software —
hardware custody that can be trivially bypassed is not custody.

### TPM 2.0 key hierarchy

The TPM key hierarchy used by `Tpm2HsmSigner` is:

```
Storage Root Key (SRK) -- persistent handle 0x81000001
   └── Signing Key (EK-derived primary) -- non-exportable Ed25519/P-256
          ├─ sign_digest(manifest_hash)
          └─ sign_digest(merkle_root)
```

* The SRK is created once and persisted in NV index; it is bound to the TPM
  and cannot be exported.
* The signing key is generated inside the TPM (never exposed to host memory),
  marked `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `noDA`, and
  `userWithAuth`. It never leaves the TPM in plaintext.
* To sign: the Referee sends a 32-byte digest over the socket; `Tpm2HsmSigner`
  sends `TPM2_Sign` to the resource manager; the TPM returns the 64-byte
  Ed25519 signature (or 64-byte P-256 signature) over exactly those bytes.

### Attestation (optional)

A TPM-backed Referee can additionally produce a `TPM2_Quote` over selected PCRs
to prove to a remote auditor that the signing key lives inside the TPM and that
the measured boot state matches the expected value. This is optional and not
part of the enclave's core evidence path — the verifier trusts the pinned
public key, not the TPM quote.

## Verification is separate from signing

The Independent Verifier holds **only** the pinned public key. It re-derives
`sha256(JCS(manifest))` itself and checks the signature, so a compromised
Referee cannot substitute a manifest unless it also breaks Ed25519. See
[`EVIDENCE.md`](EVIDENCE.md) for the recomputation the verifier performs.

## Turn gating protects the single-use capability

The Referee owns the turn counter; the client may not invent a turn that does
not exist. A turn body carrying anything other than `turn: 1` is refused with
`ERR_TURN_MISMATCH` (**HTTP 400**) *before* the capability gate is evaluated,
so a malformed frame can never burn a legitimate single-use nonce. The same
check runs on both ingress paths — HTTP (`control_plane.rs`) and VSOCK
(`vsock_server.rs`) — because Red speaks VSOCK in production. See
[`../README.md`](../README.md) for the full flow.

## Tests that keep the boundary honest

Integration tests do not mock the signer — they spawn the **real** daemon on
loopback and drive the real protocol, so a regression that reintroduces a key
into the Referee's address space would fail to compile or fail at runtime:

* `bayora-signer::tests` — key generation, persistence, public-key pinning, and
  a full end-to-end round trip over a real socket.
* `bayora-referee::tests` — manifest signatures and batch-seal signatures
  verifying against the daemon's public keys; capability mint/verify/replay and
  cross-evaluation refusal; reconnect after a dropped socket.

## Failure modes

| Failure | Behavior |
|---|---|
| Signer daemon unreachable at startup | Referee exits immediately (fail-closed) |
| Signer daemon dies mid-run | Next request fails with `ResetError::Unavailable` / `GuardError`; Referee does not fall back to software |
| TPM device missing | `--firecracker-api` with `--signer-device` fails at startup with a clear error |
| TPM key absent | `Tpm2HsmSigner::connect` fails at startup |
| Socket write fails mid-request | Single reconnect attempt; if that fails, error is surfaced to the caller — no silent fallback |
| Signature verification fails | Verifier rejects the log with `ERR_INVALID_SIGNATURE` and pinpoints the record |