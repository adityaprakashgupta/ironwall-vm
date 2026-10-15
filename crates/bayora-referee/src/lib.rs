//! Bayora Referee — the Blind Referee TCB of the Bayora Enclave (v3.0).
//!
//! The Referee is the *only* party that may move data between the untrusted
//! MicroVMs, and it does so under four invariants (the four pillars):
//!
//! * **Isolated** — the Red/Blue/LLM guests share no network namespace with
//!   each other or with the host; the Referee is their sole meeting point.
//! * **Mediated** — every flow is checked against `config/policy.yaml`
//!   ([`policy_engine`]); a `DENIED` flow is an auditable refusal, never a
//!   silent drop.
//! * **Resettable** — every evaluation starts from a golden snapshot or a
//!   logical KV erase ([`snapshot_manager`]).
//! * **Verifiable** — manifests are signed *before* prompts are processed
//!   ([`trust_anchor`]), timing is bounded ([`bounded_timing`]), and every
//!   turn is chained into a dual-sink evidence log ([`evidence_emitter`])
//!   that the standalone verifier re-derives byte for byte.
//!
//! The Referee **never holds private key material**: signing is a
//! `SIGN(digest)` call to an isolated signer process (see `bayora-signer`).
//!
//! ```text
//! crates/
//!   bayora-common    shared canonical types (JCS, manifest, chain, records)
//!   bayora-signer    isolated key custody (trust anchor + capability issuer)
//!   bayora-referee   this crate — policy, capability, timing, evidence, API
//!   bayora-verifier  standalone independent verifier (no trust required)
//! ```

pub mod bounded_timing;
pub mod capability_guard;
pub mod control_plane;
pub mod evidence_emitter;
pub mod metrics;
pub mod mini_http;
pub mod policy_engine;
pub mod referee;
pub mod snapshot_manager;
pub mod transport;
pub mod trust_anchor;

#[cfg(target_os = "linux")]
pub mod vsock_server;

pub use bounded_timing::{BoundedOutcome, TimingGuard};
pub use capability_guard::{CapabilityGuard, GuardError};
pub use control_plane::router;
pub use evidence_emitter::{
    DualSink, EmitterError, EvidenceEmitter, EvidenceSink, MemorySink, NDJsonSink, SinkError,
};
#[cfg(feature = "postgres")]
pub use evidence_emitter::PostgresSink;
pub use metrics::{Metrics, PathLabel, Posture};
pub use policy_engine::PolicyEngine;
pub use referee::{
    CreatedEvaluation, FinalizedEvaluation, RefereeError, RefereeState, TurnOutcome,
};
pub use snapshot_manager::{
    FirecrackerSnapshotManager, LogicalKvResetManager, NoopResetManager, ResetError, ResetManager,
    ResetReport,
};
pub use transport::{
    BlueRequest, BlueVerdict, Decision, LlmRequest, LlmResponse, StubTransport, TransportError,
    WorkloadTransport,
};
#[cfg(target_os = "linux")]
pub use transport::VsockTransport;
pub use trust_anchor::{
    CapabilityIssuer, IsolatedSocketSigner, SignerEndpoint, SignerError, TrustAnchorSigner,
};
