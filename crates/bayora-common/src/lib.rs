//! Shared primitives for the Bayora Enclave.
//!
//! This crate is the *only* dependency shared by the three trust domains:
//!
//! * the **Referee** (execution TCB),
//! * the **Trust Anchor signer** (the only holder of private keys),
//! * the **Independent Verifier** (post-hoc auditor).
//!
//! Because every party canonicalizes through the same RFC 8785 implementation
//! and the same hash-chain / Merkle definitions, byte-for-byte agreement is
//! guaranteed by construction rather than by convention.
//!
//! Scope note: all canonical (hashed) Bayora documents contain only strings,
//! integers, booleans, arrays and objects. Floating point numbers are
//! deliberately rejected by the JCS encoder — timings are recorded as integer
//! microseconds so both sides always hash identical bytes.

pub mod capability;
pub mod chain;
pub mod digest;
pub mod error;
pub mod events;
pub mod frame;
pub mod jcs;
pub mod manifest;
pub mod policy;
pub mod records;
pub mod signature;
pub mod signer_proto;
pub mod telemetry;
pub mod timeutil;

#[cfg(any(test, feature = "testing"))]
pub mod testutil;

pub use capability::{CapabilityClaims, CapabilityToken, IssuerPublicKey};
pub use chain::{ChainState, MerkleError};
pub use digest::Digest;
pub use error::ErrCode;
pub use events::EvaluationEvent;
pub use frame::{pad_response, parse_padded_response, PromptFrame, ResponseEnvelope};
pub use manifest::{EvaluationManifest, ImageRegistry};
pub use policy::{FlowControl, PolicyConfig, PolicyError, ResetPolicy, TimingMode};
pub use records::EvidenceRecord;
