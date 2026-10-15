//! Bayora Trust Anchor signer micro-daemon.
//!
//! This is the **only** component that holds private key material. The Referee
//! never does: it speaks the `SIGN(digest)` boundary over a restricted socket
//! (`bayora_common::signer_proto`) and receives back signatures. Compromising
//! the Referee process therefore does not yield the signing key.
//!
//! Two keys are held:
//! * `trust_anchor` — signs manifest hashes and Merkle batch roots,
//! * `capability_issuer` — mints single-use capability tokens.
//!
//! In production this maps onto a TPM 2.0 (`/dev/tpmrm0`) or PKCS#11 HSM behind
//! the same protocol; see `docs/TRUST_ANCHOR.md`.

pub mod keys;
pub mod server;

pub use keys::{KeyError, SignerKeys};
pub use server::{bind, serve, serve_on, spawn, Listener, ListenerSpec, SignerServerHandle};
