//! Single-use capability enforcement (the anti-replay half of the
//! Cross-Evaluation Contamination defence).
//!
//! The Referee *verifies* capability tokens; it never mints them (that is the
//! isolated signer's job). Two independent properties are enforced here:
//!
//! 1. **Cryptographic binding** — signature, expiry and `eval_id` must match
//!    (`IssuerPublicKey::verify`), which yields
//!    `ERR_CROSS_EVAL_MISMATCH` for a token minted for a different
//!    evaluation.
//! 2. **Single use** — the nonce is remembered on first presentation, so a
//!    replay of a *valid* token yields `ERR_CAPABILITY_REPLAY_DENIED`.
//!
//! Property 2 is stateful and therefore lives in the Referee, not in the
//! stateless verifier helper.

use bayora_common::capability::{CapError, CapabilityToken, IssuerPublicKey};
use bayora_common::error::ErrCode;
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuardError {
    #[error("capability token malformed")]
    Malformed,
    #[error("capability signature invalid")]
    BadSignature,
    #[error("capability token expired")]
    Expired,
    #[error("token for eval {token_eval} presented for eval {request_eval}")]
    CrossEvalMismatch {
        token_eval: String,
        request_eval: String,
    },
    #[error("capability nonce {nonce} for eval {eval_id} has already been consumed")]
    ReplayDenied { nonce: String, eval_id: String },
}

impl GuardError {
    /// Stable error code surfaced to the Red VM, the HUD and the audit trail.
    pub fn code(&self) -> &'static str {
        match self {
            GuardError::Malformed => ErrCode::CAPABILITY_MALFORMED,
            GuardError::BadSignature => ErrCode::CAPABILITY_BAD_SIGNATURE,
            GuardError::Expired => ErrCode::CAPABILITY_EXPIRED,
            GuardError::CrossEvalMismatch { .. } => ErrCode::CROSS_EVAL_MISMATCH,
            GuardError::ReplayDenied { .. } => ErrCode::CAPABILITY_REPLAY_DENIED,
        }
    }

    /// HTTP status used by the control plane for the same condition.
    pub fn http_status(&self) -> u16 {
        match self {
            GuardError::ReplayDenied { .. } | GuardError::CrossEvalMismatch { .. } => 403,
            GuardError::Expired | GuardError::BadSignature | GuardError::Malformed => 401,
        }
    }
}

impl From<CapError> for GuardError {
    fn from(value: CapError) -> Self {
        match value {
            CapError::Malformed => GuardError::Malformed,
            CapError::BadSignature => GuardError::BadSignature,
            CapError::Expired => GuardError::Expired,
            CapError::CrossEvalMismatch {
                token_eval,
                request_eval,
            } => GuardError::CrossEvalMismatch {
                token_eval,
                request_eval,
            },
        }
    }
}

/// Bounded LRU-ish set of consumed nonces.
///
/// Capability nonces are 64-bit random values bound to a single evaluation, so
/// the working set is naturally small; the bound exists to make memory growth
/// impossible even under a flood of well-formed tokens.
///
/// # Replay window (residual risk)
///
/// Consumed nonces are evicted once the set exceeds `capacity` (default 4096).
/// An attacker who floods the Referee with more than `capacity` distinct valid
/// tokens can cause an old nonce to be evicted, after which replaying that old
/// token is accepted again. This is a bounded replay window, not an indefinite
/// one. For deployments where replay must be impossible across restarts or
/// token floods, persist consumed nonces to a bounded on-disk set or use a
/// hardware trust anchor that enforces single-use at the signing layer.
#[derive(Debug)]
struct ConsumedNonces {
    set: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl ConsumedNonces {
    fn new(capacity: usize) -> Self {
        ConsumedNonces {
            set: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Returns `true` if the nonce was fresh (and is now consumed).
    fn insert_if_fresh(&mut self, nonce: &str) -> bool {
        if self.set.contains(nonce) {
            return false;
        }
        self.set.insert(nonce.to_string());
        self.order.push_back(nonce.to_string());
        while self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
        true
    }

    fn len(&self) -> usize {
        self.set.len()
    }
}

/// Consumes capability tokens exactly once each.
#[derive(Debug)]
pub struct CapabilityGuard {
    issuer: IssuerPublicKey,
    consumed: Mutex<ConsumedNonces>,
}

impl CapabilityGuard {
    /// `max_tracked_nonces` bounds memory; the default in the Referee is large
    /// enough for any evaluation batch.
    pub fn new(issuer: IssuerPublicKey, max_tracked_nonces: usize) -> Self {
        CapabilityGuard {
            issuer,
            consumed: Mutex::new(ConsumedNonces::new(max_tracked_nonces)),
        }
    }

    pub fn issuer_public_key_hex(&self) -> String {
        self.issuer.to_hex()
    }

    /// Verify and consume in one step. The nonce is only recorded **after**
    /// every cryptographic check passes, so an attacker cannot burn a
    /// legitimate token by presenting a forged copy of it first.
    pub fn consume(
        &self,
        token: &CapabilityToken,
        request_eval_id: &str,
        now_unix_ms: u64,
    ) -> Result<(), GuardError> {
        self.issuer
            .verify(token, request_eval_id, now_unix_ms)
            .map_err(GuardError::from)?;

        let mut consumed = self
            .consumed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !consumed.insert_if_fresh(&token.claims.nonce) {
            return Err(GuardError::ReplayDenied {
                nonce: token.claims.nonce.clone(),
                eval_id: token.claims.eval_id.clone(),
            });
        }
        Ok(())
    }

    /// Escape hatch for tests and operational tooling; never used on the
    /// request path.
    pub fn tracked_nonces(&self) -> usize {
        self.consumed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bayora_common::capability::CapabilityClaims;
    use bayora_common::signature::sign_message;
    use bayora_common::timeutil::random_nonce_hex;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    struct Fixture {
        sk: SigningKey,
        guard: CapabilityGuard,
    }

    impl Fixture {
        fn new() -> Self {
            let sk = SigningKey::from_bytes(&[11u8; 32]);
            let issuer_hex = hex::encode(sk.verifying_key().to_bytes());
            let guard = CapabilityGuard::new(IssuerPublicKey::from_hex(&issuer_hex).unwrap(), 4);
            Fixture { sk, guard }
        }

        fn token_for(&self, eval_id: &str, exp_unix_ms: u64) -> CapabilityToken {
            self.token_with_nonce(eval_id, exp_unix_ms, &random_nonce_hex())
        }

        fn token_with_nonce(
            &self,
            eval_id: &str,
            exp_unix_ms: u64,
            nonce: &str,
        ) -> CapabilityToken {
            let claims = CapabilityClaims {
                eval_id: eval_id.to_string(),
                nonce: nonce.to_string(),
                exp_unix_ms,
            };
            let sig = sign_message(&self.sk, &claims.signing_bytes().unwrap());
            CapabilityToken {
                claims,
                signature: hex::encode(sig),
            }
        }
    }

    #[test]
    fn valid_token_is_consumed_once() {
        let f = Fixture::new();
        let token = f.token_for("eval_100", u64::MAX);
        assert!(f.guard.consume(&token, "eval_100", 1).is_ok());
        assert_eq!(f.guard.tracked_nonces(), 1);
        assert_eq!(f.guard.consume(&token, "eval_100", 1), Err(GuardError::ReplayDenied {
            nonce: token.claims.nonce.clone(),
            eval_id: "eval_100".into(),
        }));
    }

    #[test]
    fn replay_denied_code_matches_spec() {
        let f = Fixture::new();
        let token = f.token_for("eval_a", u64::MAX);
        f.guard.consume(&token, "eval_a", 1).unwrap();
        let err = f.guard.consume(&token, "eval_a", 1).unwrap_err();
        assert_eq!(err.code(), "ERR_CAPABILITY_REPLAY_DENIED");
        assert_eq!(err.http_status(), 403);
    }

    #[test]
    fn cross_eval_code_matches_spec() {
        let f = Fixture::new();
        let token = f.token_for("eval_a", u64::MAX);
        let err = f.guard.consume(&token, "eval_b", 1).unwrap_err();
        assert_eq!(err.code(), "ERR_CROSS_EVAL_MISMATCH");
        // A refused cross-eval token must not burn the nonce.
        assert_eq!(f.guard.tracked_nonces(), 0);
        assert!(f.guard.consume(&token, "eval_a", 1).is_ok());
    }

    #[test]
    fn expired_and_forged_tokens_are_refused_without_burning_nonce() {
        let f = Fixture::new();
        let expired = f.token_for("eval_a", 1_000);
        assert_eq!(
            f.guard.consume(&expired, "eval_a", 2_000),
            Err(GuardError::Expired)
        );
        assert_eq!(f.guard.tracked_nonces(), 0);

        let mut forged = f.token_for("eval_a", u64::MAX);
        forged.claims.eval_id = "eval_b".into();
        assert_eq!(
            f.guard.consume(&forged, "eval_b", 1),
            Err(GuardError::BadSignature)
        );
        assert_eq!(f.guard.tracked_nonces(), 0);

        let mut malformed = f.token_for("eval_a", u64::MAX);
        malformed.signature = "not-hex".into();
        assert_eq!(
            f.guard.consume(&malformed, "eval_a", 1),
            Err(GuardError::Malformed)
        );
    }

    #[test]
    fn nonce_tracking_is_bounded() {
        let f = Fixture::new();
        assert_eq!(f.guard.tracked_nonces(), 0);
        for i in 0..10 {
            // Distinct nonces for the same evaluation.
            let nonce = format!("{:016x}", i);
            let token = f.token_with_nonce("eval_a", u64::MAX, &nonce);
            f.guard.consume(&token, "eval_a", 1).unwrap();
        }
        // Capacity is 4; the set cannot grow past it.
        assert!(f.guard.tracked_nonces() <= 4);
    }

    #[test]
    fn exactly_one_concurrent_consumer_wins() {
        let f = Fixture::new();
        let token = f.token_for("eval_race", u64::MAX);
        let guard = Arc::new(f.guard);
        let winners: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let guard = Arc::clone(&guard);
                    let token = token.clone();
                    scope.spawn(move || guard.consume(&token, "eval_race", 1).is_ok())
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|won| *won)
                .count()
        });
        assert_eq!(winners, 1, "a capability token must be consumable once");
    }
}
