//! Single-use Ed25519 capability tokens.
//!
//! Token = `JCS(CapabilityClaims)` signed by the capability issuer (control
//! plane key, held by the signer micro-daemon — never by the Referee).
//! The Referee only *verifies* and tracks consumed nonces; the private key
//! never enters the execution TCB.

use crate::digest::Digest;
use crate::jcs;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Claims bound into every capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityClaims {
    /// The evaluation this token may act on.
    pub eval_id: String,
    /// 16 hex chars (8 random bytes) — single-use anti-replay value.
    pub nonce: String,
    /// Expiry, unix milliseconds.
    pub exp_unix_ms: u64,
}

impl CapabilityClaims {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, jcs::JcsError> {
        jcs::to_bytes(self)
    }
}

/// Wire form of a capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityToken {
    pub claims: CapabilityClaims,
    /// hex-encoded 64-byte Ed25519 signature over `JCS(claims)`.
    pub signature: String,
}

/// Verification-only view of the capability issuer's public key.
#[derive(Clone)]
pub struct IssuerPublicKey(VerifyingKey);

impl IssuerPublicKey {
    pub fn from_hex(s: &str) -> Result<Self, CapError> {
        let raw = hex::decode(s.trim()).map_err(|_| CapError::Malformed)?;
        let arr: [u8; 32] = raw.try_into().map_err(|_| CapError::Malformed)?;
        let vk = VerifyingKey::from_bytes(&arr).map_err(|_| CapError::Malformed)?;
        Ok(IssuerPublicKey(vk))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    /// Full verification: signature, expiry and eval binding.
    /// Nonce replay is *stateful* and therefore enforced by
    /// `bayora_referee::capability_guard::CapabilityGuard`.
    pub fn verify(
        &self,
        token: &CapabilityToken,
        expected_eval_id: &str,
        now_unix_ms: u64,
    ) -> Result<(), CapError> {
        let msg = token.claims.signing_bytes().map_err(|_| CapError::Malformed)?;
        let sig_bytes: [u8; 64] = hex::decode(&token.signature)
            .map_err(|_| CapError::Malformed)?
            .try_into()
            .map_err(|_| CapError::Malformed)?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.0
            .verify_strict(&msg, &sig)
            .map_err(|_| CapError::BadSignature)?;
        if token.claims.exp_unix_ms != 0 && now_unix_ms > token.claims.exp_unix_ms {
            return Err(CapError::Expired);
        }
        if token.claims.eval_id != expected_eval_id {
            return Err(CapError::CrossEvalMismatch {
                token_eval: token.claims.eval_id.clone(),
                request_eval: expected_eval_id.to_string(),
            });
        }
        Ok(())
    }

    /// Digest of the claims used when a signer issues a token.
    pub fn claims_digest(claims: &CapabilityClaims) -> Result<Digest, jcs::JcsError> {
        Ok(Digest::of(&claims.signing_bytes()?))
    }
}

/// Public keys are safe to log; the wrapper keeps accidental private-key
/// formatting out of `Debug` output by construction.
impl std::fmt::Debug for IssuerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IssuerPublicKey({})", self.to_hex())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapError {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::issuer_pair;

    fn claims(eval: &str, exp: u64) -> CapabilityClaims {
        CapabilityClaims {
            eval_id: eval.into(),
            nonce: "94a8f102c4d9e812".into(),
            exp_unix_ms: exp,
        }
    }

    #[test]
    fn verify_ok_and_tamper_detection() {
        let (sk, pk) = issuer_pair();
        let c = claims("eval_100", u64::MAX);
        let msg = c.signing_bytes().unwrap();
        let sig = crate::signature::sign_message(&sk, &msg);
        let token = CapabilityToken {
            claims: c.clone(),
            signature: hex::encode(sig),
        };
        pk.verify(&token, "eval_100", 1).unwrap();

        // Tampered claims => bad signature.
        let mut bad = token.clone();
        bad.claims.eval_id = "eval_101".into();
        assert_eq!(
            pk.verify(&bad, "eval_101", 1),
            Err(CapError::BadSignature)
        );
    }

    #[test]
    fn cross_eval_and_expiry() {
        let (sk, pk) = issuer_pair();
        let c = claims("eval_100", 1_000);
        let sig = crate::signature::sign_message(&sk, &c.signing_bytes().unwrap());
        let token = CapabilityToken {
            claims: c,
            signature: hex::encode(sig),
        };
        assert!(matches!(
            pk.verify(&token, "eval_101", 1),
            Err(CapError::CrossEvalMismatch { .. })
        ));
        assert_eq!(pk.verify(&token, "eval_100", 2_000), Err(CapError::Expired));
    }

    #[test]
    fn rejects_unknown_token_fields() {
        let v = serde_json::json!({
            "claims": {"eval_id": "e", "nonce": "n", "exp_unix_ms": 1},
            "signature": "00",
            "extra": true
        });
        assert!(serde_json::from_value::<CapabilityToken>(v).is_err());
    }

    #[test]
    fn issuer_pubkey_hex_roundtrip() {
        let (_sk, pk) = issuer_pair();
        let again = IssuerPublicKey::from_hex(&pk.to_hex()).unwrap();
        assert_eq!(again.to_hex(), pk.to_hex());
        assert!(IssuerPublicKey::from_hex("nothex").is_err());
    }
}
