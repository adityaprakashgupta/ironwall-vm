//! Ed25519 verification helpers shared by the Referee and the Independent
//! Verifier (verification only — no private keys ever live in this crate's
//! public API).

use crate::digest::Digest;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Sign a 32-byte digest, returning the raw 64-byte signature.
/// Used by the signer micro-daemon (`sign_digest(digest) -> [u8; 64]`).
pub fn sign_digest(sk: &SigningKey, digest: &Digest) -> [u8; 64] {
    sk.sign(digest.as_bytes()).to_bytes()
}

/// Sign an arbitrary message (capability claims bytes).
pub fn sign_message(sk: &SigningKey, message: &[u8]) -> [u8; 64] {
    sk.sign(message).to_bytes()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigError {
    #[error("public key malformed")]
    BadKey,
    #[error("signature malformed")]
    BadSignature,
    #[error("signature verification failed")]
    Invalid,
}

pub fn verifying_key_from_hex(s: &str) -> Result<VerifyingKey, SigError> {
    let raw = hex::decode(s.trim()).map_err(|_| SigError::BadKey)?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| SigError::BadKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| SigError::BadKey)
}

/// Verify `sign_digest(digest)` output: 64-byte hex signature over the raw
/// 32-byte digest (not over its hex string).
pub fn verify_digest_signature(
    pubkey_hex: &str,
    digest: &Digest,
    signature_hex: &str,
) -> Result<(), SigError> {
    let vk = verifying_key_from_hex(pubkey_hex)?;
    let sig_bytes: [u8; 64] = hex::decode(signature_hex.trim())
        .map_err(|_| SigError::BadSignature)?
        .try_into()
        .map_err(|_| SigError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(digest.as_bytes(), &sig)
        .map_err(|_| SigError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::issuer_pair;

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = issuer_pair();
        let digest = Digest::of(b"manifest-bytes");
        let sig = sign_digest(&sk, &digest);
        verify_digest_signature(&pk.to_hex(), &digest, &hex::encode(sig)).unwrap();
    }

    #[test]
    fn tampered_digest_fails() {
        let (sk, pk) = issuer_pair();
        let digest = Digest::of(b"a");
        let sig = sign_digest(&sk, &digest);
        let other = Digest::of(b"b");
        assert_eq!(
            verify_digest_signature(&pk.to_hex(), &other, &hex::encode(sig)),
            Err(SigError::Invalid)
        );
    }

    #[test]
    fn malformed_inputs_fail() {
        let digest = Digest::of(b"a");
        assert!(verify_digest_signature("zz", &digest, "00").is_err());
        assert!(verify_digest_signature(
            &hex::encode([7u8; 32]),
            &digest,
            "nothex"
        )
        .is_err());
    }
}
