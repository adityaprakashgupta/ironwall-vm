//! Test-only helpers shared across this crate's unit tests.
//!
//! Compiled when this crate's own tests run, or when a dependent enables the
//! `testing` feature for its own test build (`#[cfg(any(test, feature =
//! "testing"))]`) — never into release artifacts.

use crate::capability::{CapabilityClaims, CapabilityToken, IssuerPublicKey};
use crate::manifest::ImageRegistry;
use crate::policy::PolicyConfig;
use ed25519_dalek::SigningKey;

/// Deterministic test keypair (seed = 7).
pub fn issuer_pair() -> (SigningKey, IssuerPublicKey) {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, IssuerPublicKey::from_hex(&pk_hex).unwrap())
}

pub fn claims(eval_id: &str) -> CapabilityClaims {
    CapabilityClaims {
        eval_id: eval_id.to_string(),
        nonce: crate::timeutil::random_nonce_hex(),
        exp_unix_ms: u64::MAX,
    }
}

/// Sign claims with the deterministic test key.
pub fn signed_token(claims: &CapabilityClaims) -> CapabilityToken {
    let (sk, _) = issuer_pair();
    let sig = crate::signature::sign_message(&sk, &claims.signing_bytes().unwrap());
    CapabilityToken {
        claims: claims.clone(),
        signature: hex::encode(sig),
    }
}

pub fn policy() -> PolicyConfig {
    PolicyConfig::from_yaml(
        r#"
policy_version: "2026.10.v3"
evaluation: { timing_mode: "EVAL_500", response_frame_bytes: 4096, max_prompt_bytes: 8192, max_tokens: 64 }
network: { red_to_blue: "MEDIATED", red_to_llm: "MEDIATED", blue_to_red: "DENIED" }
state: { reset_policy: "SNAPSHOT", cache_prompt: false }
resources:
  red:  { cpu_cores: "1",   memory_mb: 512,  pids_max: 64 }
  blue: { cpu_cores: "2",   memory_mb: 1024, pids_max: 64 }
  llm:  { cpu_cores: "3,4", memory_mb: 2048, pids_max: 64 }
audit: { require_manifest_signature: true, dual_write_append_log: true }
"#,
    )
    .unwrap()
}

pub fn registry() -> ImageRegistry {
    ImageRegistry {
        kernel_digest: "sha256:8f434346".into(),
        red_image_digest: "sha256:a1b2c3d4".into(),
        blue_image_digest: "sha256:d4e5f607".into(),
        llm_image_digest: "sha256:789abcdef0".into(),
        model_digest: "sha256:9f86d081".into(),
        blue_policy_digest: "sha256:4b227777".into(),
        firecracker_version: "v1.7.0".into(),
        referee_version: Some("sha256:ef2d127d".into()),
    }
}
