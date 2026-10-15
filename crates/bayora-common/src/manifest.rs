//! The signed Evaluation Manifest — the cryptographic binding of an evaluation
//! to the exact software, model, policy and kernel digests that governed it.

use crate::digest::Digest;
use crate::jcs;
use crate::policy::PolicyConfig;
use serde::{Deserialize, Serialize};

/// Content-addressed inventory of everything that may boot into an enclave.
/// Loaded from `config/images.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRegistry {
    pub kernel_digest: String,
    pub red_image_digest: String,
    pub blue_image_digest: String,
    pub llm_image_digest: String,
    pub model_digest: String,
    pub blue_policy_digest: String,
    pub firecracker_version: String,
    /// Digest of the running Referee binary (filled at load time unless the
    /// file explicitly provides one).
    #[serde(default)]
    pub referee_version: Option<String>,
}

impl ImageRegistry {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut reg: ImageRegistry = serde_json::from_str(&raw)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if reg.referee_version.is_none() {
            reg.referee_version = Some(crate::timeutil::current_exe_digest());
        }
        Ok(reg)
    }
}

/// The manifest signed by the Trust Anchor *before* any prompt is processed.
///
/// Serialized through RFC 8785 JCS before hashing, so key order in the struct
/// is irrelevant — every party derives `sha256(JCS(manifest))` byte-for-byte.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationManifest {
    pub evaluation_id: String,
    pub red_image_digest: String,
    pub blue_image_digest: String,
    pub llm_image_digest: String,
    pub model_digest: String,
    pub blue_policy_digest: String,
    pub referee_version: String,
    pub firecracker_version: String,
    pub kernel_digest: String,
    pub timing_policy: String,
    pub reset_policy: String,
    pub resource_policy: String,
    pub started_at: String,
    pub nonce: String,
}

impl EvaluationManifest {
    pub fn new(
        evaluation_id: impl Into<String>,
        registry: &ImageRegistry,
        policy: &PolicyConfig,
        started_at: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        EvaluationManifest {
            evaluation_id: evaluation_id.into(),
            red_image_digest: registry.red_image_digest.clone(),
            blue_image_digest: registry.blue_image_digest.clone(),
            llm_image_digest: registry.llm_image_digest.clone(),
            model_digest: registry.model_digest.clone(),
            blue_policy_digest: registry.blue_policy_digest.clone(),
            referee_version: registry
                .referee_version
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            firecracker_version: registry.firecracker_version.clone(),
            kernel_digest: registry.kernel_digest.clone(),
            timing_policy: policy.evaluation.timing_mode.as_str().to_string(),
            reset_policy: policy.state.reset_policy.as_str().to_string(),
            resource_policy: policy.resource_policy_tag(),
            started_at: started_at.into(),
            nonce: nonce.into(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, jcs::JcsError> {
        jcs::to_bytes(self)
    }

    /// `ManifestHash = sha256(JCS(manifest))`.
    pub fn hash(&self) -> Result<Digest, jcs::JcsError> {
        Ok(Digest::of(&self.canonical_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyConfig;

    fn policy() -> PolicyConfig {
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

    fn registry() -> ImageRegistry {
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

    #[test]
    fn manifest_hash_is_key_order_independent() {
        let m = EvaluationManifest::new(
            "eval_0195f2a4",
            &registry(),
            &policy(),
            "2026-09-26T16:00:00.000Z",
            "94a8f102c4d9e812",
        );
        let canonical = m.canonical_bytes().unwrap();
        // JCS output is sorted: evaluation_id first alphabetically?
        // (red..started_at ordering is decided by UTF-16 sort, not struct order)
        let round: EvaluationManifest =
            serde_json::from_slice(&canonical).expect("canonical bytes reparse");
        assert_eq!(round, m);
        assert_eq!(m.hash().unwrap(), Digest::of(&canonical));
        // Deterministic across constructions.
        let m2 = EvaluationManifest::new(
            "eval_0195f2a4",
            &registry(),
            &policy(),
            "2026-09-26T16:00:00.000Z",
            "94a8f102c4d9e812",
        );
        assert_eq!(m.hash().unwrap(), m2.hash().unwrap());
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let mut json = serde_json::to_value(EvaluationManifest::new(
            "e",
            &registry(),
            &policy(),
            "t",
            "n",
        ))
        .unwrap();
        json["surprise"] = serde_json::json!("x");
        assert!(serde_json::from_value::<EvaluationManifest>(json).is_err());
    }

    #[test]
    fn carries_policy_derived_fields() {
        let m = EvaluationManifest::new(
            "e",
            &registry(),
            &policy(),
            "t",
            "n",
        );
        assert_eq!(m.timing_policy, "EVAL_500");
        assert_eq!(m.reset_policy, "SNAPSHOT");
        assert_eq!(m.resource_policy, "cpu:1-2-3,4_mem:512-1024-2048");
        assert_eq!(m.referee_version, "sha256:ef2d127d");
    }
}
