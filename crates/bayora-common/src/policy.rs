//! Declarative policy engine schema (`config/policy.yaml`).
//!
//! The Referee loads this once at startup, validates it against hard security
//! invariants, and records its SHA-256 digest in every Evaluation Manifest so
//! a verifier can prove *which* policy governed a historical run.

use crate::digest::Digest;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Hard ceiling on ingress frames enforced by the frame parser regardless of
/// what the policy file asks for. A policy cannot raise this.
pub const HARD_MAX_PROMPT_BYTES: usize = 8192;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("failed to read policy file: {0}")]
    Io(#[from] std::io::Error),
    #[error("policy YAML malformed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("policy validation failed: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub policy_version: String,
    pub evaluation: EvaluationSection,
    pub network: NetworkSection,
    pub state: StateSection,
    pub resources: ResourcesSection,
    pub audit: AuditSection,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationSection {
    pub timing_mode: TimingMode,
    pub response_frame_bytes: usize,
    pub max_prompt_bytes: usize,
    pub max_tokens: u32,
    /// Deadline cutoff margin before `T_bucket` (ms). Defaults to 15.
    #[serde(default = "default_abort_margin_ms")]
    pub abort_margin_ms: u64,
}

fn default_abort_margin_ms() -> u64 {
    15
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimingMode {
    /// Release as soon as the downstream work completes (baseline: leaky).
    #[serde(rename = "NORMAL")]
    Normal,
    /// Hold every response to a 500 ms bucket boundary.
    #[serde(rename = "EVAL_500")]
    Eval500,
    /// Hold every response to a 1000 ms bucket boundary.
    #[serde(rename = "EVAL_1000")]
    Eval1000,
}

impl TimingMode {
    /// The observable bucket boundary, or `None` for baseline mode.
    pub fn bucket(&self) -> Option<Duration> {
        match self {
            TimingMode::Normal => None,
            TimingMode::Eval500 => Some(Duration::from_millis(500)),
            TimingMode::Eval1000 => Some(Duration::from_millis(1000)),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TimingMode::Normal => "NORMAL",
            TimingMode::Eval500 => "EVAL_500",
            TimingMode::Eval1000 => "EVAL_1000",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    pub red_to_blue: FlowControl,
    pub red_to_llm: FlowControl,
    pub blue_to_red: FlowControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowControl {
    #[serde(rename = "MEDIATED")]
    Mediated,
    #[serde(rename = "DENIED")]
    Denied,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateSection {
    pub reset_policy: ResetPolicy,
    #[serde(default)]
    pub cache_prompt: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResetPolicy {
    /// Firecracker golden snapshot restore — full guest RAM tier isolation.
    #[serde(rename = "SNAPSHOT")]
    Snapshot,
    /// llama.cpp logical KV slot erase — application tier isolation only.
    #[serde(rename = "LOGICAL_KV")]
    LogicalKv,
}

impl ResetPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResetPolicy::Snapshot => "SNAPSHOT",
            ResetPolicy::LogicalKv => "LOGICAL_KV",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesSection {
    pub red: WorkloadResources,
    pub blue: WorkloadResources,
    pub llm: WorkloadResources,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadResources {
    pub cpu_cores: String,
    pub memory_mb: u32,
    pub pids_max: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    pub require_manifest_signature: bool,
    pub dual_write_append_log: bool,
    /// Evaluations per Merkle batch seal. Defaults to 8.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_batch_size() -> usize {
    8
}

impl PolicyConfig {
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let cfg: PolicyConfig = serde_yaml::from_str(yaml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<(Self, Vec<u8>), PolicyError> {
        let raw = std::fs::read(path)?;
        let text = std::str::from_utf8(&raw).map_err(|e| {
            PolicyError::Validation(format!("policy file is not valid UTF-8: {e}"))
        })?;
        let cfg = Self::from_yaml(text)?;
        Ok((cfg, raw))
    }

    /// `sha256` over the raw policy bytes (recorded in manifests).
    pub fn yaml_digest(raw: &[u8]) -> Digest {
        Digest::of(raw)
    }

    /// Reject any configuration that weakens the four pillars.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut violations: Vec<String> = Vec::new();

        if self.evaluation.max_prompt_bytes == 0 {
            violations.push("max_prompt_bytes must be > 0".into());
        }
        if self.evaluation.max_prompt_bytes > HARD_MAX_PROMPT_BYTES {
            violations.push(format!(
                "max_prompt_bytes ({}) exceeds the hard frame ceiling of {HARD_MAX_PROMPT_BYTES}",
                self.evaluation.max_prompt_bytes
            ));
        }
        if self.evaluation.response_frame_bytes < 256 {
            violations.push("response_frame_bytes must be >= 256".into());
        }
        if self.evaluation.response_frame_bytes > 65536 {
            violations.push("response_frame_bytes must be <= 65536".into());
        }
        if self.evaluation.max_tokens == 0 {
            violations.push("max_tokens must be > 0".into());
        }
        if let Some(bucket) = self.evaluation.timing_mode.bucket() {
            let margin = Duration::from_millis(self.evaluation.abort_margin_ms);
            if margin >= bucket {
                violations.push(format!(
                    "abort_margin_ms ({}) must be smaller than the timing bucket",
                    self.evaluation.abort_margin_ms
                ));
            }
        }
        // Zero-feedback invariant: Blue must never be able to talk back to Red.
        if self.network.blue_to_red != FlowControl::Denied {
            violations.push("blue_to_red must be DENIED (zero feedback channel)".into());
        }
        if self.network.red_to_blue != FlowControl::Mediated
            && self.network.red_to_blue != FlowControl::Denied
        {
            violations.push("red_to_blue must be MEDIATED or DENIED".into());
        }
        if self.network.red_to_llm != FlowControl::Mediated
            && self.network.red_to_llm != FlowControl::Denied
        {
            violations.push("red_to_llm must be MEDIATED or DENIED".into());
        }
        for (name, res) in [
            ("red", &self.resources.red),
            ("blue", &self.resources.blue),
            ("llm", &self.resources.llm),
        ] {
            if res.pids_max == 0 {
                violations.push(format!("resources.{name}.pids_max must be > 0"));
            }
            if res.memory_mb == 0 {
                violations.push(format!("resources.{name}.memory_mb must be > 0"));
            }
        }
        if self.audit.batch_size == 0 {
            violations.push("audit.batch_size must be > 0".into());
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::Validation(violations.join("; ")))
        }
    }

    /// Human-readable resource tag recorded in the manifest,
    /// e.g. `cpu:1-2-3,4_mem:512-1024-2048`.
    pub fn resource_policy_tag(&self) -> String {
        format!(
            "cpu:{}-{}-{}_mem:{}-{}-{}",
            self.resources.red.cpu_cores,
            self.resources.blue.cpu_cores,
            self.resources.llm.cpu_cores,
            self.resources.red.memory_mb,
            self.resources.blue.memory_mb,
            self.resources.llm.memory_mb
        )
    }

    /// Whether the given flow is allowed (and how).
    pub fn flow(&self, src: Workload, dst: Workload) -> FlowControl {
        use FlowControl::{Denied, Mediated};
        use Workload::*;
        match (src, dst) {
            (Red, Blue) => self.network.red_to_blue,
            (Red, Llm) => self.network.red_to_llm,
            (Blue, Red) => self.network.blue_to_red,
            // Referee-mediated forwarding of Blue's verdict toward the LLM is
            // internal to the TCB and always allowed; guest-initiated
            // Blue -> Llm / Llm -> * traffic does not exist (no guest net).
            (Blue, Llm) | (Llm, Blue) | (Llm, Red) | (Red, Red) | (Blue, Blue) | (Llm, Llm) => {
                let _ = (Denied, Mediated);
                Denied
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Workload {
    Red,
    Blue,
    Llm,
}

impl Workload {
    pub fn as_str(&self) -> &'static str {
        match self {
            Workload::Red => "red",
            Workload::Blue => "blue",
            Workload::Llm => "llm",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
policy_version: "2026.10.v3"
evaluation:
  timing_mode: "EVAL_500"
  response_frame_bytes: 4096
  max_prompt_bytes: 8192
  max_tokens: 64
network:
  red_to_blue: "MEDIATED"
  red_to_llm: "MEDIATED"
  blue_to_red: "DENIED"
state:
  reset_policy: "SNAPSHOT"
  cache_prompt: false
resources:
  red:  { cpu_cores: "1",   memory_mb: 512,  pids_max: 64 }
  blue: { cpu_cores: "2",   memory_mb: 1024, pids_max: 64 }
  llm:  { cpu_cores: "3,4", memory_mb: 2048, pids_max: 64 }
audit:
  require_manifest_signature: true
  dual_write_append_log: true
"#;

    #[test]
    fn parses_shipped_policy_shape() {
        let p = PolicyConfig::from_yaml(POLICY).unwrap();
        assert_eq!(p.policy_version, "2026.10.v3");
        assert_eq!(p.evaluation.timing_mode, TimingMode::Eval500);
        assert_eq!(p.evaluation.abort_margin_ms, 15); // default
        assert_eq!(p.audit.batch_size, 8); // default
        assert_eq!(p.state.reset_policy, ResetPolicy::Snapshot);
        assert_eq!(
            p.resource_policy_tag(),
            "cpu:1-2-3,4_mem:512-1024-2048"
        );
    }

    #[test]
    fn rejects_raised_frame_ceiling() {
        let bad = POLICY.replace("max_prompt_bytes: 8192", "max_prompt_bytes: 16384");
        assert!(PolicyConfig::from_yaml(&bad).is_err());
    }

    #[test]
    fn rejects_blue_to_red_mediated() {
        let bad = POLICY.replace(r#"blue_to_red: "DENIED""#, r#"blue_to_red: "MEDIATED""#);
        let err = PolicyConfig::from_yaml(&bad).unwrap_err();
        assert!(err.to_string().contains("blue_to_red"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = format!("{POLICY}\nextra_top_level: true\n");
        assert!(PolicyConfig::from_yaml(&bad).is_err());
    }

    #[test]
    fn rejects_margin_ge_bucket() {
        let bad = POLICY.replace("max_tokens: 64", "max_tokens: 64\n  abort_margin_ms: 500");
        assert!(PolicyConfig::from_yaml(&bad).is_err());
    }

    #[test]
    fn flow_matrix() {
        use FlowControl::{Denied, Mediated};
        use Workload::*;
        let p = PolicyConfig::from_yaml(POLICY).unwrap();
        assert_eq!(p.flow(Red, Blue), Mediated);
        assert_eq!(p.flow(Red, Llm), Mediated);
        assert_eq!(p.flow(Blue, Red), Denied);
        assert_eq!(p.flow(Llm, Red), Denied);
        assert_eq!(p.flow(Blue, Llm), Denied); // guest-guest never exists
    }
}
