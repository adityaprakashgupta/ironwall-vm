//! The Policy Enforcement Point.
//!
//! Wraps the declarative `config/policy.yaml` into the runtime decisions the
//! Referee needs, and remembers the raw bytes so that the policy digest
//! recorded in every manifest is provably the file that governed the run.

use bayora_common::digest::Digest;
use bayora_common::policy::{FlowControl, PolicyConfig, PolicyError, ResetPolicy, TimingMode, Workload};
use std::path::Path;
use std::time::Duration;

/// Startup-time policy holder (immutable for the lifetime of a Referee).
#[derive(Debug)]
pub struct PolicyEngine {
    config: PolicyConfig,
    raw: Vec<u8>,
}

impl PolicyEngine {
    /// Load and validate a policy file. Validation failures are fatal: the
    /// Referee refuses to start with a policy that weakens a pillar.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let (config, raw) = PolicyConfig::load(path)?;
        Ok(PolicyEngine { config, raw })
    }

    /// Parse from an in-memory YAML string (tests, `--policy-stdin`).
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let config = PolicyConfig::from_yaml(yaml)?;
        Ok(PolicyEngine {
            config,
            raw: yaml.as_bytes().to_vec(),
        })
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// `sha256` over the raw policy bytes — recorded in every manifest.
    pub fn digest(&self) -> Digest {
        Digest::of(&self.raw)
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn timing_mode(&self) -> TimingMode {
        self.config.evaluation.timing_mode
    }

    /// Release bucket, or `None` for baseline (`NORMAL`) mode.
    pub fn bucket(&self) -> Option<Duration> {
        self.config.evaluation.timing_mode.bucket()
    }

    pub fn abort_margin(&self) -> Duration {
        Duration::from_millis(self.config.evaluation.abort_margin_ms)
    }

    pub fn max_prompt_bytes(&self) -> usize {
        self.config.evaluation.max_prompt_bytes
    }

    pub fn response_frame_bytes(&self) -> usize {
        self.config.evaluation.response_frame_bytes
    }

    pub fn max_tokens(&self) -> u32 {
        self.config.evaluation.max_tokens
    }

    pub fn reset_policy(&self) -> ResetPolicy {
        self.config.state.reset_policy
    }

    pub fn cache_prompt(&self) -> bool {
        self.config.state.cache_prompt
    }

    pub fn batch_size(&self) -> usize {
        self.config.audit.batch_size
    }

    pub fn require_manifest_signature(&self) -> bool {
        self.config.audit.require_manifest_signature
    }

    /// Whether the Red VM may reach `dst` at all, and in what manner.
    /// A `Denied` decision is an auditable refusal, not a silent drop.
    pub fn flow_decision(&self, src: Workload, dst: Workload) -> FlowControl {
        self.config.flow(src, dst)
    }

    /// `DENIED` flows the Referee must never broker, whichever direction the
    /// request arrives from. Used by the mediator to fail closed on any
    /// unexpected routing request.
    pub fn assert_flow_allowed(
        &self,
        src: Workload,
        dst: Workload,
    ) -> Result<FlowControl, PolicyError> {
        match self.config.flow(src, dst) {
            FlowControl::Denied => Err(PolicyError::Validation(format!(
                "flow {}->{} is DENIED by policy",
                src.as_str(),
                dst.as_str()
            ))),
            allowed => Ok(allowed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real shipped policy file, compiled into the test binary so the test
    /// fails if the file the Referee actually reads is ever broken.
    const SHIPPED: &str = include_str!("../../../config/policy.yaml");

    #[test]
    fn shipped_policy_loads_and_validates() {
        let engine = PolicyEngine::from_yaml(SHIPPED).expect("config/policy.yaml must validate");
        assert_eq!(engine.timing_mode(), TimingMode::Eval500);
        assert_eq!(engine.bucket(), Some(Duration::from_millis(500)));
        assert_eq!(engine.abort_margin(), Duration::from_millis(15));
        assert_eq!(engine.max_prompt_bytes(), 8192);
        assert_eq!(engine.response_frame_bytes(), 4096);
        assert_eq!(engine.max_tokens(), 64);
        assert_eq!(engine.reset_policy(), ResetPolicy::Snapshot);
        assert!(!engine.cache_prompt());
        assert_eq!(engine.batch_size(), 8);
        assert!(engine.require_manifest_signature());
        assert_eq!(
            engine.config().resource_policy_tag(),
            "cpu:1-2-3,4_mem:512-1024-2048"
        );
    }

    #[test]
    fn digest_is_over_raw_bytes_and_stable() {
        let a = PolicyEngine::from_yaml(SHIPPED).unwrap();
        let b = PolicyEngine::from_yaml(SHIPPED).unwrap();
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.digest(), Digest::of(SHIPPED.as_bytes()));
        assert_eq!(a.raw_bytes(), SHIPPED.as_bytes());
    }

    #[test]
    fn zero_feedback_channel_is_denied() {
        use Workload::*;
        let engine = PolicyEngine::from_yaml(SHIPPED).unwrap();
        assert_eq!(engine.flow_decision(Red, Blue), FlowControl::Mediated);
        assert_eq!(engine.flow_decision(Red, Llm), FlowControl::Mediated);
        assert_eq!(engine.flow_decision(Blue, Red), FlowControl::Denied);
        assert!(engine.assert_flow_allowed(Blue, Red).is_err());
        assert_eq!(
            engine.assert_flow_allowed(Red, Blue).unwrap(),
            FlowControl::Mediated
        );
        // Guest-to-guest paths do not exist in the topology.
        assert_eq!(engine.flow_decision(Llm, Red), FlowControl::Denied);
        assert_eq!(engine.flow_decision(Blue, Llm), FlowControl::Denied);
    }

    #[test]
    fn invalid_policy_is_rejected_at_startup() {
        // Raising the frame ceiling above the hard cap must fail closed.
        let bad = SHIPPED.replace("max_prompt_bytes: 8192", "max_prompt_bytes: 65536");
        assert!(PolicyEngine::from_yaml(&bad).is_err());

        // Opening the Blue -> Red feedback channel must fail closed.
        let bad = SHIPPED.replace(
            "blue_to_red: \"DENIED\"",
            "blue_to_red: \"MEDIATED\"",
        );
        assert!(PolicyEngine::from_yaml(&bad).is_err());
    }

    #[test]
    fn missing_file_reports_io_error() {
        let err = PolicyEngine::load(Path::new("does/not/exist.yaml")).unwrap_err();
        assert!(matches!(err, PolicyError::Io(_)));
    }
}
