/// Evaluation events — the ordered, canonically-hashed narrative of a single
/// evaluation. `EventHash = sha256(JCS(events_array))` per the evidence spec.
///
/// Completion is signalled by the *record* itself (the `Evaluation` entry in
/// the evidence log), not by an event, so the event array never depends on a
/// chain hash computed from it.
///
/// Unknown fields are rejected (`deny_unknown_fields`), and the hash chain
/// independently binds the exact bytes regardless: any mutation changes
/// `EventHash`, which the Independent Verifier recomputes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationEvent {
    /// Emitted (in memory) when the manifest is constructed and signed.
    EvaluationStarted {
        evaluation_id: String,
        manifest_hash: String,
    },
    /// A state reset ran before executing the prompt.
    StateReset {
        evaluation_id: String,
        mode: String,
        duration_us: u64,
    },
    /// The prompt was routed through the Referee.
    PromptRouted {
        evaluation_id: String,
        /// `regex_block` | `semantic_block` | `llm`
        path: String,
    },
    /// The padded response envelope was released at the bucket boundary.
    ResponseReleased {
        evaluation_id: String,
        held_us: u64,
        frame_bytes: u32,
        truncated: bool,
        response_digest: String,
    },
    /// Downstream work crossed `T_bucket - abort_margin`; future cancelled.
    DeadlineAbort {
        evaluation_id: String,
        elapsed_us: u64,
    },
}

impl EvaluationEvent {
    pub fn evaluation_id(&self) -> &str {
        match self {
            EvaluationEvent::EvaluationStarted { evaluation_id, .. }
            | EvaluationEvent::StateReset { evaluation_id, .. }
            | EvaluationEvent::PromptRouted { evaluation_id, .. }
            | EvaluationEvent::ResponseReleased { evaluation_id, .. }
            | EvaluationEvent::DeadlineAbort { evaluation_id, .. } => evaluation_id,
        }
    }
}

/// `EventHash = sha256(JCS(events))` over the ordered event array.
pub fn hash_events(events: &[EvaluationEvent]) -> Result<[u8; 32], crate::jcs::JcsError> {
    Ok(crate::digest::Digest::of(&crate::jcs::to_bytes(&events)?).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_event_fields_rejected() {
        let v = serde_json::json!({
            "event_type": "prompt_routed",
            "evaluation_id": "eval_1",
            "path": "llm",
            "injected": true
        });
        assert!(serde_json::from_value::<EvaluationEvent>(v).is_err());
    }

    #[test]
    fn event_hash_is_order_sensitive_and_deterministic() {
        let a = EvaluationEvent::EvaluationStarted {
            evaluation_id: "e".into(),
            manifest_hash: "aa".into(),
        };
        let b = EvaluationEvent::PromptRouted {
            evaluation_id: "e".into(),
            path: "llm".into(),
        };
        let h1 = hash_events(&[a.clone(), b.clone()]).unwrap();
        let h2 = hash_events(&[a.clone(), b.clone()]).unwrap();
        let h3 = hash_events(&[b, a]).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
