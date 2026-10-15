//! Canonical error codes surfaced across the Referee API, evidence records
//! and the Security Posture HUD.

pub struct ErrCode;

impl ErrCode {
    // Capability guard
    pub const CAPABILITY_REPLAY_DENIED: &'static str = "ERR_CAPABILITY_REPLAY_DENIED";
    pub const CROSS_EVAL_MISMATCH: &'static str = "ERR_CROSS_EVAL_MISMATCH";
    pub const CAPABILITY_EXPIRED: &'static str = "ERR_CAPABILITY_EXPIRED";
    pub const CAPABILITY_BAD_SIGNATURE: &'static str = "ERR_CAPABILITY_BAD_SIGNATURE";
    pub const CAPABILITY_MALFORMED: &'static str = "ERR_CAPABILITY_MALFORMED";

    // Frame parser
    pub const FRAME_TOO_LARGE: &'static str = "ERR_FRAME_TOO_LARGE";
    pub const FRAME_INVALID_UTF8: &'static str = "ERR_FRAME_INVALID_UTF8";
    pub const FRAME_MALFORMED_JSON: &'static str = "ERR_FRAME_MALFORMED_JSON";
    pub const FRAME_UNKNOWN_FIELD: &'static str = "ERR_FRAME_UNKNOWN_FIELD";
    pub const FRAME_BAD_TYPE: &'static str = "ERR_FRAME_BAD_TYPE";

    // Routing / policy
    pub const FLOW_DENIED: &'static str = "ERR_FLOW_DENIED";
    pub const UNKNOWN_EVALUATION: &'static str = "ERR_UNKNOWN_EVALUATION";
    pub const EVALUATION_FINALIZED: &'static str = "ERR_EVALUATION_FINALIZED";
    pub const DEADLINE_ABORT: &'static str = "ERR_DEADLINE_ABORT";
    // Turn protocol
    pub const TURN_MISMATCH: &'static str = "ERR_TURN_MISMATCH";
    pub const POLICY_INVALID: &'static str = "ERR_POLICY_INVALID";
    pub const SIGNER_UNAVAILABLE: &'static str = "ERR_SIGNER_UNAVAILABLE";
    pub const EVIDENCE_FAILURE: &'static str = "ERR_EVIDENCE_FAILURE";
    pub const INTERNAL: &'static str = "ERR_INTERNAL";
}
