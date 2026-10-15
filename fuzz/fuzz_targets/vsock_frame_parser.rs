#![no_main]
//! Fuzz the VSOCK ingress frame parser.
//!
//! Invariants the parser must hold for *any* byte string:
//!
//! * it never panics, never over-reads, and never allocates a body larger than
//!   the policy ceiling (`max_body`);
//! * a rejected frame is always a typed `FrameError`, never a partial parse;
//! * the length prefix is validated before the body is inspected, so a
//!   truncated or oversized prefix cannot smuggle data past the ceiling;
//! * anything that parses must re-encode and re-parse to an equal value.

use bayora_common::frame::{encode_raw_frame, parse_raw_frame, FRAME_TYPE_PROMPT};
use libfuzzer_sys::fuzz_target;

/// The production ceiling (`EvaluationPolicy::max_prompt_bytes`).
const MAX_BODY: usize = 8192;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = parse_raw_frame(data, MAX_BODY) {
        // A successfully parsed frame is always a prompt frame whose body fits.
        assert_eq!(frame.frame_type, FRAME_TYPE_PROMPT);
        let body = serde_json::to_vec(&frame).expect("PromptFrame serializes");
        assert!(
            body.len() <= MAX_BODY,
            "parser accepted a body larger than the ceiling"
        );

        // Round-trip: encoding a parsed frame must reproduce a frame that
        // parses to the same value.
        let reencoded = encode_raw_frame(&frame);
        assert!(reencoded.len() <= 4 + MAX_BODY);
        let reparsed = parse_raw_frame(&reencoded, MAX_BODY).expect("re-encode must re-parse");
        assert_eq!(frame, reparsed);

        // Frame type confusion must be rejected: flipping the type never
        // yields a parsed frame.
        let mut confused = frame.clone();
        confused.frame_type = "not_a_prompt".into();
        let bytes = encode_raw_frame(&confused);
        assert!(parse_raw_frame(&bytes, MAX_BODY).is_err());
    }

    // The unprefixed entry point must hold the same ceiling for raw bodies.
    let _ = bayora_common::frame::parse_body(data, MAX_BODY);
});
