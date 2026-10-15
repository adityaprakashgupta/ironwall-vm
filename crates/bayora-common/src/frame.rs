//! VSOCK ingress frame (strict, `deny_unknown_fields`) and the constant-size
//! padded response envelope.
//!
//! Ingress: `u32 LE length || JSON body` — the length is validated against the
//! policy ceiling *before* any body allocation.
//!
//! Egress: canonical-shaped JSON padded with ASCII spaces to exactly
//! `response_frame_bytes` (default 4096). `serde_json` tolerates trailing
//! whitespace, so clients parse the full 4096-byte buffer directly.

use crate::capability::CapabilityToken;
use serde::{Deserialize, Serialize};

/// The only frame type the Referee accepts from the Red VM.
pub const FRAME_TYPE_PROMPT: &str = "prompt";

/// Strict ingress request. Unknown fields are a hard parse error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptFrame {
    pub frame_type: String,
    pub eval_id: String,
    pub capability: CapabilityToken,
    pub turn: u32,
    pub prompt: String,
}

/// What the Red VM receives. Deliberately *no* `path` / stage field: the
/// response must not disclose which defense stage terminated the request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub status: String,
    pub data: String,
}

impl ResponseEnvelope {
    pub fn ok(data: impl Into<String>) -> Self {
        ResponseEnvelope {
            status: "ok".into(),
            data: data.into(),
        }
    }

    pub fn timeout() -> Self {
        ResponseEnvelope {
            status: "timeout".into(),
            data: String::new(),
        }
    }

    pub fn rejected(code: &str, message: &str) -> Self {
        ResponseEnvelope {
            status: "rejected".into(),
            data: format!("{code}: {message}"),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame of {got} bytes exceeds ceiling of {max}")]
    TooLarge { got: usize, max: usize },
    #[error("frame length prefix {got} is zero or exceeds ceiling of {max}")]
    BadLengthPrefix { got: usize, max: usize },
    #[error("frame body is not valid UTF-8")]
    InvalidUtf8,
    #[error("frame body is not valid JSON: {0}")]
    MalformedJson(String),
    #[error("unknown frame field: {0}")]
    UnknownField(String),
    #[error("unsupported frame_type: {0}")]
    BadType(String),
}

/// Parse `length-prefix || body` without reading from a socket — used by the
/// fuzz target and by tests. Enforces the ceiling before touching the body.
pub fn parse_raw_frame(buf: &[u8], max_body: usize) -> Result<PromptFrame, FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::BadLengthPrefix {
            got: buf.len(),
            max: max_body,
        });
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 || len > max_body || len != buf.len() - 4 {
        return Err(FrameError::BadLengthPrefix {
            got: len,
            max: max_body,
        });
    }
    parse_body(&buf[4..4 + len], max_body)
}

/// Parse an unprefixed body (already length-checked by the reader).
pub fn parse_body(body: &[u8], max_body: usize) -> Result<PromptFrame, FrameError> {
    if body.len() > max_body {
        return Err(FrameError::TooLarge {
            got: body.len(),
            max: max_body,
        });
    }
    let text = std::str::from_utf8(body).map_err(|_| FrameError::InvalidUtf8)?;
    let frame: PromptFrame = serde_json::from_str(text).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("unknown field") {
            let field = msg
                .split('`')
                .nth(1)
                .unwrap_or("<unparsed>")
                .to_string();
            FrameError::UnknownField(field)
        } else {
            FrameError::MalformedJson(msg)
        }
    })?;
    if frame.frame_type != FRAME_TYPE_PROMPT {
        return Err(FrameError::BadType(frame.frame_type.clone()));
    }
    Ok(frame)
}

/// Build the wire bytes for an outbound prompt frame (Red-side helper/tests).
pub fn encode_raw_frame(frame: &PromptFrame) -> Vec<u8> {
    let body = serde_json::to_vec(frame).expect("PromptFrame serializes");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Serialize the envelope and pad with ASCII spaces to exactly `frame_bytes`.
/// If the payload itself exceeds the frame, `data` is truncated on a UTF-8
/// character boundary (deterministically) and `truncated` is returned.
pub fn pad_response(
    envelope: &ResponseEnvelope,
    frame_bytes: usize,
) -> Result<(Vec<u8>, bool), FrameError> {
    let json = serde_json::to_vec(envelope).map_err(|e| {
        FrameError::MalformedJson(format!("response envelope serialization failed: {e}"))
    })?;
    if json.len() <= frame_bytes {
        let mut out = json;
        out.resize(frame_bytes, b' ');
        return Ok((out, false));
    }
    // Over budget: shrink `data` until the JSON fits, keeping valid UTF-8.
    let mut data = envelope.data.clone();
    loop {
        let mut trimmed = envelope.clone();
        trimmed.data = truncate_utf8(&data, data.len().saturating_sub(32));
        trimmed.data.truncate(trimmed.data.trim_end().len());
        let json = serde_json::to_vec(&trimmed).expect("envelope serializes");
        if json.len() <= frame_bytes {
            let mut out = json;
            out.resize(frame_bytes, b' ');
            return Ok((out, true));
        }
        if trimmed.data.is_empty() {
            return Err(FrameError::TooLarge {
                got: json.len(),
                max: frame_bytes,
            });
        }
        data = trimmed.data;
    }
}

/// Never splits a multi-byte character.
fn truncate_utf8(s: &str, mut max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    while max > 0 && !s.is_char_boundary(max) {
        max -= 1;
    }
    s[..max].to_string()
}

/// Parse a padded response frame back into an envelope
/// (trailing ASCII space padding is legal JSON whitespace).
pub fn parse_padded_response(buf: &[u8]) -> Result<ResponseEnvelope, FrameError> {
    let text =
        std::str::from_utf8(buf).map_err(|_| FrameError::InvalidUtf8)?;
    serde_json::from_str(text).map_err(|e| FrameError::MalformedJson(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{claims, signed_token};

    fn sample_frame() -> PromptFrame {
        PromptFrame {
            frame_type: "prompt".into(),
            eval_id: "eval_1".into(),
            capability: signed_token(&claims("eval_1")),
            turn: 1,
            prompt: "hello".into(),
        }
    }

    #[test]
    fn raw_frame_roundtrip() {
        let frame = sample_frame();
        let wire = encode_raw_frame(&frame);
        let parsed = parse_raw_frame(&wire, 8192).unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn rejects_oversized_frame_before_body() {
        // 16 KB declared length with a 16 KB body — must be refused by the
        // length prefix check alone (no heap allocation of the body happens).
        let body = vec![b'a'; 16 * 1024];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wire.extend_from_slice(&body);
        assert!(matches!(
            parse_raw_frame(&wire, 8192),
            Err(FrameError::BadLengthPrefix { .. })
        ));
    }

    #[test]
    fn rejects_invalid_utf8() {
        let mut body = br#"{"frame_type":"prompt","eval_id":"e","capability":{"claims":{"eval_id":"e","nonce":"n","exp_unix_ms":1},"signature":"00"},"turn":1,"prompt":""#.to_vec();
        body.push(0xff);
        let mut wire = Vec::new();
        wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wire.extend_from_slice(&body);
        assert!(matches!(
            parse_raw_frame(&wire, 8192),
            Err(FrameError::InvalidUtf8)
        ));
    }

    #[test]
    fn rejects_unknown_field() {
        let mut frame = sample_frame();
        let mut v = serde_json::to_value(&frame).unwrap();
        v["sneaky"] = serde_json::json!(1);
        let body = serde_json::to_vec(&v).unwrap();
        let mut wire = Vec::new();
        wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wire.extend_from_slice(&body);
        match parse_raw_frame(&wire, 8192) {
            Err(FrameError::UnknownField(f)) => assert_eq!(f, "sneaky"),
            other => panic!("expected UnknownField, got {other:?}"),
        }
        frame.turn = 1; // silence unused warning pattern
    }

    #[test]
    fn rejects_wrong_frame_type() {
        let mut f = sample_frame();
        f.frame_type = "exec".into();
        let wire = encode_raw_frame(&f);
        assert!(matches!(
            parse_raw_frame(&wire, 8192),
            Err(FrameError::BadType(_))
        ));
    }

    #[test]
    fn response_padding_is_exact_and_parses() {
        let (buf, truncated) = pad_response(&ResponseEnvelope::ok("hi"), 4096).unwrap();
        assert_eq!(buf.len(), 4096);
        assert!(!truncated);
        assert_eq!(buf.last(), Some(&b' '));
        let env = parse_padded_response(&buf).unwrap();
        assert_eq!(env, ResponseEnvelope::ok("hi"));
    }

    #[test]
    fn overlong_response_is_truncated_not_oversized() {
        let big = ResponseEnvelope::ok("x".repeat(10_000));
        let (buf, truncated) = pad_response(&big, 4096).unwrap();
        assert_eq!(buf.len(), 4096);
        assert!(truncated);
        let env = parse_padded_response(&buf).unwrap();
        assert_eq!(env.status, "ok");
        assert!(env.data.len() < 10_000);
    }
}
