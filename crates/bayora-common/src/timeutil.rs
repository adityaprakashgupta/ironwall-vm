//! Timestamp helpers — RFC 3339 with millisecond precision, UTC, `Z`-suffixed
/// (the exact form shown in the v3.0 manifest spec).

use crate::digest::Digest;
use chrono::{SecondsFormat, Utc};

/// `2026-09-26T16:00:00.000Z`
pub fn now_rfc3339_ms() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Unix time in milliseconds.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// SHA-256 of the running executable — the `referee_version` digest field.
/// Falls back to `"unknown"` if the binary cannot be read (e.g. deleted
/// after launch, exotic sandboxing).
pub fn current_exe_digest() -> String {
    match std::env::current_exe().and_then(std::fs::read) {
        Ok(bytes) => Digest::of(&bytes).prefixed(),
        Err(_) => "unknown".into(),
    }
}

/// 8 random bytes as 16 hex chars — manifest nonce / capability nonce.
pub fn random_nonce_hex() -> String {
    let bytes: [u8; 8] = rand::random();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_shape() {
        let s = now_rfc3339_ms();
        // 2026-..-..T..:..:...mmmZ => 24 chars, 'T' at index 10, '.' at 19
        assert_eq!(s.len(), 24, "got {s}");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[19..20], ".");
        assert!(s.ends_with('Z'));
    }

    #[test]
    fn nonce_is_16_hex_chars() {
        let n = random_nonce_hex();
        assert_eq!(n.len(), 16);
        assert!(n.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(random_nonce_hex(), random_nonce_hex());
    }
}
