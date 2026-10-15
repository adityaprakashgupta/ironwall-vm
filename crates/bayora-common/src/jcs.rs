//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Key ordering is by UTF-16 code unit (RFC 8785 §3.2.3), string escaping
//! follows ECMAScript `JSON.stringify`, integers are emitted verbatim.
//! Floats are rejected: Bayora evidence records timings as integer
//! microseconds so every party hashes the exact same byte sequence.

use serde::Serialize;
use serde_json::Value;
use std::io::Write;

#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    #[error("JCS: floating point numbers are not canonicalizable: {0}")]
    Float(f64),
    #[error("JCS: serialization failed: {0}")]
    Serialize(String),
}

/// Canonicalize any serializable value to its RFC 8785 byte representation.
pub fn to_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, JcsError> {
    let value = serde_json::to_value(value).map_err(|e| JcsError::Serialize(e.to_string()))?;
    let mut out = Vec::new();
    write_value(&mut out, &value)?;
    Ok(out)
}

/// Canonicalize to a UTF-8 string (identical bytes as [`to_bytes`]).
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, JcsError> {
    String::from_utf8(to_bytes(value)?).map_err(|e| JcsError::Serialize(e.to_string()))
}

/// Sort object keys by UTF-16 code units, as required by RFC 8785.
/// Plain byte ordering of UTF-8 differs from UTF-16 ordering for
/// supplementary-plane code points versus U+E000..U+FFFF, so we must
/// compare the encoded code units explicitly.
fn sort_keys_utf16(keys: &mut [&String]) {
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
}

fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                write!(out, "{u}").map_err(io_err)?;
            } else if let Some(i) = n.as_i64() {
                write!(out, "{i}").map_err(io_err)?;
            } else {
                return Err(JcsError::Float(n.as_f64().unwrap_or(f64::NAN)));
            }
        }
        Value::String(s) => {
            // serde_json's string escaper matches ECMAScript JSON.stringify:
            // escapes ", \ and U+0000..U+001F only, leaves other code points
            // as raw UTF-8, uses lowercase hex in \u00xx sequences.
            let enc = serde_json::to_string(s).map_err(|e| JcsError::Serialize(e.to_string()))?;
            out.extend_from_slice(enc.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            sort_keys_utf16(&mut keys);
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let enc =
                    serde_json::to_string(k).map_err(|e| JcsError::Serialize(e.to_string()))?;
                out.extend_from_slice(enc.as_bytes());
                out.push(b':');
                write_value(out, &map[*k])?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn io_err(e: std::io::Error) -> JcsError {
    JcsError::Serialize(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys() {
        let v = json!({"b": "asdf", "a": 2});
        assert_eq!(to_string(&v).unwrap(), r#"{"a":2,"b":"asdf"}"#);
    }

    #[test]
    fn sorts_nested_recursively() {
        let v = json!({"z": {"y": 1, "x": [ {"b": 1, "a": 2} ]}, "a": null});
        assert_eq!(
            to_string(&v).unwrap(),
            r#"{"a":null,"z":{"x":[{"a":2,"b":1}],"y":1}}"#
        );
    }

    #[test]
    fn utf16_code_unit_sorting() {
        // U+10000 encodes as surrogate pair D800 DC00; U+E000 as E000.
        // UTF-16 order puts U+10000 first; UTF-8 code point order would not.
        let v = json!({"\u{e000}": 1, "\u{10000}": 2});
        let s = to_string(&v).unwrap();
        assert!(s.find("\u{10000}").unwrap() < s.find("\u{e000}").unwrap());
    }

    #[test]
    fn integers_roundtrip_verbatim() {
        let v = json!({"max": 18446744073709551615u64, "min": -9223372036854775808i64});
        assert_eq!(
            to_string(&v).unwrap(),
            r#"{"max":18446744073709551615,"min":-9223372036854775808}"#
        );
    }

    #[test]
    fn floats_are_rejected() {
        let v = json!({"t": 1.5});
        assert!(matches!(to_string(&v), Err(JcsError::Float(_))));
    }

    #[test]
    fn mandatory_escapes_only() {
        let v = json!({"s": "a\"b\\c\nd\u{1}\t"});
        assert_eq!(
            to_string(&v).unwrap(),
            r#"{"s":"a\"b\\c\nd\u0001\t"}"#
        );
    }

    #[test]
    fn non_ascii_is_raw_utf8() {
        let v = json!({"s": "日本語"});
        assert_eq!(to_string(&v).unwrap(), "{\"s\":\"日本語\"}");
    }

    #[test]
    fn deterministic_no_whitespace() {
        let v = json!({"a":[1,2,3],"b":{"c":true,"d":[]}});
        let a = to_bytes(&v).unwrap();
        let b = to_bytes(&v).unwrap();
        assert_eq!(a, b);
        assert!(!a.contains(&b' '));
    }
}
