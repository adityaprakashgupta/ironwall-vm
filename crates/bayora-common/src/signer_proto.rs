//! Wire protocol between the Referee/Control Plane and the isolated signer
//! micro-daemon (the only process holding private key material).
//!
//! Framing: `u32 LE length || JSON body` in both directions, max 64 KiB.

use crate::capability::CapabilityToken;
use serde::{Deserialize, Serialize};

pub const MAX_SIGNER_FRAME: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerRequest {
    /// Return both public keys (hex).
    GetPubkeys,
    /// Ask the trust anchor to sign a 32-byte digest (hex, 64 chars).
    SignTrustAnchorDigest { digest_hex: String },
    /// Mint a single-use capability token for an evaluation.
    IssueCapability { eval_id: String, ttl_ms: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerResponse {
    Pubkeys {
        trust_anchor: String,
        capability_issuer: String,
    },
    Signature {
        signature: String,
    },
    Capability {
        token: CapabilityToken,
    },
    Error {
        code: String,
        message: String,
    },
}

impl SignerResponse {
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        SignerResponse::Error {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Encode a request/response as a length-prefixed frame.
pub fn encode_frame<T: Serialize>(value: &T) -> Vec<u8> {
    let body = serde_json::to_vec(value).expect("signer protocol serializes");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Decode a length-prefixed frame (body only, prefix already consumed).
pub fn decode_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityClaims;

    #[test]
    fn request_roundtrip() {
        let req = SignerRequest::IssueCapability {
            eval_id: "eval_1".into(),
            ttl_ms: 60_000,
        };
        let wire = encode_frame(&req);
        let len = u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(len, wire.len() - 4);
        let back: SignerRequest = decode_body(&wire[4..]).unwrap();
        match back {
            SignerRequest::IssueCapability { eval_id, ttl_ms } => {
                assert_eq!(eval_id, "eval_1");
                assert_eq!(ttl_ms, 60_000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn response_roundtrip_and_unknown_fields_rejected() {
        let resp = SignerResponse::Pubkeys {
            trust_anchor: "aa".into(),
            capability_issuer: "bb".into(),
        };
        let wire = encode_frame(&resp);
        let back: SignerResponse = decode_body(&wire[4..]).unwrap();
        match back {
            SignerResponse::Pubkeys { trust_anchor, .. } => assert_eq!(trust_anchor, "aa"),
            _ => panic!("wrong variant"),
        }

        // Internally tagged enum variants still enforce deny_unknown_fields.
        let extra = r#"{"status":"capability","token":{"claims":{"eval_id":"e","nonce":"n","exp_unix_ms":1},"signature":"00"},"oops":1}"#;
        assert!(decode_body::<SignerResponse>(extra.as_bytes()).is_err());

        let tok = CapabilityToken {
            claims: CapabilityClaims {
                eval_id: "e".into(),
                nonce: "n".into(),
                exp_unix_ms: 1,
            },
            signature: "00".into(),
        };
        let _ = SignerResponse::Capability { token: tok };
    }
}
