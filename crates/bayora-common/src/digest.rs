//! SHA-256 digest newtype with `sha256:<hex>` display form.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::fmt;

/// A SHA-256 digest. Serializes as plain lowercase hex (64 chars);
/// [`Digest::prefixed`] renders the `sha256:<hex>` form used inside manifests.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The hash-chain genesis value: 32 zero bytes.
    pub const ZERO: Digest = Digest([0u8; 32]);

    pub fn of(bytes: &[u8]) -> Self {
        Digest(Sha256::digest(bytes).into())
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Parse hex, tolerating an optional `sha256:` prefix.
    pub fn from_hex(s: &str) -> Result<Self, DigestError> {
        let s = s.strip_prefix("sha256:").unwrap_or(s);
        let raw = hex::decode(s).map_err(|_| DigestError::Hex)?;
        let arr: [u8; 32] = raw.try_into().map_err(|_| DigestError::Length)?;
        Ok(Digest(arr))
    }

    /// `sha256:<hex>` display form (as used for image/model digests).
    pub fn prefixed(self) -> String {
        format!("sha256:{}", self.to_hex())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Digest::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl From<[u8; 32]> for Digest {
    fn from(a: [u8; 32]) -> Self {
        Digest(a)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DigestError {
    #[error("invalid hex")]
    Hex,
    #[error("digest must be exactly 32 bytes")]
    Length,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_is_wellknown() {
        // SHA-256("") — the standard NIST vector.
        assert_eq!(
            Digest::of(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn roundtrip_hex_and_prefixed() {
        let d = Digest::of(b"bayora");
        assert_eq!(Digest::from_hex(&d.to_hex()).unwrap(), d);
        assert_eq!(Digest::from_hex(&d.prefixed()).unwrap(), d);
        assert!(d.to_hex().len() == 64);
    }

    #[test]
    fn serde_roundtrip_is_plain_hex() {
        let d = Digest::of(b"x");
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(s, format!("\"{}\"", d.to_hex()));
        let back: Digest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }
}
