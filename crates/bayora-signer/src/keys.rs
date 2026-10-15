//! Key material loading / generation (seed files, mode 0600 on unix).

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("key file {0} is malformed (expected 64 hex chars)")]
    Malformed(PathBuf),
}

/// The two long-lived keys of the Trust Anchor.
pub struct SignerKeys {
    pub trust_anchor: SigningKey,
    pub capability_issuer: SigningKey,
}

const TRUST_ANCHOR_FILE: &str = "trust_anchor.sk";
const CAPABILITY_FILE: &str = "capability_issuer.sk";

impl SignerKeys {
    /// Load both keys from `dir`, generating (and persisting, mode 0600)
    /// any that do not exist yet.
    pub fn load_or_create(dir: &Path) -> Result<Self, KeyError> {
        std::fs::create_dir_all(dir).map_err(|source| KeyError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let trust_anchor = load_or_create_key(&dir.join(TRUST_ANCHOR_FILE))?;
        let capability_issuer = load_or_create_key(&dir.join(CAPABILITY_FILE))?;
        Ok(SignerKeys {
            trust_anchor,
            capability_issuer,
        })
    }

    pub fn trust_anchor_pub_hex(&self) -> String {
        hex::encode(self.trust_anchor.verifying_key().to_bytes())
    }

    pub fn capability_issuer_pub_hex(&self) -> String {
        hex::encode(self.capability_issuer.verifying_key().to_bytes())
    }

    /// Persist public keys for external parties (Referee, Verifier) to pin.
    pub fn write_public_keys(&self, dir: &Path) -> Result<(PathBuf, PathBuf), KeyError> {
        let ta = dir.join("trust_anchor.pk");
        let ci = dir.join("capability_issuer.pk");
        write_public(&ta, &self.trust_anchor_pub_hex())?;
        write_public(&ci, &self.capability_issuer_pub_hex())?;
        Ok((ta, ci))
    }
}

fn load_or_create_key(path: &Path) -> Result<SigningKey, KeyError> {
    if path.exists() {
        let raw = std::fs::read_to_string(path).map_err(|source| KeyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        // The seed is generated with `rand::random` (32 bytes -> 64 hex chars).
        let bytes = hex::decode(raw.trim()).map_err(|_| KeyError::Malformed(path.into()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeyError::Malformed(path.into()))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let seed: [u8; 32] = rand::random();
    let sk = SigningKey::from_bytes(&seed);
    std::fs::write(path, hex::encode(seed)).map_err(|source| KeyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    restrict(path)?;
    Ok(sk)
}

fn write_public(path: &Path, hex_pub: &str) -> Result<(), KeyError> {
    std::fs::write(path, format!("{hex_pub}\n")).map_err(|source| KeyError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// chmod 0600 on unix — private key files must not be world readable.
/// On Windows the file inherits the user profile ACL.
fn restrict(path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| KeyError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Restrict a socket path to the owning user (0600) — mirrors the
/// `jailer`-style DAC hardening described in the threat model.
pub fn restrict_socket(path: &Path) -> Result<(), KeyError> {
    restrict(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reloads_identical_keys() {
        let dir = tempfile::tempdir().unwrap();
        let first = SignerKeys::load_or_create(dir.path()).unwrap();
        let second = SignerKeys::load_or_create(dir.path()).unwrap();
        assert_eq!(
            first.trust_anchor_pub_hex(),
            second.trust_anchor_pub_hex()
        );
        assert_eq!(
            first.capability_issuer_pub_hex(),
            second.capability_issuer_pub_hex()
        );
        assert_ne!(
            first.trust_anchor_pub_hex(),
            first.capability_issuer_pub_hex()
        );
        assert!(dir.path().join("trust_anchor.sk").exists());
        assert!(dir.path().join("capability_issuer.sk").exists());
    }

    #[test]
    fn public_keys_written_for_pinning() {
        let dir = tempfile::tempdir().unwrap();
        let keys = SignerKeys::load_or_create(dir.path()).unwrap();
        let (ta, ci) = keys.write_public_keys(dir.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(ta).unwrap().trim(),
            keys.trust_anchor_pub_hex()
        );
        assert_eq!(
            std::fs::read_to_string(ci).unwrap().trim(),
            keys.capability_issuer_pub_hex()
        );
    }

    #[test]
    fn malformed_key_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("trust_anchor.sk"), "nothex").unwrap();
        assert!(matches!(
            SignerKeys::load_or_create(dir.path()),
            Err(KeyError::Malformed(_))
        ));
    }
}
