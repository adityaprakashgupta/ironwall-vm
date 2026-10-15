//! The Trust Anchor boundary: `SIGN(digest) -> signature`.
//!
//! The Referee holds an [`IsolatedSocketSigner`] — a *client* of the signer
//! micro-daemon. There is deliberately no `GET_PRIVATE_KEY` operation and no
//! private key type in this module: the only way to produce a signature is to
//! ask the isolated daemon over a restricted socket
//! (`bayora_signer`, protocol in `bayora_common::signer_proto`).
//!
//! Production swaps `IsolatedSocketSigner` for a TPM 2.0 (`/dev/tpmrm0`) or
//! PKCS#11 HSM adapter implementing the same two traits; see
//! `docs/TRUST_ANCHOR.md` and [`Tpm2HsmSigner`] for the hardware path.

use async_trait::async_trait;
use bayora_common::capability::CapabilityToken;
use bayora_common::signer_proto::{
    decode_body, encode_frame, SignerRequest, SignerResponse, MAX_SIGNER_FRAME,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[cfg(unix)]
use tokio::net::UnixStream;

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("signer transport failure: {0}")]
    Transport(String),
    #[error("signer rejected request: {code}: {message}")]
    Remote { code: String, message: String },
    #[error("signer unavailable: {0}")]
    Unavailable(String),
}

/// Extract the raw 64-byte Ed25519 signature from a signer response.
fn signature_bytes(hex_sig: &str) -> Result<[u8; 64], SignerError> {
    let raw = hex::decode(hex_sig.trim())
        .map_err(|e| SignerError::Transport(format!("bad signature hex: {e}")))?;
    raw.try_into()
        .map_err(|_| SignerError::Transport("signature is not 64 bytes".into()))
}

/// The Referee-side view of the trust anchor.
#[async_trait]
pub trait TrustAnchorSigner: Send + Sync {
    /// Send a 32-byte SHA-256 digest, receive a 64-byte Ed25519 signature.
    async fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignerError>;
    /// Trust anchor public key (hex), used for pinning in the HUD and verifier.
    fn public_key_hex(&self) -> String;
}

/// The Referee-side view of the capability issuer (same isolated daemon).
#[async_trait]
pub trait CapabilityIssuer: Send + Sync {
    async fn issue_capability(
        &self,
        eval_id: &str,
        ttl_ms: u64,
    ) -> Result<CapabilityToken, SignerError>;
    fn issuer_public_key_hex(&self) -> String;
}

/// Where to reach the signer daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerEndpoint {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl SignerEndpoint {
    pub fn parse(spec: &str) -> Result<Self, String> {
        if let Some(addr) = spec.strip_prefix("tcp:") {
            let parsed: SocketAddr = addr
                .parse()
                .map_err(|e| format!("invalid tcp address {addr}: {e}"))?;
            return Ok(SignerEndpoint::Tcp(parsed));
        }
        if let Some(path) = spec.strip_prefix("unix:") {
            #[cfg(unix)]
            {
                return Ok(SignerEndpoint::Unix(PathBuf::from(path)));
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(
                    "unix sockets are unavailable on this platform; use tcp:127.0.0.1:9443".into(),
                );
            }
        }
        Err(format!(
            "unrecognised signer spec {spec:?} (expected `tcp:HOST:PORT` or `unix:PATH`)"
        ))
    }
}

impl std::fmt::Display for SignerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerEndpoint::Tcp(addr) => write!(f, "tcp:{addr}"),
            #[cfg(unix)]
            SignerEndpoint::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

enum Connection {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Connection {
    async fn connect(endpoint: &SignerEndpoint) -> Result<Self, SignerError> {
        match endpoint {
            SignerEndpoint::Tcp(addr) => TcpStream::connect(addr)
                .await
                .map(Connection::Tcp)
                .map_err(|e| SignerError::Unavailable(format!("tcp {addr}: {e}"))),
            #[cfg(unix)]
            SignerEndpoint::Unix(path) => UnixStream::connect(path)
                .await
                .map(Connection::Unix)
                .map_err(|e| SignerError::Unavailable(format!("unix {}: {e}", path.display()))),
        }
    }

    async fn round_trip(&mut self, request: &SignerRequest) -> Result<SignerResponse, SignerError> {
        let framed = encode_frame(request);
        self.write_all(&framed).await?;
        let mut prefix = [0u8; 4];
        self.read_exact(&mut prefix).await?;
        let len = u32::from_le_bytes(prefix) as usize;
        if len == 0 || len > MAX_SIGNER_FRAME {
            return Err(SignerError::Transport(format!(
                "signer response length {len} out of range"
            )));
        }
        let mut body = vec![0u8; len];
        self.read_exact(&mut body).await?;
        decode_body(&body).map_err(SignerError::Transport)
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), SignerError> {
        match self {
            Connection::Tcp(s) => s
                .write_all(bytes)
                .await
                .map_err(|e| SignerError::Transport(e.to_string())),
            #[cfg(unix)]
            Connection::Unix(s) => s
                .write_all(bytes)
                .await
                .map_err(|e| SignerError::Transport(e.to_string())),
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), SignerError> {
        match self {
            Connection::Tcp(s) => s
                .read_exact(buf)
                .await
                .map(|_| ())
                .map_err(|e| SignerError::Transport(e.to_string())),
            #[cfg(unix)]
            Connection::Unix(s) => s
                .read_exact(buf)
                .await
                .map(|_| ())
                .map_err(|e| SignerError::Transport(e.to_string())),
        }
    }
}

/// Client for the isolated signer daemon. Reconnects transparently on the
/// first request after a transport failure.
pub struct IsolatedSocketSigner {
    endpoint: SignerEndpoint,
    trust_anchor_hex: String,
    capability_issuer_hex: String,
    conn: Mutex<Option<Connection>>,
}

/// Only the endpoint and public keys are shown: the socket handle is opaque,
/// and there is no private key material in this struct to leak.
impl std::fmt::Debug for IsolatedSocketSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolatedSocketSigner")
            .field("endpoint", &self.endpoint)
            .field("trust_anchor", &self.trust_anchor_hex)
            .field("capability_issuer", &self.capability_issuer_hex)
            .finish_non_exhaustive()
    }
}

impl IsolatedSocketSigner {
    /// Connect and fetch both public keys (proves the daemon is reachable
    /// before the enclave accepts any traffic).
    pub async fn connect(endpoint: SignerEndpoint) -> Result<Self, SignerError> {
        let mut conn = Connection::connect(&endpoint).await?;
        let response = conn.round_trip(&SignerRequest::GetPubkeys).await?;
        let (trust_anchor_hex, capability_issuer_hex) = match response {
            SignerResponse::Pubkeys {
                trust_anchor,
                capability_issuer,
            } => (trust_anchor, capability_issuer),
            SignerResponse::Error { code, message } => {
                return Err(SignerError::Remote { code, message })
            }
            other => {
                return Err(SignerError::Transport(format!(
                    "unexpected signer response to GetPubkeys: {other:?}"
                )))
            }
        };
        Ok(IsolatedSocketSigner {
            endpoint,
            trust_anchor_hex,
            capability_issuer_hex,
            conn: Mutex::new(Some(conn)),
        })
    }

    pub fn endpoint(&self) -> &SignerEndpoint {
        &self.endpoint
    }

    /// One request with a single transparent reconnect (the daemon may have
    /// restarted, or the cached connection may have gone stale).
    async fn request(&self, request: SignerRequest) -> Result<SignerResponse, SignerError> {
        let mut guard = self.conn.lock().await;
        let first = match guard.as_mut() {
            Some(conn) => conn.round_trip(&request).await,
            None => Err(SignerError::Unavailable("not connected".into())),
        };
        match first {
            Ok(resp) => Ok(resp),
            Err(first_err) => {
                // Reconnect once.
                let mut conn = Connection::connect(&self.endpoint).await.map_err(|e| {
                    SignerError::Unavailable(format!("{first_err}; reconnect failed: {e}"))
                })?;
                let resp = conn.round_trip(&request).await?;
                *guard = Some(conn);
                Ok(resp)
            }
        }
    }
}

#[async_trait]
impl TrustAnchorSigner for IsolatedSocketSigner {
    async fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        let response = self
            .request(SignerRequest::SignTrustAnchorDigest {
                digest_hex: hex::encode(digest),
            })
            .await?;
        match response {
            SignerResponse::Signature { signature } => signature_bytes(&signature),
            SignerResponse::Error { code, message } => Err(SignerError::Remote { code, message }),
            other => Err(SignerError::Transport(format!(
                "unexpected signer response to SignTrustAnchorDigest: {other:?}"
            ))),
        }
    }

    fn public_key_hex(&self) -> String {
        self.trust_anchor_hex.clone()
    }
}

#[async_trait]
impl CapabilityIssuer for IsolatedSocketSigner {
    async fn issue_capability(
        &self,
        eval_id: &str,
        ttl_ms: u64,
    ) -> Result<CapabilityToken, SignerError> {
        let response = self
            .request(SignerRequest::IssueCapability {
                eval_id: eval_id.to_string(),
                ttl_ms,
            })
            .await?;
        match response {
            SignerResponse::Capability { token } => Ok(token),
            SignerResponse::Error { code, message } => Err(SignerError::Remote { code, message }),
            other => Err(SignerError::Transport(format!(
                "unexpected signer response to IssueCapability: {other:?}"
            ))),
        }
    }

    fn issuer_public_key_hex(&self) -> String {
        self.capability_issuer_hex.clone()
    }
}

/// Production TPM 2.0 / PKCS#11 adapter.
///
/// TPM 2.0 does not implement EdDSA natively, so the hardware path mirrors the
/// software path exactly: a small helper daemon owns the key (TPM-sealed or
/// HSM-resident) and speaks the same `SIGN(digest)` protocol over a device-
/// backed socket. This adapter exists to make that boundary explicit and to
/// fail closed (rather than silently falling back to a software key) when the
/// hardware anchor is missing.
pub struct Tpm2HsmSigner {
    /// e.g. `/dev/tpmrm0` (TPM resource manager) or a PKCS#11 socket path.
    device: PathBuf,
    /// Socket of the hardware-backed signer helper.
    endpoint: SignerEndpoint,
    inner: IsolatedSocketSigner,
}

impl Tpm2HsmSigner {
    /// Fails if the device node is absent — no silent software fallback.
    pub async fn connect(device: PathBuf, endpoint: SignerEndpoint) -> Result<Self, SignerError> {
        let device_ok = if device.exists() {
            true
        } else {
            // On non-unix dev hosts the node cannot exist; report clearly.
            return Err(SignerError::Unavailable(format!(
                "hardware trust anchor device {} not present",
                device.display()
            )));
        };
        debug_assert!(device_ok);
        let inner = IsolatedSocketSigner::connect(endpoint.clone()).await?;
        Ok(Tpm2HsmSigner {
            device,
            endpoint,
            inner,
        })
    }

    pub fn device(&self) -> &std::path::Path {
        &self.device
    }

    pub fn endpoint(&self) -> &SignerEndpoint {
        &self.endpoint
    }
}

#[async_trait]
impl TrustAnchorSigner for Tpm2HsmSigner {
    async fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        self.inner.sign_digest(digest).await
    }

    fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bayora_common::digest::Digest;
    use bayora_common::signature::verify_digest_signature;
    use bayora_signer::{bind, spawn, ListenerSpec, SignerKeys};
    use std::sync::Arc;

    async fn spawn_signer() -> (
        IsolatedSocketSigner,
        Arc<SignerKeys>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(SignerKeys::load_or_create(dir.path()).unwrap());
        let listener = bind(&ListenerSpec::Tcp("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        spawn(listener, Arc::clone(&keys));
        let signer = IsolatedSocketSigner::connect(SignerEndpoint::Tcp(addr))
            .await
            .unwrap();
        (signer, keys, dir)
    }

    #[tokio::test]
    async fn sign_digest_round_trip() {
        let (signer, keys, _dir) = spawn_signer().await;
        let digest = Digest::of(b"manifest");
        let sig = signer.sign_digest(digest.as_bytes()).await.unwrap();
        verify_digest_signature(&keys.trust_anchor_pub_hex(), &digest, &hex::encode(sig))
            .unwrap();
        assert_eq!(signer.public_key_hex(), keys.trust_anchor_pub_hex());
    }

    #[tokio::test]
    async fn issue_capability_round_trip() {
        use bayora_common::capability::IssuerPublicKey;
        let (signer, keys, _dir) = spawn_signer().await;
        let token = signer.issue_capability("eval_1", 60_000).await.unwrap();
        assert_eq!(token.claims.eval_id, "eval_1");
        let pk = IssuerPublicKey::from_hex(&keys.capability_issuer_pub_hex()).unwrap();
        pk.verify(&token, "eval_1", token.claims.exp_unix_ms - 1)
            .unwrap();
    }

    #[tokio::test]
    async fn unavailable_daemon_is_a_clean_error() {
        // Nothing listening on this port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = IsolatedSocketSigner::connect(SignerEndpoint::Tcp(addr))
            .await
            .unwrap_err();
        assert!(matches!(err, SignerError::Unavailable(_)));
    }

    #[tokio::test]
    async fn reconnects_after_daemon_restart() {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(SignerKeys::load_or_create(dir.path()).unwrap());
        let listener = bind(&ListenerSpec::Tcp("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let first = spawn(listener, Arc::clone(&keys));
        let signer = IsolatedSocketSigner::connect(SignerEndpoint::Tcp(addr))
            .await
            .unwrap();
        let digest = Digest::of(b"before-restart");
        signer.sign_digest(digest.as_bytes()).await.unwrap();

        first.abort();
        let _ = first.await;
        // Rebind the same port and serve again.
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let listener = bayora_signer::Listener::Tcp(listener);
        spawn(listener, Arc::clone(&keys));

        let signed = signer.sign_digest(digest.as_bytes()).await;
        assert!(signed.is_ok(), "client must transparently reconnect: {signed:?}");
    }

    #[test]
    fn endpoint_parsing() {
        assert!(SignerEndpoint::parse("tcp:127.0.0.1:9443").is_ok());
        assert!(SignerEndpoint::parse("bogus").is_err());
        #[cfg(unix)]
        assert!(SignerEndpoint::parse("unix:/run/bayora.signer.sock").is_ok());
    }

    #[test]
    fn signature_bytes_rejects_wrong_length() {
        assert!(signature_bytes("00").is_err());
        assert!(signature_bytes(&hex::encode([1u8; 64])).is_ok());
    }
}
