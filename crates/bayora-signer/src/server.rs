//! Socket server implementing the `SIGN(digest)` trust-anchor boundary.
//!
//! Transport options:
//! * `unix:/run/bayora/signer.sock` — restricted UNIX socket, mode 0600
//!   (production PoC path; the Referee and the key holder are separate
//!   processes with separate UIDs under `jailer`).
//! * `tcp:127.0.0.1:9443` — loopback TCP, used for development on hosts
//!   without `AF_UNIX` (e.g. Windows).

use crate::keys::SignerKeys;
use bayora_common::capability::{CapabilityClaims, CapabilityToken};
use bayora_common::digest::Digest;
use bayora_common::error::ErrCode;
use bayora_common::signature::{sign_digest, sign_message};
use bayora_common::signer_proto::{SignerRequest, SignerResponse, MAX_SIGNER_FRAME};
use bayora_common::timeutil::{now_unix_ms, random_nonce_hex};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Where the signer listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerSpec {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ListenerSpec {
    /// `tcp:127.0.0.1:9443` or `unix:/run/bayora/signer.sock`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        if let Some(addr) = spec.strip_prefix("tcp:") {
            let parsed: SocketAddr = addr
                .parse()
                .map_err(|e| format!("invalid tcp address {addr}: {e}"))?;
            return Ok(ListenerSpec::Tcp(parsed));
        }
        if let Some(path) = spec.strip_prefix("unix:") {
            #[cfg(unix)]
            {
                return Ok(ListenerSpec::Unix(PathBuf::from(path)));
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err("unix sockets are not supported on this platform; use tcp:127.0.0.1:PORT".into());
            }
        }
        Err(format!(
            "unrecognised listener spec {spec:?} (expected `tcp:HOST:PORT` or `unix:PATH`)"
        ))
    }
}

impl std::fmt::Display for ListenerSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenerSpec::Tcp(addr) => write!(f, "tcp:{addr}"),
            #[cfg(unix)]
            ListenerSpec::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

/// A bound signer listener.
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl Listener {
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Listener::Tcp(l) => l.local_addr().ok(),
            #[cfg(unix)]
            Listener::Unix(_) => None,
        }
    }

    async fn accept(&self) -> std::io::Result<Conn> {
        match self {
            Listener::Tcp(l) => l.accept().await.map(|(s, _)| Conn::Tcp(s)),
            #[cfg(unix)]
            Listener::Unix(l) => l.accept().await.map(|(s, _)| Conn::Unix(s)),
        }
    }
}

/// Bind a signer listener.
pub async fn bind(spec: &ListenerSpec) -> std::io::Result<Listener> {
    match spec {
        ListenerSpec::Tcp(addr) => Ok(Listener::Tcp(TcpListener::bind(addr).await?)),
        #[cfg(unix)]
        ListenerSpec::Unix(path) => {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let listener = UnixListener::bind(path)?;
            // Restrict the socket to the owning user before serving.
            crate::keys::restrict_socket(path).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string())
            })?;
            Ok(Listener::Unix(listener))
        }
    }
}

/// Bind and serve until the process exits.
pub async fn serve(spec: ListenerSpec, keys: Arc<SignerKeys>) -> anyhow::Result<()> {
    let listener = bind(&spec).await?;
    tracing::info!(
        listen = %spec,
        trust_anchor = %keys.trust_anchor_pub_hex(),
        capability_issuer = %keys.capability_issuer_pub_hex(),
        "trust anchor signer online"
    );
    serve_on(listener, keys).await
}

/// Serve on an already-bound listener (used by tests with port 0).
pub async fn serve_on(listener: Listener, keys: Arc<SignerKeys>) -> anyhow::Result<()> {
    loop {
        let conn = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "signer accept failed");
                continue;
            }
        };
        let keys = Arc::clone(&keys);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(conn, &keys).await {
                tracing::debug!(error = %e, "signer connection closed");
            }
        });
    }
}

/// Spawn the signer on an already-bound listener, returning its join handle.
pub fn spawn(listener: Listener, keys: Arc<SignerKeys>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = serve_on(listener, keys).await {
            tracing::error!(error = %e, "signer server stopped");
        }
    })
}

/// Metadata for callers that need to reach the daemon they spawned.
#[derive(Debug, Clone)]
pub struct SignerServerHandle {
    pub spec: String,
}

enum Conn {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Conn {
    async fn read_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut prefix = [0u8; 4];
        let read = match self {
            Conn::Tcp(s) => read_prefix(s, &mut prefix).await?,
            #[cfg(unix)]
            Conn::Unix(s) => read_prefix(s, &mut prefix).await?,
        };
        if !read {
            return Ok(None); // clean EOF between frames
        }
        let len = u32::from_le_bytes(prefix) as usize;
        if len == 0 || len > MAX_SIGNER_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("signer frame length {len} out of range"),
            ));
        }
        let mut body = vec![0u8; len];
        match self {
            Conn::Tcp(s) => s.read_exact(&mut body).await?,
            #[cfg(unix)]
            Conn::Unix(s) => s.read_exact(&mut body).await?,
        };
        Ok(Some(body))
    }

    async fn write_frame(&mut self, body: &[u8]) -> std::io::Result<()> {
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        match self {
            Conn::Tcp(s) => s.write_all(&out).await?,
            #[cfg(unix)]
            Conn::Unix(s) => s.write_all(&out).await?,
        }
        match self {
            Conn::Tcp(s) => s.flush().await?,
            #[cfg(unix)]
            Conn::Unix(s) => s.flush().await?,
        }
        Ok(())
    }
}

async fn read_prefix<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    prefix: &mut [u8; 4],
) -> std::io::Result<bool> {
    use tokio::io::AsyncReadExt as _;
    let mut filled = 0;
    while filled < 4 {
        match stream.read(&mut prefix[filled..]).await? {
            0 if filled == 0 => return Ok(false),
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated signer frame prefix",
                ))
            }
            n => filled += n,
        }
    }
    Ok(true)
}

async fn handle_conn(mut conn: Conn, keys: &SignerKeys) -> std::io::Result<()> {
    while let Some(body) = conn.read_frame().await? {
        let response = match bayora_common::signer_proto::decode_body::<SignerRequest>(&body) {
            Ok(req) => handle_request(req, keys, now_unix_ms()),
            Err(e) => SignerResponse::error("ERR_SIGNER_BAD_REQUEST", e),
        };
        let encoded = bayora_common::signer_proto::encode_frame(&response);
        conn.write_frame(&encoded[4..]).await?;
    }
    Ok(())
}

/// Pure request handler — unit-testable, no I/O.
pub fn handle_request(req: SignerRequest, keys: &SignerKeys, now_ms: u64) -> SignerResponse {
    match req {
        SignerRequest::GetPubkeys => SignerResponse::Pubkeys {
            trust_anchor: keys.trust_anchor_pub_hex(),
            capability_issuer: keys.capability_issuer_pub_hex(),
        },
        SignerRequest::SignTrustAnchorDigest { digest_hex } => match Digest::from_hex(&digest_hex)
        {
            Ok(digest) => {
                let sig = sign_digest(&keys.trust_anchor, &digest);
                SignerResponse::Signature {
                    signature: hex::encode(sig),
                }
            }
            Err(e) => SignerResponse::error(ErrCode::INTERNAL, format!("bad digest: {e}")),
        },
        SignerRequest::IssueCapability { eval_id, ttl_ms } => {
            let claims = CapabilityClaims {
                eval_id,
                nonce: random_nonce_hex(),
                exp_unix_ms: now_ms.saturating_add(ttl_ms),
            };
            match claims.signing_bytes() {
                Ok(bytes) => {
                    let sig = sign_message(&keys.capability_issuer, &bytes);
                    SignerResponse::Capability {
                        token: CapabilityToken {
                            claims,
                            signature: hex::encode(sig),
                        },
                    }
                }
                Err(e) => SignerResponse::error(ErrCode::INTERNAL, format!("claims: {e}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bayora_common::capability::IssuerPublicKey;
    use bayora_common::signer_proto::{encode_frame, SignerRequest, SignerResponse};
    use bayora_common::signature::verify_digest_signature;
    use std::time::Duration;

    fn keys() -> SignerKeys {
        let dir = std::env::temp_dir().join(format!("bayora-signer-test-{}", random_nonce_hex()));
        SignerKeys::load_or_create(&dir).unwrap()
    }

    #[test]
    fn sign_digest_boundary_is_exact() {
        let keys = keys();
        let digest = Digest::of(b"manifest-bytes");
        let resp = handle_request(
            SignerRequest::SignTrustAnchorDigest {
                digest_hex: digest.to_hex(),
            },
            &keys,
            0,
        );
        match resp {
            SignerResponse::Signature { signature } => {
                verify_digest_signature(&keys.trust_anchor_pub_hex(), &digest, &signature).unwrap();
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn capability_mint_is_verifiable_and_single_key() {
        let keys = keys();
        let issuer = IssuerPublicKey::from_hex(&keys.capability_issuer_pub_hex()).unwrap();
        let resp = handle_request(
            SignerRequest::IssueCapability {
                eval_id: "eval_100".into(),
                ttl_ms: 60_000,
            },
            &keys,
            1_000,
        );
        match resp {
            SignerResponse::Capability { token } => {
                issuer.verify(&token, "eval_100", 2_000).unwrap();
                assert_eq!(token.claims.exp_unix_ms, 61_000);
                assert_eq!(token.claims.nonce.len(), 16);
                // Cross-eval is refused by the verifier, not the signer.
                assert!(issuer.verify(&token, "eval_101", 2_000).is_err());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn bad_digest_hex_is_an_error() {
        let keys = keys();
        let resp = handle_request(
            SignerRequest::SignTrustAnchorDigest {
                digest_hex: "zz".into(),
            },
            &keys,
            0,
        );
        assert!(matches!(resp, SignerResponse::Error { .. }));
    }

    #[test]
    fn listener_spec_parsing() {
        assert_eq!(
            ListenerSpec::parse("tcp:127.0.0.1:9443").unwrap(),
            ListenerSpec::Tcp("127.0.0.1:9443".parse().unwrap())
        );
        #[cfg(unix)]
        assert_eq!(
            ListenerSpec::parse("unix:/tmp/bayora.sock").unwrap(),
            ListenerSpec::Unix(PathBuf::from("/tmp/bayora.sock"))
        );
        assert!(ListenerSpec::parse("bogus").is_err());
    }

    #[tokio::test]
    async fn end_to_end_over_socket() {
        let keys = Arc::new(keys());
        let listener = bind(&ListenerSpec::Tcp("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = spawn(listener, Arc::clone(&keys));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let digest = Digest::of(b"over-the-wire");
        let req = encode_frame(&SignerRequest::SignTrustAnchorDigest {
            digest_hex: digest.to_hex(),
        });
        stream.write_all(&req).await.unwrap();

        let mut prefix = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut prefix))
            .await
            .unwrap()
            .unwrap();
        let len = u32::from_le_bytes(prefix) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.unwrap();
        let resp: SignerResponse =
            bayora_common::signer_proto::decode_body(&body).unwrap();
        match resp {
            SignerResponse::Signature { signature } => {
                verify_digest_signature(&keys.trust_anchor_pub_hex(), &digest, &signature)
                    .unwrap();
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
