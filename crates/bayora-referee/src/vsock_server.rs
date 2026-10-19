//! VSOCK ingress — the production path the Red MicroVM actually speaks.
//!
//! Frame format is `u32 LE length || JSON body` with a hard ceiling of
//! `max_prompt_bytes` enforced *before* the body is read, and a reply of
//! exactly `response_frame_bytes` padded with ASCII spaces.
//!
//! Two host-side transports reach this module, and the frame protocol is
//! identical over both:
//!
//! * native `AF_VSOCK` ([`serve`]) — works for CID-loopback peers on any host
//!   with vsock support, which is how the loopback demo runs;
//! * Firecracker's AF_UNIX mediation ([`bind_uds`]/[`serve_uds`]) — the only
//!   option for guests inside real Firecracker MicroVMs, because Firecracker
//!   bypasses `vhost-vsock` and native `AF_VSOCK` cannot see them.
//!
//! This module is Linux-only by nature: `AF_VSOCK` does not exist on Windows,
//! so the Windows build compiles the control-plane API only and the VSOCK
//! server is exercised in WSL / on the demo host.

use crate::referee::{RefereeError, RefereeState, TurnOutcome};
use bayora_common::frame::{parse_body, pad_response, ResponseEnvelope};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener};

/// `VMADDR_CID_ANY` — bind on every CID (the host side of the enclave).
const VMADDR_CID_ANY: u32 = u32::MAX;

/// The Referee runs exactly one turn per evaluation, so a frame may only
/// restate that fact, never invent one. Checked *before* the capability gate
/// on every ingress path — including this one, where the peer is Red — so a
/// malformed frame can never burn a legitimate single-use nonce.
pub(crate) fn turn_gate(turn: u32) -> Result<(), RefereeError> {
    if turn == 1 {
        Ok(())
    } else {
        Err(RefereeError::TurnMismatch {
            requested: turn,
            expected: 1,
        })
    }
}

/// Serve the Red MicroVM's frame protocol until the process exits.
pub async fn serve(state: Arc<RefereeState>, port: u32) -> anyhow::Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
        .map_err(|e| anyhow::anyhow!("vsock bind on port {port}: {e}"))?;
    tracing::info!(port, "vsock referee listening");
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "vsock accept failed");
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(state, stream).await {
                tracing::debug!(error = %e, "vsock connection closed");
            }
        });
    }
}

/// Bind the Red ingress listener for Firecracker's AF_UNIX vsock mediation.
///
/// When the Red MicroVM connects to CID 2 inside a Firecracker guest, the
/// vsock device forwards that connection to a host-side Unix socket named
/// `<uds_path>_<port>` (Firecracker's docs/vsock.md): the host *listens* and
/// Firecracker dials *it* — the mirror image of the host-initiated
/// `CONNECT <port>` handshake the outbound transport performs. There is no
/// handshake on this direction; the accepted stream speaks the frame protocol
/// immediately.
///
/// Binding must happen before the Red VM boots (Red connects once, with its
/// one-shot task), which is why the Referee starts first and
/// `boot_enclave.sh` waits for this socket file to exist. Binding is done
/// eagerly and returned to the caller so a failure aborts Referee startup
/// instead of leaving an enclave up with no ingress.
///
/// A Unix socket file outlives its process: after a crash or restart, bind
/// fails with `EADDRINUSE` even though nothing is listening. The stale file
/// is only removed after proving no live peer answers — a second Referee can
/// never silently steal the guest's connections.
#[cfg(unix)]
pub async fn bind_uds(path: &std::path::Path) -> std::io::Result<tokio::net::UnixListener> {
    use tokio::net::UnixListener;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match UnixListener::bind(path) {
        Ok(listener) => Ok(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let probe = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                tokio::net::UnixStream::connect(path),
            )
            .await;
            let stale = match probe {
                // A refused probe proves the file is a leftover: nothing
                // accepts there any more.
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => true,
                // A live peer — or any outcome we cannot disprove — is not
                // ours to evict.
                Ok(_) | Err(_) => false,
            };
            if !stale {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("another Referee already listens on {}", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
            UnixListener::bind(path)
        }
        Err(e) => Err(e),
    }
}

/// Serve the Red MicroVM's frame protocol over an AF_UNIX listener obtained
/// from [`bind_uds`], until the process exits.
#[cfg(unix)]
pub async fn serve_uds(
    state: Arc<RefereeState>,
    port: u32,
    path: &std::path::Path,
    listener: tokio::net::UnixListener,
) {
    tracing::info!(port, path = %path.display(), "vsock referee listening (AF_UNIX, firecracker-mediated)");
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                tracing::warn!(error = %e, "uds accept failed");
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(state, stream).await {
                tracing::debug!(error = %e, "uds connection closed");
            }
        });
    }
}

async fn handle_connection<S>(state: Arc<RefereeState>, mut stream: S) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let max_body = state.policy().max_prompt_bytes();

    // Length prefix first: an oversized declaration is refused before any
    // body bytes are requested.
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await?;
    let len = u32::from_le_bytes(prefix) as usize;
    if len == 0 || len > max_body {
        let err = bayora_common::frame::FrameError::BadLengthPrefix { got: len, max: max_body };
        return write_error(&state, &mut stream, err).await;
    }

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    let frame = match parse_body(&body, max_body) {
        Ok(frame) => frame,
        Err(err) => return write_error(&state, &mut stream, err).await,
    };

    // Red is untrusted: the frame-level turn check runs before anything is
    // consumed, exactly as it does on the HTTP control plane.
    if let Err(err) = turn_gate(frame.turn) {
        return write_rejected(&state, &mut stream, err.code(), &err.to_string()).await;
    }

    match state
        .run_turn(&frame.eval_id, &frame.capability, &frame.prompt)
        .await
    {
        Ok(outcome) => {
            stream.write_all(&outcome.frame).await?;
            stream.flush().await?;
            tracing::debug!(
                eval = %outcome.evaluation_id,
                path = outcome.path.as_str(),
                held_us = outcome.held_us,
                "released frame"
            );
            Ok(())
        }
        Err(err) => {
            tracing::debug!(code = err.code(), "vsock turn refused: {}", err);
            write_rejected(&state, &mut stream, err.code(), &err.to_string()).await
        }
    }
}

/// Reply with a canonical error code, padded to the constant frame size so the
/// wire never varies — rejections must be as constant as acceptances.
async fn write_rejected<S>(
    state: &RefereeState,
    stream: &mut S,
    code: &str,
    message: &str,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let envelope = ResponseEnvelope::rejected(code, message);
    let (frame, _truncated) = pad_response(&envelope, state.policy().response_frame_bytes())?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

/// A frame-level rejection (before a capability or evaluation exists): reply
/// with the canonical error code, still padded to the constant frame size so
/// the wire never varies.
async fn write_error<S>(
    state: &RefereeState,
    stream: &mut S,
    err: bayora_common::frame::FrameError,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let code = match err {
        bayora_common::frame::FrameError::TooLarge { .. }
        | bayora_common::frame::FrameError::BadLengthPrefix { .. } => {
            bayora_common::error::ErrCode::FRAME_TOO_LARGE
        }
        bayora_common::frame::FrameError::InvalidUtf8 => {
            bayora_common::error::ErrCode::FRAME_INVALID_UTF8
        }
        bayora_common::frame::FrameError::MalformedJson(_) => {
            bayora_common::error::ErrCode::FRAME_MALFORMED_JSON
        }
        bayora_common::frame::FrameError::UnknownField(_) => {
            bayora_common::error::ErrCode::FRAME_UNKNOWN_FIELD
        }
        bayora_common::frame::FrameError::BadType(_) => {
            bayora_common::error::ErrCode::FRAME_BAD_TYPE
        }
    };
    write_rejected(state, stream, code, &err.to_string()).await
}

/// Shared helper used by tests and by the host-side Red client to encode a
/// prompt frame (`u32 LE length || JSON`).
pub fn encode_frame(frame: &bayora_common::frame::PromptFrame) -> Vec<u8> {
    bayora_common::frame::encode_raw_frame(frame)
}

/// Extract the outcome's padded bytes for a caller that already has one.
pub fn released_bytes(outcome: &TurnOutcome) -> &[u8] {
    &outcome.frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use bayora_common::error::ErrCode;

    #[test]
    fn turn_gate_accepts_the_only_turn_that_exists() {
        assert!(turn_gate(1).is_ok());
    }

    #[test]
    fn turn_gate_refuses_an_invented_turn_with_the_canonical_code() {
        let err = turn_gate(2).unwrap_err();
        assert_eq!(err.code(), ErrCode::TURN_MISMATCH);
        assert_eq!(err.http_status(), 400);
        // Turn 0 is just as invalid: the Referee owns the counter.
        assert!(matches!(
            turn_gate(0),
            Err(RefereeError::TurnMismatch {
                requested: 0,
                expected: 1
            })
        ));
    }
}
