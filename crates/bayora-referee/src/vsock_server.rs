//! VSOCK ingress — the production path the Red MicroVM actually speaks.
//!
//! Frame format is `u32 LE length || JSON body` with a hard ceiling of
//! `max_prompt_bytes` enforced *before* the body is read, and a reply of
//! exactly `response_frame_bytes` padded with ASCII spaces.
//!
//! This module is Linux-only by nature: `AF_VSOCK` does not exist on Windows,
//! so the Windows build compiles the control-plane API only and the VSOCK
//! server is exercised in WSL / on the demo host.

use crate::referee::{RefereeError, RefereeState, TurnOutcome};
use bayora_common::frame::{parse_body, pad_response, ResponseEnvelope};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

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

async fn handle_connection(state: Arc<RefereeState>, mut stream: VsockStream) -> anyhow::Result<()> {
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
async fn write_rejected(
    state: &RefereeState,
    stream: &mut VsockStream,
    code: &str,
    message: &str,
) -> anyhow::Result<()> {
    let envelope = ResponseEnvelope::rejected(code, message);
    let (frame, _truncated) = pad_response(&envelope, state.policy().response_frame_bytes())?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

/// A frame-level rejection (before a capability or evaluation exists): reply
/// with the canonical error code, still padded to the constant frame size so
/// the wire never varies.
async fn write_error(
    state: &RefereeState,
    stream: &mut VsockStream,
    err: bayora_common::frame::FrameError,
) -> anyhow::Result<()> {
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
