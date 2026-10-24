//! `bayora-llm-agent` — the LLM guest agent for the Bayora Enclave.
//!
//! Runs inside the LLM MicroVM (or as a standalone dev process) and speaks the
//! Referee's mediated frame protocol over AF_VSOCK:
//!
//!     in : u32 LE length || JSON LlmRequest   {"eval_id": …, "prompt": …, "max_tokens": …}
//!     out: u32 LE length || JSON LlmResponse  {"output": …}
//!
//! Backed by [`crate::bayora_llm_engine::LlmEngine`] (llama-cpp-4). At runtime
//! it needs exactly two files: this static binary and one GGUF model. No
//! Python, no host stdlib, no system-library drift.
//!
//! ```bash
//! # Inside the LLM MicroVM (PID 1 via init.sh):
//! bayora-llm-agent --model /opt/bayora/model.gguf --port 9002
//!
//! # Standalone dev mode (no VM):
//! bayora-llm-agent --model model.gguf --port 9002 --unix-socket /tmp/llm.sock
//! ```

use bayora_llm_engine::{LlmEngine, LlmRequest, LlmResponse, MAX_TOKENS_CEILING};
use clap::Parser;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

/// Hard ceiling on ingress frames — matches the Referee's policy ceiling.
const MAX_BODY_BYTES: usize = 8192;

#[derive(Parser, Debug)]
#[command(
    name = "bayora-llm-agent",
    about = "Bayora LLM guest agent — GGUF inference over mediated VSOCK"
)]
struct Args {
    /// Path to the GGUF model weights file (the only runtime artifact needed).
    #[arg(long)]
    model: PathBuf,

    /// VSOCK port to listen on (default 9002, matches wire.py LLM_PORT).
    #[arg(long, default_value_t = 9002)]
    port: u32,

    /// Context size in tokens (default 512).
    #[arg(long, default_value_t = 512)]
    ctx_size: u32,

    /// CPU threads for inference (default 1).
    #[arg(long, default_value_t = 1)]
    threads: u32,

    /// Reset the model context after every connection (clears KV cache).
    /// Use this when running without the Referee's snapshot reset.
    #[arg(long, default_value = "per-connection", value_parser = clap::value_parser!(ResetMode))]
    reset_mode: ResetMode,

    /// Optional Unix-socket listen path (dev mode on hosts without AF_VSOCK).
    #[arg(long)]
    unix_socket: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResetMode {
    None,
    PerConnection,
}

impl clap::ValueEnum for ResetMode {
    fn value_variants<'a>() -> &'a [Self] {
        &[ResetMode::None, ResetMode::PerConnection]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            ResetMode::None => Some(clap::builder::PossibleValue::new("none")),
            ResetMode::PerConnection => {
                Some(clap::builder::PossibleValue::new("per-connection"))
            }
        }
    }
}

/// Length-prefixed JSON frame: `u32 LE length || body`.
fn encode_frame<T: Serialize + ?Sized>(value: &T) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(value).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("json encode: {e}"))
    })?;
    if body.len() > MAX_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "body of {} bytes exceeds ceiling of {}",
                body.len(),
                MAX_BODY_BYTES
            ),
        ));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Read exactly `count` bytes from the stream.
async fn read_exact<S: AsyncReadExt + Unpin>(stream: &mut S, count: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; count];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Read one length-prefixed JSON frame.
async fn read_frame<T: DeserializeOwned, S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> io::Result<T> {
    let prefix = read_exact(stream, 4).await?;
    let len = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    if len == 0 || len > MAX_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("length prefix {len} outside 1..{}", MAX_BODY_BYTES),
        ));
    }
    let body = read_exact(stream, len).await?;
    let text = std::str::from_utf8(&body).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("body is not valid UTF-8: {e}"),
        )
    })?;
    serde_json::from_str(text).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("body is not valid JSON: {e}"),
        )
    })
}

/// Write a JSON frame and flush.
async fn write_frame<T: Serialize + ?Sized, S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    value: &T,
) -> io::Result<()> {
    let frame = encode_frame(value)?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

/// Handle a single connection: read one LlmRequest, run inference, send one
/// LlmResponse. Fail-closed on any error — never send a partial generation.
async fn handle_connection<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    engine: &mut LlmEngine,
    stream: &mut S,
    reset_after: bool,
) -> io::Result<()> {
    let request: LlmRequest = read_frame(stream).await?;

    debug!(
        eval_id = %request.eval_id,
        prompt_len = request.prompt.len(),
        max_tokens = request.max_tokens,
        "llm request received"
    );

    if request.max_tokens > MAX_TOKENS_CEILING {
        warn!(
            max_tokens = request.max_tokens,
            ceiling = MAX_TOKENS_CEILING,
            "max_tokens exceeds ceiling, refusing"
        );
        let err = serde_json::json!({
            "error": "ERR_MAX_TOKENS_EXCEEDED",
            "message": format!("max_tokens {} exceeds ceiling of {}", request.max_tokens, MAX_TOKENS_CEILING)
        });
        return write_frame(stream, &err).await;
    }

    let output = engine
        .infer(&request.prompt, request.max_tokens)
        .map_err(|e| {
            error!(
                eval_id = %request.eval_id,
                error = %e,
                "llm inference failed"
            );
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;

    let response = LlmResponse { output };

    debug!(
        eval_id = %request.eval_id,
        output_len = response.output.len(),
        "llm response ready"
    );

    write_frame(stream, &response).await?;

    if reset_after {
        engine.reset().map_err(|e| {
            error!(error = %e, "llm context reset failed");
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;
    }

    Ok(())
}

async fn run_vsock_server(
    mut engine: LlmEngine,
    port: u32,
    reset_after: bool,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use tokio_vsock::{VsockAddr, VsockListener};

        let listener = VsockListener::bind(VsockAddr::new(u32::MAX, port))
            .map_err(|e| anyhow::anyhow!("vsock bind on port {port}: {e}"))?;
        info!(port, "llm agent listening on AF_VSOCK");

        loop {
            let (mut stream, _addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "vsock accept failed");
                    continue;
                }
            };
            let reset_after = reset_after;
            if let Err(e) = handle_connection(&mut engine, &mut stream, reset_after).await {
                warn!(error = %e, "connection handler error");
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (engine, port, reset_after);
        Err(anyhow::anyhow!("AF_VSOCK requires Linux; use --unix-socket instead"))
    }
}

async fn run_unix_server(
    mut engine: LlmEngine,
    socket_path: PathBuf,
    reset_after: bool,
) -> anyhow::Result<()> {
    use tokio::net::UnixListener;

    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    info!(path = %socket_path.display(), "llm agent listening on Unix socket");

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "unix accept failed");
                continue;
            }
        };
        let reset_after = reset_after;
        if let Err(e) = handle_connection(&mut engine, &mut stream, reset_after).await {
            warn!(error = %e, "connection handler error");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bayora_llm_agent=info".into()),
        )
        .init();

    let args = Args::parse();

    if !args.model.exists() {
        anyhow::bail!("model file not found: {}", args.model.display());
    }

    let mut engine = LlmEngine::new()?;
    engine.load(&args.model, args.ctx_size, args.threads)?;

    info!(
        model = %args.model.display(),
        ctx_size = args.ctx_size,
        threads = args.threads,
        "llm engine initialised"
    );

    let reset_after = matches!(args.reset_mode, ResetMode::PerConnection);

    match args.unix_socket {
        Some(socket_path) => run_unix_server(engine, socket_path, reset_after).await,
        None => run_vsock_server(engine, args.port, reset_after).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_frame_is_length_prefixed() {
        let frame = encode_frame(&serde_json::json!({"a": 1})).unwrap();
        let declared =
            u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(declared, frame.len() - 4);
    }

    #[test]
    fn oversized_body_is_refused() {
        let big = serde_json::json!({"prompt": "x".repeat(MAX_BODY_BYTES + 1)});
        assert!(encode_frame(&big).is_err());
    }
}
