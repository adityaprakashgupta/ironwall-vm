//! `bayora-referee` — Blind Referee executable.
//!
//! Boots the control plane (and, on Linux, the VSOCK listener the Red
//! MicroVM speaks), after proving at startup that every trust prerequisite
//! holds: policy validates, images are content-addressed, the signer
//! responds, and the public keys it pins match the signer's answers.

use bayora_referee::control_plane::router;
use bayora_referee::evidence_emitter::{DualSink, EvidenceEmitter, NDJsonSink};
use bayora_referee::metrics::Metrics;
use bayora_referee::policy_engine::PolicyEngine;
use bayora_referee::referee::RefereeState;
use bayora_referee::snapshot_manager::{LogicalKvResetManager, NoopResetManager, ResetManager};
use bayora_referee::transport::{StubTransport, WorkloadTransport};
use bayora_referee::trust_anchor::{CapabilityIssuer, IsolatedSocketSigner, SignerEndpoint, TrustAnchorSigner};
use bayora_common::capability::IssuerPublicKey;
use bayora_common::manifest::ImageRegistry;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "bayora-referee",
    about = "Bayora Enclave Blind Referee — policy, capability, bounded timing, evidence",
    version
)]
struct Args {
    /// Declarative policy file (validated at startup).
    #[arg(long, default_value = "config/policy.yaml")]
    policy: PathBuf,

    /// Content-addressed image registry.
    #[arg(long, default_value = "config/images.json")]
    images: PathBuf,

    /// Control-plane listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// Signer endpoint: `unix:/run/bayora/signer.sock` or `tcp:127.0.0.1:9443`.
    #[arg(long, default_value = "tcp:127.0.0.1:9443")]
    signer: String,

    /// Append-only evidence log (audit-trusted copy).
    #[arg(long, default_value = "evidence/evidence_log.ndjson")]
    evidence_log: PathBuf,

    /// Optional PostgreSQL dual sink (`--postgres-url`), fast query path.
    #[cfg(feature = "postgres")]
    #[arg(long)]
    postgres_url: Option<String>,

    /// Downstream transport: `stub` (demo/tests) or `vsock` (MicroVMs).
    #[arg(long, default_value = "stub")]
    transport: String,

    /// VSOCK endpoint of the Blue-team VM.
    #[arg(long, default_value_t = 4)]
    blue_cid: u32,
    #[arg(long, default_value_t = 9001)]
    blue_port: u32,

    /// VSOCK endpoint of the LLM VM.
    #[arg(long, default_value_t = 5)]
    llm_cid: u32,
    #[arg(long, default_value_t = 9002)]
    llm_port: u32,

    /// Workload reset: `noop` (demo), `snapshot` (Firecracker) or `kv` (llama.cpp).
    #[arg(long, default_value = "noop")]
    reset: String,

    /// Firecracker API socket (used with `--reset snapshot`).
    #[arg(long, default_value = "/run/firecracker/llm.sock")]
    firecracker_api: PathBuf,

    /// Golden snapshot to restore (used with `--reset snapshot`).
    #[arg(long, default_value = "microvm/snapshots/llm-golden.snap")]
    snapshot_path: PathBuf,

    /// llama.cpp endpoint (used with `--reset kv`).
    #[arg(long, default_value = "http://127.0.0.1:8081")]
    llama_url: String,

    /// Capability TTL issued at evaluation creation.
    #[arg(long, default_value_t = 60_000)]
    capability_ttl_ms: u64,

    /// Cap tracked capability nonces (memory bound).
    #[arg(long, default_value_t = 4096)]
    max_tracked_nonces: usize,

    /// Also serve the Red MicroVM over VSOCK (Linux only).
    #[arg(long)]
    vsock_port: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bayora_referee=info,bayora_signer=info".into()),
        )
        .init();

    let args = Args::parse();

    // 1. Policy: validate before anything else can start.
    let policy = Arc::new(PolicyEngine::load(&args.policy).map_err(|e| {
        anyhow::anyhow!("policy {} rejected: {e}", args.policy.display())
    })?);
    tracing::info!(
        version = %policy.config().policy_version,
        digest = %policy.digest(),
        timing = policy.timing_mode().as_str(),
        reset = policy.reset_policy().as_str(),
        "policy loaded"
    );

    // 2. Images: content-addressed inventory.
    let images = Arc::new(ImageRegistry::load(&args.images).map_err(|e| anyhow::anyhow!(e))?);
    tracing::info!(
        kernel = %images.kernel_digest,
        model = %images.model_digest,
        firecracker = %images.firecracker_version,
        "image registry loaded"
    );

    // 3. Signer: connect and pin keys (fail closed if unreachable).
    let endpoint = SignerEndpoint::parse(&args.signer).map_err(anyhow::Error::msg)?;
    let signer = Arc::new(IsolatedSocketSigner::connect(endpoint).await.map_err(|e| {
        anyhow::anyhow!("signer unreachable at {}: {e}", args.signer)
    })?);
    let issuer: Arc<dyn CapabilityIssuer> = signer.clone();
    let trust_anchor: Arc<dyn TrustAnchorSigner> = signer.clone();
    tracing::info!(
        trust_anchor = %signer.public_key_hex(),
        issuer = %signer.issuer_public_key_hex(),
        "signer connected"
    );
    let guard = Arc::new(bayora_referee::CapabilityGuard::new(
        IssuerPublicKey::from_hex(&signer.issuer_public_key_hex())
            .map_err(|e| anyhow::anyhow!("signer returned an unusable issuer key: {e}"))?,
        args.max_tracked_nonces,
    ));

    // 4. Evidence sinks: append log always, PostgreSQL when configured.
    let ndjson = Arc::new(NDJsonSink::open(&args.evidence_log).await?);
    #[allow(unused_mut)]
    let mut sinks: Vec<Arc<dyn bayora_referee::EvidenceSink>> = vec![ndjson.clone()];
    #[cfg(feature = "postgres")]
    if let Some(url) = &args.postgres_url {
        sinks.push(Arc::new(
            bayora_referee::PostgresSink::connect(url).await?,
        ));
    }
    tracing::info!(sinks = ?DualSink::new(sinks.clone()).descriptions(), "evidence sinks ready");

    let evidence = Arc::new(EvidenceEmitter::new(
        DualSink::new(sinks),
        trust_anchor.clone(),
        policy.require_manifest_signature(),
        policy.batch_size(),
    ));

    // 5. Transport + reset manager.
    let transport: Arc<dyn WorkloadTransport> = match args.transport.as_str() {
        "stub" => Arc::new(StubTransport::default()),
        #[cfg(target_os = "linux")]
        "vsock" => Arc::new(bayora_referee::VsockTransport {
            blue_cid: args.blue_cid,
            blue_port: args.blue_port,
            llm_cid: args.llm_cid,
            llm_port: args.llm_port,
            timeout: std::time::Duration::from_secs(30),
        }),
        #[cfg(not(target_os = "linux"))]
        "vsock" => {
            anyhow::bail!("--transport vsock requires Linux; run under WSL or use --transport stub")
        }
        other => anyhow::bail!("unknown --transport {other:?} (expected stub|vsock)"),
    };
    let reset: Arc<dyn ResetManager> = match args.reset.as_str() {
        "noop" => Arc::new(NoopResetManager::new(policy.reset_policy())),
        "snapshot" => Arc::new(bayora_referee::FirecrackerSnapshotManager::new(
            &args.firecracker_api,
            &args.snapshot_path,
        )),
        "kv" => Arc::new(LogicalKvResetManager::new(&args.llama_url, 0)),
        other => anyhow::bail!("unknown --reset {other:?} (expected noop|snapshot|kv)"),
    };
    tracing::info!(transport = %transport.describe(), reset = %reset.describe(), "downstream configured");

    // 6. State + HTTP API.
    let state = Arc::new(RefereeState::new(
        policy.clone(),
        images,
        trust_anchor,
        issuer,
        guard,
        transport,
        reset,
        evidence,
        Arc::new(Metrics::new()),
        args.capability_ttl_ms,
    ));

    // 7. Optional VSOCK listener for the Red MicroVM.
    #[cfg(target_os = "linux")]
    if let Some(port) = args.vsock_port {
        let vsock_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = bayora_referee::vsock_server::serve(vsock_state, port).await {
                tracing::error!(error = %e, "vsock server exited");
            }
        });
    }
    #[cfg(not(target_os = "linux"))]
    if args.vsock_port.is_some() {
        anyhow::bail!("--vsock-port requires Linux; run under WSL");
    }

    // 8. Control plane.
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(listen = %args.listen, "control plane online");
    println!("bayora-referee listening on http://{}", args.listen);
    println!("  policy digest : {}", policy.digest());
    println!("  trust anchor  : {}", signer.public_key_hex());
    println!("  evidence log  : {}", args.evidence_log.display());
    axum::serve(listener, router(state)).await?;
    Ok(())
}
