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

    /// TPM 2.0 device path for hardware-backed signing (e.g. /dev/tpmrm0).
    /// When set, the Trust Anchor uses Tpm2HsmSigner instead of the software
    /// socket signer. The device node must exist or startup fails closed.
    #[arg(long)]
    signer_device: Option<PathBuf>,

    /// Append-only evidence log (audit-trusted copy).
    #[arg(long, default_value = "evidence/evidence_log.ndjson")]
    evidence_log: PathBuf,

    /// Optional PostgreSQL dual sink (`--postgres-url`), fast query path.
    #[cfg(feature = "postgres")]
    #[arg(long)]
    postgres_url: Option<String>,

    /// Downstream transport: `stub` (demo/tests), `vsock` (native AF_VSOCK —
    /// the CID-loopback demo) or `firecracker` (Firecracker's AF_UNIX vsock
    /// mediation, for guests inside real MicroVMs; Linux only).
    #[arg(long, default_value = "stub")]
    transport: String,

    /// Runtime directory holding the enclave's Firecracker-mediated vsock
    /// endpoints: `blue.vsock`, `llm.vsock`, `red.vsock_<port>`, plus the
    /// LLM instance's API socket and pid file.
    #[arg(long, default_value = "/run/bayora")]
    runtime_dir: PathBuf,

    /// Native VSOCK endpoint of the Blue-team VM (`--transport vsock`).
    #[arg(long, default_value_t = 4)]
    blue_cid: u32,
    #[arg(long, default_value_t = 9001)]
    blue_port: u32,

    /// Native VSOCK endpoint of the LLM VM (`--transport vsock`).
    #[arg(long, default_value_t = 5)]
    llm_cid: u32,
    #[arg(long, default_value_t = 9002)]
    llm_port: u32,

    /// Workload reset: `noop` (demo), `snapshot` (Firecracker) or `kv` (llama.cpp).
    #[arg(long, default_value = "noop")]
    reset: String,

    /// Firecracker API socket (used with `--reset snapshot`; default:
    /// `<runtime-dir>/fc-llm.sock`).
    #[arg(long)]
    firecracker_api: Option<PathBuf>,

    /// Binary the `snapshot` reset respawns for every evaluation (the restore
    /// is a fresh process: Firecracker accepts one snapshot load per process).
    #[cfg_attr(not(unix), allow(dead_code))]
    #[arg(long, default_value = "firecracker")]
    firecracker_bin: PathBuf,

    /// Golden snapshot to restore (used with `--reset snapshot`); guest RAM is
    /// read from the sibling file with the same stem and a `.mem` extension.
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

    /// Red MicroVM ingress port (Linux only). With `--transport firecracker`
    /// this is the host AF_UNIX listener `<runtime-dir>/red.vsock_<port>` that
    /// Firecracker dials when the guest connects to CID 2; default 5000 in
    /// that mode.
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
    let (signer, issuer): (Arc<dyn TrustAnchorSigner>, Arc<dyn CapabilityIssuer>) =
        match &args.signer_device {
            Some(device) => {
                // TPM 2.0 / hardware-backed signer path. Fails closed if the
                // device node is absent. Two separate connections are made
                // because Tpm2HsmSigner owns its inner socket signer.
                let ta = bayora_referee::trust_anchor::Tpm2HsmSigner::connect(
                    device.clone(),
                    endpoint.clone(),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("TPM device {} unavailable: {e}", device.display())
                })?;
                let iss = bayora_referee::trust_anchor::Tpm2HsmSigner::connect(
                    device.clone(),
                    endpoint.clone(),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("TPM device {} unavailable: {e}", device.display())
                })?;
                (
                    Arc::new(ta) as Arc<dyn TrustAnchorSigner>,
                    Arc::new(iss) as Arc<dyn CapabilityIssuer>,
                )
            }
            None => {
                let s = Arc::new(
                    IsolatedSocketSigner::connect(endpoint).await.map_err(|e| {
                        anyhow::anyhow!("signer unreachable at {}: {e}", args.signer)
                    })?,
                );
                (
                    s.clone() as Arc<dyn TrustAnchorSigner>,
                    s.clone() as Arc<dyn CapabilityIssuer>,
                )
            }
        };
    let trust_anchor = signer.clone();
    tracing::info!(
        trust_anchor = %signer.public_key_hex(),
        issuer = %issuer.issuer_public_key_hex(),
        "signer connected"
    );
    let guard = Arc::new(bayora_referee::CapabilityGuard::new(
        IssuerPublicKey::from_hex(&issuer.issuer_public_key_hex())
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
    let firecracker_api: PathBuf = args
        .firecracker_api
        .clone()
        .unwrap_or_else(|| args.runtime_dir.join("fc-llm.sock"));
    #[cfg_attr(not(unix), allow(unused_variables))]
    let blue_uds = args.runtime_dir.join("blue.vsock");
    #[cfg_attr(not(unix), allow(unused_variables))]
    let llm_uds = args.runtime_dir.join("llm.vsock");

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
        #[cfg(unix)]
        "firecracker" => Arc::new(bayora_referee::FirecrackerUdsTransport {
            blue_uds: blue_uds.clone(),
            blue_port: args.blue_port,
            llm_uds: llm_uds.clone(),
            llm_port: args.llm_port,
            timeout: std::time::Duration::from_secs(30),
        }),
        #[cfg(not(unix))]
        "firecracker" => {
            anyhow::bail!("--transport firecracker requires Linux (AF_UNIX vsock mediation)")
        }
        other => anyhow::bail!("unknown --transport {other:?} (expected stub|vsock|firecracker)"),
    };
    let reset: Arc<dyn ResetManager> = match args.reset.as_str() {
        "noop" => Arc::new(NoopResetManager::new(policy.reset_policy())),
        "snapshot" => {
            let manager = bayora_referee::FirecrackerSnapshotManager::new(
                &firecracker_api,
                &args.snapshot_path,
            );
            // A snapshot restore is a fresh Firecracker process — the load is
            // accepted exactly once per process — so the reset manager owns
            // the process lifecycle: kill, respawn, load, and (in
            // firecracker mode, where the guest socket is observable) wait
            // until the restored workload answers before the turn proceeds.
            #[cfg(unix)]
            let manager = manager.with_process(
                &args.firecracker_bin,
                &llm_uds,
                (args.transport == "firecracker").then_some(args.llm_port),
            );
            Arc::new(manager)
        }
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

    // 7. Red MicroVM ingress. `--transport firecracker` defaults to the
    //    guest default port (5000) because that direction is Firecracker's
    //    only route into a real guest; native vsock stays opt-in.
    #[cfg(target_os = "linux")]
    let red_port: Option<u32> = args
        .vsock_port
        .or_else(|| (args.transport == "firecracker").then_some(5000));
    #[cfg(not(target_os = "linux"))]
    let red_port: Option<u32> = args.vsock_port;

    #[cfg(target_os = "linux")]
    if let Some(port) = red_port {
        let ingress_state = Arc::clone(&state);
        if args.transport == "firecracker" {
            // Firecracker forwards guest-initiated connections to the host
            // Unix socket `<uds_path>_<port>`, and Red dials exactly once
            // with its one-shot task — so the listener must exist *before*
            // the Red VM boots. Bind eagerly: an unusable ingress aborts
            // startup instead of leaving an enclave up with no way in.
            let path = args.runtime_dir.join(format!("red.vsock_{port}"));
            let listener = bayora_referee::vsock_server::bind_uds(&path)
                .await
                .map_err(|e| anyhow::anyhow!("red ingress bind {}: {e}", path.display()))?;
            tokio::spawn(async move {
                bayora_referee::vsock_server::serve_uds(ingress_state, port, &path, listener)
                    .await;
            });
        } else {
            tokio::spawn(async move {
                if let Err(e) = bayora_referee::vsock_server::serve(ingress_state, port).await {
                    tracing::error!(error = %e, "vsock server exited");
                }
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    if red_port.is_some() {
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
