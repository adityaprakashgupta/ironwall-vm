//! `bayora-signer` — isolated Trust Anchor signer micro-daemon.
//!
//! Holds the Ed25519 trust-anchor key (signs manifest hashes and Merkle
//! batch roots) and the capability-issuer key (mints single-use capability
//! tokens). The Referee never sees either private key.

use bayora_signer::{serve, ListenerSpec, SignerKeys};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "bayora-signer",
    about = "Bayora Enclave Trust Anchor signer (isolated key custody)",
    version
)]
struct Args {
    /// Directory holding `trust_anchor.sk` and `capability_issuer.sk`
    /// (created on first run; keys are generated if absent).
    #[arg(long, default_value = "keys")]
    key_dir: PathBuf,

    /// Listener spec: `unix:/run/bayora/signer.sock` (production PoC) or
    /// `tcp:127.0.0.1:9443` (development).
    #[arg(long, default_value = "tcp:127.0.0.1:9443")]
    listen: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let spec = ListenerSpec::parse(&args.listen).map_err(|e| anyhow::anyhow!(e))?;
    let keys = Arc::new(SignerKeys::load_or_create(&args.key_dir)?);
    let (ta_path, ci_path) = keys.write_public_keys(&args.key_dir)?;

    println!("trust anchor public key : {}", keys.trust_anchor_pub_hex());
    println!(
        "capability issuer  (pk) : {}",
        keys.capability_issuer_pub_hex()
    );
    println!("pinned public keys      : {}", ta_path.display());
    println!("                          {}", ci_path.display());
    println!("listening               : {spec}");

    serve(spec, keys).await
}
