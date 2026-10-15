//! `bayora-verifier` — the standalone Independent Verifier CLI.
//!
//! Trusts only the pinned Trust Anchor public key. Re-derives every canonical
//! byte, chain link, Merkle root and signature from the append-only evidence
//! log; prints `VALID` and exits 0, or pinpoints the first inconsistency and
//! exits 1.
//!
//! ```text
//! bayora-verifier --log evidence/evidence_log.ndjson \
//!                 --pubkey keys/trust_anchor.pk \
//!                 [--postgres-url postgres://…] \
//!                 [--expect-evaluations 12] [--expect-seals 2] \
//!                 [--expect-chain-head <hex>] \
//!                 [--require-all-sealed] [--strict-timing] [--json]
//! ```

use bayora_verifier::{load_public_key, verify_path, VerifyOptions};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "bayora-verifier",
    about = "Independent Verifier for the Bayora Enclave evidence plane",
    version
)]
struct Args {
    /// Append-only evidence log (NDJSON) to verify.
    #[arg(long, value_name = "PATH")]
    log: PathBuf,

    /// Trust Anchor public key: 64 hex characters or a path to a key file.
    #[arg(long, value_name = "HEX_OR_PATH")]
    pubkey: String,

    /// Also compare the append-only log with the PostgreSQL copy and report
    /// any divergence (a byte-level tamper check).
    #[cfg(feature = "postgres")]
    #[arg(long, value_name = "URL")]
    postgres_url: Option<String>,

    /// Fail unless the log holds exactly this many evaluations (truncation
    /// detection).
    #[arg(long, value_name = "N")]
    expect_evaluations: Option<u64>,

    /// Fail unless the log holds exactly this many batch seals.
    #[arg(long, value_name = "N")]
    expect_seals: Option<u64>,

    /// Fail unless the recomputed chain head equals this hex value.
    #[arg(long, value_name = "HEX")]
    expect_chain_head: Option<String>,

    /// Fail if any evaluation is not covered by a batch seal.
    #[arg(long)]
    require_all_sealed: bool,

    /// Promote the timing audit to a hard check: a bounded run whose log still
    /// exposes the defence stage is reported invalid.
    #[arg(long)]
    strict_timing: bool,

    /// Emit the full report as JSON instead of a human summary.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            println!("INVALID");
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let pubkey = load_public_key(&args.pubkey).map_err(|e| e.to_string())?;
    let options = VerifyOptions {
        expect_evaluations: args.expect_evaluations,
        expect_seals: args.expect_seals,
        expect_chain_head: args.expect_chain_head.clone(),
        require_all_sealed: args.require_all_sealed,
        strict_timing: args.strict_timing,
        allow_empty: false,
    };

    let report = verify_path(&args.log, &pubkey, &options).map_err(|e| e.to_string())?;

    // Optional: prove the fast query copy is byte-identical to the append log.
    #[cfg(feature = "postgres")]
    let sink_line = if let Some(url) = &args.postgres_url {
        let text = std::fs::read_to_string(&args.log).map_err(|e| e.to_string())?;
        let log_rows = bayora_verifier::canonical_lines(&text)
            .map_err(|e| e.to_string())?;
        let pg_rows = read_postgres(url)?;
        bayora_verifier::compare_sinks(&log_rows, &pg_rows).map_err(|e| e.to_string())?;
        Some(format!("append log == PostgreSQL ({} records)", log_rows.len()))
    } else {
        None
    };

    if args.json {
        let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
        println!("{json}");
    } else {
        println!("VALID");
        println!("  evaluations   : {}", report.evaluations);
        println!("  batch seals   : {}", report.seals);
        println!("  unsealed      : {}", report.unsealed_evaluations);
        println!("  chain head    : {}", report.final_chain_head);
        println!("  trust anchor  : {}", report.trust_anchor_public_key);
        let accuracy = if report.timing.accuracy_measurable {
            format!("{:.2}", report.timing.inference_accuracy)
        } else {
            format!(
                "not measurable ({} samples across {} stage(s); need 9+ over 2+)",
                report.timing.samples, report.timing.distinct_stage_labels
            )
        };
        println!(
            "  timing        : {} - {} sample(s), held {}..{}us, stddev {:.0}us ({:.4}% of mean), inference accuracy {}{}",
            report.timing.mode,
            report.timing.samples,
            report.timing.held_us_min,
            report.timing.held_us_max,
            report.timing.stddev_us,
            report.timing.relative_spread() * 100.0,
            accuracy,
            if report.timing.bounded { " (bounded)" } else { " (not bounded)" }
        );
        if args.strict_timing && !report.timing.accuracy_measurable {
            println!(
                "  timing check  : inconclusive under --strict-timing - too few samples to infer anything"
            );
        }
        #[cfg(feature = "postgres")]
        if let Some(line) = &sink_line {
            println!("  sinks         : {line}");
        }
    }

    Ok(())
}

/// Read the canonical record bytes back out of the PostgreSQL dual-sink copy.
///
/// Schema (see `microvm`/migration notes): `evidence_records(id BIGSERIAL
/// PRIMARY KEY, record_bytes BYTEA NOT NULL)`. `id` preserves append order.
#[cfg(feature = "postgres")]
fn read_postgres(url: &str) -> Result<Vec<Vec<u8>>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let rows = client
            .query("SELECT record_bytes FROM evidence_records ORDER BY id", &[])
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<_, Vec<u8>>(0))
            .collect())
    })
}
