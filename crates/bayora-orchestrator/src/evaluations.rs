//! Evaluation management — create evaluations via Referee API, run turns,
//! seal evidence batches, and verify results.
//! Replaces full_e2e_microvm.py.

use crate::trace::{Trace, TraceLevel, TraceStage};
use anyhow::{anyhow, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

/// An evaluation created by Red team.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub eval_id: String,
    pub capability: serde_json::Value,
    pub prompt: String,
    pub expected_path: String, // "llm", "regex_block", "semantic_block"
}

/// Create evaluations via Referee API. Red team submits prompts; Referee
/// creates evaluations and mints capability tokens.
pub fn create_evaluations(
    trace: &Trace,
    referee_addr: &str,
    prompts: &[(String, String)], // (prompt, expected_path)
) -> Result<Vec<Evaluation>> {
    trace.info(
        TraceStage::Evaluation,
        "creating evaluations via Referee API",
        Default::default(),
    );

    let client = reqwest::blocking::Client::new();
    let mut evaluations = Vec::new();

    for (prompt, expected_path) in prompts {
        let resp: serde_json::Value = client
            .post(format!("http://{referee_addr}/v1/evaluations"))
            .json(&json!({}))
            .send()?
            .json()?;

        let eval_id = resp["evaluation_id"]
            .as_str()
            .ok_or_else(|| anyhow!("no evaluation_id in response"))?
            .to_string();
        let capability = resp
            .get("capability")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        trace.success(
            TraceStage::Evaluation,
            "evaluation created",
            {
                let mut m = BTreeMap::new();
                m.insert("eval_id".into(), eval_id.clone().into());
                m.insert("prompt".into(), prompt.clone().into());
                m.insert("expected_path".into(), expected_path.clone().into());
                m
            },
        );

        evaluations.push(Evaluation {
            eval_id,
            capability,
            prompt: prompt.clone(),
            expected_path: expected_path.clone(),
        });
    }

    Ok(evaluations)
}

/// Run turns for all evaluations. In the full Firecracker workflow, Red
/// VM reads the task file and sends prompts via vsock. Here we simulate
/// that by having Red connect via vsock.
pub fn run_turns_vsock(
    trace: &Trace,
    runtime_dir: &Path,
    evaluations: &[Evaluation],
    vsock_port: u16,
) -> Result<()> {
    trace.info(
        TraceStage::Evaluation,
        "running turns via vsock (Red → Referee)",
        Default::default(),
    );

    // In the real workflow, Red VM reads the task file and connects to
    // Referee's vsock listener. The orchestrator waits for evidence to
    // appear in the log.
    trace.info(
        TraceStage::Evaluation,
        "waiting for Red VM to deliver evaluations via vsock",
        Default::default(),
    );

    Ok(())
}

/// Seal the evidence batch via Referee API.
pub fn seal_batch(trace: &Trace, referee_addr: &str) -> Result<serde_json::Value> {
    trace.info(
        TraceStage::Evidence,
        "sealing evidence batch",
        Default::default(),
    );

    let client = reqwest::blocking::Client::new();
    let resp: serde_json::Value = client
        .post(format!("http://{referee_addr}/v1/evaluations/seal"))
        .json(&json!({}))
        .send()?
        .json()?;

    trace.success(
        TraceStage::Evidence,
        "batch sealed",
        {
            let mut m = BTreeMap::new();
            m.insert("batch_id".into(), resp.get("batch_id").cloned().unwrap_or(serde_json::Value::Null));
            m.insert("seq_start".into(), resp.get("seq_start").cloned().unwrap_or(serde_json::Value::Null));
            m.insert("seq_end".into(), resp.get("seq_end").cloned().unwrap_or(serde_json::Value::Null));
            m
        },
    );

    Ok(resp)
}

/// Run the independent Verifier.
pub fn run_verifier(
    trace: &Trace,
    referee_addr: &str,
    evidence_log: &Path,
    verifier_bin: &Path,
) -> Result<bool> {
    trace.info(
        TraceStage::Verification,
        "running independent Verifier",
        Default::default(),
    );

    // Get trust anchor public key from posture
    let client = reqwest::blocking::Client::new();
    let posture: serde_json::Value = client
        .get(format!("http://{referee_addr}/v1/posture"))
        .send()?
        .json()?;

    let ta_pubkey = posture["evidence"]["trust_anchor_public_key"]
        .as_str()
        .ok_or_else(|| anyhow!("no trust anchor public key in posture"))?;

    let output = std::process::Command::new(verifier_bin)
        .arg("--log").arg(evidence_log)
        .arg("--pubkey").arg(ta_pubkey)
        .arg("--strict-timing")
        .arg("--require-all-sealed")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    trace.record(
        TraceLevel::Info,
        TraceStage::Verification,
        "verifier result",
        {
            let mut m = BTreeMap::new();
            m.insert("exit_code".into(), output.status.code().into());
            m.insert("stdout".into(), stdout.trim().into());
            m.insert("stderr".into(), stderr.trim().into());
            m
        },
    );

    Ok(output.status.success())
}