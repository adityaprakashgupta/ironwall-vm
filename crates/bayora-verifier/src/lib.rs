//! Independent Verifier — the fifth layer of the Bayora Enclave.
//!
//! This crate trusts **nothing** the Referee reports. It re-derives every
//! canonical byte from the append-only evidence log and refuses the log unless
//! all of the following hold, in order:
//!
//! 1. every line is the *canonical* (RFC 8785 JCS) serialization of its record
//!    — reordered keys, injected fields and stray whitespace are rejected;
//! 2. `ManifestHash = sha256(JCS(manifest))` and the Trust Anchor signature
//!    over that raw digest both verify under the pinned public key;
//! 3. `EventHash = sha256(JCS(events))`, the events are bound to their
//!    manifest, and the environment digests do not change mid-log;
//! 4. `ChainHash_i = sha256(ChainHash_{i-1} || ManifestHash_i || EventHash_i)`
//!    with a 32-zero-byte genesis, in strictly increasing `seq` order;
//! 5. every batch seal's Merkle root recomputes from its leaves, each leaf
//!    equals the chain hash at that `seq`, no seal overlaps another, and the
//!    root signature verifies;
//! 6. the *observable* timings recorded in the log are consistent with
//!    Bounded Observable Execution (constant-size frames, collapsed timing
//!    dispersion — reported always, enforced under `--strict-timing`).
//!
//! Every failure pinpoints the offending line and field, because "the log is
//! invalid" is useless to an auditor.
//!
//! The optional PostgreSQL comparison detects *sink divergence*: if the fast
//! query copy disagrees with the append-only copy by a single byte, the run is
//! reported as tampered.

use bayora_common::chain::{merkle_root, ChainState};
use bayora_common::digest::Digest;
use bayora_common::events::{hash_events, EvaluationEvent};
use bayora_common::manifest::EvaluationManifest;
use bayora_common::records::EvidenceRecord;
use bayora_common::signature::verify_digest_signature;
use bayora_common::telemetry::{inference_accuracy, mean, sample_stddev};
use serde::Serialize;
use std::collections::HashSet;

/// A declared-bounded mode counts as *one observable band* when the observed
/// latencies spread by less than this fraction of their mean. Real held-bucket
/// timing varies only by scheduler jitter, which reaches ~1.5% of the bucket on
/// a busy developer host (measured, not assumed); an unbounded release instead
/// spreads by ~30–70%, because the three defence stages differ by more than the
/// bucket itself. The gap between the two is wide, so the threshold is set at
/// 5% to keep a genuinely bounded run from being reported unbounded by noise.
/// The sharp instrument is the side-channel *inference accuracy*, which
/// `--strict-timing` requires; this is only a coarse dispersion gate.
pub const BOUNDED_RELATIVE_SPREAD: f64 = 0.05;

/// How far above its declared bucket a released frame may land before the
/// bound is considered violated: the policy abort margin (15 ms) plus room for
/// scheduler jitter on a shared host.
pub const BOUNDED_WINDOW_SLACK_US: u64 = 30_000;

/// How far below its declared bucket a released frame may land. Releasing at a
/// boundary can measure a hair early because of clock granularity.
pub const BOUNDED_WINDOW_EARLY_US: u64 = 2_000;

/// Recover the declared bucket from a timing-mode name such as `EVAL_500`
/// (500 ms). Returns `None` for names that declare no bucket, e.g. `NORMAL`.
pub fn bucket_us_from_mode(mode: &str) -> Option<u64> {
    let rest = mode.strip_prefix("EVAL_")?;
    let millis: u64 = rest.parse().ok()?;
    Some(millis * 1_000)
}

/// Everything that can make a log invalid, each carrying a precise location.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Failure {
    #[error("evidence log is empty: nothing to verify")]
    EmptyLog,
    #[error("cannot read the evidence log: {detail}")]
    Io { detail: String },
    #[error("line {line}: record is not well formed: {detail}")]
    MalformedLine { line: usize, detail: String },
    #[error(
        "line {line}: record bytes are not the canonical (RFC 8785) form of the record — \
         the log has been reformatted or injected"
    )]
    NonCanonicalLine { line: usize },
    #[error(
        "line {line}: manifest hash mismatch for {evaluation_id}: recorded {recorded}, \
         recomputed {recomputed}"
    )]
    ManifestHashMismatch {
        line: usize,
        evaluation_id: String,
        recorded: String,
        recomputed: String,
    },
    #[error("line {line}: manifest signature for {evaluation_id} does not verify under the pinned Trust Anchor key")]
    ManifestSignatureInvalid { line: usize, evaluation_id: String },
    #[error(
        "line {line}: event hash mismatch for {evaluation_id}: recorded {recorded}, \
         recomputed {recomputed}"
    )]
    EventHashMismatch {
        line: usize,
        evaluation_id: String,
        recorded: String,
        recomputed: String,
    },
    #[error("line {line}: events of {evaluation_id} are not bound to their manifest: {detail}")]
    EventBindingMismatch {
        line: usize,
        evaluation_id: String,
        detail: String,
    },
    #[error(
        "line {line}: chain link broken at seq {seq} ({evaluation_id}): recorded prev \
         {recorded_prev}, expected {expected_prev}"
    )]
    ChainLinkMismatch {
        line: usize,
        seq: u64,
        evaluation_id: String,
        recorded_prev: String,
        expected_prev: String,
    },
    #[error(
        "line {line}: chain hash mismatch at seq {seq} ({evaluation_id}): recorded {recorded}, \
         recomputed {recomputed}"
    )]
    ChainHashMismatch {
        line: usize,
        seq: u64,
        evaluation_id: String,
        recorded: String,
        recomputed: String,
    },
    #[error(
        "line {line}: sequence gap at {evaluation_id}: expected seq {expected_seq}, recorded {recorded_seq}"
    )]
    SequenceGap {
        line: usize,
        evaluation_id: String,
        expected_seq: u64,
        recorded_seq: u64,
    },
    #[error("line {line}: evaluation id {evaluation_id} appears twice")]
    DuplicateEvaluationId { line: usize, evaluation_id: String },
    #[error("line {line}: manifest nonce {nonce} (from {evaluation_id}) was reused")]
    DuplicateNonce {
        line: usize,
        evaluation_id: String,
        nonce: String,
    },
    #[error(
        "line {line}: {evaluation_id} changes the enclave environment: field {field} was {first}, \
         now {second}"
    )]
    EnvironmentMismatch {
        line: usize,
        evaluation_id: String,
        field: &'static str,
        first: String,
        second: String,
    },
    #[error("line {line}: {evaluation_id} declares timing policy {second} but the log started as {first}")]
    TimingPolicyInconsistent {
        line: usize,
        evaluation_id: String,
        first: String,
        second: String,
    },
    #[error(
        "line {line}: {evaluation_id} released {frame_bytes} bytes but earlier turns released \
         {expected} — constant-size egress was violated"
    )]
    NonConstantFrameSize {
        line: usize,
        evaluation_id: String,
        expected: u32,
        frame_bytes: u32,
    },
    #[error("line {line}: {evaluation_id} has an unrecognised routing path {path:?}")]
    UnknownPath {
        line: usize,
        evaluation_id: String,
        path: String,
    },
    #[error(
        "line {line}: seal {batch_id} Merkle root mismatch: recorded {recorded}, recomputed {recomputed}"
    )]
    MerkleRootMismatch {
        line: usize,
        batch_id: String,
        recorded: String,
        recomputed: String,
    },
    #[error("line {line}: seal {batch_id} signature does not verify under the pinned Trust Anchor key")]
    SealSignatureInvalid { line: usize, batch_id: String },
    #[error("line {line}: seal {batch_id} range is invalid: {detail}")]
    SealRangeInvalid {
        line: usize,
        batch_id: String,
        detail: String,
    },
    #[error("line {line}: seal {batch_id} leaf {leaf_index} does not match the chain hash at seq {seq}")]
    SealLeavesMismatch {
        line: usize,
        batch_id: String,
        leaf_index: usize,
        seq: u64,
    },
    #[error("line {line}: seal {batch_id} overlaps a previous seal (starts at seq {seq_start}, previous ended at seq {previous_end})")]
    SealOverlap {
        line: usize,
        batch_id: String,
        seq_start: u64,
        previous_end: u64,
    },
    #[error("line {line}: seal {batch_id} covers seq {seq_end} which is not present in the log")]
    SealBeyondLog {
        line: usize,
        batch_id: String,
        seq_end: u64,
    },
    #[error("expected {expected} evaluations but the log holds {found}")]
    EvaluationCountMismatch { expected: u64, found: u64 },
    #[error("expected {expected} batch seals but the log holds {found}")]
    SealCountMismatch { expected: u64, found: u64 },
    #[error("chain head mismatch: expected {expected}, recomputed {recomputed}")]
    ChainHeadMismatch { expected: String, recomputed: String },
    #[error("{count} evaluation(s) are not covered by any batch seal (first unsealed seq {first_seq})")]
    UnsealedEvaluations { count: u64, first_seq: u64 },
    #[error(
        "timing side channel in {mode}: {samples} samples yield attacker inference accuracy \
         {inference_accuracy:.2} (must stay below 0.50)"
    )]
    TimingLeak {
        mode: String,
        samples: usize,
        inference_accuracy: f64,
    },
    #[error("sink divergence at record {index}: {detail}")]
    SinkDivergence { index: usize, detail: String },
    #[error("public key {value:?} is neither a 64-hex-character key nor a readable key file")]
    BadPublicKey { value: String },
}

/// Knobs an auditor can tighten.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Fail unless exactly this many evaluation records are present
    /// (detects truncation).
    pub expect_evaluations: Option<u64>,
    /// Fail unless exactly this many batch seals are present.
    pub expect_seals: Option<u64>,
    /// Pin the published chain head.
    pub expect_chain_head: Option<String>,
    /// Fail if any evaluation is not covered by a batch seal.
    pub require_all_sealed: bool,
    /// Promote the timing audit from a report line to a hard check.
    pub strict_timing: bool,
    /// Treat an empty log as valid (used when polling a not-yet-started run).
    pub allow_empty: bool,
}

/// Per-evaluation facts the verifier re-derived from the log.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EvaluationSummary {
    pub seq: u64,
    pub evaluation_id: String,
    pub manifest_hash: String,
    pub chain_hash: String,
    pub path: String,
    pub held_us: u64,
    pub frame_bytes: u32,
    pub deadline_aborted: bool,
    pub sealed: bool,
}

/// The timing side-channel audit, recomputed from evidence alone.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TimingAudit {
    /// `NORMAL` / `EVAL_500` / `EVAL_1000`, from the signed manifests.
    pub mode: String,
    pub samples: usize,
    /// How many distinct observable latencies the log contains. In paused-time
    /// tests this is 1; on real hardware scheduling jitter makes it 1..N, so
    /// compare [`Self::stddev_us`] against [`Self::mean_us`] instead.
    pub distinct_held_us: usize,
    pub mean_us: f64,
    pub held_us_min: u64,
    pub held_us_max: u64,
    pub stddev_us: f64,
    /// What an observer could recover from these timings about the defence
    /// stage that handled each prompt (chance ≈ 0.33 for three stages).
    pub inference_accuracy: f64,
    /// How many distinct defence-stage labels appear in the log (the
    /// `PromptRouted.path` values), i.e. whether there is anything to infer.
    pub distinct_stage_labels: usize,
    /// Whether [`Self::inference_accuracy`] means anything yet. With fewer
    /// than 9 samples across at least 2 stages, k-means (k=3) gives every
    /// point its own cluster and the number is vacuously perfect — the audit
    /// is inconclusive, not leaked. This is the same precondition
    /// `--strict-timing` uses before failing.
    pub accuracy_measurable: bool,
    /// True when every turn released the same frame size (constant egress).
    pub constant_frame_size: bool,
    /// True when the mode is declared bounded *and* the observed latencies sit
    /// in one band (relative spread under 1% of the mean). Sample-count
    /// independent: a real `EVAL_*` run with jitter still reports `true`,
    /// while three separated defence-stage bands do not.
    pub bounded: bool,
}

impl TimingAudit {
    /// `stddev / mean` — how dispersed the observed latencies are relative to
    /// their magnitude. One band ⇒ near zero; separated stages ⇒ order 1.
    pub fn relative_spread(&self) -> f64 {
        if self.mean_us <= 0.0 {
            1.0
        } else {
            self.stddev_us / self.mean_us
        }
    }
}

/// The verifier's verdict when it succeeds.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Report {
    pub evaluations: u64,
    pub seals: u64,
    pub unsealed_evaluations: u64,
    pub final_chain_head: String,
    pub trust_anchor_public_key: String,
    pub timing: TimingAudit,
    pub evaluations_detail: Vec<EvaluationSummary>,
}

impl Report {
    /// One-line human summary (`VALID`-prefixed) for the CLI.
    pub fn summary_line(&self) -> String {
        let accuracy = if self.timing.accuracy_measurable {
            format!("{:.2}", self.timing.inference_accuracy)
        } else {
            format!(
                "n/a ({} sample(s) is not enough to infer anything)",
                self.timing.samples
            )
        };
        format!(
            "VALID: {} evaluation(s), {} seal(s), chain head {}, timing {} ({} distinct held times, inference accuracy {})",
            self.evaluations,
            self.seals,
            &self.final_chain_head[..16.min(self.final_chain_head.len())],
            self.timing.mode,
            self.timing.distinct_held_us,
            accuracy
        )
    }
}

/// A parsed, canonical, location-tagged record.
struct ParsedRecord {
    line: usize,
    bytes: Vec<u8>,
    record: EvidenceRecord,
}

/// Parse every non-empty line, enforcing canonical bytes and rejecting
/// injected or reformatted records.
fn parse_records(log: &str) -> Result<Vec<ParsedRecord>, Failure> {
    let mut parsed = Vec::new();
    for (index, raw) in log.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim_end_matches(['\r', '\n']);
        if trimmed.trim().is_empty() {
            continue;
        }
        let bytes = trimmed.as_bytes();
        let record = EvidenceRecord::from_bytes(bytes)
            .map_err(|e| Failure::MalformedLine { line, detail: e })?;
        let canonical = record
            .canonical_bytes()
            .map_err(|e| Failure::MalformedLine {
                line,
                detail: e.to_string(),
            })?;
        if canonical != bytes {
            return Err(Failure::NonCanonicalLine { line });
        }
        parsed.push(ParsedRecord {
            line,
            bytes: bytes.to_vec(),
            record,
        });
    }
    Ok(parsed)
}

/// Canonical bytes of every record in the log (used for sink comparison).
pub fn canonical_lines(log: &str) -> Result<Vec<Vec<u8>>, Failure> {
    Ok(parse_records(log)?
        .into_iter()
        .map(|p| p.bytes)
        .collect())
}

/// The immutable environment digests a manifest pins. A log whose manifests
/// disagree on any of these is not a single trustworthy run.
fn environment_of(m: &EvaluationManifest) -> Vec<(&'static str, &str)> {
    vec![
        ("red_image_digest", &m.red_image_digest),
        ("blue_image_digest", &m.blue_image_digest),
        ("llm_image_digest", &m.llm_image_digest),
        ("model_digest", &m.model_digest),
        ("blue_policy_digest", &m.blue_policy_digest),
        ("kernel_digest", &m.kernel_digest),
        ("referee_version", &m.referee_version),
        ("firecracker_version", &m.firecracker_version),
    ]
}

fn path_label(path: &str) -> Option<usize> {
    match path {
        "regex_block" => Some(0),
        "semantic_block" => Some(1),
        "llm" => Some(2),
        _ => None,
    }
}

/// Verify an evidence log held in memory.
pub fn verify_str(
    log: &str,
    trust_anchor_pubkey_hex: &str,
    options: &VerifyOptions,
) -> Result<Report, Failure> {
    let parsed = parse_records(log)?;
    if parsed.is_empty() && !options.allow_empty {
        return Err(Failure::EmptyLog);
    }

    let mut chain = ChainState::genesis();
    let mut chain_hashes: Vec<Digest> = Vec::new();
    let mut evaluations = 0u64;
    let mut seals = 0u64;
    let mut sealed: HashSet<u64> = HashSet::new();
    let mut last_sealed_end: Option<u64> = None;
    let mut ids: HashSet<String> = HashSet::new();
    let mut nonces: HashSet<String> = HashSet::new();
    let mut environment: Option<Vec<(&'static str, String)>> = None;
    let mut mode: Option<String> = None;
    let mut frame_size: Option<u32> = None;
    let mut timing_points: Vec<f64> = Vec::new();
    let mut timing_labels: Vec<usize> = Vec::new();
    let mut detail: Vec<EvaluationSummary> = Vec::new();

    for ParsedRecord { line, record, .. } in parsed {
        match record {
            EvidenceRecord::Evaluation {
                seq,
                manifest,
                manifest_hash,
                manifest_signature,
                events,
                event_hash,
                prev_chain_hash,
                chain_hash,
            } => {
                let evaluation_id = manifest.evaluation_id.clone();

                // 1. Manifest hash must be exactly sha256(JCS(manifest)).
                let recomputed_manifest_hash =
                    manifest.hash().map_err(|e| Failure::MalformedLine {
                        line,
                        detail: e.to_string(),
                    })?;
                if recomputed_manifest_hash.to_hex() != manifest_hash {
                    return Err(Failure::ManifestHashMismatch {
                        line,
                        evaluation_id,
                        recorded: manifest_hash,
                        recomputed: recomputed_manifest_hash.to_hex(),
                    });
                }

                // 2. The Trust Anchor signed this exact digest, before the run.
                verify_digest_signature(
                    trust_anchor_pubkey_hex,
                    &recomputed_manifest_hash,
                    &manifest_signature,
                )
                .map_err(|_| Failure::ManifestSignatureInvalid {
                    line,
                    evaluation_id: evaluation_id.clone(),
                })?;

                // 3. Event hash + event/manifest binding.
                let recomputed_event_hash =
                    Digest(hash_events(&events).map_err(|e| Failure::MalformedLine {
                        line,
                        detail: e.to_string(),
                    })?);
                if recomputed_event_hash.to_hex() != event_hash {
                    return Err(Failure::EventHashMismatch {
                        line,
                        evaluation_id,
                        recorded: event_hash,
                        recomputed: recomputed_event_hash.to_hex(),
                    });
                }
                for event in &events {
                    if event.evaluation_id() != manifest.evaluation_id {
                        return Err(Failure::EventBindingMismatch {
                            line,
                            evaluation_id,
                            detail: format!(
                                "event names evaluation {:?}",
                                event.evaluation_id()
                            ),
                        });
                    }
                }
                match events.first() {
                    Some(EvaluationEvent::EvaluationStarted {
                        manifest_hash: started_hash,
                        ..
                    }) if *started_hash == manifest_hash => {}
                    _ => {
                        return Err(Failure::EventBindingMismatch {
                            line,
                            evaluation_id,
                            detail: "the first event must be `evaluation_started` carrying this \
                                     manifest's hash"
                                .into(),
                        })
                    }
                }

                // 4. Chain link, in order.
                let expected_prev = chain.prev_hash();
                let (computed_seq, computed_chain) =
                    chain.link(&recomputed_manifest_hash, &recomputed_event_hash);
                if prev_chain_hash != expected_prev.to_hex() {
                    return Err(Failure::ChainLinkMismatch {
                        line,
                        seq,
                        evaluation_id,
                        recorded_prev: prev_chain_hash,
                        expected_prev: expected_prev.to_hex(),
                    });
                }
                if chain_hash != computed_chain.to_hex() {
                    return Err(Failure::ChainHashMismatch {
                        line,
                        seq,
                        evaluation_id,
                        recorded: chain_hash,
                        recomputed: computed_chain.to_hex(),
                    });
                }
                if seq != computed_seq {
                    return Err(Failure::SequenceGap {
                        line,
                        evaluation_id,
                        expected_seq: computed_seq,
                        recorded_seq: seq,
                    });
                }
                chain_hashes.push(computed_chain);
                evaluations += 1;

                // 5. Uniqueness invariants.
                if !ids.insert(evaluation_id.clone()) {
                    return Err(Failure::DuplicateEvaluationId {
                        line,
                        evaluation_id,
                    });
                }
                if !nonces.insert(manifest.nonce.clone()) {
                    return Err(Failure::DuplicateNonce {
                        line,
                        evaluation_id,
                        nonce: manifest.nonce,
                    });
                }

                // 6. The pinned environment must not drift mid-log.
                let current = environment_of(&manifest);
                match &environment {
                    None => {
                        environment =
                            Some(current.iter().map(|(k, v)| (*k, v.to_string())).collect())
                    }
                    Some(first) => {
                        for (field, value) in current {
                            let original = first
                                .iter()
                                .find(|(k, _)| *k == field)
                                .map(|(_, v)| v.clone())
                                .unwrap_or_default();
                            if original != value {
                                return Err(Failure::EnvironmentMismatch {
                                    line,
                                    evaluation_id,
                                    field,
                                    first: original,
                                    second: value.to_string(),
                                });
                            }
                        }
                    }
                }

                // 7. Timing policy must not change mid-log.
                match &mode {
                    None => mode = Some(manifest.timing_policy.clone()),
                    Some(first) if *first != manifest.timing_policy => {
                        return Err(Failure::TimingPolicyInconsistent {
                            line,
                            evaluation_id,
                            first: first.clone(),
                            second: manifest.timing_policy,
                        })
                    }
                    _ => {}
                }

                // 8. Observable-shape checks: one route, one release, and a
                //    frame size that never varies.
                let routed: Vec<&str> = events
                    .iter()
                    .filter_map(|e| match e {
                        EvaluationEvent::PromptRouted { path, .. } => Some(path.as_str()),
                        _ => None,
                    })
                    .collect();
                let released: Vec<(u64, u32)> = events
                    .iter()
                    .filter_map(|e| match e {
                        EvaluationEvent::ResponseReleased {
                            held_us,
                            frame_bytes,
                            ..
                        } => Some((*held_us, *frame_bytes)),
                        _ => None,
                    })
                    .collect();
                if routed.len() != 1 || released.len() != 1 {
                    return Err(Failure::EventBindingMismatch {
                        line,
                        evaluation_id,
                        detail: format!(
                            "expected exactly one prompt_routed and one response_released, found \
                             {} and {}",
                            routed.len(),
                            released.len()
                        ),
                    });
                }
                let path = routed[0];
                let label = path_label(path).ok_or_else(|| Failure::UnknownPath {
                    line,
                    evaluation_id: evaluation_id.clone(),
                    path: path.to_string(),
                })?;
                let (held_us, frame_bytes) = released[0];
                match frame_size {
                    None => frame_size = Some(frame_bytes),
                    Some(expected) if expected != frame_bytes => {
                        return Err(Failure::NonConstantFrameSize {
                            line,
                            evaluation_id,
                            expected,
                            frame_bytes,
                        })
                    }
                    _ => {}
                }
                let deadline_aborted = events
                    .iter()
                    .any(|e| matches!(e, EvaluationEvent::DeadlineAbort { .. }));

                timing_points.push(held_us as f64);
                timing_labels.push(label);
                detail.push(EvaluationSummary {
                    seq,
                    evaluation_id,
                    manifest_hash: recomputed_manifest_hash.to_hex(),
                    chain_hash: computed_chain.to_hex(),
                    path: path.to_string(),
                    held_us,
                    frame_bytes,
                    deadline_aborted,
                    sealed: false,
                });
            }

            EvidenceRecord::BatchSeal {
                batch_id,
                seq_start,
                seq_end,
                leaves,
                merkle_root: recorded_root,
                signature,
                sealed_at: _,
            } => {
                // Recompute the root from the recorded leaves.
                let leaf_digests: Vec<Digest> = leaves
                    .iter()
                    .map(|l| Digest::from_hex(l))
                    .collect::<Result<_, _>>()
                    .map_err(|e| Failure::MalformedLine {
                        line,
                        detail: format!("seal {batch_id} leaf: {e}"),
                    })?;
                let recomputed = merkle_root(&leaf_digests).map_err(|e| {
                    Failure::MalformedLine {
                        line,
                        detail: e.to_string(),
                    }
                })?;
                if recomputed.to_hex() != recorded_root {
                    return Err(Failure::MerkleRootMismatch {
                        line,
                        batch_id,
                        recorded: recorded_root,
                        recomputed: recomputed.to_hex(),
                    });
                }
                verify_digest_signature(trust_anchor_pubkey_hex, &recomputed, &signature).map_err(
                    |_| Failure::SealSignatureInvalid {
                        line,
                        batch_id: batch_id.clone(),
                    },
                )?;

                // Range must be contiguous and inside the log.
                let Some(expected_len) = seq_end.checked_sub(seq_start).map(|d| d + 1) else {
                    return Err(Failure::SealRangeInvalid {
                        line,
                        batch_id,
                        detail: format!("seq_end {seq_end} precedes seq_start {seq_start}"),
                    });
                };
                if expected_len != leaves.len() as u64 {
                    return Err(Failure::SealRangeInvalid {
                        line,
                        batch_id,
                        detail: format!(
                            "range {seq_start}..={seq_end} needs {expected_len} leaves but {} were \
                             recorded",
                            leaves.len()
                        ),
                    });
                }
                if seq_end >= chain_hashes.len() as u64 {
                    return Err(Failure::SealBeyondLog {
                        line,
                        batch_id,
                        seq_end,
                    });
                }
                if let Some(previous_end) = last_sealed_end {
                    if seq_start <= previous_end {
                        return Err(Failure::SealOverlap {
                            line,
                            batch_id,
                            seq_start,
                            previous_end,
                        });
                    }
                }

                // Each leaf must equal the chain hash it commits to.
                for (offset, leaf) in leaves.iter().enumerate() {
                    let seq = seq_start + offset as u64;
                    if chain_hashes[seq as usize].to_hex() != *leaf {
                        return Err(Failure::SealLeavesMismatch {
                            line,
                            batch_id,
                            leaf_index: offset,
                            seq,
                        });
                    }
                    sealed.insert(seq);
                }
                last_sealed_end = Some(seq_end);
                seals += 1;
            }
        }
    }

    if evaluations == 0 {
        if options.allow_empty {
            return Ok(Report {
                evaluations: 0,
                seals,
                unsealed_evaluations: 0,
                final_chain_head: chain.prev_hash().to_hex(),
                trust_anchor_public_key: trust_anchor_pubkey_hex.to_string(),
                timing: TimingAudit {
                    mode: mode.unwrap_or_else(|| "UNKNOWN".into()),
                    samples: 0,
                    distinct_held_us: 0,
                    mean_us: 0.0,
                    held_us_min: 0,
                    held_us_max: 0,
                    stddev_us: 0.0,
                    inference_accuracy: 0.0,
                    accuracy_measurable: false,
                    distinct_stage_labels: 0,
                    constant_frame_size: true,
                    bounded: false,
                },
                evaluations_detail: Vec::new(),
            });
        }
        return Err(Failure::EmptyLog);
    }

    // Coverage + expectation checks.
    let unsealed: Vec<u64> = (0..evaluations).filter(|s| !sealed.contains(s)).collect();
    if options.require_all_sealed && !unsealed.is_empty() {
        return Err(Failure::UnsealedEvaluations {
            count: unsealed.len() as u64,
            first_seq: unsealed[0],
        });
    }
    if let Some(expected) = options.expect_evaluations {
        if expected != evaluations {
            return Err(Failure::EvaluationCountMismatch {
                expected,
                found: evaluations,
            });
        }
    }
    if let Some(expected) = options.expect_seals {
        if expected != seals {
            return Err(Failure::SealCountMismatch {
                expected,
                found: seals,
            });
        }
    }
    let final_chain_head = chain.prev_hash().to_hex();
    if let Some(expected) = &options.expect_chain_head {
        if expected != &final_chain_head {
            return Err(Failure::ChainHeadMismatch {
                expected: expected.clone(),
                recomputed: final_chain_head,
            });
        }
    }

    // Timing audit — recomputed independently from the log alone.
    let mode = mode.unwrap_or_else(|| "UNKNOWN".into());
    let distinct: HashSet<String> =
        timing_points.iter().map(|p| format!("{p:.0}")).collect();
    let accuracy = inference_accuracy(&timing_points, &timing_labels, 3);
    let distinct_labels: HashSet<usize> = timing_labels.iter().copied().collect();
    // Below this floor k-means (k=3) isolates each point and the accuracy
    // figure is meaningless; `--strict-timing` must not fail on it either.
    let accuracy_measurable = timing_points.len() >= 9 && distinct_labels.len() >= 2;
    let mean_us = mean(&timing_points);
    let stddev_us = sample_stddev(&timing_points);
    let relative_spread = if mean_us <= 0.0 {
        1.0
    } else {
        stddev_us / mean_us
    };
    // One observable band: scheduling jitter on a held bucket is orders of
    // magnitude smaller than the bucket itself, while three separate defence
    // stages spread by ~100% of the mean.
    let single_band = relative_spread < BOUNDED_RELATIVE_SPREAD;
    let declared_bounded = mode.starts_with("EVAL");
    // Structural half of the same claim: every released frame must actually sit
    // at the declared bucket. Dispersion alone could look tight while the whole
    // band sat somewhere else (e.g. the bucket never applied at all).
    let inside_declared_window = match bucket_us_from_mode(&mode) {
        Some(bucket) => timing_points.iter().all(|p| {
            let low = bucket.saturating_sub(BOUNDED_WINDOW_EARLY_US) as f64;
            let high = (bucket + BOUNDED_WINDOW_SLACK_US) as f64;
            *p >= low && *p <= high
        }),
        None => single_band,
    };
    let timing = TimingAudit {
        mode: mode.clone(),
        samples: timing_points.len(),
        distinct_held_us: distinct.len(),
        mean_us,
        held_us_min: timing_points.iter().map(|p| *p as u64).min().unwrap_or(0),
        held_us_max: timing_points.iter().map(|p| *p as u64).max().unwrap_or(0),
        stddev_us,
        inference_accuracy: accuracy,
        accuracy_measurable: accuracy_measurable,
        distinct_stage_labels: distinct_labels.len(),
        constant_frame_size: true,
        bounded: declared_bounded && single_band && inside_declared_window,
    };

    // Strict mode promotes the side-channel measurement to a hard failure, but
    // only when the timings both make the stage recoverable (accuracy) *and*
    // are actually dispersed: a genuinely single band cannot leak, whatever
    // k-means makes of jitter noise, so it is never flagged.
    if options.strict_timing
        && declared_bounded
        && accuracy_measurable
        && accuracy >= 0.5
        && !single_band
    {
        return Err(Failure::TimingLeak {
            mode,
            samples: timing_points.len(),
            inference_accuracy: accuracy,
        });
    }

    for summary in detail.iter_mut() {
        summary.sealed = sealed.contains(&summary.seq);
    }

    Ok(Report {
        evaluations,
        seals,
        unsealed_evaluations: unsealed.len() as u64,
        final_chain_head,
        trust_anchor_public_key: trust_anchor_pubkey_hex.to_string(),
        timing,
        evaluations_detail: detail,
    })
}

/// Verify the append-only log at `path`.
pub fn verify_path(
    path: &std::path::Path,
    trust_anchor_pubkey_hex: &str,
    options: &VerifyOptions,
) -> Result<Report, Failure> {
    let content = std::fs::read_to_string(path).map_err(|e| Failure::Io {
        detail: format!("{}: {e}", path.display()),
    })?;
    verify_str(&content, trust_anchor_pubkey_hex, options)
}

/// Detect sink divergence between the append-only log and the PostgreSQL copy.
/// The two must agree byte for byte, record for record.
pub fn compare_sinks(log_rows: &[Vec<u8>], postgres_rows: &[Vec<u8>]) -> Result<(), Failure> {
    if log_rows.len() != postgres_rows.len() {
        return Err(Failure::SinkDivergence {
            index: log_rows.len().min(postgres_rows.len()),
            detail: format!(
                "record counts differ: append log has {}, PostgreSQL has {}",
                log_rows.len(),
                postgres_rows.len()
            ),
        });
    }
    for (index, (log_row, pg_row)) in log_rows.iter().zip(postgres_rows.iter()).enumerate() {
        if log_row != pg_row {
            return Err(Failure::SinkDivergence {
                index,
                detail: "canonical bytes differ between the append log and PostgreSQL".into(),
            });
        }
    }
    Ok(())
}

/// Resolve `--pubkey`: either a raw 64-hex-character key, or a path to a key
/// file whose first 64-hex-character token is the key.
pub fn load_public_key(value: &str) -> Result<String, Failure> {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(trimmed.to_ascii_lowercase());
    }
    let path = std::path::Path::new(trimmed);
    if path.is_file() {
        let content = std::fs::read_to_string(path).map_err(|_| Failure::BadPublicKey {
            value: value.to_string(),
        })?;
        // Accept a bare key line or `key = <hex>` style files.
        for token in content.split(|c: char| !c.is_ascii_hexdigit()) {
            if token.len() == 64 {
                return Ok(token.to_ascii_lowercase());
            }
        }
    }
    Err(Failure::BadPublicKey {
        value: value.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bayora_common::policy::PolicyConfig;
    use bayora_common::signature::sign_digest;
    use ed25519_dalek::SigningKey;

    /// Builds a synthetic-but-honest evidence log the same way the Referee
    /// does, so the verifier can be tested against a known-good baseline and
    /// then against surgical tampering.
    struct LogBuilder {
        chain: ChainState,
        sk: SigningKey,
        lines: Vec<String>,
        client_publication: String,
    }

    impl LogBuilder {
        fn new() -> Self {
            let sk = SigningKey::from_bytes(&[7u8; 32]);
            let client_publication = hex::encode(sk.verifying_key().to_bytes());
            LogBuilder {
                chain: ChainState::genesis(),
                sk,
                lines: Vec::new(),
                client_publication,
            }
        }

        fn manifest(&self, id: &str, mode: &str) -> EvaluationManifest {
            let policy = PolicyConfig::from_yaml(&format!(
                r#"
policy_version: "2026.10.v3"
evaluation: {{ timing_mode: "{mode}", response_frame_bytes: 4096, max_prompt_bytes: 8192, max_tokens: 64 }}
network: {{ red_to_blue: "MEDIATED", red_to_llm: "MEDIATED", blue_to_red: "DENIED" }}
state: {{ reset_policy: "SNAPSHOT", cache_prompt: false }}
resources:
  red:  {{ cpu_cores: "1",   memory_mb: 512,  pids_max: 64 }}
  blue: {{ cpu_cores: "2",   memory_mb: 1024, pids_max: 64 }}
  llm:  {{ cpu_cores: "3,4", memory_mb: 2048, pids_max: 64 }}
audit: {{ require_manifest_signature: true, dual_write_append_log: true }}
"#
            ))
            .unwrap();
            EvaluationManifest::new(
                id,
                &bayora_common::testutil::registry(),
                &policy,
                "2026-09-26T16:00:00.000Z",
                format!("{id}-nonce-00000000000000000000"),
            )
        }

        /// Append one evaluation record (chair-linked and signed).
        fn push_evaluation(&mut self, id: &str, mode: &str, path: &str, held_us: u64) -> u32 {
            let manifest = self.manifest(id, mode);
            let manifest_hash = manifest.hash().unwrap();
            let events = vec![
                EvaluationEvent::EvaluationStarted {
                    evaluation_id: id.to_string(),
                    manifest_hash: manifest_hash.to_hex(),
                },
                EvaluationEvent::StateReset {
                    evaluation_id: id.to_string(),
                    mode: "SNAPSHOT".into(),
                    duration_us: 330_000,
                },
                EvaluationEvent::PromptRouted {
                    evaluation_id: id.to_string(),
                    path: path.to_string(),
                },
                EvaluationEvent::ResponseReleased {
                    evaluation_id: id.to_string(),
                    held_us,
                    frame_bytes: 4096,
                    truncated: false,
                    response_digest: Digest::of(format!("{id}-frame").as_bytes()).to_hex(),
                },
            ];
            let event_hash = Digest(hash_events(&events).unwrap());
            let prev = self.chain.prev_hash();
            let (seq, chain_hash) = self.chain.link(&manifest_hash, &event_hash);
            let signature = hex::encode(sign_digest(&self.sk, &manifest_hash));
            let record = EvidenceRecord::Evaluation {
                seq,
                manifest,
                manifest_hash: manifest_hash.to_hex(),
                manifest_signature: signature,
                events,
                event_hash: event_hash.to_hex(),
                prev_chain_hash: prev.to_hex(),
                chain_hash: chain_hash.to_hex(),
            };
            self.lines
                .push(String::from_utf8(record.canonical_bytes().unwrap()).unwrap());
            4096
        }

        /// Seal every evaluation from `seq_start` to the current head.
        fn push_seal(&mut self, batch_id: &str, seq_start: u64) {
            let leaves: Vec<Digest> = self
                .lines
                .iter()
                .map(|l| {
                    let rec = EvidenceRecord::from_bytes(l.as_bytes()).unwrap();
                    match rec {
                        EvidenceRecord::Evaluation { chain_hash, .. } => {
                            Digest::from_hex(&chain_hash).unwrap()
                        }
                        _ => unreachable!(),
                    }
                })
                .collect();
            let seq_end = self.chain.len() - 1;
            let leaves = leaves[seq_start as usize..=seq_end as usize].to_vec();
            let root = merkle_root(&leaves).unwrap();
            let signature = hex::encode(sign_digest(&self.sk, &root));
            let record = EvidenceRecord::BatchSeal {
                batch_id: batch_id.to_string(),
                seq_start,
                seq_end,
                leaves: leaves.iter().map(|d| d.to_hex()).collect(),
                merkle_root: root.to_hex(),
                signature,
                sealed_at: "2026-09-26T16:05:00.000Z".into(),
            };
            self.lines
                .push(String::from_utf8(record.canonical_bytes().unwrap()).unwrap());
        }

        fn finish(self) -> (String, String) {
            (self.lines.join("\n") + "\n", self.client_publication)
        }
    }

    fn default_options() -> VerifyOptions {
        VerifyOptions::default()
    }

    /// A realistic bounded run: nine evaluations across all three stages, all
    /// held to exactly 500 ms, sealed in one batch.
    fn bounded_log() -> (String, String) {
        let mut b = LogBuilder::new();
        for i in 0..9u64 {
            let path = ["regex_block", "semantic_block", "llm"][(i % 3) as usize];
            b.push_evaluation(&format!("eval_{i:04}"), "EVAL_1000", path, 1_000_000);
        }
        b.push_seal("batch_9", 0);
        b.finish()
    }

    /// A baseline run with three well-separated timing bands.
    fn baseline_log() -> (String, String) {
        let mut b = LogBuilder::new();
        for i in 0..9u64 {
            let (path, held) = match i % 3 {
                0 => ("regex_block", 2_000 + i * 30),
                1 => ("semantic_block", 160_000 + i * 300),
                _ => ("llm", 340_000 + i * 400),
            };
            b.push_evaluation(&format!("eval_{i:04}"), "NORMAL", path, held);
        }
        b.push_seal("batch_9", 0);
        b.finish()
    }

    #[test]
    fn honest_bounded_log_is_valid() {
        let (log, pubkey) = bounded_log();
        let report = verify_str(&log, &pubkey, &default_options()).unwrap();
        assert_eq!(report.evaluations, 9);
        assert_eq!(report.seals, 1);
        assert_eq!(report.unsealed_evaluations, 0);
        assert_eq!(report.timing.mode, "EVAL_1000");
        assert_eq!(report.timing.distinct_held_us, 1);
        assert_eq!(report.timing.stddev_us, 0.0);
        assert!(report.timing.bounded);
        assert!(
            report.timing.inference_accuracy < 0.5,
            "bounded timings must not be inferable, got {}",
            report.timing.inference_accuracy
        );
        assert_eq!(report.evaluations_detail.len(), 9);
        assert!(report.evaluations_detail.iter().all(|e| e.sealed));
        assert!(report.summary_line().starts_with("VALID"));
    }

    #[test]
    fn baseline_log_exposes_the_timing_side_channel() {
        let (log, pubkey) = baseline_log();
        let report = verify_str(&log, &pubkey, &default_options()).unwrap();
        assert_eq!(report.timing.mode, "NORMAL");
        assert_eq!(report.timing.distinct_held_us, 9);
        assert!(
            report.timing.inference_accuracy > 0.99,
            "baseline bands must be classifiable, got {}",
            report.timing.inference_accuracy
        );
        assert!(!report.timing.bounded);
        // NORMAL mode is not a bounded mode, so strict timing does not fire.
        assert!(verify_str(&log, &pubkey, &strict()).is_ok());
    }

    fn strict() -> VerifyOptions {
        VerifyOptions {
            strict_timing: true,
            ..Default::default()
        }
    }

    #[test]
    fn strict_timing_flags_a_leaky_bounded_log() {
        // EVAL_1000 on paper, but the three stages take different times: the log
        // itself proves the bound was not applied.
        let mut b = LogBuilder::new();
        for i in 0..9u64 {
            let (path, held) = match i % 3 {
                0 => ("regex_block", 1_000_000),
                1 => ("semantic_block", 1_160_000),
                _ => ("llm", 1_340_000),
            };
            b.push_evaluation(&format!("eval_{i:04}"), "EVAL_1000", path, held);
        }
        b.push_seal("batch_9", 0);
        let (log, pubkey) = b.finish();
        let err = verify_str(&log, &pubkey, &strict()).unwrap_err();
        assert!(matches!(err, Failure::TimingLeak { .. }), "got {err:?}");
        // Non-strict mode still verifies structure and reports the leak.
        let report = verify_str(&log, &pubkey, &default_options()).unwrap();
        assert!(!report.timing.bounded);
    }

    #[test]
    fn scheduler_jitter_does_not_break_the_bounded_verdict() {
        // Real hardware: releasing at a bucket boundary lands on 1000ms ±
        // scheduler jitter, so every sample is a *different* value. They still
        // form one band, so the audit must report `bounded` and strict timing
        // must not false-positive on k-means clustering of pure jitter noise.
        let mut b = LogBuilder::new();
        for i in 0..9u64 {
            let (path, held) = match i % 3 {
                0 => ("regex_block", 1_000_000 + i * 13),
                1 => ("semantic_block", 1_000_013 - i * 7),
                _ => ("llm", 1_000_020 + i * 5),
            };
            b.push_evaluation(&format!("eval_{i:04}"), "EVAL_1000", path, held);
        }
        b.push_seal("batch_9", 0);
        let (log, pubkey) = b.finish();

        let report = verify_str(&log, &pubkey, &strict()).unwrap();
        assert!(
            report.timing.distinct_held_us > 1,
            "this fixture is deliberately jittered"
        );
        assert!(report.timing.stddev_us > 0.0);
        assert!(
            report.timing.held_us_max - report.timing.held_us_min < 1000,
            "jitter must stay far below the 1000ms bucket"
        );
        assert!(
            report.timing.relative_spread() < BOUNDED_RELATIVE_SPREAD,
            "one band: relative spread {:.6}",
            report.timing.relative_spread()
        );
        assert!(
            report.timing.bounded,
            "a jittered but bucketed EVAL_1000 run is still bounded"
        );
        assert_eq!(report.evaluations, 9);
    }

    #[test]
    fn a_band_that_misses_the_declared_bucket_is_not_bounded() {
        // Tight single band, but at 600 ms: the declared 1000 ms bound was never
        // applied. Dispersion alone calls this "one band", so the structural
        // window check has to catch it.
        let mut b = LogBuilder::new();
        for i in 0..9u64 {
            b.push_evaluation(&format!("eval_{i:04}"), "EVAL_1000", "llm", 600_000 + i);
        }
        b.push_seal("batch_9", 0);
        let (log, pubkey) = b.finish();

        let report = verify_str(&log, &pubkey, &default_options()).unwrap();
        assert!(
            report.timing.relative_spread() < BOUNDED_RELATIVE_SPREAD,
            "the band really is tight: {:.6}",
            report.timing.relative_spread()
        );
        assert!(
            !report.timing.bounded,
            "a tight band outside the declared bucket is still a broken bound"
        );
    }

    #[test]
    fn bucket_us_from_mode_reads_the_declared_bucket() {
        assert_eq!(bucket_us_from_mode("EVAL_1000"), Some(1_000_000));
        assert_eq!(bucket_us_from_mode("EVAL_1500"), Some(1_500_000));
        assert_eq!(bucket_us_from_mode("NORMAL"), None);
        assert_eq!(bucket_us_from_mode("EVAL_"), None);
    }

    #[test]
    fn tampered_manifest_is_pinpointed() {
        let (log, pubkey) = bounded_log();
        // Swap the model digest inside the first evaluation's manifest.
        let mut lines: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        lines[0] = lines[0].replace(
            &bayora_common::testutil::registry().model_digest,
            "sha256:deadbeef",
        );
        let tampered = lines.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        match err {
            Failure::ManifestHashMismatch { line, evaluation_id, .. } => {
                assert_eq!(line, 1);
                assert_eq!(evaluation_id, "eval_0000");
            }
            other => panic!("expected ManifestHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampered_event_is_pinpointed() {
        let (log, pubkey) = bounded_log();
        let mut lines: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        // Rewrite the released latency of the *fourth* line (seq 3).
        lines[3] = lines[3].replace("\"held_us\":1000000", "\"held_us\":123456");
        let tampered = lines.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        match err {
            Failure::EventHashMismatch { line, evaluation_id, .. } => {
                assert_eq!(line, 4);
                assert_eq!(evaluation_id, "eval_0003");
            }
            other => panic!("expected EventHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampered_signature_is_pinpointed() {
        let (log, pubkey) = bounded_log();
        let mut lines: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        // Flip the last hex digit of the manifest signature.
        let value = EvidenceRecord::from_bytes(lines[2].as_bytes()).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
        let sig = v["manifest_signature"].as_str().unwrap();
        let flipped = format!("{}{}", &sig[..sig.len() - 1], if sig.ends_with('0') { '1' } else { '0' });
        v["manifest_signature"] = serde_json::Value::String(flipped);
        lines[2] = serde_json::to_string(&v).unwrap();
        let _ = value;
        let tampered = lines.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        match err {
            Failure::ManifestSignatureInvalid { line, evaluation_id } => {
                assert_eq!(line, 3);
                assert_eq!(evaluation_id, "eval_0002");
            }
            other => panic!("expected ManifestSignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn broken_chain_link_is_pinpointed() {
        let (log, pubkey) = bounded_log();
        let mut lines: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        let mut v: serde_json::Value = serde_json::from_str(&lines[5]).unwrap();
        v["prev_chain_hash"] = serde_json::Value::String("00".repeat(32));
        lines[5] = serde_json::to_string(&v).unwrap();
        let tampered = lines.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        match err {
            Failure::ChainLinkMismatch { line, seq, .. } => {
                assert_eq!(line, 6);
                assert_eq!(seq, 5);
            }
            other => panic!("expected ChainLinkMismatch, got {other:?}"),
        }
    }

    #[test]
    fn reordered_records_are_detected() {
        let (log, pubkey) = bounded_log();
        let mut lines: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        lines.swap(0, 1);
        let tampered = lines.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        assert!(
            matches!(
                err,
                Failure::SequenceGap { .. } | Failure::ChainLinkMismatch { .. }
            ),
            "reordering must break the chain, got {err:?}"
        );
    }

    #[test]
    fn deleted_evaluation_is_caught_by_the_seal() {
        let (log, pubkey) = bounded_log();
        let lines: Vec<&str> = log.lines().collect();
        // Drop the record at seq 4; the seal still lists nine leaves.
        let mut kept: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        kept.remove(4);
        let tampered = kept.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        assert!(
            matches!(
                err,
                Failure::ChainLinkMismatch { .. }
                    | Failure::SequenceGap { .. }
                    | Failure::SealLeavesMismatch { .. }
                    | Failure::SealRangeInvalid { .. }
                    | Failure::SealBeyondLog { .. }
            ),
            "a deleted record must break the chain or the seal, got {err:?}"
        );
    }

    #[test]
    fn tampered_merkle_root_is_pinpointed() {
        let (log, pubkey) = bounded_log();
        let mut lines: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        let last = lines.len() - 1;
        let mut v: serde_json::Value = serde_json::from_str(&lines[last]).unwrap();
        v["merkle_root"] = serde_json::Value::String("ab".repeat(32));
        lines[last] = serde_json::to_string(&v).unwrap();
        let tampered = lines.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        match err {
            Failure::MerkleRootMismatch { line, batch_id, .. } => {
                assert_eq!(line, 10);
                assert_eq!(batch_id, "batch_9");
            }
            other => panic!("expected MerkleRootMismatch, got {other:?}"),
        }
    }

    #[test]
    fn injected_field_is_rejected_as_non_canonical() {
        let (log, pubkey) = bounded_log();
        let mut lines: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        // Inject a field: canonical bytes no longer match.
        lines[1] = lines[1].replacen('{', "{\"injected\":true,", 1);
        let tampered = lines.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        assert!(
            matches!(err, Failure::NonCanonicalLine { line: 2 } | Failure::MalformedLine { line: 2, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn whitespace_reformatting_is_rejected() {
        let (log, pubkey) = bounded_log();
        let mut lines: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        lines[0] = lines[0].replacen(':', ": ", 1);
        let tampered = lines.join("\n") + "\n";
        let err = verify_str(&tampered, &pubkey, &default_options()).unwrap_err();
        assert_eq!(err, Failure::NonCanonicalLine { line: 1 });
    }

    #[test]
    fn truncated_log_is_detected_by_expectations() {
        let (log, pubkey) = bounded_log();
        let lines: Vec<&str> = log.lines().collect();
        // Keep only the first three evaluations; drop the seal too.
        let truncated = lines[..3].join("\n") + "\n";
        // Structure alone is still internally consistent...
        assert!(verify_str(&truncated, &pubkey, &default_options()).is_ok());
        // ...but a pinned count catches the truncation.
        let options = VerifyOptions {
            expect_evaluations: Some(9),
            expect_seals: Some(1),
            ..Default::default()
        };
        let err = verify_str(&truncated, &pubkey, &options).unwrap_err();
        assert_eq!(
            err,
            Failure::EvaluationCountMismatch {
                expected: 9,
                found: 3
            }
        );
    }

    #[test]
    fn require_all_sealed_flags_unsealed_evaluations() {
        let mut b = LogBuilder::new();
        for i in 0..3u64 {
            b.push_evaluation(&format!("eval_{i:04}"), "EVAL_1000", "llm", 1_000_000);
        }
        // Seal only the first two.
        let leaves: Vec<String> = b
            .lines
            .iter()
            .take(2)
            .map(|l| match EvidenceRecord::from_bytes(l.as_bytes()).unwrap() {
                EvidenceRecord::Evaluation { chain_hash, .. } => chain_hash,
                _ => unreachable!(),
            })
            .collect();
        let root = bayora_common::records::recomputed_merkle_root(&leaves).unwrap();
        let sig = hex::encode(sign_digest(&b.sk, &root));
        let record = EvidenceRecord::BatchSeal {
            batch_id: "batch_2".into(),
            seq_start: 0,
            seq_end: 1,
            leaves,
            merkle_root: root.to_hex(),
            signature: sig,
            sealed_at: "2026-09-26T16:05:00.000Z".into(),
        };
        b.lines
            .push(String::from_utf8(record.canonical_bytes().unwrap()).unwrap());
        let (log, pubkey) = b.finish();

        let report = verify_str(&log, &pubkey, &default_options()).unwrap();
        assert_eq!(report.unsealed_evaluations, 1);
        assert_eq!(report.evaluations_detail[2].sealed, false);

        let options = VerifyOptions {
            require_all_sealed: true,
            ..Default::default()
        };
        let err = verify_str(&log, &pubkey, &options).unwrap_err();
        assert_eq!(err, Failure::UnsealedEvaluations { count: 1, first_seq: 2 });
    }

    #[test]
    fn chain_head_pin_is_enforced() {
        let (log, pubkey) = bounded_log();
        let report = verify_str(&log, &pubkey, &default_options()).unwrap();
        let options = VerifyOptions {
            expect_chain_head: Some(report.final_chain_head.clone()),
            ..Default::default()
        };
        assert!(verify_str(&log, &pubkey, &options).is_ok());
        let options = VerifyOptions {
            expect_chain_head: Some("ff".repeat(32)),
            ..Default::default()
        };
        assert!(matches!(
            verify_str(&log, &pubkey, &options).unwrap_err(),
            Failure::ChainHeadMismatch { .. }
        ));
    }

    #[test]
    fn wrong_public_key_rejects_every_signature() {
        let (log, _pubkey) = bounded_log();
        let other = hex::encode(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
        let err = verify_str(&log, &other, &default_options()).unwrap_err();
        assert_eq!(
            err,
            Failure::ManifestSignatureInvalid {
                line: 1,
                evaluation_id: "eval_0000".into()
            }
        );
    }

    #[test]
    fn environment_drift_mid_log_is_detected() {
        // Two records; the second claims a different kernel.
        let mut b = LogBuilder::new();
        b.push_evaluation("eval_a", "EVAL_1000", "llm", 1_000_000);
        let second = b.manifest("eval_b", "EVAL_1000");
        let mut line = {
            let record = EvidenceRecord::Evaluation {
                seq: 1,
                manifest: second,
                manifest_hash: String::new(),
                manifest_signature: String::new(),
                events: vec![EvaluationEvent::EvaluationStarted {
                    evaluation_id: "eval_b".into(),
                    manifest_hash: String::new(),
                }],
                event_hash: String::new(),
                prev_chain_hash: String::new(),
                chain_hash: String::new(),
            };
            record.canonical_bytes().unwrap()
        };
        // Rewrite the kernel digest and re-hash/re-sign so only the environment
        // check can catch it (everything else is internally consistent).
        let mut v: serde_json::Value = serde_json::from_slice(&line).unwrap();
        v["manifest"]["kernel_digest"] = serde_json::Value::String("sha256:deadkernel".into());
        let manifest: EvaluationManifest = serde_json::from_value(v["manifest"].clone()).unwrap();
        let mh = manifest.hash().unwrap();
        v["manifest_hash"] = serde_json::Value::String(mh.to_hex());
        v["manifest_signature"] =
            serde_json::Value::String(hex::encode(sign_digest(&b.sk, &mh)));
        let events = vec![
            EvaluationEvent::EvaluationStarted {
                evaluation_id: "eval_b".into(),
                manifest_hash: mh.to_hex(),
            },
            EvaluationEvent::PromptRouted {
                evaluation_id: "eval_b".into(),
                path: "llm".into(),
            },
            EvaluationEvent::ResponseReleased {
                evaluation_id: "eval_b".into(),
                held_us: 1_000_000,
                frame_bytes: 4096,
                truncated: false,
                response_digest: "aa".repeat(32),
            },
        ];
        let eh = Digest(hash_events(&events).unwrap());
        v["events"] = serde_json::to_value(&events).unwrap();
        v["event_hash"] = serde_json::Value::String(eh.to_hex());
        let prev = b.chain.prev_hash();
        let (seq, chain_hash) = b.chain.link(&mh, &eh);
        assert_eq!(seq, 1);
        v["prev_chain_hash"] = serde_json::Value::String(prev.to_hex());
        v["chain_hash"] = serde_json::Value::String(chain_hash.to_hex());
        let record: EvidenceRecord = serde_json::from_value(v).unwrap();
        line = record.canonical_bytes().unwrap();
        b.lines.push(String::from_utf8(line).unwrap());
        let (log, pubkey) = b.finish();

        let err = verify_str(&log, &pubkey, &default_options()).unwrap_err();
        match err {
            Failure::EnvironmentMismatch { line, field, .. } => {
                assert_eq!(line, 2);
                assert_eq!(field, "kernel_digest");
            }
            other => panic!("expected EnvironmentMismatch, got {other:?}"),
        }
    }

    #[test]
    fn frame_size_variance_is_detected() {
        let mut b = LogBuilder::new();
        b.push_evaluation("eval_a", "EVAL_1000", "llm", 1_000_000);
        // Second evaluation releases a longer frame: observable length leak.
        let manifest = b.manifest("eval_b", "EVAL_1000");
        let mh = manifest.hash().unwrap();
        let events = vec![
            EvaluationEvent::EvaluationStarted {
                evaluation_id: "eval_b".into(),
                manifest_hash: mh.to_hex(),
            },
            EvaluationEvent::PromptRouted {
                evaluation_id: "eval_b".into(),
                path: "llm".into(),
            },
            EvaluationEvent::ResponseReleased {
                evaluation_id: "eval_b".into(),
                held_us: 1_000_000,
                frame_bytes: 8192,
                truncated: false,
                response_digest: "bb".repeat(32),
            },
        ];
        let eh = Digest(hash_events(&events).unwrap());
        let prev = b.chain.prev_hash();
        let (seq, chain_hash) = b.chain.link(&mh, &eh);
        let signature = hex::encode(sign_digest(&b.sk, &mh));
        let record = EvidenceRecord::Evaluation {
            seq,
            manifest,
            manifest_hash: mh.to_hex(),
            manifest_signature: signature,
            events,
            event_hash: eh.to_hex(),
            prev_chain_hash: prev.to_hex(),
            chain_hash: chain_hash.to_hex(),
        };
        b.lines
            .push(String::from_utf8(record.canonical_bytes().unwrap()).unwrap());
        let (log, pubkey) = b.finish();

        let err = verify_str(&log, &pubkey, &default_options()).unwrap_err();
        assert_eq!(
            err,
            Failure::NonConstantFrameSize {
                line: 2,
                evaluation_id: "eval_b".into(),
                expected: 4096,
                frame_bytes: 8192
            }
        );
    }

    #[test]
    fn empty_log_is_rejected_unless_allowed() {
        assert_eq!(
            verify_str("", "00".repeat(32).as_str(), &default_options()).unwrap_err(),
            Failure::EmptyLog
        );
        let options = VerifyOptions {
            allow_empty: true,
            ..Default::default()
        };
        let report = verify_str("\n\n", &"00".repeat(32), &options).unwrap();
        assert_eq!(report.evaluations, 0);
    }

    #[test]
    fn sink_divergence_is_detected() {
        let (log, _) = bounded_log();
        let rows = canonical_lines(&log).unwrap();
        assert!(compare_sinks(&rows, &rows).is_ok());

        let mut tampered = rows.clone();
        tampered[2] = tampered[2].clone();
        tampered[2][5] ^= 0x01;
        let err = compare_sinks(&rows, &tampered).unwrap_err();
        assert_eq!(
            err,
            Failure::SinkDivergence {
                index: 2,
                detail: "canonical bytes differ between the append log and PostgreSQL".into()
            }
        );

        let mut short = rows.clone();
        short.pop();
        assert!(matches!(
            compare_sinks(&rows, &short).unwrap_err(),
            Failure::SinkDivergence { .. }
        ));
    }

    #[test]
    fn duplicate_nonce_is_detected() {
        let mut b = LogBuilder::new();
        // Two manifests sharing the same nonce (a reused run identity).
        let m1 = b.manifest("eval_a", "EVAL_1000");
        let m2 = EvaluationManifest {
            nonce: m1.nonce.clone(),
            ..b.manifest("eval_b", "EVAL_1000")
        };
        for manifest in [m1, m2] {
            let mh = manifest.hash().unwrap();
            let events = vec![
                EvaluationEvent::EvaluationStarted {
                    evaluation_id: manifest.evaluation_id.clone(),
                    manifest_hash: mh.to_hex(),
                },
                EvaluationEvent::PromptRouted {
                    evaluation_id: manifest.evaluation_id.clone(),
                    path: "llm".into(),
                },
                EvaluationEvent::ResponseReleased {
                    evaluation_id: manifest.evaluation_id.clone(),
                    held_us: 1_000_000,
                    frame_bytes: 4096,
                    truncated: false,
                    response_digest: "cc".repeat(32),
                },
            ];
            let eh = Digest(hash_events(&events).unwrap());
            let prev = b.chain.prev_hash();
            let (seq, chain_hash) = b.chain.link(&mh, &eh);
            let signature = hex::encode(sign_digest(&b.sk, &mh));
            let record = EvidenceRecord::Evaluation {
                seq,
                manifest,
                manifest_hash: mh.to_hex(),
                manifest_signature: signature,
                events,
                event_hash: eh.to_hex(),
                prev_chain_hash: prev.to_hex(),
                chain_hash: chain_hash.to_hex(),
            };
            b.lines
                .push(String::from_utf8(record.canonical_bytes().unwrap()).unwrap());
        }
        let (log, pubkey) = b.finish();
        let err = verify_str(&log, &pubkey, &default_options()).unwrap_err();
        assert!(
            matches!(err, Failure::DuplicateNonce { line: 2, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn public_key_loading_accepts_hex_and_files() {
        let hex_key = "ab".repeat(32);
        assert_eq!(load_public_key(&hex_key).unwrap(), hex_key);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust_anchor.pk");
        std::fs::write(&path, format!("{hex_key}\n")).unwrap();
        assert_eq!(
            load_public_key(path.to_str().unwrap()).unwrap(),
            hex_key
        );

        assert!(load_public_key("not-a-key").is_err());
        assert!(load_public_key(&"a".repeat(63)).is_err());
    }

    #[test]
    fn verify_path_reads_from_disk() {
        let (log, pubkey) = bounded_log();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence_log.ndjson");
        std::fs::write(&path, &log).unwrap();
        let report = verify_path(&path, &pubkey, &default_options()).unwrap();
        assert_eq!(report.evaluations, 9);

        let err = verify_path(
            &dir.path().join("missing.ndjson"),
            &pubkey,
            &default_options(),
        )
        .unwrap_err();
        assert!(matches!(err, Failure::Io { .. }));
    }
}
