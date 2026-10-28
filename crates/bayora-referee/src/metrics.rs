//! The Security Posture HUD's data layer.
//!
//! Aggregates per-turn observables into the numbers the HUD shows an
//! audience:
//!
//! * **Inference accuracy** — how well an eavesdropper could recover the
//!   defence stage from response timings alone (`bayora_common::telemetry`).
//!   Baseline `NORMAL` shows near-100%; `EVAL_500` collapses it to chance.
//! * **Timing dispersion** — sample standard deviation of held times.
//! * **Policy guard counters** — capability replays, cross-eval refusals,
//!   frame rejections, deadline aborts, per-mode totals.
//!
//! Nothing here touches keys or evidence bytes; it is telemetry only.

use bayora_common::policy::TimingMode;
use bayora_common::telemetry::{inference_accuracy, mean as sample_mean, sample_stddev};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Which defence stage handled a prompt, as a stable integer label for the
/// inference-accuracy computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathLabel {
    /// Blocked by the regex denylist (fastest band).
    RegexBlock,
    /// Blocked by the semantic classifier (middle band).
    SemanticBlock,
    /// Passed to the LLM (slowest band).
    Llm,
}

impl PathLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            PathLabel::RegexBlock => "regex_block",
            PathLabel::SemanticBlock => "semantic_block",
            PathLabel::Llm => "llm",
        }
    }

    pub fn index(&self) -> usize {
        match self {
            PathLabel::RegexBlock => 0,
            PathLabel::SemanticBlock => 1,
            PathLabel::Llm => 2,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ModeStats {
    pub samples: usize,
    pub mean_us: f64,
    pub stddev_us: f64,
    pub inference_accuracy: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Posture {
    /// Mode label -> stats, when that mode has samples.
    pub modes: HashMap<String, ModeStats>,
    pub capability_replays: u64,
    pub cross_eval_mismatches: u64,
    pub frame_rejections: u64,
    pub deadline_aborts: u64,
    pub evaluations_completed: u64,
    pub resets: u64,
    /// Last trust-anchor / verifier check result, if any.
    pub last_verification: Option<String>,
}

#[derive(Debug, Default)]
struct Inner {
    samples: HashMap<TimingMode, Vec<(f64, usize)>>,
    capability_replays: u64,
    cross_eval_mismatches: u64,
    frame_rejections: u64,
    deadline_aborts: u64,
    evaluations_completed: u64,
    resets: u64,
    last_verification: Option<String>,
}

/// Thread-safe metrics accumulator.
#[derive(Debug, Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed turn: observed held time and true path label.
    pub fn record_turn(&self, mode: TimingMode, held_us: u64, path: PathLabel) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .samples
            .entry(mode)
            .or_default()
            .push((held_us as f64, path.index()));
    }

    pub fn record_capability_replay(&self) {
        self.inner.lock().unwrap().capability_replays += 1;
    }

    pub fn record_cross_eval_mismatch(&self) {
        self.inner.lock().unwrap().cross_eval_mismatches += 1;
    }

    pub fn record_frame_rejection(&self) {
        self.inner.lock().unwrap().frame_rejections += 1;
    }

    pub fn record_deadline_abort(&self) {
        self.inner.lock().unwrap().deadline_aborts += 1;
    }

    pub fn record_evaluation_completed(&self) {
        self.inner.lock().unwrap().evaluations_completed += 1;
    }

    pub fn record_reset(&self) {
        self.inner.lock().unwrap().resets += 1;
    }

    pub fn record_verification(&self, summary: impl Into<String>) {
        self.inner.lock().unwrap().last_verification = Some(summary.into());
    }

    fn stats_for(samples: &[(f64, usize)]) -> ModeStats {
        let points: Vec<f64> = samples.iter().map(|(p, _)| *p).collect();
        let labels: Vec<usize> = samples.iter().map(|(_, l)| *l).collect();
        // Three defence stages exist by construction; k=3 lets an identical
        // (collapsed) timing set fall back to chance-level accuracy.
        let accuracy = if points.is_empty() {
            0.0
        } else {
            inference_accuracy(&points, &labels, 3)
        };
        ModeStats {
            samples: points.len(),
            mean_us: sample_mean(&points),
            stddev_us: sample_stddev(&points),
            inference_accuracy: accuracy,
        }
    }

    /// Immutable snapshot for the HUD endpoint.
    pub fn posture(&self) -> Posture {
        let inner = self.inner.lock().unwrap();
        let mut modes = HashMap::new();
        for (mode, samples) in &inner.samples {
            modes.insert(mode.as_str().to_string(), Self::stats_for(samples));
        }
        Posture {
            modes,
            capability_replays: inner.capability_replays,
            cross_eval_mismatches: inner.cross_eval_mismatches,
            frame_rejections: inner.frame_rejections,
            deadline_aborts: inner.deadline_aborts,
            evaluations_completed: inner.evaluations_completed,
            resets: inner.resets,
            last_verification: inner.last_verification.clone(),
        }
    }

    /// Raw held-time samples for a mode (tests).
    pub fn samples(&self, mode: TimingMode) -> Vec<f64> {
        self.inner
            .lock()
            .unwrap()
            .samples
            .get(&mode)
            .map(|v| v.iter().map(|(p, _)| *p).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labelled(mode: TimingMode, bands: &[(f64, PathLabel)]) -> Metrics {
        let m = Metrics::new();
        for (held_us, path) in bands {
            m.record_turn(mode, *held_us as u64, *path);
        }
        m
    }

    #[test]
    fn baseline_bands_are_highly_inferable() {
        // 2 ms / 160 ms / 340 ms, well separated.
        let mut bands = Vec::new();
        for i in 0..10 {
            bands.push((2_000.0 + i as f64 * 20.0, PathLabel::RegexBlock));
            bands.push((160_000.0 + i as f64 * 200.0, PathLabel::SemanticBlock));
            bands.push((340_000.0 + i as f64 * 200.0, PathLabel::Llm));
        }
        let metrics = labelled(TimingMode::Normal, &bands);
        let posture = metrics.posture();
        let stats = &posture.modes["NORMAL"];
        assert_eq!(stats.samples, 30);
        assert!(stats.inference_accuracy > 0.99, "leaked: {:?}", stats);
        assert!(stats.stddev_us > 100_000.0);
    }

    #[test]
    fn bounded_mode_collapses_inference_to_chance() {
        // EVAL_1000: every response released at exactly 1000 ms.
        let mut bands = Vec::new();
        for _ in 0..10 {
            bands.push((1_000_000.0, PathLabel::RegexBlock));
            bands.push((1_000_000.0, PathLabel::SemanticBlock));
            bands.push((1_000_000.0, PathLabel::Llm));
        }
        let metrics = labelled(TimingMode::Eval1000, &bands);
        let stats = &metrics.posture().modes["EVAL_1000"];
        assert_eq!(stats.stddev_us, 0.0, "no dispersion once bounded");
        assert!(
            stats.inference_accuracy < 0.5,
            "attacker must be at chance, got {}",
            stats.inference_accuracy
        );
    }

    #[test]
    fn counters_accumulate() {
        let metrics = Metrics::new();
        metrics.record_capability_replay();
        metrics.record_capability_replay();
        metrics.record_cross_eval_mismatch();
        metrics.record_frame_rejection();
        metrics.record_deadline_abort();
        metrics.record_evaluation_completed();
        metrics.record_reset();
        metrics.record_verification("VALID (3 evaluations, 1 seal)");
        let posture = metrics.posture();
        assert_eq!(posture.capability_replays, 2);
        assert_eq!(posture.cross_eval_mismatches, 1);
        assert_eq!(posture.frame_rejections, 1);
        assert_eq!(posture.deadline_aborts, 1);
        assert_eq!(posture.evaluations_completed, 1);
        assert_eq!(posture.resets, 1);
        assert_eq!(posture.last_verification.as_deref(), Some("VALID (3 evaluations, 1 seal)"));
    }

    #[test]
    fn unvisited_modes_are_absent() {
        let metrics = Metrics::new();
        metrics.record_turn(TimingMode::Eval1000, 1_000_000, PathLabel::Llm);
        let posture = metrics.posture();
        assert!(posture.modes.contains_key("EVAL_1000"));
        assert!(!posture.modes.contains_key("NORMAL"));
        assert!(metrics.samples(TimingMode::Normal).is_empty());
    }

    #[test]
    fn samples_are_retrievable_per_mode() {
        let metrics = Metrics::new();
        metrics.record_turn(TimingMode::Eval1000, 1_000_000, PathLabel::Llm);
        metrics.record_turn(TimingMode::Normal, 2_000, PathLabel::RegexBlock);
        assert_eq!(metrics.samples(TimingMode::Eval1000), vec![1_000_000.0]);
        assert_eq!(metrics.samples(TimingMode::Normal), vec![2_000.0]);
    }
}
