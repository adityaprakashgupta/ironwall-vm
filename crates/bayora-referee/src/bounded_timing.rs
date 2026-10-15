//! Bounded Observable Execution — the timing-inference defence.
//!
//! The attacker model is an *observer* of the egress channel: the Red VM can
//! time how long a response took. In baseline (`NORMAL`) mode those timings
//! reveal which defence stage handled the prompt (regex ~2 ms, semantic
//! classifier ~160 ms, full LLM path ~340 ms), which is exactly the side
//! channel that lets an adversary probe the Blue-team policy without seeing it.
//!
//! The fix is structural rather than statistical: every response in
//! `EVAL_500` mode is released at the *same* 500 ms bucket boundary, because
//! work that has not finished by `T_bucket − abort_margin` is cancelled and
//! replaced by a constant timeout envelope. Observable timing therefore carries
//! no information about the path taken.
//!
//! Both halves are required:
//! * [`TimingGuard::execute`] bounds and possibly cancels the work, and
//! * [`TimingGuard::wait_for_release`] holds the caller until the boundary, so
//!   *fast* paths are not distinguishable either.
//!
//! All instants are `tokio::time::Instant`, so the whole mechanism can be
//! tested deterministically with `#[tokio::test(start_paused = true)]`.

use bayora_common::policy::TimingMode;
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;

/// Outcome of a bounded execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedOutcome<T> {
    /// Work finished before the abort deadline.
    Completed(T),
    /// Work was cancelled at `T_bucket − abort_margin`; the caller must
    /// substitute a constant timeout envelope.
    DeadlineAborted { at: Duration },
}

impl<T> BoundedOutcome<T> {
    pub fn is_aborted(&self) -> bool {
        matches!(self, BoundedOutcome::DeadlineAborted { .. })
    }

    pub fn completed(self) -> Option<T> {
        match self {
            BoundedOutcome::Completed(value) => Some(value),
            BoundedOutcome::DeadlineAborted { .. } => None,
        }
    }
}

/// Wall-clock budget for a single turn.
#[derive(Debug, Clone)]
pub struct TimingGuard {
    mode: TimingMode,
    started: Instant,
    abort_margin: Duration,
    bucket: Option<Duration>,
}

impl TimingGuard {
    /// Start the clock. `mode` decides the bucket; `abort_margin` is the
    /// safety gap in front of it.
    pub fn new(mode: TimingMode, abort_margin: Duration) -> Self {
        TimingGuard {
            mode,
            started: Instant::now(),
            abort_margin,
            bucket: mode.bucket(),
        }
    }

    /// Start the clock from an explicit instant (tests / replay).
    pub fn starting_at(mode: TimingMode, abort_margin: Duration, started: Instant) -> Self {
        TimingGuard {
            mode,
            started,
            abort_margin,
            bucket: mode.bucket(),
        }
    }

    pub fn mode(&self) -> TimingMode {
        self.mode
    }

    pub fn started(&self) -> Instant {
        self.started
    }

    pub fn bucket(&self) -> Option<Duration> {
        self.bucket
    }

    pub fn abort_margin(&self) -> Duration {
        self.abort_margin
    }

    /// `T_bucket`, if the mode has one.
    pub fn release_at(&self) -> Option<Instant> {
        self.bucket.map(|bucket| self.started + bucket)
    }

    /// `T_bucket − abort_margin`.
    pub fn abort_at(&self) -> Option<Instant> {
        self.bucket
            .map(|bucket| self.started + bucket.saturating_sub(self.abort_margin))
    }

    /// Elapsed time since the guard started.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Elapsed time in whole microseconds — the unit used in evidence records,
    /// where floats are not canonicalizable.
    pub fn elapsed_us(&self) -> u64 {
        self.elapsed().as_micros() as u64
    }

    /// Run `work` under the bucket deadline.
    ///
    /// * `NORMAL` — no bucket at all: resolve exactly when `work` does.
    /// * `EVAL_*` — race `work` against `T_bucket − abort_margin`. The race is
    ///   biased toward `work`, so work that finishes at exactly the deadline
    ///   still counts as completed rather than aborted.
    pub async fn execute<F: Future>(&self, work: F) -> BoundedOutcome<F::Output> {
        match self.abort_at() {
            None => BoundedOutcome::Completed(work.await),
            Some(abort_at) => {
                tokio::select! {
                    biased;
                    output = work => BoundedOutcome::Completed(output),
                    _ = tokio::time::sleep_until(abort_at) => BoundedOutcome::DeadlineAborted {
                        at: abort_at.duration_since(self.started),
                    },
                }
            }
        }
    }

    /// Hold until `T_bucket`. Callers must always invoke this *after*
    /// [`TimingGuard::execute`], including on the abort path, so that both
    /// outcomes are released at the same observable instant.
    pub async fn wait_for_release(&self) {
        if let Some(release_at) = self.release_at() {
            tokio::time::sleep_until(release_at).await;
        }
    }

    /// True once the release boundary has passed (used to decide whether the
    /// padded frame can be emitted immediately).
    pub fn released(&self) -> bool {
        match self.release_at() {
            Some(release_at) => Instant::now() >= release_at,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARGIN: Duration = Duration::from_millis(15);

    #[tokio::test(start_paused = true)]
    async fn normal_mode_does_not_hold() {
        let guard = TimingGuard::new(TimingMode::Normal, MARGIN);
        assert_eq!(guard.bucket(), None);
        let outcome = guard
            .execute(async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                "fast"
            })
            .await;
        assert_eq!(outcome, BoundedOutcome::Completed("fast"));
        guard.wait_for_release().await; // no-op in NORMAL mode
        assert_eq!(guard.elapsed(), Duration::from_millis(50));
    }

    #[tokio::test(start_paused = true)]
    async fn eval_500_holds_fast_paths_to_the_bucket() {
        let guard = TimingGuard::new(TimingMode::Eval500, MARGIN);
        // A 2 ms regex block must still be observed at 500 ms.
        let outcome = guard
            .execute(async {
                tokio::time::sleep(Duration::from_millis(2)).await;
                "blocked"
            })
            .await;
        assert!(!outcome.is_aborted());
        guard.wait_for_release().await;
        assert_eq!(guard.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn eval_500_aborts_work_past_the_deadline() {
        let guard = TimingGuard::new(TimingMode::Eval500, MARGIN);
        // 700 ms of LLM work cannot fit; it is cancelled at 485 ms.
        let outcome = guard
            .execute(async {
                tokio::time::sleep(Duration::from_millis(700)).await;
                "llm"
            })
            .await;
        match outcome {
            BoundedOutcome::DeadlineAborted { at } => {
                assert_eq!(at, Duration::from_millis(485));
            }
            other => panic!("expected abort, got {other:?}"),
        }
        // Release still happens exactly at the bucket boundary.
        guard.wait_for_release().await;
        assert_eq!(guard.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn every_path_lands_on_the_same_observable_boundary() {
        // The whole point: 2 ms, 160 ms and an aborted 700 ms path must all
        // present identical observable latency.
        let mut observed = Vec::new();
        for work_ms in [2u64, 160, 480, 700] {
            let guard = TimingGuard::new(TimingMode::Eval500, MARGIN);
            let _ = guard
                .execute(async move {
                    tokio::time::sleep(Duration::from_millis(work_ms)).await;
                    ()
                })
                .await;
            guard.wait_for_release().await;
            observed.push(guard.elapsed());
        }
        assert!(
            observed.iter().all(|d| *d == Duration::from_millis(500)),
            "all paths must be indistinguishable, got {observed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn eval_1000_uses_a_one_second_bucket() {
        let guard = TimingGuard::new(TimingMode::Eval1000, MARGIN);
        assert_eq!(guard.release_at().unwrap(), guard.started() + Duration::from_millis(1000));
        assert_eq!(
            guard.abort_at().unwrap(),
            guard.started() + Duration::from_millis(985)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn work_finishing_exactly_at_the_deadline_counts_as_completed() {
        let guard = TimingGuard::new(TimingMode::Eval500, MARGIN);
        let outcome = guard
            .execute(async {
                tokio::time::sleep(Duration::from_millis(485)).await;
                "just-in-time"
            })
            .await;
        // Biased select prefers the work future that is ready at the deadline.
        assert_eq!(outcome, BoundedOutcome::Completed("just-in-time"));
    }

    #[tokio::test(start_paused = true)]
    async fn elapsed_us_is_integer_microseconds() {
        let guard = TimingGuard::new(TimingMode::Normal, MARGIN);
        // Tokio's timer wheel has millisecond granularity under paused time,
        // so sleep in whole milliseconds and assert the exact microsecond
        // count (evidence records must never contain floats).
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(guard.elapsed_us(), 2_000);
        assert_eq!(guard.elapsed_us(), guard.elapsed().as_micros() as u64);
    }

    #[test]
    fn abort_deadline_never_precedes_the_start() {
        let guard = TimingGuard::new(TimingMode::Eval500, Duration::from_millis(900));
        // Bucket 500 ms < margin 900 ms would be rejected by policy, but the
        // guard itself must saturate rather than panic.
        let abort_at = guard.abort_at().unwrap();
        assert!(abort_at >= guard.started());
    }
}
