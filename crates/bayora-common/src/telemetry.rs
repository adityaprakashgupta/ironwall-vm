//! Telemetry primitives behind the Security Posture HUD:
//! sample variance, 1-D K-Means, and the empirical attacker-inference
//! accuracy (cluster assignment vs. true defense-stage label).

/// Bessel-corrected sample variance `s² = Σ(tᵢ − t̄)² / (n − 1)`.
/// Returns `0.0` for n < 2.
pub fn sample_variance(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let ss = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>();
    ss / (n - 1.0)
}

pub fn sample_stddev(xs: &[f64]) -> f64 {
    sample_variance(xs).sqrt()
}

pub fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Deterministic 1-D K-Means with quantile-initialized centers.
/// Returns the cluster id for each point. Identical points collapse into a
/// single cluster — which is exactly the observable difference between
/// baseline (three timing bands) and Bounded Observable Execution.
pub fn kmeans_1d(points: &[f64], k: usize, iterations: usize) -> Vec<usize> {
    if points.is_empty() || k == 0 {
        return Vec::new();
    }
    let k = k.min(points.len());
    let mut sorted = points.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // Quantile init (deterministic; no RNG => reproducible HUD numbers).
    let mut centers: Vec<f64> = Vec::with_capacity(k);
    for i in 0..k {
        let idx = ((i + 1) * sorted.len() / (k + 1)).min(sorted.len() - 1);
        centers.push(sorted[idx]);
    }
    // Nudge identical centers apart so ties distribute deterministically.
    for i in 1..centers.len() {
        if centers[i] <= centers[i - 1] {
            centers[i] = centers[i - 1] + f64::EPSILON;
        }
    }

    let mut assign = vec![0usize; points.len()];
    for _ in 0..iterations.max(1) {
        let mut changed = false;
        for (i, p) in points.iter().enumerate() {
            let mut best = 0;
            let mut best_d = f64::MAX;
            for (c, center) in centers.iter().enumerate() {
                let d = (p - center).abs();
                if d < best_d {
                    best_d = d;
                    best = c;
                }
            }
            if assign[i] != best {
                assign[i] = best;
                changed = true;
            }
        }
        // Recompute centers.
        let mut sums = vec![0.0f64; k];
        let mut counts = vec![0usize; k];
        for (i, p) in points.iter().enumerate() {
            sums[assign[i]] += p;
            counts[assign[i]] += 1;
        }
        for c in 0..k {
            if counts[c] > 0 {
                centers[c] = sums[c] / counts[c] as f64;
            }
        }
        if !changed {
            break;
        }
    }
    assign
}

/// Attacker inference accuracy: cluster the observed timings into `k`
/// clusters, then map each cluster to its majority true label (ties broken
/// toward the lowest label id). Returns a value in `[0, 1]`.
///
/// * baseline: three separable timing bands => accuracy near 1.0
/// * EVAL_500: all timings identical => one cluster absorbs everything =>
///   accuracy collapses to the majority-label share (~1/k for balanced classes)
pub fn inference_accuracy(points: &[f64], labels: &[usize], k: usize) -> f64 {
    assert_eq!(points.len(), labels.len(), "points/labels length mismatch");
    if points.is_empty() {
        return 0.0;
    }
    let clusters = kmeans_1d(points, k, 32);
    // cluster -> (label -> count)
    let mut tallies: std::collections::HashMap<usize, std::collections::HashMap<usize, usize>> =
        std::collections::HashMap::new();
    for (cluster, label) in clusters.iter().zip(labels.iter()) {
        *tallies
            .entry(*cluster)
            .or_default()
            .entry(*label)
            .or_default() += 1;
    }
    // Deterministic majority label per cluster; ties -> smallest label id.
    let majority: std::collections::HashMap<usize, usize> = tallies
        .iter()
        .map(|(cluster, tally)| {
            let label = tally
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
                .map(|(label, _)| *label)
                .unwrap_or(0);
            (*cluster, label)
        })
        .collect();
    let correct = clusters
        .iter()
        .zip(labels.iter())
        .filter(|(cluster, label)| majority.get(cluster) == Some(*label))
        .count();
    correct as f64 / points.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variance_matches_hand_computation() {
        // {2, 4, 4, 4, 5, 5, 7, 9}: mean 5, SS = 32, n-1 = 7
        let xs = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        assert!((sample_variance(&xs) - 32.0 / 7.0).abs() < 1e-12);
        assert!(sample_variance(&[5.0]) == 0.0);
    }

    #[test]
    fn separated_bands_are_fully_inferable() {
        // Three well-separated timing bands with balanced labels.
        let mut points = Vec::new();
        let mut labels = Vec::new();
        for (band, label) in [(2.0, 0usize), (180.0, 1), (340.0, 2)] {
            for i in 0..10 {
                points.push(band + i as f64 * 0.1);
                labels.push(label);
            }
        }
        let acc = inference_accuracy(&points, &labels, 3);
        assert!(
            acc > 0.99,
            "baseline bands must be classifiable, got {acc}"
        );
    }

    #[test]
    fn collapsed_points_collapse_to_majority_share() {
        // EVAL_500: every sample lands on the same bucket boundary.
        let points = vec![500.0; 30];
        let labels: Vec<usize> = (0..30).map(|i| i % 3).collect();
        let acc = inference_accuracy(&points, &labels, 3);
        assert!(
            (acc - 10.0 / 30.0).abs() < 1e-9,
            "collapsed timings must reduce to majority share (~33%), got {acc}"
        );
        assert!(acc < 0.5, "attacker must be near chance, got {acc}");
    }

    #[test]
    fn kmeans_deterministic() {
        let pts = [1.0, 1.1, 5.0, 5.2, 9.0, 9.1];
        let a = kmeans_1d(&pts, 3, 32);
        let b = kmeans_1d(&pts, 3, 32);
        assert_eq!(a, b);
        assert_eq!(a, vec![0, 0, 1, 1, 2, 2]);
    }
}
