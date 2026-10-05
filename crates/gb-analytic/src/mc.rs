//! Seeded Monte Carlo helpers for the cross-checks.
//!
//! Samplers are implemented here rather than taken from another crate, so the random numbers
//! a given seed produces cannot change when a dependency changes its algorithms. Uniform
//! variates use the top 53 bits of a 64-bit draw; geometric and exponential variates use
//! inverse transforms through `libm`.

use rand_core::Rng;

/// Uniform variate in `[0, 1)`.
pub fn uniform<R: Rng + ?Sized>(rng: &mut R) -> f64 {
    (rng.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
}

/// Uniform variate in `(0, 1]`, safe to pass to a logarithm.
pub fn uniform_positive<R: Rng + ?Sized>(rng: &mut R) -> f64 {
    1.0 - uniform(rng)
}

/// True with probability `p`.
pub fn bernoulli<R: Rng + ?Sized>(rng: &mut R, p: f64) -> bool {
    uniform(rng) < p
}

/// Failures before the first success in independent trials with success probability `q`:
/// `P(X = k) = (1 - q)^k q` for `k = 0, 1, 2, …`.
pub fn geometric_failures<R: Rng + ?Sized>(rng: &mut R, q: f64) -> u64 {
    if q >= 1.0 {
        return 0;
    }
    let draw = libm::log(uniform_positive(rng)) / libm::log1p(-q);
    // Saturating float-to-integer conversion; `draw` is finite and non-negative here.
    draw.floor() as u64
}

/// Exponential variate with the given rate.
pub fn exponential<R: Rng + ?Sized>(rng: &mut R, rate: f64) -> f64 {
    -libm::log(uniform_positive(rng)) / rate
}

/// Uniform integer in `0..n`, without modulo bias (Lemire's method). `n` must be positive.
pub fn uniform_below<R: Rng + ?Sized>(rng: &mut R, n: u64) -> u64 {
    let threshold = n.wrapping_neg() % n;
    loop {
        let product = u128::from(rng.next_u64()) * u128::from(n);
        if (product as u64) >= threshold {
            return (product >> 64) as u64;
        }
    }
}

/// In-place Fisher–Yates shuffle.
pub fn shuffle<T, R: Rng + ?Sized>(rng: &mut R, items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let j = uniform_below(rng, i as u64 + 1) as usize;
        items.swap(i, j);
    }
}

/// Running mean and variance (Welford's algorithm).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunningStats {
    count: u64,
    mean: f64,
    sum_squared_deviations: f64,
}

impl RunningStats {
    /// Adds one observation.
    pub fn push(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        self.sum_squared_deviations += delta * (value - self.mean);
    }

    /// Number of observations.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Sample mean.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Unbiased sample variance (zero with fewer than two observations).
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.sum_squared_deviations / (self.count - 1) as f64
        }
    }

    /// Standard error of the mean.
    pub fn standard_error(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            (self.variance() / self.count as f64).sqrt()
        }
    }

    /// Mean and standard error as an [`Estimate`].
    pub fn estimate(&self) -> Estimate {
        Estimate {
            value: self.mean(),
            standard_error: self.standard_error(),
            samples: self.count,
        }
    }
}

/// A Monte Carlo estimate with its standard error.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimate {
    /// Point estimate.
    pub value: f64,
    /// Standard error of the estimate.
    pub standard_error: f64,
    /// Number of independent samples (or batches) behind it.
    pub samples: u64,
}

impl Estimate {
    /// True when `reference` lies within `k` standard errors of the estimate, widened by an
    /// explicit `allowance` for known bias of a first-order formula.
    pub fn agrees_with(&self, reference: f64, k: f64, allowance: f64) -> bool {
        (self.value - reference).abs() <= k * self.standard_error + allowance
    }
}

/// Ratio-of-sums estimate `Σ numerators / Σ denominators`, with its standard error from
/// `batches` equal batches (batch means).
pub fn ratio_of_sums(numerators: &[f64], denominators: &[f64], batches: usize) -> Estimate {
    let total = numerators.iter().sum::<f64>() / denominators.iter().sum::<f64>();
    let batches = batches.clamp(2, numerators.len().max(2));
    let size = numerators.len() / batches;
    let mut stats = RunningStats::default();
    for b in 0..batches {
        let range = b * size..((b + 1) * size).min(numerators.len());
        let n: f64 = numerators[range.clone()].iter().sum();
        let d: f64 = denominators[range].iter().sum();
        if d > 0.0 {
            stats.push(n / d);
        }
    }
    Estimate {
        value: total,
        standard_error: stats.standard_error(),
        samples: stats.count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gb_runlog::rng_stream;

    #[test]
    fn uniform_variates_lie_in_the_unit_interval_with_mean_one_half() {
        // Reference: E[U] = 1/2, SD = 1/sqrt(12); tolerance: 5 standard errors.
        let mut rng = rng_stream(1, "mc-uniform");
        let mut stats = RunningStats::default();
        for _ in 0..100_000 {
            let u = uniform(&mut rng);
            assert!((0.0..1.0).contains(&u));
            stats.push(u);
        }
        assert!(stats.estimate().agrees_with(0.5, 5.0, 0.0));
    }

    #[test]
    fn geometric_failures_have_mean_one_minus_q_over_q() {
        // Reference: E[X] = (1 - q)/q = 9 for q = 0.1; tolerance: 5 standard errors.
        let mut rng = rng_stream(2, "mc-geometric");
        let mut stats = RunningStats::default();
        for _ in 0..100_000 {
            stats.push(geometric_failures(&mut rng, 0.1) as f64);
        }
        assert!(
            stats.estimate().agrees_with(9.0, 5.0, 0.0),
            "{:?}",
            stats.estimate()
        );
        assert_eq!(geometric_failures(&mut rng, 1.0), 0);
    }

    #[test]
    fn exponential_variates_have_mean_one_over_rate() {
        // Reference: E[X] = 1/rate = 0.25; tolerance: 5 standard errors.
        let mut rng = rng_stream(3, "mc-exponential");
        let mut stats = RunningStats::default();
        for _ in 0..100_000 {
            stats.push(exponential(&mut rng, 4.0));
        }
        assert!(stats.estimate().agrees_with(0.25, 5.0, 0.0));
    }

    #[test]
    fn uniform_below_stays_in_range_and_covers_it() {
        let mut rng = rng_stream(4, "mc-below");
        let mut seen = [false; 7];
        for _ in 0..1_000 {
            let x = uniform_below(&mut rng, 7) as usize;
            seen[x] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut rng = rng_stream(5, "mc-shuffle");
        let mut items: Vec<u32> = (0..100).collect();
        shuffle(&mut rng, &mut items);
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..100).collect::<Vec<_>>());
        assert_ne!(items, sorted);
    }

    #[test]
    fn bernoulli_frequency_matches_p() {
        // Reference: p = 0.3; tolerance: 5 standard errors.
        let mut rng = rng_stream(6, "mc-bernoulli");
        let mut stats = RunningStats::default();
        for _ in 0..100_000 {
            stats.push(f64::from(u8::from(bernoulli(&mut rng, 0.3))));
        }
        assert!(stats.estimate().agrees_with(0.3, 5.0, 0.0));
    }

    #[test]
    fn running_stats_match_textbook_values() {
        let mut stats = RunningStats::default();
        for x in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            stats.push(x);
        }
        assert_eq!(stats.mean(), 5.0);
        assert!((stats.variance() - 32.0 / 7.0).abs() < 1e-12);
        assert_eq!(stats.count(), 8);
    }

    #[test]
    fn ratio_of_sums_uses_all_data_for_the_point_estimate() {
        let estimate = ratio_of_sums(&[1.0, 2.0, 3.0, 4.0], &[2.0, 2.0, 2.0, 2.0], 2);
        assert_eq!(estimate.value, 10.0 / 8.0);
        assert_eq!(estimate.samples, 2);
    }
}
