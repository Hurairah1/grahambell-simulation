//! Section F — same-step ties between PoW-ID blocks (SPEC §3.5, §3.7).
//!
//! Every miner's hash chain starts at the same `t0` and advances one step per second, so
//! winning blocks carry whole-second timestamps. With `N` miners and per-step success
//! probability `q = 1/(N·I)`, the number of successes in one step is `K ~ Bin(N, q)`. The
//! round ends at the first step with `K ≥ 1`. That step holds a **tie** (two or more valid
//! blocks for the same height) with probability
//!
//! ```text
//! P(tie) = P(K ≥ 2) / P(K ≥ 1) = [1 − (1−q)^N − N·q·(1−q)^{N−1}] / [1 − (1−q)^N].
//! ```
//!
//! As `N` grows this tends to the Poisson value with `λ = N·q = 1/I`:
//! `(1 − e^{−λ} − λe^{−λ}) / (1 − e^{−λ})`, about 1.66% at 30 s. The \[P\] tie-break keeps the
//! block with the lower hash. Hashes are uniform, so it picks uniformly among the tied
//! blocks.

use crate::error::{Result, ensure};
use crate::logspace::ln_binomial_coefficient;
use crate::mc::{RunningStats, geometric_failures};
use crate::validation::Check;
use gb_config::Config;
use gb_runlog::rng_stream;
use serde::Serialize;

/// Probability that exactly `k` of `miners` succeed in one step, with `q = 1/(N·I)`.
pub fn successes_in_step(miners: u64, interval_s: f64, k: u64) -> f64 {
    let q = 1.0 / (miners as f64 * interval_s);
    libm::exp(
        ln_binomial_coefficient(miners, k)
            + k as f64 * libm::log(q)
            + (miners - k) as f64 * libm::log1p(-q),
    )
}

/// Probability that the winning step of a round holds two or more valid blocks.
pub fn tie_probability(miners: u64, interval_s: f64) -> Result<f64> {
    ensure(
        miners >= 2 && interval_s > 0.0,
        "need at least two miners and a positive interval",
    )?;
    let q = 1.0 / (miners as f64 * interval_s);
    let any = -libm::expm1(miners as f64 * libm::log1p(-q));
    Ok((any - successes_in_step(miners, interval_s, 1)) / any)
}

/// Probability that the winning step holds exactly `k` blocks, given at least one.
pub fn tie_size_probability(miners: u64, interval_s: f64, k: u64) -> f64 {
    let q = 1.0 / (miners as f64 * interval_s);
    let any = -libm::expm1(miners as f64 * libm::log1p(-q));
    successes_in_step(miners, interval_s, k) / any
}

/// Large-network limit of [`tie_probability`], with `λ = 1/I`.
pub fn poisson_tie_probability(interval_s: f64) -> f64 {
    let lambda = 1.0 / interval_s;
    let none = libm::exp(-lambda);
    let any = -libm::expm1(-lambda);
    (any - lambda * none) / any
}

/// F1 row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TieRow {
    /// Competing unregistered miners N.
    pub competing_miners: u64,
    /// Target interval I, seconds.
    pub interval_s: f64,
    /// Per-step success probability q.
    pub per_step_success_probability: f64,
    /// Probability that a round ends in a tie.
    pub tie_probability: f64,
    /// Expected tied rounds per year, at the target rate.
    pub ties_per_year: f64,
    /// Large-network (Poisson) limit.
    pub poisson_limit: f64,
    /// Probability of exactly 2 blocks at the winning step.
    pub two_way: f64,
    /// Probability of exactly 3 blocks at the winning step.
    pub three_way: f64,
    /// Probability of 4 or more blocks at the winning step.
    pub four_or_more: f64,
}

/// Builds the F1 table from the configuration.
pub fn section_f(config: &Config) -> Result<Vec<TieRow>> {
    let grid = &config.analytic.ties;
    let mut rows = Vec::new();
    for &miners in &grid.competing_miners {
        for &interval in &grid.intervals_s {
            let tie = tie_probability(miners, interval)?;
            let two = tie_size_probability(miners, interval, 2);
            let three = tie_size_probability(miners, interval, 3);
            rows.push(TieRow {
                competing_miners: miners,
                interval_s: interval,
                per_step_success_probability: 1.0 / (miners as f64 * interval),
                tie_probability: tie,
                ties_per_year: tie * config.model.seconds_per_year as f64 / interval,
                poisson_limit: poisson_tie_probability(interval),
                two_way: two,
                three_way: three,
                four_or_more: (tie - two - three).max(0.0),
            });
        }
    }
    Ok(rows)
}

/// Simulates rounds: every miner draws its first winning step; a tie is two or more miners
/// sharing the earliest step. Returns the per-round tie indicator statistics.
fn simulate_ties(seed: u64, miners: u64, interval_s: f64, rounds: u64) -> RunningStats {
    let mut rng = rng_stream(seed, &format!("F-ties-{miners}-{interval_s}"));
    let q = 1.0 / (miners as f64 * interval_s);
    let mut stats = RunningStats::default();
    for _ in 0..rounds {
        let (mut earliest, mut count) = (u64::MAX, 0u32);
        for _ in 0..miners {
            let step = geometric_failures(&mut rng, q);
            if step < earliest {
                earliest = step;
                count = 1;
            } else if step == earliest {
                count += 1;
            }
        }
        stats.push(f64::from(u8::from(count >= 2)));
    }
    stats
}

/// Section F cross-checks.
pub fn checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let interval = config.issuance.pow_id_target_interval_s.value;
    let stats = simulate_ties(config.run.seed, mc.tie_miners, interval, mc.tie_rounds);
    let exact = tie_probability(mc.tie_miners, interval)?;
    Ok(vec![
        Check::monte_carlo(
            "F",
            "F-mc-tie-rate",
            &format!(
                "{} miners, I={interval} s: simulated share of rounds whose earliest step is shared vs exact binomial formula",
                mc.tie_miners
            ),
            exact,
            stats.estimate(),
            mc.tolerance_standard_errors,
            0.0,
        ),
        Check::relative(
            "F",
            "F-poisson-limit",
            "tie probability at N = 5,000,000 vs the Poisson limit with λ = 1/I",
            poisson_tie_probability(interval),
            tie_probability(5_000_000, interval)?,
            1e-6,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tie_rate_at_30_seconds_is_about_1_66_percent() {
        let tie = tie_probability(5_000_000, 30.0).unwrap();
        assert!((tie - 0.016_574).abs() < 1e-5, "{tie}");
    }

    #[test]
    fn tie_sizes_sum_to_the_tie_probability() {
        let tie = tie_probability(1_000_000, 30.0).unwrap();
        let sizes: f64 = (2..=20)
            .map(|k| tie_size_probability(1_000_000, 30.0, k))
            .sum();
        assert!((sizes - tie).abs() < 1e-12);
    }

    #[test]
    fn shorter_intervals_produce_more_ties() {
        let fast = tie_probability(1_000_000, 10.0).unwrap();
        let slow = tie_probability(1_000_000, 60.0).unwrap();
        assert!(fast > slow);
    }

    #[test]
    fn a_single_miner_cannot_tie() {
        assert!(tie_probability(1, 30.0).is_err());
    }

    #[test]
    fn section_f_table_covers_the_grid() {
        let config = Config::default();
        let rows = section_f(&config).unwrap();
        assert_eq!(rows.len(), 6);
        assert!(
            rows.iter()
                .all(|r| r.two_way + r.three_way + r.four_or_more - r.tie_probability < 1e-12)
        );
    }

    #[test]
    fn all_section_f_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.tie_rounds = 60_000;
        for check in checks(&config).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
