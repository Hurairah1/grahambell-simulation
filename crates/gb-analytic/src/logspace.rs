//! Independent floating-point implementations of the tail probabilities, in log space.
//!
//! These exist only to cross-check [`crate::dist`]. They share no code with it: binomial
//! coefficients come from sums of logarithms, and tails from a log-sum-exp. Working in logs
//! keeps tiny probabilities (far below `f64`'s smallest value) representable as `log10`.

/// Natural log of `C(n, k)`, as a sum of `ln((n - k' + i) / i)` with `k' = min(k, n - k)`.
///
/// Returns negative infinity when `k > n`.
pub fn ln_binomial_coefficient(n: u64, k: u64) -> f64 {
    if k > n {
        return f64::NEG_INFINITY;
    }
    let k = k.min(n - k);
    (1..=k)
        .map(|i| libm::log((n - k + i) as f64 / i as f64))
        .sum()
}

/// `log10` of `Σ exp(terms)`, computed stably. Negative infinity for an empty sum.
pub fn log10_sum_exp(ln_terms: &[f64]) -> f64 {
    let max = ln_terms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if max == f64::NEG_INFINITY {
        return f64::NEG_INFINITY;
    }
    let sum: f64 = ln_terms.iter().map(|t| libm::exp(t - max)).sum();
    (max + libm::log(sum)) / std::f64::consts::LN_10
}

/// Natural log of the binomial probability `P(X = k)` for `X ~ Bin(n, p)`.
pub fn ln_binomial_pmf(n: u64, k: u64, p: f64) -> f64 {
    ln_binomial_coefficient(n, k) + k as f64 * libm::log(p) + (n - k) as f64 * libm::log1p(-p)
}

/// Natural log of the hypergeometric probability `P(X = k)` when drawing `n` from a
/// population of `m` with `big_k` attackers.
pub fn ln_hypergeometric_pmf(m: u64, big_k: u64, n: u64, k: u64) -> f64 {
    if k > big_k || n < k || n - k > m - big_k {
        return f64::NEG_INFINITY;
    }
    ln_binomial_coefficient(big_k, k) + ln_binomial_coefficient(m - big_k, n - k)
        - ln_binomial_coefficient(m, n)
}

/// `log10 P(X ≥ k)` for `X ~ Bin(n, p)`.
pub fn log10_binomial_tail_at_least(n: u64, k: u64, p: f64) -> f64 {
    let terms: Vec<f64> = (k..=n).map(|x| ln_binomial_pmf(n, x, p)).collect();
    log10_sum_exp(&terms)
}

/// `log10 P(X ≥ k)` for the hypergeometric distribution.
pub fn log10_hypergeometric_tail_at_least(m: u64, big_k: u64, n: u64, k: u64) -> f64 {
    let terms: Vec<f64> = (k..=n)
        .map(|x| ln_hypergeometric_pmf(m, big_k, n, x))
        .collect();
    log10_sum_exp(&terms)
}

/// Natural log of the joint probability that two disjoint seat groups of sizes `first` and
/// `second`, drawn without replacement, hold `x` and `y` attacker seats.
pub fn ln_joint_hypergeometric(m: u64, big_k: u64, first: u64, second: u64, x: u64, y: u64) -> f64 {
    if x > first || y > second || x > big_k {
        return f64::NEG_INFINITY;
    }
    let first_term = ln_hypergeometric_pmf(m, big_k, first, x);
    let second_term = ln_hypergeometric_pmf(m - first, big_k - x, second, y);
    first_term + second_term
}

/// `log10` of the probability of a region of the two-group distribution.
///
/// `ln_cell(x, y)` gives the natural log of each cell's probability.
pub fn log10_region(
    first: u64,
    second: u64,
    ln_cell: impl Fn(u64, u64) -> f64,
    predicate: impl Fn(u64, u64) -> bool,
) -> f64 {
    let mut terms = Vec::new();
    for x in 0..=first {
        for y in 0..=second {
            if predicate(x, y) {
                terms.push(ln_cell(x, y));
            }
        }
    }
    log10_sum_exp(&terms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ln_binomial_coefficient_matches_exact_values() {
        assert!((ln_binomial_coefficient(30, 21) - libm::log(14_307_150.0)).abs() < 1e-12);
        assert_eq!(ln_binomial_coefficient(5, 0), 0.0);
        assert_eq!(ln_binomial_coefficient(5, 6), f64::NEG_INFINITY);
    }

    #[test]
    fn binomial_tail_of_a_fair_coin_matches_the_exact_fraction() {
        // P(Bin(10, 1/2) >= 7) = 176/1024.
        let expected = libm::log10(176.0 / 1024.0);
        assert!((log10_binomial_tail_at_least(10, 7, 0.5) - expected).abs() < 1e-13);
    }

    #[test]
    fn hypergeometric_probabilities_sum_to_one() {
        let terms: Vec<f64> = (0..=40)
            .map(|k| ln_hypergeometric_pmf(1000, 330, 40, k))
            .collect();
        assert!(log10_sum_exp(&terms).abs() < 1e-13);
    }

    #[test]
    fn joint_region_over_everything_has_probability_one() {
        let ln_cell = |x, y| ln_joint_hypergeometric(500, 100, 10, 30, x, y);
        assert!(log10_region(10, 30, ln_cell, |_, _| true).abs() < 1e-12);
    }

    #[test]
    fn empty_sums_are_negative_infinity() {
        assert_eq!(log10_sum_exp(&[]), f64::NEG_INFINITY);
        assert_eq!(ln_hypergeometric_pmf(10, 2, 5, 3), f64::NEG_INFINITY);
    }
}
