//! p-values for the equivalence tests (C6): χ² and Kolmogorov–Smirnov.

/// Regularised upper incomplete gamma `Q(a, x)` (Numerical Recipes: series for `x < a + 1`,
/// continued fraction otherwise).
pub fn gamma_q(a: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    let ln_prefix = -x + a * libm::log(x) - libm::lgamma(a);
    if x < a + 1.0 {
        let (mut term, mut sum, mut ap) = (1.0 / a, 1.0 / a, a);
        for _ in 0..10_000 {
            ap += 1.0;
            term *= x / ap;
            sum += term;
            if term.abs() < sum.abs() * 1e-15 {
                break;
            }
        }
        1.0 - sum * libm::exp(ln_prefix)
    } else {
        let tiny = 1e-300;
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / tiny;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..10_000 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < tiny {
                d = tiny;
            }
            c = b + an / c;
            if c.abs() < tiny {
                c = tiny;
            }
            d = 1.0 / d;
            let delta = d * c;
            h *= delta;
            if (delta - 1.0).abs() < 1e-15 {
                break;
            }
        }
        libm::exp(ln_prefix) * h
    }
}

/// p-value of a χ² statistic with `dof` degrees of freedom.
pub fn chi_square_p(statistic: f64, dof: f64) -> f64 {
    gamma_q(dof / 2.0, statistic / 2.0)
}

/// Two-sample χ² homogeneity test on binned counts; returns (statistic, degrees of freedom,
/// p-value). Bins empty in both samples are skipped.
pub fn chi_square_two_sample(a: &[u64], b: &[u64]) -> (f64, f64, f64) {
    let (na, nb) = (a.iter().sum::<u64>() as f64, b.iter().sum::<u64>() as f64);
    let mut stat = 0.0;
    let mut bins: f64 = 0.0;
    for (x, y) in a.iter().zip(b) {
        let total = (*x + *y) as f64;
        if total == 0.0 {
            continue;
        }
        bins += 1.0;
        let ea = total * na / (na + nb);
        let eb = total * nb / (na + nb);
        stat += (*x as f64 - ea).powi(2) / ea + (*y as f64 - eb).powi(2) / eb;
    }
    let dof = (bins - 1.0).max(1.0);
    (stat, dof, chi_square_p(stat, dof))
}

/// One-sample Kolmogorov–Smirnov test of `values` against U(0, 1); returns (D, p-value).
pub fn ks_uniform(values: &[f64]) -> (f64, f64) {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len() as f64;
    let d = v
        .iter()
        .enumerate()
        .map(|(i, x)| ((i as f64 + 1.0) / n - x).max(x - i as f64 / n))
        .fold(0.0, f64::max);
    let sqrt_n = n.sqrt();
    let lambda = (sqrt_n + 0.12 + 0.11 / sqrt_n) * d;
    (d, kolmogorov_q(lambda))
}

/// `Q_KS(λ) = 2 Σ_{j≥1} (−1)^{j−1} e^{−2 j² λ²}`.
pub fn kolmogorov_q(lambda: f64) -> f64 {
    if lambda < 1e-3 {
        return 1.0;
    }
    let mut sum = 0.0;
    for j in 1..200 {
        let jf = j as f64;
        let term = libm::exp(-2.0 * jf * jf * lambda * lambda);
        sum += if j % 2 == 1 { term } else { -term };
        if term < 1e-16 {
            break;
        }
    }
    (2.0 * sum).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chi_square_p_values_match_tables() {
        // Reference: χ² tables. P(χ²₁ > 3.841) = 0.05; P(χ²₁₀ > 18.307) = 0.05;
        // P(χ²₂ > x) = e^(−x/2).
        assert!((chi_square_p(3.841_459, 1.0) - 0.05).abs() < 1e-5);
        assert!((chi_square_p(18.307_04, 10.0) - 0.05).abs() < 1e-5);
        assert!((chi_square_p(4.0, 2.0) - libm::exp(-2.0)).abs() < 1e-12);
        // For even degrees of freedom, P(χ²₂ₖ > x) = e^(−x/2) Σ_{i<k} (x/2)^i / i! (Poisson).
        let poisson: f64 = (0..5)
            .map(|i| libm::pow(25.0, i as f64) / libm::tgamma(i as f64 + 1.0))
            .sum::<f64>()
            * libm::exp(-25.0);
        assert!((chi_square_p(50.0, 10.0) / poisson - 1.0).abs() < 1e-9);
    }

    #[test]
    fn kolmogorov_tail_matches_tables() {
        // Reference: Q_KS(1.358) ≈ 0.05 and Q_KS(1.628) ≈ 0.01.
        assert!((kolmogorov_q(1.358_1) - 0.05).abs() < 1e-3);
        assert!((kolmogorov_q(1.627_6) - 0.01).abs() < 1e-3);
    }

    #[test]
    fn uniform_grid_passes_and_a_skewed_sample_fails() {
        let grid: Vec<f64> = (0..1_000).map(|i| (i as f64 + 0.5) / 1_000.0).collect();
        assert!(ks_uniform(&grid).1 > 0.99);
        let skewed: Vec<f64> = grid.iter().map(|x| x * x).collect();
        assert!(ks_uniform(&skewed).1 < 1e-6);
    }
}
