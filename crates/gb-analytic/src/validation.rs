//! Cross-check records written to `validation.csv`.
//!
//! Every section contributes checks that compare a result with an independent reference: an
//! exact substitution, a different algorithm, or a seeded Monte Carlo simulation. Each check
//! states its reference, its tolerance and whether it passed.

use crate::mc::Estimate;
use serde::Serialize;

/// One cross-check.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Check {
    /// Section letter, for example `A`.
    pub section: &'static str,
    /// Short identifier.
    pub check: String,
    /// What is compared with what.
    pub description: String,
    /// Reference value.
    pub reference: f64,
    /// Value being checked.
    pub value: f64,
    /// Allowed difference, in the unit given by `tolerance_kind`.
    pub tolerance: f64,
    /// How the tolerance is applied.
    pub tolerance_kind: &'static str,
    /// Monte Carlo samples or number of rows checked (0 when not applicable).
    pub samples: u64,
    /// Whether the check passed.
    pub passed: bool,
}

impl Check {
    /// Exact equality (for example of two rationals), recorded with their `f64` values.
    pub fn exact(
        section: &'static str,
        check: &str,
        description: &str,
        reference: f64,
        value: f64,
        equal: bool,
    ) -> Check {
        Check {
            section,
            check: check.to_string(),
            description: description.to_string(),
            reference,
            value,
            tolerance: 0.0,
            tolerance_kind: "exact",
            samples: 0,
            passed: equal,
        }
    }

    /// Relative agreement: `|value - reference| ≤ tolerance × |reference|`.
    pub fn relative(
        section: &'static str,
        check: &str,
        description: &str,
        reference: f64,
        value: f64,
        tolerance: f64,
    ) -> Check {
        let passed = (value - reference).abs() <= tolerance * reference.abs();
        Check {
            section,
            check: check.to_string(),
            description: description.to_string(),
            reference,
            value,
            tolerance,
            tolerance_kind: "relative",
            samples: 0,
            passed,
        }
    }

    /// Absolute agreement: `|value - reference| ≤ tolerance`.
    pub fn absolute(
        section: &'static str,
        check: &str,
        description: &str,
        reference: f64,
        value: f64,
        tolerance: f64,
    ) -> Check {
        let passed = (value - reference).abs() <= tolerance;
        Check {
            section,
            check: check.to_string(),
            description: description.to_string(),
            reference,
            value,
            tolerance,
            tolerance_kind: "absolute",
            samples: 0,
            passed,
        }
    }

    /// A count of failing rows that must be zero, out of `rows` checked.
    pub fn all_rows(
        section: &'static str,
        check: &str,
        description: &str,
        failures: u64,
        rows: u64,
    ) -> Check {
        Check {
            section,
            check: check.to_string(),
            description: description.to_string(),
            reference: 0.0,
            value: failures as f64,
            tolerance: 0.0,
            tolerance_kind: "failing rows",
            samples: rows,
            passed: failures == 0,
        }
    }

    /// Monte Carlo agreement within `k` standard errors plus an explicit `allowance` for the
    /// known bias of a first-order formula.
    pub fn monte_carlo(
        section: &'static str,
        check: &str,
        description: &str,
        reference: f64,
        estimate: Estimate,
        k: f64,
        allowance: f64,
    ) -> Check {
        Check {
            section,
            check: check.to_string(),
            description: description.to_string(),
            reference,
            value: estimate.value,
            tolerance: k * estimate.standard_error + allowance,
            tolerance_kind: "absolute (k standard errors + stated allowance)",
            samples: estimate.samples,
            passed: estimate.agrees_with(reference, k, allowance),
        }
    }

    /// One-sided check: `value ≥ reference − tolerance`.
    pub fn at_least(
        section: &'static str,
        check: &str,
        description: &str,
        reference: f64,
        value: f64,
        tolerance: f64,
        samples: u64,
    ) -> Check {
        Check {
            section,
            check: check.to_string(),
            description: description.to_string(),
            reference,
            value,
            tolerance,
            tolerance_kind: "lower bound (value ≥ reference − tolerance)",
            samples,
            passed: value >= reference - tolerance,
        }
    }

    /// One-sided check: `value ≤ reference + tolerance`.
    pub fn at_most(
        section: &'static str,
        check: &str,
        description: &str,
        reference: f64,
        value: f64,
        tolerance: f64,
        samples: u64,
    ) -> Check {
        Check {
            section,
            check: check.to_string(),
            description: description.to_string(),
            reference,
            value,
            tolerance,
            tolerance_kind: "upper bound (value ≤ reference + tolerance)",
            samples,
            passed: value <= reference + tolerance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_check_passes_inside_and_fails_outside_the_tolerance() {
        assert!(Check::relative("A", "x", "", 100.0, 100.5, 0.01).passed);
        assert!(!Check::relative("A", "x", "", 100.0, 102.0, 0.01).passed);
    }

    #[test]
    fn monte_carlo_check_uses_standard_errors_and_allowance() {
        let estimate = Estimate {
            value: 10.4,
            standard_error: 0.1,
            samples: 100,
        };
        assert!(Check::monte_carlo("A", "x", "", 10.0, estimate, 5.0, 0.0).passed);
        assert!(!Check::monte_carlo("A", "x", "", 10.0, estimate, 3.0, 0.0).passed);
        assert!(Check::monte_carlo("A", "x", "", 10.0, estimate, 3.0, 0.2).passed);
    }

    #[test]
    fn row_count_check_requires_zero_failures() {
        assert!(Check::all_rows("A", "x", "", 0, 10).passed);
        assert!(!Check::all_rows("A", "x", "", 1, 10).passed);
    }

    #[test]
    fn upper_bound_check_is_one_sided() {
        assert!(Check::at_most("D", "x", "", 1.0, 0.5, 0.05, 10).passed);
        assert!(!Check::at_most("D", "x", "", 1.0, 1.2, 0.05, 10).passed);
        assert!(Check::at_least("A", "x", "", 1.0, 0.999_999_999_9, 1e-9, 0).passed);
        assert!(!Check::at_least("A", "x", "", 1.0, 0.9, 1e-9, 0).passed);
        assert!(Check::absolute("D", "x", "", 1.0, 1.04, 0.05).passed);
        assert!(Check::exact("D", "x", "", 1.0, 1.0, true).passed);
    }
}
