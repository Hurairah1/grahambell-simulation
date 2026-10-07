//! M1 analytical baseline for GrahamBell Stage 1.
//!
//! Exact closed forms and exact probabilities that the later simulators must reproduce before
//! they are trusted (SPEC §11.3). Each section module builds its tables from a
//! [`gb_config::Config`] and provides independent cross-checks.
//!
//! | Section | Module | SPEC |
//! |---|---|---|
//! | A — time for an attacker to reach 33/51/67% of active IDs; adaptive cap | [`time_threshold`] | §0 C2, §3.9, §10 H2 |
//! | B — witness capture and stall probabilities | [`witness`] | §4, §8 S15, §10 H6 |
//! | C — Chain Allocation Committee stalling and capture | [`cac`] | §4.3, §8 S21 |
//! | D — restart attack, old vs per-round entropy | [`restart`] | §3.4, §8 S5, §10 H4 |
//! | E — difficulty hopping | [`hopping`] | §3.8, §8 S6, §10 H5 |
//! | F — same-step ties between PoW-ID blocks | [`ties`] | §3.5, §3.7 |
//! | G — quorum trade-off: stall, sign alone, conflicting approvals | [`quorum_tradeoff`] | §2, §3.7, §4.2–§4.6 |
//! | H — quorum feasibility under honest downtime | [`quorum_feasibility`] | §2, §3.2, §4.5–§4.7 |
//! | I — KWC size trade-off: security, liveness, load | [`kwc_size`] | §2, §4.1–§4.2, §12 |
//!
//! Supporting modules:
//!
//! - [`allocation`]: the adopted allocation's composition and episode counts, and the
//!   illustrative absence model, shared by sections B, G and I;
//! - [`exact`] and [`dist`]: exact rational arithmetic and distributions;
//! - [`logspace`]: an independent floating-point implementation used as a cross-check;
//! - [`mc`]: seeded Monte Carlo helpers;
//! - [`validation`]: the record every cross-check produces.
//!
//! This crate performs no I/O; `gb-cli` writes the tables, charts and summary.

pub mod allocation;
pub mod cac;
pub mod dist;
pub mod error;
pub mod exact;
pub mod hopping;
pub mod kwc_size;
pub mod logspace;
pub mod mc;
pub mod quorum_feasibility;
pub mod quorum_tradeoff;
pub mod restart;
pub mod ties;
pub mod time_threshold;
pub mod validation;
pub mod witness;

pub use error::{AnalyticError, Result};

use gb_config::Config;
use validation::Check;

/// Every M1 table and cross-check.
#[derive(Debug, Clone, PartialEq)]
pub struct M1Results {
    /// Section A tables.
    pub a: time_threshold::SectionA,
    /// Section B tables.
    pub b: witness::SectionB,
    /// Section C tables.
    pub c: cac::SectionC,
    /// Section D table.
    pub d: Vec<restart::RestartRow>,
    /// Section D advantage curve.
    pub d_curve: Vec<restart::CurveRow>,
    /// Section E table.
    pub e: Vec<hopping::HopRow>,
    /// Section F table.
    pub f: Vec<ties::TieRow>,
    /// Section G tables.
    pub g: quorum_tradeoff::SectionG,
    /// Section H tables.
    pub h: quorum_feasibility::SectionH,
    /// Section I tables.
    pub i: kwc_size::SectionI,
    /// All cross-checks, in section order.
    pub checks: Vec<Check>,
}

impl M1Results {
    /// True when every cross-check passed.
    pub fn all_checks_passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }
}

/// Builds every M1 table and runs every cross-check.
pub fn run(config: &Config) -> Result<M1Results> {
    let a = time_threshold::section_a(config)?;
    let b = witness::section_b(config)?;
    let c = cac::section_c(config)?;
    let d = restart::section_d(config)?;
    let d_curve = restart::advantage_curve(config)?;
    let e = hopping::section_e(config)?;
    let f = ties::section_f(config)?;
    let g = quorum_tradeoff::section_g(config)?;
    let h = quorum_feasibility::section_h(config)?;
    let i = kwc_size::section_i(config)?;
    let mut checks = time_threshold::checks(config)?;
    checks.extend(witness::checks(config, &b)?);
    checks.extend(cac::checks(config)?);
    checks.extend(restart::checks(config)?);
    checks.extend(hopping::checks(config)?);
    checks.extend(ties::checks(config)?);
    checks.extend(quorum_tradeoff::checks(config, &g, &b, &c)?);
    checks.extend(quorum_feasibility::checks(config, &h)?);
    checks.extend(kwc_size::checks(config, &i, &g, &h)?);
    Ok(M1Results {
        a,
        b,
        c,
        d,
        d_curve,
        e,
        f,
        g,
        h,
        i,
        checks,
    })
}
