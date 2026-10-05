//! Section B — witness capture and stall probabilities (SPEC §2, §4.1–§4.2, §8 S15, §10 H6).
//!
//! An attacker controls a fraction `p` of registered IDs. Every registered ID sits in exactly
//! one WC, and seats are modelled as a uniformly random partition of IDs into WCs. A KWC is a
//! leader WC plus `s` subordinate WCs, so its seats are a uniformly random subset of all IDs.
//!
//! # States
//!
//! For registered miners the PoWit quorum is `k1` of the leader's `n1` seats **and** `k2` of
//! the subordinates' `n2` seats. For unregistered miners it is any `ku` of all `n1 + n2`
//! seats.
//!
//! - **(i) block** — the attacker holds enough seats to deny the quorum: `≥ n1 − k1 + 1` leader
//!   seats or `≥ n2 − k2 + 1` subordinate seats (registered), or `≥ n − ku + 1` seats
//!   (unregistered).
//! - **(ii) sign** — the attacker alone meets the quorum: `≥ k1` and `≥ k2` (registered), or
//!   `≥ ku` (unregistered).
//! - **(iii) all seats** — the attacker holds every seat (relevant to entropy grinding).
//!
//! # Seat models
//!
//! The **hypergeometric** model is exact for a network of `W` KWCs holding `M = 10·W` IDs of
//! which exactly `K = p·M` are the attacker's. The **binomial** model is its infinite-network
//! limit, with each seat the attacker's independently with probability `p`.
//!
//! # Network level
//!
//! The expected number of KWCs in a state is `W·q` exactly, by linearity of expectation.
//! KWCs share WCs, so they are not independent. Under the binomial model each state is an
//! increasing event in the attacker indicators, so by Harris' inequality the independence
//! value `1 − (1 − q)^W` is an **upper bound** on P(at least one). A KWC shares WCs with at
//! most `d = (1 + s)·s` others, so some `⌈W/(d + 1)⌉` KWCs share no WC. They are independent,
//! which gives the lower bound `1 − (1 − q)^⌈W/(d+1)⌉`.

use crate::dist::{ExactDistribution, JointDistribution, SeatModel};
use crate::error::{Result, ensure};
use crate::exact::{Q, decimal, integer, log10, scientific, to_f64};
use crate::logspace;
use crate::mc::{RunningStats, shuffle};
use crate::validation::Check;
use gb_config::Config;
use gb_runlog::rng_stream;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use serde::Serialize;

/// Which miners a quorum applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinerKind {
    /// Registered miners: leader-WC and subordinate quorums.
    Registered,
    /// Unregistered miners: one quorum over all KWC members.
    Unregistered,
}

impl MinerKind {
    /// Label used in tables.
    pub fn label(self) -> &'static str {
        match self {
            MinerKind::Registered => "registered",
            MinerKind::Unregistered => "unregistered",
        }
    }
}

/// KWC state an attacker can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KwcState {
    /// (i) Enough seats to deny the quorum.
    Block,
    /// (ii) Enough seats to meet the quorum without honest members.
    Sign,
    /// (iii) Every seat.
    AllSeats,
}

impl KwcState {
    /// Label used in tables.
    pub fn label(self) -> &'static str {
        match self {
            KwcState::Block => "(i) block",
            KwcState::Sign => "(ii) sign without honest members",
            KwcState::AllSeats => "(iii) all seats",
        }
    }
}

/// A KWC layout and its quorums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KwcSpec {
    /// Label, for example `40-node`.
    pub label: String,
    /// Seats per WC.
    pub wc_size: u64,
    /// Subordinate WCs per KWC.
    pub subordinate_wcs: u64,
    /// Registered quorum from the leader WC.
    pub leader_min: u64,
    /// Registered quorum from the subordinate WCs.
    pub subordinate_min: u64,
    /// Unregistered quorum over all seats.
    pub unregistered_min: u64,
}

impl KwcSpec {
    /// The 40-node layout (1 leader + 3 subordinate WCs) from the configuration.
    pub fn forty_node(config: &Config) -> KwcSpec {
        KwcSpec::from_config(config, 3)
    }

    /// The 30-node comparison layout (1 leader + 2 subordinate WCs).
    pub fn thirty_node(config: &Config) -> KwcSpec {
        KwcSpec::from_config(config, 2)
    }

    fn from_config(config: &Config, subordinate_wcs: u64) -> KwcSpec {
        let wc_size = u64::from(config.witness.wc_size.value);
        let q = &config.quorum;
        let (subordinate_min, unregistered_min) = if subordinate_wcs == 2 {
            (
                q.registered_subordinate_min_30_node.value,
                q.unregistered_total_min_30_node.value,
            )
        } else {
            (
                q.registered_subordinate_min.value,
                q.unregistered_total_min.value,
            )
        };
        KwcSpec {
            label: format!("{}-node", wc_size * (1 + subordinate_wcs)),
            wc_size,
            subordinate_wcs,
            leader_min: u64::from(q.registered_leader_min.value),
            subordinate_min: u64::from(subordinate_min),
            unregistered_min: u64::from(unregistered_min),
        }
    }

    /// Leader-WC seats, `n1`.
    pub fn leader_seats(&self) -> u64 {
        self.wc_size
    }

    /// Subordinate seats, `n2`.
    pub fn subordinate_seats(&self) -> u64 {
        self.wc_size * self.subordinate_wcs
    }

    /// All seats, `n1 + n2`.
    pub fn total_seats(&self) -> u64 {
        self.leader_seats() + self.subordinate_seats()
    }

    /// Other KWCs that share at least one WC with a given KWC, at most `(1 + s)·s`.
    pub fn overlap_degree(&self) -> u64 {
        (1 + self.subordinate_wcs) * self.subordinate_wcs
    }

    /// True when `leader` and `subordinate` attacker seats put the KWC in `state`.
    pub fn registered_state(&self, state: KwcState, leader: u64, subordinate: u64) -> bool {
        let (n1, n2) = (self.leader_seats(), self.subordinate_seats());
        match state {
            KwcState::Block => {
                leader > n1 - self.leader_min || subordinate > n2 - self.subordinate_min
            }
            KwcState::Sign => leader >= self.leader_min && subordinate >= self.subordinate_min,
            KwcState::AllSeats => leader == n1 && subordinate == n2,
        }
    }

    /// True when `seats` attacker seats put the KWC in `state` for unregistered miners.
    pub fn unregistered_state(&self, state: KwcState, seats: u64) -> bool {
        let n = self.total_seats();
        match state {
            KwcState::Block => seats > n - self.unregistered_min,
            KwcState::Sign => seats >= self.unregistered_min,
            KwcState::AllSeats => seats == n,
        }
    }
}

/// Attacker IDs in a population of `population` when the attacker holds `fraction` of them,
/// rounded to the nearest integer (exact for every value in the default grids).
pub fn attacker_ids(fraction: &Q, population: u64) -> u64 {
    let exact = fraction * integer(population);
    let twice_numerator: BigInt = exact.numer() * 2u8 + exact.denom();
    let twice_denominator: BigInt = exact.denom() * 2u8;
    twice_numerator
        .div_floor(&twice_denominator)
        .to_u64()
        .unwrap_or(0)
}

/// Exact probability that a KWC is in `state`, for the given miner kind and seat model.
pub fn state_probability(
    spec: &KwcSpec,
    kind: MinerKind,
    state: KwcState,
    model: &SeatModel,
) -> Result<Q> {
    ensure(
        spec.leader_min <= spec.leader_seats()
            && spec.subordinate_min <= spec.subordinate_seats()
            && spec.unregistered_min <= spec.total_seats()
            && spec.leader_min > 0
            && spec.subordinate_min > 0
            && spec.unregistered_min > 0,
        "quorums must lie between 1 and the number of seats",
    )?;
    Ok(match kind {
        MinerKind::Registered => {
            let joint =
                JointDistribution::new(spec.leader_seats(), spec.subordinate_seats(), model)?;
            joint.probability_where(|x, y| spec.registered_state(state, x, y))
        }
        MinerKind::Unregistered => {
            let single = ExactDistribution::new(spec.total_seats(), model)?;
            single.probability_where(|x| spec.unregistered_state(state, x))
        }
    })
}

/// Independent log-space computation of [`state_probability`], as `log10`.
pub fn state_log10_probability_logspace(
    spec: &KwcSpec,
    kind: MinerKind,
    state: KwcState,
    model: &SeatModel,
) -> f64 {
    let (n1, n2) = (spec.leader_seats(), spec.subordinate_seats());
    match (kind, model) {
        (MinerKind::Registered, SeatModel::Binomial(p)) => {
            let p = to_f64(p);
            let cell =
                |x, y| logspace::ln_binomial_pmf(n1, x, p) + logspace::ln_binomial_pmf(n2, y, p);
            logspace::log10_region(n1, n2, cell, |x, y| spec.registered_state(state, x, y))
        }
        (
            MinerKind::Registered,
            SeatModel::Hypergeometric {
                population,
                attackers,
            },
        ) => {
            let cell =
                |x, y| logspace::ln_joint_hypergeometric(*population, *attackers, n1, n2, x, y);
            logspace::log10_region(n1, n2, cell, |x, y| spec.registered_state(state, x, y))
        }
        (MinerKind::Unregistered, SeatModel::Binomial(p)) => {
            let p = to_f64(p);
            let terms: Vec<f64> = (0..=n1 + n2)
                .filter(|x| spec.unregistered_state(state, *x))
                .map(|x| logspace::ln_binomial_pmf(n1 + n2, x, p))
                .collect();
            logspace::log10_sum_exp(&terms)
        }
        (
            MinerKind::Unregistered,
            SeatModel::Hypergeometric {
                population,
                attackers,
            },
        ) => {
            let terms: Vec<f64> = (0..=n1 + n2)
                .filter(|x| spec.unregistered_state(state, *x))
                .map(|x| logspace::ln_hypergeometric_pmf(*population, *attackers, n1 + n2, x))
                .collect();
            logspace::log10_sum_exp(&terms)
        }
    }
}

/// Network-level summary for one per-KWC probability `q`.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkSummary {
    /// Expected number of KWCs in the state, `W·q` (exact).
    pub expected_count: Q,
    /// `1 − (1 − q)^W`: the independence value, an upper bound under the binomial model.
    pub at_least_one_independence: f64,
    /// `1 − (1 − q)^⌈W/(d+1)⌉`: a lower bound from KWCs that share no WC.
    pub at_least_one_lower_bound: f64,
}

/// Summarises `q` over a network of `kwcs` KWCs with the given overlap degree.
pub fn network_summary(q: &Q, kwcs: u64, overlap_degree: u64) -> NetworkSummary {
    let ln_miss = libm::log1p(-to_f64(q));
    let disjoint = kwcs.div_ceil(overlap_degree + 1);
    NetworkSummary {
        expected_count: q * integer(kwcs),
        at_least_one_independence: -libm::expm1(kwcs as f64 * ln_miss),
        at_least_one_lower_bound: -libm::expm1(disjoint as f64 * ln_miss),
    }
}

/// KWC compositions formed over a horizon under the SPEC §10 H6 refresh model.
///
/// Starts with `initial_kwcs`. Adds one new KWC per new WC (`R / wc_size` per year), and
/// `(1 + s)` compositions per ban replacement, because a replaced member's WC sits in
/// `1 + s` KWCs. Bans occur at `ban_rate` of registered IDs per year, and registered IDs
/// grow from `wc_size·W0` at `R` per year.
pub fn composition_count(
    initial_kwcs: u64,
    horizon_years: f64,
    issuance_per_year: f64,
    wc_size: u64,
    subordinate_wcs: u64,
    ban_rate: f64,
) -> f64 {
    let w0 = initial_kwcs as f64;
    let new_kwcs = horizon_years * issuance_per_year / wc_size as f64;
    let id_years = wc_size as f64 * w0 * horizon_years
        + issuance_per_year * horizon_years * horizon_years / 2.0;
    let replacements = (1 + subordinate_wcs) as f64 * ban_rate * id_years;
    w0 + new_kwcs + replacements
}

/// KWC membership for a Golomb-ruler ring: KWC `w` is led by WC `w` and has subordinate WCs
/// `(w + offset) mod W` (the allocation proposal in `docs/ARCHITECTURE.md`).
pub fn golomb_ring(wcs: u64, offsets: &[u64]) -> Vec<Vec<u64>> {
    (0..wcs)
        .map(|w| {
            std::iter::once(w)
                .chain(offsets.iter().map(|o| (w + o) % wcs))
                .collect()
        })
        .collect()
}

/// Violations of the ring requirements: each WC leads one KWC and is a subordinate in exactly
/// `offsets.len()` KWCs, no two WCs monitor each other, and any two KWCs share at most one WC.
pub fn ring_violations(ring: &[Vec<u64>]) -> u64 {
    let wcs = ring.len();
    let subordinate_count = ring.first().map(|k| k.len() - 1).unwrap_or(0);
    let mut violations = 0;
    let mut roles = vec![0usize; wcs];
    let mut monitors = std::collections::BTreeSet::new();
    for kwc in ring {
        for &member in &kwc[1..] {
            roles[member as usize] += 1;
            monitors.insert((member, kwc[0]));
        }
        let mut members = kwc.clone();
        members.sort_unstable();
        members.dedup();
        violations += u64::from(members.len() != kwc.len());
    }
    violations += roles.iter().filter(|r| **r != subordinate_count).count() as u64;
    violations += monitors
        .iter()
        .filter(|(a, b)| monitors.contains(&(*b, *a)))
        .count() as u64;
    for (i, a) in ring.iter().enumerate() {
        for b in &ring[i + 1..] {
            let shared = a.iter().filter(|x| b.contains(x)).count();
            violations += u64::from(shared > 1);
        }
    }
    violations
}

// ----------------------------------------------------------------------------- tables

/// B1: per-KWC probability.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KwcRow {
    /// Layout, for example `40-node`.
    pub layout: String,
    /// Miner kind.
    pub miner_kind: &'static str,
    /// State.
    pub state: &'static str,
    /// Attacker fraction p of registered IDs.
    pub attacker_fraction: f64,
    /// "binomial" or "hypergeometric".
    pub model: &'static str,
    /// Network size in KWCs (hypergeometric only).
    pub kwcs: Option<u64>,
    /// Attacker IDs in the network (hypergeometric only).
    pub attacker_ids: Option<u64>,
    /// Exact probability in scientific notation.
    pub probability: String,
    /// `log10` of the probability.
    pub log10_probability: f64,
    /// Independent KWC compositions at which one KWC is expected in this state, `1/q`.
    pub compositions_for_one_expected: String,
}

/// B2: network-level counts (hypergeometric at each size).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NetworkRow {
    /// Layout.
    pub layout: String,
    /// Miner kind.
    pub miner_kind: &'static str,
    /// State.
    pub state: &'static str,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// Network size in KWCs.
    pub kwcs: u64,
    /// Expected KWCs in the state, `W·q`.
    pub expected_kwcs: String,
    /// `1 − (1 − q)^W` (upper bound under the binomial model).
    pub p_at_least_one_independence: f64,
    /// Lower bound from KWCs that share no WC.
    pub p_at_least_one_lower_bound: f64,
}

/// B3: binomial vs hypergeometric.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ComparisonRow {
    /// Layout.
    pub layout: String,
    /// Miner kind.
    pub miner_kind: &'static str,
    /// State.
    pub state: &'static str,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// Network size in KWCs.
    pub kwcs: u64,
    /// Binomial probability.
    pub binomial: String,
    /// Hypergeometric probability.
    pub hypergeometric: String,
    /// Absolute difference, hypergeometric − binomial.
    pub absolute_difference: String,
    /// Relative difference, hypergeometric / binomial − 1.
    pub relative_difference: f64,
}

/// B4: expected sign-capable KWC compositions over the horizon (SPEC §10 H6 refresh model).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompositionRow {
    /// Miner kind whose quorum is used.
    pub miner_kind: &'static str,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// KWCs at the start.
    pub initial_kwcs: u64,
    /// Ban replacements per year as a fraction of registered IDs (sensitivity).
    pub ban_replacement_rate_per_year: f64,
    /// Horizon in years.
    pub horizon_years: f64,
    /// KWC compositions formed over the horizon, each counted as an independent draw.
    pub compositions: f64,
    /// Per-composition probability of (ii), binomial model.
    pub sign_probability: String,
    /// Expected sign-capable compositions over the horizon.
    pub expected_sign_capable: f64,
}

/// All section B tables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SectionB {
    /// B1.
    pub kwc: Vec<KwcRow>,
    /// B2.
    pub network: Vec<NetworkRow>,
    /// B3.
    pub comparison: Vec<ComparisonRow>,
    /// B4.
    pub compositions: Vec<CompositionRow>,
}

const KINDS: [MinerKind; 2] = [MinerKind::Registered, MinerKind::Unregistered];
const STATES: [KwcState; 3] = [KwcState::Block, KwcState::Sign, KwcState::AllSeats];

/// Builds every section B table from the configuration.
pub fn section_b(config: &Config) -> Result<SectionB> {
    let grid = &config.analytic.witness;
    let mut tables = SectionB::default();
    for spec in [KwcSpec::forty_node(config), KwcSpec::thirty_node(config)] {
        for p_f in &grid.attacker_fractions {
            let p = decimal(*p_f)?;
            for kind in KINDS {
                for state in STATES {
                    let binomial =
                        state_probability(&spec, kind, state, &SeatModel::Binomial(p.clone()))?;
                    tables.kwc.push(kwc_row(
                        &spec, kind, state, *p_f, "binomial", None, None, &binomial,
                    ));
                    for &kwcs in &grid.kwc_counts {
                        let population = spec.wc_size * kwcs;
                        let attackers = attacker_ids(&p, population);
                        let model = SeatModel::Hypergeometric {
                            population,
                            attackers,
                        };
                        let q = state_probability(&spec, kind, state, &model)?;
                        tables.kwc.push(kwc_row(
                            &spec,
                            kind,
                            state,
                            *p_f,
                            "hypergeometric",
                            Some(kwcs),
                            Some(attackers),
                            &q,
                        ));
                        tables
                            .network
                            .push(network_row(&spec, kind, state, *p_f, kwcs, &q));
                        tables.comparison.push(comparison_row(
                            &spec, kind, state, *p_f, kwcs, &binomial, &q,
                        ));
                    }
                }
            }
        }
    }
    tables.compositions = composition_rows(config)?;
    Ok(tables)
}

#[allow(clippy::too_many_arguments)]
fn kwc_row(
    spec: &KwcSpec,
    kind: MinerKind,
    state: KwcState,
    p: f64,
    model: &'static str,
    kwcs: Option<u64>,
    attackers: Option<u64>,
    q: &Q,
) -> KwcRow {
    KwcRow {
        layout: spec.label.clone(),
        miner_kind: kind.label(),
        state: state.label(),
        attacker_fraction: p,
        model,
        kwcs,
        attacker_ids: attackers,
        probability: scientific(q, 6),
        log10_probability: log10(q).unwrap_or(f64::NEG_INFINITY),
        compositions_for_one_expected: if q.is_zero() {
            "never".to_string()
        } else {
            scientific(&q.recip(), 4)
        },
    }
}

fn network_row(
    spec: &KwcSpec,
    kind: MinerKind,
    state: KwcState,
    p: f64,
    kwcs: u64,
    q: &Q,
) -> NetworkRow {
    let summary = network_summary(q, kwcs, spec.overlap_degree());
    NetworkRow {
        layout: spec.label.clone(),
        miner_kind: kind.label(),
        state: state.label(),
        attacker_fraction: p,
        kwcs,
        expected_kwcs: scientific(&summary.expected_count, 6),
        p_at_least_one_independence: summary.at_least_one_independence,
        p_at_least_one_lower_bound: summary.at_least_one_lower_bound,
    }
}

fn comparison_row(
    spec: &KwcSpec,
    kind: MinerKind,
    state: KwcState,
    p: f64,
    kwcs: u64,
    binomial: &Q,
    hypergeometric: &Q,
) -> ComparisonRow {
    let relative = if binomial.is_zero() {
        0.0
    } else {
        to_f64(&(hypergeometric / binomial - Q::one()))
    };
    ComparisonRow {
        layout: spec.label.clone(),
        miner_kind: kind.label(),
        state: state.label(),
        attacker_fraction: p,
        kwcs,
        binomial: scientific(binomial, 6),
        hypergeometric: scientific(hypergeometric, 6),
        absolute_difference: scientific(&(hypergeometric - binomial), 4),
        relative_difference: relative,
    }
}

fn composition_rows(config: &Config) -> Result<Vec<CompositionRow>> {
    let grid = &config.analytic.witness;
    let spec = KwcSpec::forty_node(config);
    let issuance = config.issuance_per_year();
    let mut rows = Vec::new();
    for kind in KINDS {
        for p_f in &grid.attacker_fractions {
            let q = state_probability(
                &spec,
                kind,
                KwcState::Sign,
                &SeatModel::Binomial(decimal(*p_f)?),
            )?;
            for &w0 in &grid.composition_initial_kwc_counts {
                for &ban in &grid.ban_replacement_rates_per_year {
                    let compositions = composition_count(
                        w0,
                        grid.composition_horizon_years,
                        issuance,
                        spec.wc_size,
                        spec.subordinate_wcs,
                        ban,
                    );
                    rows.push(CompositionRow {
                        miner_kind: kind.label(),
                        attacker_fraction: *p_f,
                        initial_kwcs: w0,
                        ban_replacement_rate_per_year: ban,
                        horizon_years: grid.composition_horizon_years,
                        compositions,
                        sign_probability: scientific(&q, 6),
                        expected_sign_capable: compositions * to_f64(&q),
                    });
                }
            }
        }
    }
    Ok(rows)
}

// ----------------------------------------------------------------------------- checks

/// Section B cross-checks.
pub fn checks(config: &Config, tables: &SectionB) -> Result<Vec<Check>> {
    let mut checks = vec![
        log_space_check(config)?,
        invariant_check(tables),
        convergence_check(tables),
        ring_check(),
        dynamic_programming_check(config)?,
    ];
    checks.extend(partition_monte_carlo_checks(config)?);
    Ok(checks)
}

fn log_space_check(config: &Config) -> Result<Check> {
    let grid = &config.analytic.witness;
    let mut failures = 0;
    let mut rows = 0;
    for spec in [KwcSpec::forty_node(config), KwcSpec::thirty_node(config)] {
        for p_f in &grid.attacker_fractions {
            let p = decimal(*p_f)?;
            let mut models = vec![SeatModel::Binomial(p.clone())];
            for &kwcs in &grid.kwc_counts {
                let population = spec.wc_size * kwcs;
                models.push(SeatModel::Hypergeometric {
                    population,
                    attackers: attacker_ids(&p, population),
                });
            }
            for model in &models {
                for kind in KINDS {
                    for state in STATES {
                        rows += 1;
                        let exact = state_probability(&spec, kind, state, model)?;
                        let reference = state_log10_probability_logspace(&spec, kind, state, model);
                        let value = log10(&exact).unwrap_or(f64::NEG_INFINITY);
                        if (value - reference).abs() > 1e-9 {
                            failures += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(Check::all_rows(
        "B",
        "B-log-space",
        "exact rational probabilities agree with an independent log-space f64 computation within 1e-9 in log10",
        failures,
        rows,
    ))
}

fn invariant_check(tables: &SectionB) -> Check {
    let mut failures = 0;
    let mut rows = 0;
    let key = |r: &KwcRow| {
        (
            r.layout.clone(),
            r.miner_kind,
            r.model,
            r.kwcs,
            r.attacker_fraction,
        )
    };
    for row in tables
        .kwc
        .iter()
        .filter(|r| r.state == KwcState::Sign.label())
    {
        rows += 1;
        let block = tables
            .kwc
            .iter()
            .find(|b| b.state == KwcState::Block.label() && key(b) == key(row));
        if block.is_none_or(|b| b.log10_probability < row.log10_probability) {
            failures += 1;
        }
    }
    let mut series = std::collections::BTreeMap::new();
    for row in &tables.kwc {
        series
            .entry((
                row.layout.clone(),
                row.miner_kind,
                row.state,
                row.model,
                row.kwcs,
            ))
            .or_insert_with(Vec::new)
            .push((row.attacker_fraction, row.log10_probability));
    }
    for values in series.values() {
        rows += 1;
        if values
            .windows(2)
            .any(|w| w[1].0 > w[0].0 && w[1].1 < w[0].1)
        {
            failures += 1;
        }
    }
    Check::all_rows(
        "B",
        "B-invariants",
        "P(sign) <= P(block) in every row, and every probability rises with the attacker fraction",
        failures,
        rows,
    )
}

fn convergence_check(tables: &SectionB) -> Check {
    let mut series = std::collections::BTreeMap::new();
    for row in &tables.comparison {
        series
            .entry((
                row.layout.clone(),
                row.miner_kind,
                row.state,
                row.attacker_fraction.to_bits(),
            ))
            .or_insert_with(Vec::new)
            .push((row.kwcs, row.relative_difference.abs()));
    }
    let failures = series
        .values()
        .filter(|values| {
            let mut sorted = (*values).clone();
            sorted.sort_by_key(|(kwcs, _)| *kwcs);
            sorted.windows(2).any(|w| w[1].1 > w[0].1)
        })
        .count() as u64;
    Check::all_rows(
        "B",
        "B-hypergeometric-converges",
        "the relative gap between hypergeometric and binomial shrinks as the network grows",
        failures,
        series.len() as u64,
    )
}

fn ring_check() -> Check {
    let mut violations = 0;
    let mut layouts = 0;
    for wcs in [13_u64, 14, 20, 50, 200] {
        layouts += 2;
        violations += ring_violations(&golomb_ring(wcs, &[1, 4, 6]));
        violations += ring_violations(&golomb_ring(wcs.max(7), &[1, 3]));
    }
    Check::all_rows(
        "B",
        "B-golomb-ring",
        "proposed ring: each WC leads one KWC, is subordinate in exactly s, no mutual pairs, KWCs share at most one WC",
        violations,
        layouts,
    )
}

fn dynamic_programming_check(config: &Config) -> Result<Check> {
    let spec = KwcSpec::forty_node(config);
    let (population, attackers) = (400, 132);
    let model = SeatModel::Hypergeometric {
        population,
        attackers,
    };
    let joint = crate::dist::joint_hypergeometric_by_sequential_draws(
        population,
        attackers,
        spec.leader_seats(),
        spec.subordinate_seats(),
    );
    let mut failures = 0;
    for state in STATES {
        let closed = state_probability(&spec, MinerKind::Registered, state, &model)?;
        let mut by_draws = Q::zero();
        for (x, row) in joint.iter().enumerate() {
            for (y, value) in row.iter().enumerate() {
                if spec.registered_state(state, x as u64, y as u64) {
                    by_draws += value;
                }
            }
        }
        failures += u64::from(closed != by_draws);
    }
    Ok(Check::all_rows(
        "B",
        "B-sequential-draws",
        "closed-form joint hypergeometric equals sequential draws exactly (M=400, K=132, 40-node registered)",
        failures,
        STATES.len() as u64,
    ))
}

/// Per-replicate fractions of KWCs in each (kind, state) pair over random partitions.
fn partition_frequencies(
    seed: u64,
    spec: &KwcSpec,
    wcs: u64,
    attackers: u64,
    replicates: u64,
    cases: &[(MinerKind, KwcState)],
) -> Vec<RunningStats> {
    let offsets: Vec<u64> = if spec.subordinate_wcs == 3 {
        vec![1, 4, 6]
    } else {
        vec![1, 3]
    };
    let ring = golomb_ring(wcs, &offsets);
    let population = (spec.wc_size * wcs) as usize;
    let mut ids: Vec<bool> = (0..population).map(|i| (i as u64) < attackers).collect();
    let mut rng = rng_stream(seed, &format!("B-partition-{}-{attackers}", spec.label));
    let mut stats = vec![RunningStats::default(); cases.len()];
    for _ in 0..replicates {
        shuffle(&mut rng, &mut ids);
        let counts: Vec<u64> = ids
            .chunks(spec.wc_size as usize)
            .map(|wc| wc.iter().filter(|a| **a).count() as u64)
            .collect();
        let mut hits = vec![0u64; cases.len()];
        for kwc in &ring {
            let leader = counts[kwc[0] as usize];
            let subordinate: u64 = kwc[1..].iter().map(|w| counts[*w as usize]).sum();
            for (i, (kind, state)) in cases.iter().enumerate() {
                let hit = match kind {
                    MinerKind::Registered => spec.registered_state(*state, leader, subordinate),
                    MinerKind::Unregistered => {
                        spec.unregistered_state(*state, leader + subordinate)
                    }
                };
                hits[i] += u64::from(hit);
            }
        }
        for (i, stat) in stats.iter_mut().enumerate() {
            stat.push(hits[i] as f64 / wcs as f64);
        }
    }
    stats
}

fn partition_monte_carlo_checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let spec = KwcSpec::forty_node(config);
    let population = spec.wc_size * mc.partition_wcs;
    let mut checks = Vec::new();
    let cases = [
        (MinerKind::Registered, KwcState::Block),
        (MinerKind::Registered, KwcState::Sign),
        (MinerKind::Unregistered, KwcState::Block),
        (MinerKind::Unregistered, KwcState::Sign),
    ];
    for p_f in [0.3, 0.4] {
        let p = decimal(p_f)?;
        let attackers = attacker_ids(&p, population);
        let stats = partition_frequencies(
            config.run.seed,
            &spec,
            mc.partition_wcs,
            attackers,
            mc.partition_replicates,
            &cases,
        );
        let model = SeatModel::Hypergeometric {
            population,
            attackers,
        };
        for ((kind, state), stat) in cases.iter().zip(&stats) {
            let exact = to_f64(&state_probability(&spec, *kind, *state, &model)?);
            if exact * (population as f64) < 1.0 {
                continue; // too rare to check with this sample size
            }
            checks.push(Check::monte_carlo(
                "B",
                &format!("B-mc-partition-{}-{}-p{p_f}", kind.label(), state_name(*state)),
                &format!(
                    "random partitions of {population} IDs into WCs on the proposed ring: fraction of KWCs in {} ({}) vs exact hypergeometric",
                    state.label(),
                    kind.label()
                ),
                exact,
                stat.estimate(),
                mc.tolerance_standard_errors,
                0.0,
            ));
        }
    }
    Ok(checks)
}

fn state_name(state: KwcState) -> &'static str {
    match state {
        KwcState::Block => "block",
        KwcState::Sign => "sign",
        KwcState::AllSeats => "all",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exact::ratio;

    fn spec() -> KwcSpec {
        KwcSpec::forty_node(&Config::default())
    }

    #[test]
    fn forty_node_layout_has_the_spec_quorums_and_block_thresholds() {
        let s = spec();
        assert_eq!(
            (s.leader_seats(), s.subordinate_seats(), s.total_seats()),
            (10, 30, 40)
        );
        assert!(s.registered_state(KwcState::Block, 4, 0));
        assert!(!s.registered_state(KwcState::Block, 3, 9));
        assert!(s.registered_state(KwcState::Block, 0, 10));
        assert!(s.unregistered_state(KwcState::Block, 14));
        assert!(!s.unregistered_state(KwcState::Block, 13));
        assert!(s.registered_state(KwcState::Sign, 7, 21));
        assert!(!s.registered_state(KwcState::Sign, 6, 30));
        assert_eq!(s.overlap_degree(), 12);
    }

    #[test]
    fn thirty_node_layout_uses_its_own_quorums() {
        let s = KwcSpec::thirty_node(&Config::default());
        assert_eq!((s.subordinate_min, s.unregistered_min), (14, 20));
        assert!(s.registered_state(KwcState::Block, 0, 7));
        assert!(s.unregistered_state(KwcState::Block, 11));
        assert_eq!(s.overlap_degree(), 6);
    }

    #[test]
    fn binomial_sign_probability_is_the_product_of_the_two_tails() {
        // Reference: P(Bin(10,p) >= 7) × P(Bin(30,p) >= 21), from separate distributions.
        let p = ratio(1, 4);
        let model = SeatModel::Binomial(p.clone());
        let leader = ExactDistribution::new(10, &model).unwrap().at_least(7);
        let subs = ExactDistribution::new(30, &model).unwrap().at_least(21);
        let q = state_probability(&spec(), MinerKind::Registered, KwcState::Sign, &model).unwrap();
        assert_eq!(q, leader * subs);
        assert!((to_f64(&q) - 9.880_222_4e-10).abs() < 1e-15);
    }

    #[test]
    fn all_seats_is_p_to_the_fortieth_for_both_miner_kinds() {
        let p = ratio(1, 20);
        let model = SeatModel::Binomial(p.clone());
        let expected = num_traits::pow(p, 40);
        for kind in KINDS {
            let q = state_probability(&spec(), kind, KwcState::AllSeats, &model).unwrap();
            assert_eq!(q, expected);
        }
    }

    #[test]
    fn attacker_ids_round_to_the_nearest_integer() {
        assert_eq!(attacker_ids(&ratio(33, 100), 100_000), 33_000);
        assert_eq!(attacker_ids(&ratio(1, 3), 10), 3);
        assert_eq!(attacker_ids(&ratio(1, 2), 3), 2);
    }

    #[test]
    fn network_summary_brackets_the_independence_value() {
        let q = ratio(1, 1_000_000);
        let summary = network_summary(&q, 100_000, 12);
        assert_eq!(summary.expected_count, ratio(1, 10));
        assert!(summary.at_least_one_lower_bound < summary.at_least_one_independence);
        assert!((summary.at_least_one_independence - (1.0 - (-0.1f64).exp())).abs() < 1e-6);
    }

    #[test]
    fn composition_count_without_bans_adds_one_kwc_per_ten_new_ids() {
        let count = composition_count(100_000, 10.0, 1_051_200.0, 10, 3, 0.0);
        assert!((count - (100_000.0 + 1_051_200.0)).abs() < 1e-6);
        let with_bans = composition_count(100_000, 10.0, 1_051_200.0, 10, 3, 0.01);
        assert!(with_bans > count);
    }

    #[test]
    fn golomb_rings_meet_every_requirement() {
        assert_eq!(ring_violations(&golomb_ring(13, &[1, 4, 6])), 0);
        assert_eq!(ring_violations(&golomb_ring(1_000, &[1, 4, 6])), 0);
        assert_eq!(ring_violations(&golomb_ring(7, &[1, 3])), 0);
    }

    #[test]
    fn consecutive_offsets_violate_the_one_shared_wc_rule() {
        assert!(ring_violations(&golomb_ring(20, &[1, 2, 3])) > 0);
    }

    #[test]
    fn hypergeometric_is_below_binomial_for_rare_sign_events() {
        let p = ratio(5, 100);
        let binomial = state_probability(
            &spec(),
            MinerKind::Registered,
            KwcState::Sign,
            &SeatModel::Binomial(p.clone()),
        )
        .unwrap();
        let model = SeatModel::Hypergeometric {
            population: 100_000,
            attackers: 5_000,
        };
        let hyper =
            state_probability(&spec(), MinerKind::Registered, KwcState::Sign, &model).unwrap();
        assert!(hyper < binomial);
    }

    #[test]
    fn invalid_quorums_are_rejected() {
        let mut bad = spec();
        bad.leader_min = 11;
        assert!(
            state_probability(
                &bad,
                MinerKind::Registered,
                KwcState::Sign,
                &SeatModel::Binomial(ratio(1, 2))
            )
            .is_err()
        );
    }

    #[test]
    fn section_b_tables_cover_both_layouts_and_all_states() {
        let config = Config::default();
        let b = section_b(&config).unwrap();
        let fractions = config.analytic.witness.attacker_fractions.len();
        let sizes = config.analytic.witness.kwc_counts.len();
        assert_eq!(b.kwc.len(), 2 * fractions * 2 * 3 * (1 + sizes));
        assert_eq!(b.network.len(), 2 * fractions * 2 * 3 * sizes);
        assert!(!b.compositions.is_empty());
    }

    #[test]
    fn all_section_b_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.partition_replicates = 600;
        let tables = section_b(&config).unwrap();
        for check in checks(&config, &tables).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
