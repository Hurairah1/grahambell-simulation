//! The adopted allocation (SPEC §4.2): how KWC compositions change, and how often a KWC enters
//! a state, as IDs are inserted and removed.
//!
//! # Events
//!
//! Seats change only on **insertions** (a new ID, or an ID returning after its seat was
//! vacated) and **removals** (a ban, or, under SPEC v0.4, a continuous absence longer than the
//! long-absence threshold L). Under the v0.3 rule every absence that deactivated an ID vacated
//! its seat; it is kept as a comparison.
//!
//! - An insertion changes one member of an existing WC, and so the composition of the `r` KWCs
//!   that WC sits in (`r = 1 +` the number of ring offsets). One insertion in `wc_size`
//!   completes a WC: its own KWC forms, and the KWCs whose ring offsets wrap around relink.
//! - A removal changes one member of a WC and, one time in `wc_size`, dissolves the last WC,
//!   which relinks the KWCs whose offsets wrap.
//!
//! The **relink profile** records, for a ring that grows (or shrinks) by one WC, how many KWCs
//! have exactly `j` of their subordinate WCs replaced. It is computed from the ring offsets.
//!
//! # Compositions and episodes
//!
//! Counting every changed composition as an independent draw gives the SPEC §10 H6 refresh
//! count, an upper bound on distinct episodes. The **episode count** (the primary measure since
//! SPEC v0.4) adds, for every change, the probability that the KWC enters the state at that
//! change: P(before ∉ S, after ∈ S). Seats are modelled as independent draws with attacker
//! probability `p` (the binomial model), and replaced WCs as independent fresh draws.
//!
//! # Absences
//!
//! Absence durations follow an illustrative model until M3 supplies household profiles:
//! Lomax, P(D > x) = (1 + x/σ)^(−α), as the primary model, and an exponential as a comparison.

use crate::dist::{ExactDistribution, SeatModel};
use crate::error::{Result, ensure};
use crate::exact::{Q, to_f64};
use crate::witness::golomb_ring;
use gb_config::Config;
use std::collections::BTreeSet;

/// Seconds in a day.
const DAY_S: f64 = 86_400.0;

/// The configured absence-duration models: the primary Lomax model, then the exponential
/// comparison.
pub fn absence_models(config: &Config) -> Vec<AbsenceDurations> {
    let g = &config.analytic.absence;
    vec![
        AbsenceDurations::Lomax {
            scale_days: g.duration_scale_days,
            shape: g.duration_shape,
        },
        AbsenceDurations::Exponential {
            mean_days: g.comparison_exponential_mean_days,
        },
    ]
}

/// Long-absence thresholds L to report, in days: the parameter's sweep, or its value.
pub fn long_absence_days(config: &Config) -> Vec<f64> {
    let param = &config.offline.long_absence_threshold_s;
    let seconds = param
        .sweep
        .as_ref()
        .map(|s| s.values.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![param.value]);
    seconds.iter().map(|s| s / DAY_S).collect()
}

/// The seat rules to compare: v0.3, then v0.4 at every configured threshold L.
pub fn seat_rules(config: &Config) -> Vec<SeatRule> {
    std::iter::once(SeatRule::V03)
        .chain(
            long_absence_days(config)
                .into_iter()
                .map(|days| SeatRule::V04 {
                    long_absence_days: days,
                }),
        )
        .collect()
}

/// PoW-ID blocks in `days` at the configured target interval.
pub fn days_in_blocks(config: &Config, days: f64) -> f64 {
    days * DAY_S / config.issuance.pow_id_target_interval_s.value
}

/// How a ring changes when it grows or shrinks by one WC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelinkProfile {
    /// Growth: `(j, count)`: `count` existing KWCs get `j` new subordinate WCs (one new KWC also
    /// forms).
    pub growth: Vec<(u64, u64)>,
    /// Shrink: `(j, count)`: `count` remaining KWCs get `j` new subordinate WCs (the last
    /// KWC disappears).
    pub shrink: Vec<(u64, u64)>,
}

impl RelinkProfile {
    /// KWCs relinked when the ring grows by one WC.
    pub fn growth_relinks(&self) -> u64 {
        self.growth.iter().map(|(_, c)| c).sum()
    }

    /// KWCs relinked when the ring shrinks by one WC.
    pub fn shrink_relinks(&self) -> u64 {
        self.shrink.iter().map(|(_, c)| c).sum()
    }
}

fn profile_between(before: &[Vec<u64>], after: &[Vec<u64>]) -> Vec<(u64, u64)> {
    let mut counts = std::collections::BTreeMap::new();
    for (old, new) in before.iter().zip(after) {
        let old_subs: BTreeSet<u64> = old[1..].iter().copied().collect();
        let replaced = new[1..].iter().filter(|w| !old_subs.contains(w)).count() as u64;
        if replaced > 0 {
            *counts.entry(replaced).or_insert(0u64) += 1;
        }
    }
    counts.into_iter().collect()
}

/// Relink profile of the ring with the given subordinate offsets.
///
/// Compares the ring on `W` WCs with the rings on `W + 1` and `W − 1` WCs, KWC by KWC, for a `W`
/// large enough that no offset wraps twice.
pub fn relink_profile(offsets: &[u64]) -> RelinkProfile {
    let largest = offsets.iter().copied().max().unwrap_or(0);
    let wcs = 4 * largest + 13;
    let ring = golomb_ring(wcs, offsets);
    let grown = golomb_ring(wcs + 1, offsets);
    let shrunk = golomb_ring(wcs - 1, offsets);
    RelinkProfile {
        growth: profile_between(&ring, &grown),
        shrink: profile_between(&ring[..shrunk.len()], &shrunk),
    }
}

/// Compositions formed per insertion and per removal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompositionRates {
    /// KWCs each WC sits in, `r`.
    pub roles: u64,
    /// Seats per WC.
    pub wc_size: u64,
    /// Compositions per insertion: `r + (1 + growth relinks)/wc_size`.
    pub per_insertion: f64,
    /// Compositions per removal: `r + shrink relinks/wc_size`.
    pub per_removal: f64,
}

impl CompositionRates {
    /// Rates for WCs of `wc_size` seats on the ring with `offsets`.
    pub fn new(wc_size: u64, offsets: &[u64], profile: &RelinkProfile) -> Self {
        let roles = 1 + offsets.len() as u64;
        let w = wc_size as f64;
        CompositionRates {
            roles,
            wc_size,
            per_insertion: roles as f64 + (1 + profile.growth_relinks()) as f64 / w,
            per_removal: roles as f64 + profile.shrink_relinks() as f64 / w,
        }
    }
}

/// Illustrative absence-duration model (days).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AbsenceDurations {
    /// Primary model: P(D > x) = (1 + x/σ)^(−α).
    Lomax {
        /// Scale σ, days.
        scale_days: f64,
        /// Shape α.
        shape: f64,
    },
    /// Comparison model: P(D > x) = e^(−x/m).
    Exponential {
        /// Mean m, days.
        mean_days: f64,
    },
}

impl AbsenceDurations {
    /// Label used in tables.
    pub fn label(&self) -> &'static str {
        match self {
            AbsenceDurations::Lomax { .. } => "Lomax (primary)",
            AbsenceDurations::Exponential { .. } => "exponential (comparison)",
        }
    }

    /// P(D > `days`).
    pub fn survival(&self, days: f64) -> f64 {
        match *self {
            AbsenceDurations::Lomax { scale_days, shape } => {
                libm::pow(1.0 + days / scale_days, -shape)
            }
            AbsenceDurations::Exponential { mean_days } => libm::exp(-days / mean_days),
        }
    }

    /// E[min(D, `days`)], the mean time an absence lasts while capped at `days`.
    pub fn capped_mean(&self, days: f64) -> f64 {
        match *self {
            AbsenceDurations::Lomax { scale_days, shape } => {
                if (shape - 1.0).abs() < 1e-12 {
                    scale_days * libm::log1p(days / scale_days)
                } else {
                    scale_days / (shape - 1.0)
                        * (1.0 - libm::pow(1.0 + days / scale_days, 1.0 - shape))
                }
            }
            AbsenceDurations::Exponential { mean_days } => {
                -mean_days * libm::expm1(-days / mean_days)
            }
        }
    }
}

/// Which absences vacate a seat.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeatRule {
    /// SPEC v0.3 (comparison): every absence that deactivates an ID vacates its seat.
    V03,
    /// SPEC v0.4: only a continuous absence longer than `long_absence_days` does.
    V04 {
        /// Long-absence threshold L, days.
        long_absence_days: f64,
    },
}

impl SeatRule {
    /// Label used in tables, for example `v0.4, L = 30 days`.
    pub fn label(&self) -> String {
        match self {
            SeatRule::V03 => "v0.3: every absence vacates the seat".to_string(),
            SeatRule::V04 { long_absence_days } => {
                format!("v0.4: L = {} days", trim_number(*long_absence_days))
            }
        }
    }

    /// Long-absence threshold in days, for the v0.4 rule.
    pub fn long_absence_days(&self) -> Option<f64> {
        match self {
            SeatRule::V03 => None,
            SeatRule::V04 { long_absence_days } => Some(*long_absence_days),
        }
    }

    /// Share of absences that vacate a seat.
    pub fn vacating_share(&self, durations: &AbsenceDurations) -> f64 {
        match self {
            SeatRule::V03 => 1.0,
            SeatRule::V04 { long_absence_days } => durations.survival(*long_absence_days),
        }
    }
}

fn trim_number(x: f64) -> String {
    let text = format!("{x:.3}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Inputs to the counts over a horizon.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HorizonInputs {
    /// KWCs at the start, `W0`.
    pub initial_kwcs: u64,
    /// Horizon `H`, years.
    pub horizon_years: f64,
    /// New IDs per year, `R`.
    pub issuance_per_year: f64,
    /// Bans per registered ID per year.
    pub ban_rate: f64,
    /// Seat-vacating absences per registered ID per year (each followed by a return and a
    /// re-insertion).
    pub vacating_absences: f64,
}

impl HorizonInputs {
    /// Inputs over the configured horizon (`analytic.witness.composition_horizon_years`) at the
    /// configured issuance rate, from `initial_kwcs` KWCs.
    pub fn from_config(
        config: &Config,
        initial_kwcs: u64,
        ban_rate: f64,
        vacating_absences: f64,
    ) -> Self {
        HorizonInputs {
            initial_kwcs,
            horizon_years: config.analytic.witness.composition_horizon_years,
            issuance_per_year: config.issuance_per_year(),
            ban_rate,
            vacating_absences,
        }
    }

    /// Registered-ID-years: IDs grow from `wc_size·W0` at `R` per year.
    pub fn id_years(&self, wc_size: u64) -> f64 {
        let h = self.horizon_years;
        wc_size as f64 * self.initial_kwcs as f64 * h + self.issuance_per_year * h * h / 2.0
    }

    /// Insertions: new IDs plus returns after a vacated seat.
    pub fn insertions(&self, wc_size: u64) -> f64 {
        self.issuance_per_year * self.horizon_years
            + self.vacating_absences * self.id_years(wc_size)
    }

    /// Removals: bans plus seat-vacating absences.
    pub fn removals(&self, wc_size: u64) -> f64 {
        (self.ban_rate + self.vacating_absences) * self.id_years(wc_size)
    }
}

/// KWC compositions formed over the horizon: the initial KWCs plus every insertion and
/// removal.
pub fn composition_count(inputs: &HorizonInputs, rates: &CompositionRates) -> f64 {
    inputs.initial_kwcs as f64
        + inputs.insertions(rates.wc_size) * rates.per_insertion
        + inputs.removals(rates.wc_size) * rates.per_removal
}

/// KWC compositions under the v0.2 counting model (comparison): one new KWC per new WC and
/// `r` compositions per ban replacement.
pub fn composition_count_v02(inputs: &HorizonInputs, rates: &CompositionRates) -> f64 {
    let w = rates.wc_size as f64;
    inputs.initial_kwcs as f64
        + inputs.horizon_years * inputs.issuance_per_year / w
        + rates.roles as f64 * inputs.ban_rate * inputs.id_years(rates.wc_size)
}

/// Binomial seat model of a KWC: a leader group and a subordinate group whose seats are each
/// the attacker's with probability `p`, with probabilities held as `f64` (correctly rounded
/// from exact values).
#[derive(Debug, Clone, PartialEq)]
pub struct BinomialSeats {
    leader: u64,
    subordinate: u64,
    wc_size: u64,
    p: f64,
    pmf_leader: Vec<f64>,
    pmf_subordinate: Vec<f64>,
    exact_p: Q,
}

fn binomial_pmf(seats: u64, p: &Q) -> Result<Vec<f64>> {
    let d = ExactDistribution::new(seats, &SeatModel::Binomial(p.clone()))?;
    Ok((0..=seats).map(|k| to_f64(&d.pmf(k))).collect())
}

impl BinomialSeats {
    /// Seats of a KWC with `leader` leader seats and `subordinate` subordinate seats, in WCs of
    /// `wc_size`, each the attacker's with probability `p`.
    pub fn new(leader: u64, subordinate: u64, wc_size: u64, p: &Q) -> Result<Self> {
        ensure(
            wc_size > 0 && subordinate % wc_size == 0,
            "subordinate seats must be whole WCs",
        )?;
        Ok(BinomialSeats {
            leader,
            subordinate,
            wc_size,
            p: to_f64(p),
            pmf_leader: binomial_pmf(leader, p)?,
            pmf_subordinate: binomial_pmf(subordinate, p)?,
            exact_p: p.clone(),
        })
    }

    /// Probability that the KWC is in the state `inside(leader seats, subordinate seats)`.
    pub fn probability(&self, inside: &dyn Fn(u64, u64) -> bool) -> f64 {
        let mut total = 0.0;
        for (x, px) in self.pmf_leader.iter().enumerate() {
            for (y, py) in self.pmf_subordinate.iter().enumerate() {
                if inside(x as u64, y as u64) {
                    total += px * py;
                }
            }
        }
        total
    }

    /// Probability that replacing one uniformly chosen seat by a fresh member moves the KWC
    /// into the state from outside it.
    pub fn one_seat_entry(&self, inside: &dyn Fn(u64, u64) -> bool) -> f64 {
        let (n1, n2) = (self.leader, self.subordinate);
        let n = (n1 + n2) as f64;
        let (p, q) = (self.p, 1.0 - self.p);
        let mut total = 0.0;
        for (x, px) in self.pmf_leader.iter().enumerate() {
            let x = x as u64;
            for (y, py) in self.pmf_subordinate.iter().enumerate() {
                let y = y as u64;
                if inside(x, y) {
                    continue;
                }
                let mut moves = 0.0;
                if x < n1 && inside(x + 1, y) {
                    moves += (n1 - x) as f64 / n * p;
                }
                if x > 0 && inside(x - 1, y) {
                    moves += x as f64 / n * q;
                }
                if y < n2 && inside(x, y + 1) {
                    moves += (n2 - y) as f64 / n * p;
                }
                if y > 0 && inside(x, y - 1) {
                    moves += y as f64 / n * q;
                }
                total += px * py * moves;
            }
        }
        total
    }

    /// Probability that replacing `wcs` subordinate WCs by independent fresh WCs moves the KWC
    /// into the state from outside it.
    pub fn replacement_entry(&self, wcs: u64, inside: &dyn Fn(u64, u64) -> bool) -> Result<f64> {
        let replaced = wcs * self.wc_size;
        ensure(
            replaced <= self.subordinate,
            "cannot replace more subordinate WCs than the KWC has",
        )?;
        let keep = binomial_pmf(self.subordinate - replaced, &self.exact_p)?;
        let fresh = binomial_pmf(replaced, &self.exact_p)?;
        let mut total = 0.0;
        for (x, px) in self.pmf_leader.iter().enumerate() {
            for (t, pt) in keep.iter().enumerate() {
                let (mut outside, mut entering) = (0.0, 0.0);
                for (y, py) in fresh.iter().enumerate() {
                    if inside(x as u64, (t + y) as u64) {
                        entering += py;
                    } else {
                        outside += py;
                    }
                }
                total += px * pt * outside * entering;
            }
        }
        Ok(total)
    }
}

/// Probabilities of entering a state at each kind of change.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntryRates {
    /// Probability of the state for one composition, `q`.
    pub q: f64,
    /// Entry probability for a one-seat change, `e₁`.
    pub one_seat: f64,
    /// Expected entries from ring changes per insertion: `(q + Σ m_j e_j)/wc_size`.
    pub growth_ring: f64,
    /// Expected entries from ring changes per removal: `Σ m′_j e_j/wc_size`.
    pub shrink_ring: f64,
}

/// Entry rates for the state `inside` under the given seats and relink profile.
pub fn entry_rates(
    seats: &BinomialSeats,
    profile: &RelinkProfile,
    inside: &dyn Fn(u64, u64) -> bool,
) -> Result<EntryRates> {
    let q = seats.probability(inside);
    let w = seats.wc_size as f64;
    let ring = |pairs: &[(u64, u64)]| -> Result<f64> {
        let mut total = 0.0;
        for (wcs, count) in pairs {
            total += *count as f64 * seats.replacement_entry(*wcs, inside)?;
        }
        Ok(total)
    };
    let growth = ring(&profile.growth)?;
    let shrink = ring(&profile.shrink)?;
    Ok(EntryRates {
        q,
        one_seat: seats.one_seat_entry(inside),
        growth_ring: (q + growth) / w,
        shrink_ring: shrink / w,
    })
}

/// Expected distinct episodes in the state over the horizon: the initial KWCs in the state,
/// plus the expected entries at every insertion and removal.
pub fn episode_count(
    inputs: &HorizonInputs,
    rates: &CompositionRates,
    entries: &EntryRates,
) -> f64 {
    let per_insertion = rates.roles as f64 * entries.one_seat + entries.growth_ring;
    let per_removal = rates.roles as f64 * entries.one_seat + entries.shrink_ring;
    inputs.initial_kwcs as f64 * entries.q
        + inputs.insertions(rates.wc_size) * per_insertion
        + inputs.removals(rates.wc_size) * per_removal
}

/// Simpson's rule on `[0, upper]` with `intervals` (even) sub-intervals; used to cross-check
/// [`AbsenceDurations::capped_mean`].
pub fn simpson(f: impl Fn(f64) -> f64, upper: f64, intervals: u32) -> f64 {
    let n = intervals + intervals % 2;
    let h = upper / f64::from(n);
    let mut total = f(0.0) + f(upper);
    for i in 1..n {
        let weight = if i % 2 == 1 { 4.0 } else { 2.0 };
        total += weight * f(f64::from(i) * h);
    }
    total * h / 3.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exact::ratio;

    #[test]
    fn spec_ring_relinks_two_one_wc_three_two_wc_and_one_three_wc_kwcs() {
        // Preview computed in the plan by comparing rings of W and W ± 1 WCs.
        let profile = relink_profile(&[1, 4, 6]);
        assert_eq!(profile.growth, vec![(1, 2), (2, 3), (3, 1)]);
        assert_eq!(profile.shrink, vec![(1, 2), (2, 3), (3, 1)]);
        let thirty = relink_profile(&[1, 3]);
        assert_eq!(thirty.growth, vec![(1, 2), (2, 1)]);
    }

    #[test]
    fn composition_rates_reproduce_4_7_and_4_6() {
        let profile = relink_profile(&[1, 4, 6]);
        let rates = CompositionRates::new(10, &[1, 4, 6], &profile);
        assert!((rates.per_insertion - 4.7).abs() < 1e-12);
        assert!((rates.per_removal - 4.6).abs() < 1e-12);
    }

    #[test]
    fn lomax_and_exponential_match_their_closed_forms() {
        let lomax = AbsenceDurations::Lomax {
            scale_days: 2.0,
            shape: 1.5,
        };
        // (1 + 30/2)^(-1.5) = 16^(-1.5) = 1/64.
        assert!((lomax.survival(30.0) - 1.0 / 64.0).abs() < 1e-15);
        // 4·(1 − 16^(−0.5)) = 3.
        assert!((lomax.capped_mean(30.0) - 3.0).abs() < 1e-12);
        let exponential = AbsenceDurations::Exponential { mean_days: 7.0 };
        assert!((exponential.survival(7.0) - (-1.0f64).exp()).abs() < 1e-15);
        assert!((exponential.capped_mean(1e6) - 7.0).abs() < 1e-9);
    }

    #[test]
    fn capped_means_agree_with_quadrature() {
        for model in [
            AbsenceDurations::Lomax {
                scale_days: 2.0,
                shape: 1.5,
            },
            AbsenceDurations::Lomax {
                scale_days: 3.0,
                shape: 1.0,
            },
            AbsenceDurations::Exponential { mean_days: 7.0 },
        ] {
            for days in [3.0, 30.0, 365.0] {
                let numeric = simpson(|x| model.survival(x), days, 200_000);
                let closed = model.capped_mean(days);
                assert!((numeric - closed).abs() < 1e-9 * closed, "{model:?} {days}");
            }
        }
    }

    #[test]
    fn seat_rules_vacate_all_or_only_long_absences() {
        let lomax = AbsenceDurations::Lomax {
            scale_days: 2.0,
            shape: 1.5,
        };
        assert_eq!(SeatRule::V03.vacating_share(&lomax), 1.0);
        let v04 = SeatRule::V04 {
            long_absence_days: 30.0,
        };
        assert!((v04.vacating_share(&lomax) - 1.0 / 64.0).abs() < 1e-15);
        assert_eq!(v04.label(), "v0.4: L = 30 days");
    }

    #[test]
    fn one_seat_entry_matches_the_pool_formula() {
        // Reference: P(X = 26)·(14/40)·p for "at least 27 of 40" at p = 1/4.
        let p = ratio(1, 4);
        let seats = BinomialSeats::new(10, 30, 10, &p).unwrap();
        let inside = |x: u64, y: u64| x + y >= 27;
        let pool = ExactDistribution::new(40, &SeatModel::Binomial(p.clone())).unwrap();
        let reference = to_f64(&(pool.pmf(26) * ratio(14, 40) * &p));
        let value = seats.one_seat_entry(&inside);
        assert!((value - reference).abs() < 1e-12 * reference);
    }

    #[test]
    fn replacing_every_subordinate_wc_of_a_subordinate_state_is_a_fresh_draw() {
        // With the state depending only on the subordinates, replacing all three subordinate
        // WCs gives entry probability q(1 − q).
        let p = ratio(1, 3);
        let seats = BinomialSeats::new(10, 30, 10, &p).unwrap();
        let inside = |_: u64, y: u64| y >= 12;
        let q = seats.probability(&inside);
        let entry = seats.replacement_entry(3, &inside).unwrap();
        assert!((entry - q * (1.0 - q)).abs() < 1e-12);
    }

    #[test]
    fn episodes_lie_between_the_initial_kwcs_and_the_composition_bound() {
        let p = ratio(1, 4);
        let seats = BinomialSeats::new(10, 30, 10, &p).unwrap();
        let profile = relink_profile(&[1, 4, 6]);
        let rates = CompositionRates::new(10, &[1, 4, 6], &profile);
        let inside = |x: u64, y: u64| x + y >= 27;
        let entries = entry_rates(&seats, &profile, &inside).unwrap();
        let inputs = HorizonInputs {
            initial_kwcs: 100_000,
            horizon_years: 10.0,
            issuance_per_year: 1_051_200.0,
            ban_rate: 0.0,
            vacating_absences: 0.0,
        };
        let episodes = episode_count(&inputs, &rates, &entries);
        let bound = composition_count(&inputs, &rates) * entries.q;
        assert!(episodes > 100_000.0 * entries.q && episodes < bound);
        // Plan preview: 0.476 episodes against 0.926 for the composition count.
        assert!((episodes - 0.476).abs() < 0.001, "{episodes}");
        assert!((bound - 0.926).abs() < 0.001, "{bound}");
    }

    #[test]
    fn configured_thresholds_are_three_to_365_days_and_30_days_is_86_400_blocks() {
        let config = Config::default();
        assert_eq!(
            long_absence_days(&config),
            vec![3.0, 7.0, 30.0, 90.0, 365.0]
        );
        assert_eq!(seat_rules(&config).len(), 6);
        assert_eq!(days_in_blocks(&config, 3.0), 8_640.0);
        assert_eq!(days_in_blocks(&config, 30.0), 86_400.0);
        assert_eq!(absence_models(&config).len(), 2);
    }

    #[test]
    fn insertions_and_removals_include_vacating_absences() {
        let inputs = HorizonInputs {
            initial_kwcs: 100_000,
            horizon_years: 10.0,
            issuance_per_year: 1_051_200.0,
            ban_rate: 0.01,
            vacating_absences: 0.5,
        };
        let id_years = 10.0 * 100_000.0 * 10.0 + 1_051_200.0 * 50.0;
        assert!((inputs.insertions(10) - (10_512_000.0 + 0.5 * id_years)).abs() < 1e-3);
        assert!((inputs.removals(10) - 0.51 * id_years).abs() < 1e-3);
    }
}
