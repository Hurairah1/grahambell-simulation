//! Section A — how long an attacker needs to reach a share of active IDs.
//!
//! Implements the time floor of SPEC §0 C2 and §10 H2, and the adaptive-issuance cap of
//! SPEC §3.9.
//!
//! # The linear race
//!
//! Every variant here is a race between two straight lines, measured in years:
//!
//! - attacker active IDs: `A(t) = a·t`;
//! - all active IDs: `N(t) = n0 + n1·t`.
//!
//! The attacker's share `A/N` rises from 0 towards `a/n1`. It reaches a threshold `T` when
//! `a·t ≥ T·(n0 + n1·t)`, that is at
//!
//! ```text
//! t* = T·n0 / (a − T·n1)        when a − T·n1 > 0,
//! ```
//!
//! and never otherwise (for `n0 > 0`). The variants differ only in `(a, n0, n1)`. Here `G` is
//! the historical active base, `R` issuance per year, `s` the attacker's share of new
//! issuance, `f` the honest online fraction and `g` honest active-base growth per year.
//!
//! | Variant | a | n0 | n1 |
//! |---|---|---|---|
//! | base | sR | G | R |
//! | online fraction, realistic (f applies to all honest IDs) | sR | fG | sR + f(1−s)R |
//! | online fraction, optimistic bound (f applies to the base only) | sR | fG | R |
//! | honest growth (architect's general form) | sR | G | g + sR |
//!
//! The base case gives `t* = T·G / (R(s − T))`. The long-run share in the realistic variant is
//! `s / (s + f(1 − s))`.
//!
//! # The adaptive cap (SPEC §3.9)
//!
//! A 100%-capture attacker or one with share `s` of issuance faces a rate capped at
//! `R = registered/T_min`, with registered IDs counted at checkpoints. Measuring IDs in units
//! of `G` and time in units of `T_min`, registered IDs grow at the rate fixed at the last
//! checkpoint, and the attacker holds `s·(N − 1)`. It reaches `T` when `N = ρ = s/(s − T)`.
//!
//! - **Frozen cap** (rate fixed at `G/T_min`): `t* = T/(s − T)` T_min.
//! - **Continuous cap**: `N = e^t`, so `t* = ln ρ` T_min.
//! - **Checkpoints every `x` T_min**: `N` grows linearly at the rate set by `N` at the last
//!   checkpoint. The time depends on when the attack starts relative to the schedule. If the
//!   first checkpoint comes `w` after the start and the crossing falls in interval `j ≥ 1`,
//!   `t = w + (j−1)x + ρ/((1+w)(1+x)^{j−1}) − 1`, which is convex in `w`. Its minimum is at
//!   `(1+w)² = ρ/(1+x)^{j−1}`, clipped to the range of `w` for which the crossing falls in
//!   interval `j`.
//! - **Safety factor `k`** (SPEC §3.9, v0.3): the cap `registered/(k·T_min)` is the same
//!   problem measured in units of `k·T_min`, with checkpoints every `x/k` of those units. Its
//!   worst-phase time is therefore `k · t_worst(ρ, x/k)` T_min. With `x = 1` and `k = 7/6`
//!   this is exactly 1 for a 100%-capture attacker reaching 51%.

use crate::error::{Result, ensure};
use crate::exact::{Q, decimal, integer, ratio, to_f64};
use crate::mc::{RunningStats, bernoulli};
use crate::validation::Check;
use gb_config::Config;
use gb_runlog::rng_stream;
use num_traits::{One, Signed, ToPrimitive, Zero};
use serde::Serialize;

/// Outcome of a race against a threshold.
#[derive(Debug, Clone, PartialEq)]
pub enum Reach {
    /// The threshold is never reached in finite time.
    Never,
    /// The share is at or above the threshold from the start (empty historical base).
    Immediately,
    /// The threshold is reached after this many time units.
    After(Q),
}

impl Reach {
    /// Time as `f64`, or `None` when the threshold is never reached.
    pub fn time(&self) -> Option<f64> {
        match self {
            Reach::Never => None,
            Reach::Immediately => Some(0.0),
            Reach::After(t) => Some(to_f64(t)),
        }
    }

    /// Label used in tables.
    pub fn label(&self) -> &'static str {
        match self {
            Reach::Never => "never reached",
            Reach::Immediately => "immediately",
            Reach::After(_) => "reached",
        }
    }
}

/// A race between attacker active IDs `a·t` and all active IDs `n0 + n1·t`.
#[derive(Debug, Clone, PartialEq)]
pub struct LinearRace {
    /// Attacker active IDs gained per unit time, `a`.
    pub attacker_rate: Q,
    /// Active IDs at time zero, `n0`.
    pub base: Q,
    /// All active IDs gained per unit time, `n1`.
    pub active_rate: Q,
}

impl LinearRace {
    /// Attacker share of active IDs at time `t`.
    pub fn share_at(&self, t: &Q) -> Q {
        let total = &self.base + &self.active_rate * t;
        if total.is_zero() {
            Q::zero()
        } else {
            &self.attacker_rate * t / total
        }
    }

    /// When the attacker share first reaches `threshold`.
    pub fn crossing_time(&self, threshold: &Q) -> Reach {
        let margin = &self.attacker_rate - threshold * &self.active_rate;
        if self.base.is_zero() {
            if !self.attacker_rate.is_zero() && !margin.is_negative() {
                Reach::Immediately
            } else {
                Reach::Never
            }
        } else if margin.is_positive() {
            Reach::After(threshold * &self.base / margin)
        } else {
            Reach::Never
        }
    }

    /// The share approached as time grows, `a / n1`.
    pub fn long_run_share(&self) -> Q {
        if self.active_rate.is_zero() {
            Q::zero()
        } else {
            &self.attacker_rate / &self.active_rate
        }
    }
}

/// Base race: the historical base `genesis` stays active, all new IDs are active.
pub fn base_race(genesis: &Q, issuance: &Q, share: &Q) -> LinearRace {
    LinearRace {
        attacker_rate: share * issuance,
        base: genesis.clone(),
        active_rate: issuance.clone(),
    }
}

/// Realistic online fraction: a fraction `online` of all honest IDs, old and new, is active;
/// the attacker is fully online.
pub fn realistic_online_race(genesis: &Q, issuance: &Q, share: &Q, online: &Q) -> LinearRace {
    let attacker_rate = share * issuance;
    let honest_rate = online * (Q::one() - share) * issuance;
    LinearRace {
        active_rate: &attacker_rate + honest_rate,
        attacker_rate,
        base: online * genesis,
    }
}

/// Optimistic bound: only the historical base is reduced by `online`; new honest IDs are
/// fully active (the M1 brief's formulation).
pub fn optimistic_online_race(genesis: &Q, issuance: &Q, share: &Q, online: &Q) -> LinearRace {
    LinearRace {
        attacker_rate: share * issuance,
        base: online * genesis,
        active_rate: issuance.clone(),
    }
}

/// Honest active base growing by `growth` IDs per year while the attacker gains `share`
/// of issuance. `growth = (1 − s)·R` recovers [`base_race`].
pub fn honest_growth_race(genesis: &Q, issuance: &Q, share: &Q, growth: &Q) -> LinearRace {
    let attacker_rate = share * issuance;
    LinearRace {
        active_rate: growth + &attacker_rate,
        attacker_rate,
        base: genesis.clone(),
    }
}

/// Long-run attacker share in the realistic online-fraction variant, `s / (s + f(1 − s))`.
pub fn long_run_share_realistic(share: &Q, online: &Q) -> Q {
    let denominator = share + online * (Q::one() - share);
    if denominator.is_zero() {
        Q::zero()
    } else {
        share / denominator
    }
}

/// `ρ = s/(s − T)`: registered IDs, in units of the starting base, at which an attacker with
/// issuance share `s` reaches threshold `T`. `None` when `s ≤ T`.
pub fn crossing_multiple(share: &Q, threshold: &Q) -> Option<Q> {
    let margin = share - threshold;
    margin.is_positive().then(|| share / margin)
}

/// Frozen cap: time to threshold, in units of `T_min`, when the rate stays at `G/T_min`.
pub fn cap_frozen_time(share: &Q, threshold: &Q) -> Reach {
    base_race(&Q::one(), &Q::one(), share).crossing_time(threshold)
}

/// Continuous cap: `ln ρ`, in units of `T_min`. `None` when the threshold is never reached.
pub fn cap_continuous_time(rho: f64) -> f64 {
    libm::log(rho)
}

/// Checkpointed cap, exactly: time (units of `T_min`) to reach `ρ` when checkpoints occur
/// every `interval` and the first comes `first_checkpoint` after the attack starts.
pub fn cap_checkpoint_time_exact(rho: &Q, interval: &Q, first_checkpoint: &Q) -> Q {
    let mut time = Q::zero();
    let mut registered = Q::one();
    let mut rate = Q::one();
    let mut next = first_checkpoint.clone();
    loop {
        let at_next = &registered + &rate * (&next - &time);
        if at_next >= *rho {
            return time + (rho - registered) / rate;
        }
        registered = at_next;
        time = next.clone();
        rate = registered.clone();
        next = &time + interval;
    }
}

/// Floating-point version of [`cap_checkpoint_time_exact`].
pub fn cap_checkpoint_time(rho: f64, interval: f64, first_checkpoint: f64) -> f64 {
    let (mut time, mut registered, mut rate, mut next) = (0.0, 1.0, 1.0, first_checkpoint);
    loop {
        let at_next = registered + rate * (next - time);
        if at_next >= rho {
            return time + (rho - registered) / rate;
        }
        registered = at_next;
        time = next;
        rate = registered;
        next = time + interval;
    }
}

/// Fastest crossing over all start phases, with the phase that achieves it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorstPhase {
    /// Time to threshold, in units of `T_min`.
    pub time: f64,
    /// Time from the attack start to the first checkpoint, in units of `T_min`.
    pub first_checkpoint: f64,
}

/// Worst start phase for a checkpointed cap with checkpoints every `interval` (units of
/// `T_min`). See the module documentation for the derivation.
pub fn cap_checkpoint_worst_phase(rho: f64, interval: f64) -> WorstPhase {
    let mut candidates = vec![interval];
    if rho - 1.0 <= interval {
        candidates.push((rho - 1.0).max(f64::MIN_POSITIVE));
    }
    let mut j = 1;
    loop {
        let growth = libm::pow(1.0 + interval, f64::from(j - 1));
        if growth >= rho {
            break;
        }
        let lower = rho / ((1.0 + interval) * growth) - 1.0;
        let upper = (rho / growth - 1.0).min(interval);
        if lower < upper {
            let stationary = libm::sqrt(rho / growth) - 1.0;
            candidates.extend([stationary.clamp(lower, upper), lower, upper]);
        }
        j += 1;
    }
    candidates
        .into_iter()
        .filter(|w| *w > 0.0 && *w <= interval)
        .map(|w| WorstPhase {
            time: cap_checkpoint_time(rho, interval, w),
            first_checkpoint: w,
        })
        .fold(
            WorstPhase {
                time: f64::INFINITY,
                first_checkpoint: interval,
            },
            |best, c| if c.time < best.time { c } else { best },
        )
}

/// Worst start phase for a cap `registered/(k·T_min)` recalculated every `interval` (both
/// times in units of `T_min`). See the module documentation.
pub fn cap_scaled_worst_phase(rho: f64, interval: f64, k: f64) -> WorstPhase {
    let worst = cap_checkpoint_worst_phase(rho, interval / k);
    WorstPhase {
        time: k * worst.time,
        first_checkpoint: k * worst.first_checkpoint,
    }
}

/// Smallest safety factor `k` such that a cap of `registered/(k·T_min)` keeps the worst-phase
/// time at or above `T_min`. `interval` is the checkpoint interval in units of `T_min`, or
/// `None` for a continuously updated cap (`k = 1/ln ρ`).
pub fn cap_safety_factor(rho: f64, interval: Option<f64>) -> f64 {
    let Some(interval) = interval else {
        return 1.0 / libm::log(rho);
    };
    // With the cap scaled by k, time units become k·T_min and checkpoints come every
    // interval/k of those units.
    let scaled_time = |k: f64| cap_scaled_worst_phase(rho, interval, k).time;
    let (mut low, mut high) = (0.25 / (rho - 1.0).max(1e-9), 4.0 / libm::log(rho));
    for _ in 0..200 {
        let mid = 0.5 * (low + high);
        if scaled_time(mid) >= 1.0 {
            high = mid;
        } else {
            low = mid;
        }
    }
    high
}

/// Genesis IDs that must be issued so that, with only `online` of them active, a
/// 100%-capture attacker at the fixed rate needs `t_min_years` to reach `threshold`:
/// `T_min·R·(1 − T) / (T·f)`.
pub fn genesis_to_issue(t_min_years: &Q, issuance: &Q, threshold: &Q, online: &Q) -> Q {
    t_min_years * issuance * (Q::one() - threshold) / (threshold * online)
}

// ----------------------------------------------------------------------------- tables

/// A1: time to threshold, base model.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThresholdRow {
    /// Historical active base G.
    pub genesis_ids: u64,
    /// Issuance R per year.
    pub issuance_per_year: f64,
    /// Attacker share s of new issuance.
    pub attacker_share: f64,
    /// Threshold T of active IDs.
    pub threshold: f64,
    /// "reached", "never reached" or "immediately".
    pub outcome: &'static str,
    /// Years to reach T (empty when never reached).
    pub years: Option<f64>,
    /// Years in units of G/R.
    pub years_in_units_of_g_over_r: Option<f64>,
    /// Share approached as time grows.
    pub long_run_share: f64,
}

/// A2: time to threshold with an honest online fraction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OnlineRow {
    /// "realistic" (f applies to all honest IDs) or "optimistic bound" (base only).
    pub variant: &'static str,
    /// Historical base G (issued).
    pub genesis_ids: u64,
    /// Honest online fraction f.
    pub online_fraction: f64,
    /// Attacker share s of new issuance.
    pub attacker_share: f64,
    /// Threshold T.
    pub threshold: f64,
    /// Outcome label.
    pub outcome: &'static str,
    /// Years to reach T.
    pub years: Option<f64>,
    /// Long-run attacker share of active IDs.
    pub long_run_share: f64,
}

/// A3: time to threshold with honest active-base growth g.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GrowthRow {
    /// Historical active base G.
    pub genesis_ids: u64,
    /// Growth as a multiple of R, or "(1-s)R" for the base case.
    pub growth: String,
    /// Honest active-base growth g, IDs per year.
    pub honest_growth_per_year: f64,
    /// Attacker share s of new issuance.
    pub attacker_share: f64,
    /// Threshold T.
    pub threshold: f64,
    /// Outcome label.
    pub outcome: &'static str,
    /// Years to reach T.
    pub years: Option<f64>,
    /// Smallest s that reaches T in finite time, `T·g / (R(1 − T))`.
    pub minimum_share_for_finite_time: f64,
}

/// A4 model label: checkpoints, worst start phase, with the safety factor for that interval.
pub const CAP_WITH_SAFETY_FACTOR: &str = "checkpoint worst phase with safety factor k";
/// A4 model label: the configured cap (SPEC §3.9 defaults: k = 7/6, checkpoints every T_min).
pub const CAP_CONFIGURED: &str = "configured cap (SPEC §3.9 default)";

/// A4: adaptive cap, time to threshold in units of T_min.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapRow {
    /// "frozen", "continuous", "checkpoint aligned", "checkpoint worst phase",
    /// [`CAP_WITH_SAFETY_FACTOR`] or [`CAP_CONFIGURED`].
    pub model: &'static str,
    /// Checkpoint interval as a fraction of T_min (checkpoint models only).
    pub checkpoint_interval_fraction_of_t_min: Option<f64>,
    /// Safety factor k in the cap `registered/(k·T_min)` (1 when absent).
    pub safety_factor: Option<f64>,
    /// Attacker share s of issuance.
    pub attacker_share: f64,
    /// Threshold T.
    pub threshold: f64,
    /// Outcome label.
    pub outcome: &'static str,
    /// Time to threshold in units of T_min.
    pub time_in_t_min: Option<f64>,
    /// Worst phase: time from attack start to first checkpoint, as a fraction of the interval.
    pub worst_first_checkpoint_fraction_of_interval: Option<f64>,
}

/// A4 safety factors: the k that keeps the worst-phase time at T_min.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SafetyRow {
    /// "frozen", "continuous" or "checkpoint".
    pub model: &'static str,
    /// Checkpoint interval as a fraction of T_min.
    pub checkpoint_interval_fraction_of_t_min: Option<f64>,
    /// Attacker share (1 = wins every ID).
    pub attacker_share: f64,
    /// Threshold defining the floor.
    pub threshold: f64,
    /// Worst-phase time without a safety factor, units of T_min.
    pub worst_time_in_t_min_without_factor: f64,
    /// Safety factor k for the cap `registered/(k·T_min)`.
    pub safety_factor: f64,
}

/// A5: attacker share of active IDs over time, base model.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrajectoryRow {
    /// Attacker share s of new issuance.
    pub attacker_share: f64,
    /// Historical active base G.
    pub genesis_ids: u64,
    /// Years since the attack started.
    pub year: f64,
    /// Attacker share of active IDs.
    pub share_of_active_ids: f64,
}

/// A6: genesis IDs to issue for the time floor.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GenesisRow {
    /// Floor T_min in years.
    pub t_min_years: f64,
    /// Fraction of genesis IDs that stay active.
    pub online_fraction: f64,
    /// Threshold defining the floor.
    pub threshold: f64,
    /// Active IDs needed at the fixed rate, `T_min·R·(1 − T)/T`.
    pub active_ids_needed: f64,
    /// Genesis IDs to issue, `active_ids_needed / f`.
    pub genesis_ids_to_issue: f64,
}

/// A7: long-run attacker share of active IDs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LongRunRow {
    /// Attacker share s of new issuance.
    pub attacker_share: f64,
    /// Honest online fraction f (applies to all honest IDs).
    pub online_fraction: f64,
    /// `s / (s + f(1 − s))`.
    pub long_run_share: f64,
    /// Long-run share under the optimistic bound (= s).
    pub long_run_share_optimistic_bound: f64,
    /// Thresholds eventually crossed, for example "33%; 51%", or "none".
    pub thresholds_eventually_crossed: String,
}

/// All section A tables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SectionA {
    /// A1.
    pub thresholds: Vec<ThresholdRow>,
    /// A2.
    pub online: Vec<OnlineRow>,
    /// A3.
    pub growth: Vec<GrowthRow>,
    /// A4.
    pub cap: Vec<CapRow>,
    /// A4 safety factors.
    pub safety: Vec<SafetyRow>,
    /// A5.
    pub trajectories: Vec<TrajectoryRow>,
    /// A6.
    pub genesis: Vec<GenesisRow>,
    /// A7.
    pub long_run: Vec<LongRunRow>,
}

/// Exact grids for section A, converted once from the configuration.
struct Grids {
    issuance: Q,
    genesis: Vec<(u64, Q)>,
    shares: Vec<(f64, Q)>,
    thresholds: Vec<(f64, Q)>,
    online: Vec<(f64, Q)>,
    growth: Vec<(f64, Q)>,
    t_min: Vec<(f64, Q)>,
    checkpoints: Vec<(f64, Q)>,
    floor: (f64, Q),
    configured_interval: f64,
    configured_k: f64,
}

fn decimals(values: &[f64]) -> Result<Vec<(f64, Q)>> {
    values.iter().map(|v| Ok((*v, decimal(*v)?))).collect()
}

fn grids(config: &Config) -> Result<Grids> {
    let grid = &config.analytic.time_to_threshold;
    let interval = decimal(config.issuance.pow_id_target_interval_s.value)?;
    ensure(interval.is_positive(), "PoW-ID interval must be positive")?;
    Ok(Grids {
        issuance: integer(config.model.seconds_per_year) / interval,
        genesis: grid.genesis_ids.iter().map(|g| (*g, integer(*g))).collect(),
        shares: decimals(&grid.attacker_shares)?,
        thresholds: decimals(&grid.thresholds)?,
        online: decimals(&grid.online_fractions)?,
        growth: decimals(&grid.honest_growth_multiples_of_r)?,
        t_min: decimals(&grid.t_min_years)?,
        checkpoints: decimals(&grid.checkpoint_fractions_of_t_min)?,
        floor: (grid.floor_threshold, decimal(grid.floor_threshold)?),
        configured_interval: config
            .issuance
            .cap_checkpoint_interval_fraction_of_t_min
            .value,
        configured_k: config
            .issuance
            .cap_safety_factor
            .value
            .to_f64()
            .ok_or_else(|| {
                crate::error::AnalyticError::InvalidInput(
                    "the adaptive-cap safety factor has a zero denominator".to_string(),
                )
            })?,
    })
}

/// Worst-phase time, in units of T_min, of the configured cap for a 100%-capture attacker
/// reaching the floor threshold, with the start phase that achieves it.
pub fn configured_cap_floor(config: &Config) -> Result<WorstPhase> {
    let g = grids(config)?;
    let rho = crossing_multiple(&Q::one(), &g.floor.1).ok_or_else(|| {
        crate::error::AnalyticError::InvalidInput("the floor threshold must be below 1".to_string())
    })?;
    Ok(cap_scaled_worst_phase(
        to_f64(&rho),
        g.configured_interval,
        g.configured_k,
    ))
}

/// Builds every section A table from the configuration.
pub fn section_a(config: &Config) -> Result<SectionA> {
    let g = grids(config)?;
    Ok(SectionA {
        thresholds: threshold_rows(&g),
        online: online_rows(&g),
        growth: growth_rows(&g),
        cap: cap_rows(&g),
        safety: safety_rows(&g),
        trajectories: trajectory_rows(config, &g)?,
        genesis: genesis_rows(&g),
        long_run: long_run_rows(&g),
    })
}

fn threshold_rows(g: &Grids) -> Vec<ThresholdRow> {
    let mut rows = Vec::new();
    for (genesis_ids, genesis) in &g.genesis {
        for (share_f, share) in &g.shares {
            let race = base_race(genesis, &g.issuance, share);
            for (threshold_f, threshold) in &g.thresholds {
                let reach = race.crossing_time(threshold);
                let unit = to_f64(&(genesis / &g.issuance));
                rows.push(ThresholdRow {
                    genesis_ids: *genesis_ids,
                    issuance_per_year: to_f64(&g.issuance),
                    attacker_share: *share_f,
                    threshold: *threshold_f,
                    outcome: reach.label(),
                    years: reach.time(),
                    years_in_units_of_g_over_r: reach.time().map(|t| t / unit),
                    long_run_share: to_f64(&race.long_run_share()),
                });
            }
        }
    }
    rows
}

fn online_rows(g: &Grids) -> Vec<OnlineRow> {
    let mut rows = Vec::new();
    type RaceFn = fn(&Q, &Q, &Q, &Q) -> LinearRace;
    let variants: [(&'static str, RaceFn); 2] = [
        ("realistic", realistic_online_race),
        ("optimistic bound", optimistic_online_race),
    ];
    for (variant, race_fn) in variants {
        for (genesis_ids, genesis) in &g.genesis {
            for (online_f, online) in &g.online {
                for (share_f, share) in &g.shares {
                    let race = race_fn(genesis, &g.issuance, share, online);
                    for (threshold_f, threshold) in &g.thresholds {
                        let reach = race.crossing_time(threshold);
                        rows.push(OnlineRow {
                            variant,
                            genesis_ids: *genesis_ids,
                            online_fraction: *online_f,
                            attacker_share: *share_f,
                            threshold: *threshold_f,
                            outcome: reach.label(),
                            years: reach.time(),
                            long_run_share: to_f64(&race.long_run_share()),
                        });
                    }
                }
            }
        }
    }
    rows
}

fn growth_rows(g: &Grids) -> Vec<GrowthRow> {
    let mut rows = Vec::new();
    for (genesis_ids, genesis) in &g.genesis {
        for (share_f, share) in &g.shares {
            let mut growths: Vec<(String, Q)> = g
                .growth
                .iter()
                .map(|(m, q)| (format!("{m}R"), q * &g.issuance))
                .collect();
            growths.push(("(1-s)R base".to_string(), (Q::one() - share) * &g.issuance));
            for (label, growth) in growths {
                let race = honest_growth_race(genesis, &g.issuance, share, &growth);
                for (threshold_f, threshold) in &g.thresholds {
                    let reach = race.crossing_time(threshold);
                    let minimum = threshold * &growth / (&g.issuance * (Q::one() - threshold));
                    rows.push(GrowthRow {
                        genesis_ids: *genesis_ids,
                        growth: label.clone(),
                        honest_growth_per_year: to_f64(&growth),
                        attacker_share: *share_f,
                        threshold: *threshold_f,
                        outcome: reach.label(),
                        years: reach.time(),
                        minimum_share_for_finite_time: to_f64(&minimum),
                    });
                }
            }
        }
    }
    rows
}

fn cap_rows(g: &Grids) -> Vec<CapRow> {
    let mut rows = Vec::new();
    // Safety factor that holds the floor at the worst phase, for each checkpoint interval.
    let floor_rho = crossing_multiple(&Q::one(), &g.floor.1).map(|r| to_f64(&r));
    let factors: Vec<(f64, Option<f64>)> = g
        .checkpoints
        .iter()
        .map(|(f, _)| (*f, floor_rho.map(|r| cap_safety_factor(r, Some(*f)))))
        .collect();
    for (share_f, share) in &g.shares {
        for (threshold_f, threshold) in &g.thresholds {
            let rho = crossing_multiple(share, threshold);
            let frozen = cap_frozen_time(share, threshold);
            let row = |model, fraction, k, time, phase| {
                cap_row(model, fraction, k, *share_f, *threshold_f, time, phase)
            };
            rows.push(row("frozen", None, None, frozen.time(), None));
            let rho_f = rho.as_ref().map(to_f64);
            rows.push(row(
                "continuous",
                None,
                None,
                rho_f.map(cap_continuous_time),
                None,
            ));
            for ((fraction_f, fraction), (_, k)) in g.checkpoints.iter().zip(&factors) {
                let aligned = rho
                    .as_ref()
                    .map(|r| to_f64(&cap_checkpoint_time_exact(r, fraction, fraction)));
                rows.push(row(
                    "checkpoint aligned",
                    Some(*fraction_f),
                    None,
                    aligned,
                    None,
                ));
                let worst = rho_f.map(|r| cap_checkpoint_worst_phase(r, *fraction_f));
                rows.push(row(
                    "checkpoint worst phase",
                    Some(*fraction_f),
                    None,
                    worst.map(|w| w.time),
                    worst.map(|w| w.first_checkpoint / *fraction_f),
                ));
                let Some(k) = *k else { continue };
                let scaled = rho_f.map(|r| cap_scaled_worst_phase(r, *fraction_f, k));
                rows.push(row(
                    CAP_WITH_SAFETY_FACTOR,
                    Some(*fraction_f),
                    Some(k),
                    scaled.map(|w| w.time),
                    scaled.map(|w| w.first_checkpoint / *fraction_f),
                ));
            }
            let configured =
                rho_f.map(|r| cap_scaled_worst_phase(r, g.configured_interval, g.configured_k));
            rows.push(row(
                CAP_CONFIGURED,
                Some(g.configured_interval),
                Some(g.configured_k),
                configured.map(|w| w.time),
                configured.map(|w| w.first_checkpoint / g.configured_interval),
            ));
        }
    }
    rows
}

fn cap_row(
    model: &'static str,
    fraction: Option<f64>,
    safety_factor: Option<f64>,
    share: f64,
    threshold: f64,
    time: Option<f64>,
    phase: Option<f64>,
) -> CapRow {
    CapRow {
        model,
        checkpoint_interval_fraction_of_t_min: fraction,
        safety_factor,
        attacker_share: share,
        threshold,
        outcome: if time.is_some() {
            "reached"
        } else {
            "never reached"
        },
        time_in_t_min: time,
        worst_first_checkpoint_fraction_of_interval: phase,
    }
}

fn safety_rows(g: &Grids) -> Vec<SafetyRow> {
    let (floor_f, floor) = (&g.floor.0, &g.floor.1);
    let Some(rho) = crossing_multiple(&Q::one(), floor) else {
        return Vec::new();
    };
    let rho = to_f64(&rho);
    let frozen_time = to_f64(&(floor / (Q::one() - floor)));
    let mut rows = vec![
        SafetyRow {
            model: "frozen",
            checkpoint_interval_fraction_of_t_min: None,
            attacker_share: 1.0,
            threshold: *floor_f,
            worst_time_in_t_min_without_factor: frozen_time,
            safety_factor: 1.0 / frozen_time,
        },
        SafetyRow {
            model: "continuous",
            checkpoint_interval_fraction_of_t_min: None,
            attacker_share: 1.0,
            threshold: *floor_f,
            worst_time_in_t_min_without_factor: cap_continuous_time(rho),
            safety_factor: cap_safety_factor(rho, None),
        },
    ];
    for (fraction_f, _) in &g.checkpoints {
        rows.push(SafetyRow {
            model: "checkpoint",
            checkpoint_interval_fraction_of_t_min: Some(*fraction_f),
            attacker_share: 1.0,
            threshold: *floor_f,
            worst_time_in_t_min_without_factor: cap_checkpoint_worst_phase(rho, *fraction_f).time,
            safety_factor: cap_safety_factor(rho, Some(*fraction_f)),
        });
    }
    rows
}

fn trajectory_rows(config: &Config, g: &Grids) -> Result<Vec<TrajectoryRow>> {
    let grid = &config.analytic.time_to_threshold;
    let genesis_ids = config.genesis.ids.value;
    let genesis = integer(genesis_ids);
    let step = decimal(grid.trajectory_step_years)?;
    let horizon = decimal(grid.trajectory_horizon_years)?;
    let mut rows = Vec::new();
    for (share_f, share) in &g.shares {
        let race = base_race(&genesis, &g.issuance, share);
        let mut year = Q::zero();
        while year <= horizon {
            rows.push(TrajectoryRow {
                attacker_share: *share_f,
                genesis_ids,
                year: to_f64(&year),
                share_of_active_ids: to_f64(&race.share_at(&year)),
            });
            year += &step;
        }
    }
    Ok(rows)
}

fn genesis_rows(g: &Grids) -> Vec<GenesisRow> {
    let mut rows = Vec::new();
    for (t_min_f, t_min) in &g.t_min {
        for (online_f, online) in &g.online {
            let issue = genesis_to_issue(t_min, &g.issuance, &g.floor.1, online);
            rows.push(GenesisRow {
                t_min_years: *t_min_f,
                online_fraction: *online_f,
                threshold: g.floor.0,
                active_ids_needed: to_f64(&(&issue * online)),
                genesis_ids_to_issue: to_f64(&issue),
            });
        }
    }
    rows
}

fn long_run_rows(g: &Grids) -> Vec<LongRunRow> {
    let mut rows = Vec::new();
    for (share_f, share) in &g.shares {
        for (online_f, online) in &g.online {
            let long_run = long_run_share_realistic(share, online);
            let crossed: Vec<String> = g
                .thresholds
                .iter()
                .filter(|(_, t)| long_run > *t)
                .map(|(t, _)| format!("{}%", (t * 100.0).round()))
                .collect();
            rows.push(LongRunRow {
                attacker_share: *share_f,
                online_fraction: *online_f,
                long_run_share: to_f64(&long_run),
                long_run_share_optimistic_bound: *share_f,
                thresholds_eventually_crossed: if crossed.is_empty() {
                    "none".to_string()
                } else {
                    crossed.join("; ")
                },
            });
        }
    }
    rows
}

// ----------------------------------------------------------------------------- checks

/// Section A cross-checks.
pub fn checks(config: &Config) -> Result<Vec<Check>> {
    let g = grids(config)?;
    let mut checks = sanity_checks();
    checks.push(substitution_check(&g));
    checks.extend(issuance_monte_carlo_checks(config)?);
    checks.extend(cap_checks(&g));
    checks.extend(configured_cap_checks(config, &g)?);
    checks.extend(long_run_checks(&g));
    Ok(checks)
}

/// The three sanity values required by the M1 brief.
pub fn sanity_checks() -> Vec<Check> {
    let genesis = integer(2_000_000);
    let issuance = integer(1_050_000);
    let threshold = ratio(51, 100);
    let mut checks = Vec::new();
    for (share, expected, id) in [
        (ratio(52, 100), ratio(680, 7), "A-sanity-s052"),
        (Q::one(), ratio(680, 343), "A-sanity-s100"),
    ] {
        let reach = base_race(&genesis, &issuance, &share).crossing_time(&threshold);
        let value = reach.time().unwrap_or(f64::NAN);
        checks.push(Check::exact(
            "A",
            id,
            &format!(
                "G=2M, R=1.05M/yr, s={}, T=0.51: closed form equals {expected} years exactly",
                to_f64(&share)
            ),
            to_f64(&expected),
            value,
            reach == Reach::After(expected),
        ));
    }
    let never = base_race(&genesis, &issuance, &ratio(51, 100)).crossing_time(&threshold);
    checks.push(Check::exact(
        "A",
        "A-sanity-s051",
        "G=2M, R=1.05M/yr, s=0.51, T=0.51: no finite solution",
        1.0,
        f64::from(u8::from(never == Reach::Never)),
        never == Reach::Never,
    ));
    checks
}

fn substitution_check(g: &Grids) -> Check {
    let mut failures = 0;
    let mut rows = 0;
    for (_, genesis) in &g.genesis {
        for (_, share) in &g.shares {
            for (_, online) in &g.online {
                let races = [
                    base_race(genesis, &g.issuance, share),
                    realistic_online_race(genesis, &g.issuance, share, online),
                    optimistic_online_race(genesis, &g.issuance, share, online),
                ];
                for race in races {
                    for (_, threshold) in &g.thresholds {
                        if let Reach::After(t) = race.crossing_time(threshold) {
                            rows += 1;
                            let just_before = &t * ratio(999_999, 1_000_000);
                            if race.share_at(&t) != *threshold
                                || race.share_at(&just_before) >= *threshold
                            {
                                failures += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    Check::all_rows(
        "A",
        "A-substitution",
        "every finite closed-form time t* gives share(t*) = T exactly and share < T just before",
        failures,
        rows,
    )
}

/// Mean blocks until the attacker first holds `threshold` of active IDs, simulated block by
/// block: each block goes to the attacker with probability `share`; an honest block's new ID
/// is active with probability `online`.
fn simulate_first_passage(
    seed: u64,
    label: &str,
    genesis_active: u64,
    share: f64,
    threshold: &Q,
    online: f64,
    replicates: u64,
) -> RunningStats {
    let mut rng = rng_stream(seed, label);
    let numerator = threshold.numer().to_u128().unwrap_or(u128::MAX);
    let denominator = threshold.denom().to_u128().unwrap_or(1);
    let mut stats = RunningStats::default();
    for _ in 0..replicates {
        let (mut attacker, mut active, mut blocks) = (0u128, u128::from(genesis_active), 0u64);
        while denominator * attacker < numerator * active {
            blocks += 1;
            if bernoulli(&mut rng, share) {
                attacker += 1;
                active += 1;
            } else if bernoulli(&mut rng, online) {
                active += 1;
            }
        }
        stats.push(blocks as f64);
    }
    stats
}

fn issuance_monte_carlo_checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let seed = config.run.seed;
    let k = mc.tolerance_standard_errors;
    let genesis = mc.issuance_genesis_ids;
    let threshold = ratio(51, 100);
    let mut checks = Vec::new();
    let cases = [
        (0.6, ratio(6, 10), 1.0, Q::one(), "A-mc-base-s060"),
        (0.75, ratio(75, 100), 1.0, Q::one(), "A-mc-base-s075"),
        (1.0, Q::one(), 1.0, Q::one(), "A-mc-base-s100"),
        (
            0.6,
            ratio(6, 10),
            0.7,
            ratio(7, 10),
            "A-mc-realistic-s060-f070",
        ),
    ];
    for (share_f, share, online_f, online, id) in cases {
        let genesis_q = integer(genesis);
        let race = realistic_online_race(&genesis_q, &Q::one(), &share, &online);
        let Reach::After(t_star) = race.crossing_time(&threshold) else {
            continue;
        };
        let genesis_active = to_f64(&(&online * &genesis_q)).round() as u64;
        let stats = simulate_first_passage(
            seed,
            id,
            genesis_active,
            share_f,
            &threshold,
            online_f,
            mc.issuance_replicates,
        );
        // Wald's identity: E[blocks] = (T·G_active + E[overshoot]) / drift, with the overshoot
        // in [0, 1 − T). So the mean lies in [t*, t* + (1 − T)/drift].
        let drift = to_f64(&(&race.attacker_rate - &threshold * &race.active_rate));
        let overshoot = to_f64(&(Q::one() - &threshold)) / drift;
        let reference = to_f64(&t_star) + 0.5 * overshoot;
        checks.push(Check::monte_carlo(
            "A",
            id,
            &format!(
                "per-block simulation (G={genesis}, s={share_f}, f={online_f}, T=0.51): mean blocks to threshold vs closed form t* (+ Wald overshoot band)"
            ),
            reference,
            stats.estimate(),
            k,
            0.5 * overshoot,
        ));
    }
    Ok(checks)
}

fn cap_checks(g: &Grids) -> Vec<Check> {
    let mut checks = Vec::new();
    let threshold = ratio(51, 100);
    let rho_q = Q::one() / (Q::one() - &threshold);
    let rho = to_f64(&rho_q);
    let aligned = cap_checkpoint_time_exact(&rho_q, &Q::one(), &Q::one());
    checks.push(Check::exact(
        "A",
        "A-cap-aligned-exact",
        "checkpoint every T_min, attack aligned, s=1, T=0.51: time equals 50/49 T_min exactly",
        50.0 / 49.0,
        to_f64(&aligned),
        aligned == ratio(50, 49),
    ));
    let worst = cap_checkpoint_worst_phase(rho, 1.0);
    checks.push(Check::absolute(
        "A",
        "A-cap-worst-exact",
        "checkpoint every T_min, worst start phase, s=1, T=0.51: 2(sqrt(rho) - 1) = 6/7 T_min",
        6.0 / 7.0,
        worst.time,
        1e-12,
    ));
    for (fraction, _) in &g.checkpoints {
        let analytic = cap_checkpoint_worst_phase(rho, *fraction).time;
        let grid_min = (1..=20_000)
            .map(|i| cap_checkpoint_time(rho, *fraction, *fraction * f64::from(i) / 20_000.0))
            .fold(f64::INFINITY, f64::min);
        checks.push(Check::absolute(
            "A",
            &format!("A-cap-worst-vs-grid-{fraction}"),
            &format!(
                "checkpoint interval {fraction} T_min: analytic worst phase vs dense grid of 20,000 start phases"
            ),
            grid_min,
            analytic,
            1e-6,
        ));
    }
    let fine = cap_checkpoint_time(rho, 1e-5, 1e-5);
    checks.push(Check::relative(
        "A",
        "A-cap-continuous-vs-fine-checkpoints",
        "continuous cap ln(rho) vs checkpoints every 1e-5 T_min",
        cap_continuous_time(rho),
        fine,
        1e-4,
    ));
    let genesis = 100_000_u64;
    let target = (0.51 * genesis as f64 / 0.49).ceil() as u64;
    let harmonic: f64 = (0..target).map(|i| 1.0 / (genesis + i) as f64).sum();
    checks.push(Check::relative(
        "A",
        "A-cap-continuous-vs-harmonic-sum",
        "continuous cap ln(rho) vs per-block sum of T_min/N_i (G=100,000, s=1, T=0.51)",
        cap_continuous_time(rho),
        harmonic,
        1e-4,
    ));
    let k = cap_safety_factor(rho, Some(1.0));
    checks.push(Check::absolute(
        "A",
        "A-cap-safety-factor-t-min",
        "safety factor for checkpoints every T_min equals 7/6",
        7.0 / 6.0,
        k,
        1e-9,
    ));
    checks
}

fn configured_cap_checks(config: &Config, g: &Grids) -> Result<Vec<Check>> {
    let worst = configured_cap_floor(config)?;
    let rho = to_f64(&(Q::one() / (Q::one() - &g.floor.1)));
    let (x, k) = (g.configured_interval, g.configured_k);
    let grid_min = (1..=20_000)
        .map(|i| k * cap_checkpoint_time(rho, x / k, (x / k) * f64::from(i) / 20_000.0))
        .fold(f64::INFINITY, f64::min);
    Ok(vec![
        Check::at_least(
            "A",
            "A-cap-configured-floor",
            &format!(
                "configured cap (k = {k:.6}, checkpoints every {x} T_min), s=1, T={}: worst-start time is at least T_min (SPEC §3.9 guarantee)",
                g.floor.0
            ),
            1.0,
            worst.time,
            1e-9,
            0,
        ),
        Check::absolute(
            "A",
            "A-cap-configured-vs-grid",
            "configured cap: analytic worst start vs dense grid of 20,000 start phases",
            grid_min,
            worst.time,
            1e-6,
        ),
    ])
}

fn long_run_checks(g: &Grids) -> Vec<Check> {
    let mut disagreements = 0;
    let mut far_failures = 0;
    let mut rows = 0;
    let far = integer(1_000_000_000);
    for (_, genesis) in &g.genesis {
        for (_, share) in &g.shares {
            for (_, online) in &g.online {
                let race = realistic_online_race(genesis, &g.issuance, share, online);
                let long_run = long_run_share_realistic(share, online);
                if long_run != race.long_run_share() {
                    disagreements += 1;
                }
                let late = to_f64(&race.share_at(&far));
                if (late - to_f64(&long_run)).abs() > 1e-6 {
                    far_failures += 1;
                }
                for (_, threshold) in &g.thresholds {
                    rows += 1;
                    let finite = matches!(race.crossing_time(threshold), Reach::After(_));
                    if finite != (long_run > *threshold) {
                        disagreements += 1;
                    }
                }
            }
        }
    }
    vec![
        Check::all_rows(
            "A",
            "A-long-run-classification",
            "long-run share s/(s+f(1-s)) exceeds T exactly when the finite-time formula gives a time",
            disagreements,
            rows,
        ),
        Check::all_rows(
            "A",
            "A-long-run-vs-trajectory",
            "long-run share matches the share after 1e9 years within 1e-6",
            far_failures,
            (g.genesis.len() * g.shares.len() * g.online.len()) as u64,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn race(g: u64, r: u64, s: Q) -> LinearRace {
        base_race(&integer(g), &integer(r), &s)
    }

    #[test]
    fn sanity_two_million_base_at_52_percent_takes_680_over_7_years() {
        let reach = race(2_000_000, 1_050_000, ratio(52, 100)).crossing_time(&ratio(51, 100));
        assert_eq!(reach, Reach::After(ratio(680, 7)));
        assert!((reach.time().unwrap() - 97.142_857_142_857_14).abs() < 1e-9);
    }

    #[test]
    fn sanity_full_capture_takes_680_over_343_years() {
        let reach = race(2_000_000, 1_050_000, Q::one()).crossing_time(&ratio(51, 100));
        assert_eq!(reach, Reach::After(ratio(680, 343)));
        assert!((reach.time().unwrap() - 1.982_507_288_629_738).abs() < 1e-12);
    }

    #[test]
    fn sanity_share_equal_to_threshold_never_reaches_it() {
        let reach = race(2_000_000, 1_050_000, ratio(51, 100)).crossing_time(&ratio(51, 100));
        assert_eq!(reach, Reach::Never);
        assert_eq!(reach.label(), "never reached");
    }

    #[test]
    fn empty_base_reaches_immediately_when_share_is_high_enough() {
        let empty = race(0, 1_000, ratio(6, 10));
        assert_eq!(empty.crossing_time(&ratio(51, 100)), Reach::Immediately);
        assert_eq!(empty.crossing_time(&ratio(67, 100)), Reach::Never);
    }

    #[test]
    fn full_online_fraction_matches_the_base_model() {
        let (g, r, s, t) = (
            integer(2_100_000),
            integer(1_051_200),
            ratio(6, 10),
            ratio(51, 100),
        );
        let base = base_race(&g, &r, &s).crossing_time(&t);
        assert_eq!(
            realistic_online_race(&g, &r, &s, &Q::one()).crossing_time(&t),
            base
        );
        assert_eq!(
            optimistic_online_race(&g, &r, &s, &Q::one()).crossing_time(&t),
            base
        );
    }

    #[test]
    fn growth_equal_to_honest_issuance_share_matches_the_base_model() {
        let (g, r, s, t) = (
            integer(2_000_000),
            integer(1_050_000),
            ratio(52, 100),
            ratio(51, 100),
        );
        let growth = (Q::one() - &s) * &r;
        assert_eq!(
            honest_growth_race(&g, &r, &s, &growth).crossing_time(&t),
            base_race(&g, &r, &s).crossing_time(&t)
        );
    }

    #[test]
    fn realistic_online_fraction_lets_a_minority_issuer_reach_majority() {
        // With f = 0.5, s > 0.3423 suffices in the long run.
        let threshold = ratio(51, 100);
        let reach = realistic_online_race(
            &integer(2_100_000),
            &integer(1_051_200),
            &ratio(35, 100),
            &ratio(1, 2),
        )
        .crossing_time(&threshold);
        assert!(matches!(reach, Reach::After(_)));
        assert!(long_run_share_realistic(&ratio(35, 100), &ratio(1, 2)) > threshold);
        assert!(long_run_share_realistic(&ratio(34, 100), &ratio(1, 2)) < threshold);
    }

    #[test]
    fn five_percent_issuer_settles_near_9_5_percent_when_half_of_honest_ids_are_online() {
        let share = long_run_share_realistic(&ratio(5, 100), &ratio(1, 2));
        assert_eq!(share, ratio(2, 21));
    }

    #[test]
    fn frozen_cap_with_full_capture_takes_t_over_one_minus_t() {
        assert_eq!(
            cap_frozen_time(&Q::one(), &ratio(51, 100)),
            Reach::After(ratio(51, 49))
        );
    }

    #[test]
    fn aligned_checkpoint_every_t_min_takes_50_over_49() {
        let rho = Q::one() / (Q::one() - ratio(51, 100));
        assert_eq!(
            cap_checkpoint_time_exact(&rho, &Q::one(), &Q::one()),
            ratio(50, 49)
        );
    }

    #[test]
    fn worst_phase_for_checkpoint_every_t_min_is_six_sevenths() {
        let worst = cap_checkpoint_worst_phase(100.0 / 49.0, 1.0);
        assert!((worst.time - 6.0 / 7.0).abs() < 1e-12);
        // Optimal first checkpoint: 1 + w = sqrt(rho) = 10/7.
        assert!((worst.first_checkpoint - 3.0 / 7.0).abs() < 1e-12);
    }

    #[test]
    fn worst_phase_is_never_slower_than_the_aligned_start() {
        for interval in [0.25, 0.5, 1.0] {
            let rho = 100.0 / 49.0;
            let worst = cap_checkpoint_worst_phase(rho, interval).time;
            assert!(worst <= cap_checkpoint_time(rho, interval, interval) + 1e-15);
            assert!(worst >= cap_continuous_time(rho) - 1e-12);
        }
    }

    #[test]
    fn safety_factors_match_the_plan_values() {
        let rho = 100.0 / 49.0;
        assert!((cap_safety_factor(rho, Some(1.0)) - 7.0 / 6.0).abs() < 1e-9);
        assert!((cap_safety_factor(rho, None) - 1.0 / libm::log(rho)).abs() < 1e-15);
        let half = cap_safety_factor(rho, Some(0.5));
        let quarter = cap_safety_factor(rho, Some(0.25));
        assert!((1.2..1.25).contains(&half), "{half}");
        assert!((1.27..1.32).contains(&quarter), "{quarter}");
    }

    #[test]
    fn scaled_time_increases_with_the_safety_factor() {
        let rho = 100.0 / 49.0;
        let scaled = |k: f64| k * cap_checkpoint_worst_phase(rho, 0.5 / k).time;
        let values: Vec<f64> = (80..=160).map(|i| scaled(f64::from(i) / 100.0)).collect();
        assert!(values.windows(2).all(|w| w[1] >= w[0]));
    }

    #[test]
    fn spec_default_safety_factor_restores_the_floor_exactly() {
        // k = 7/6 with checkpoints every T_min: 7/6 × 6/7 = 1 (module documentation).
        let worst = cap_scaled_worst_phase(100.0 / 49.0, 1.0, 7.0 / 6.0);
        assert!((worst.time - 1.0).abs() < 1e-12, "{}", worst.time);
        let floor = configured_cap_floor(&Config::default()).unwrap();
        assert!((floor.time - 1.0).abs() < 1e-12);
    }

    #[test]
    fn a_larger_safety_factor_only_lengthens_the_worst_time() {
        let rho = 100.0 / 49.0;
        let at = |k| cap_scaled_worst_phase(rho, 1.0, k).time;
        assert!(at(1.0) < at(7.0 / 6.0) && at(7.0 / 6.0) < at(1.5));
        assert!((at(1.0) - 6.0 / 7.0).abs() < 1e-12);
    }

    #[test]
    fn cap_table_has_safety_factor_and_configured_rows() {
        let config = Config::default();
        let a = section_a(&config).unwrap();
        let floor_rows: Vec<_> = a
            .cap
            .iter()
            .filter(|r| r.attacker_share == 1.0 && r.threshold == 0.51)
            .collect();
        let configured = floor_rows
            .iter()
            .find(|r| r.model == CAP_CONFIGURED)
            .unwrap();
        assert!((configured.time_in_t_min.unwrap() - 1.0).abs() < 1e-12);
        let with_k: Vec<_> = floor_rows
            .iter()
            .filter(|r| r.model == CAP_WITH_SAFETY_FACTOR)
            .collect();
        assert_eq!(with_k.len(), 3);
        assert!(
            with_k
                .iter()
                .all(|r| (r.time_in_t_min.unwrap() - 1.0).abs() < 1e-8)
        );
    }

    #[test]
    fn genesis_needed_for_two_year_floor_at_full_activity_is_about_2_02_million() {
        let issue = genesis_to_issue(&integer(2), &integer(1_051_200), &ratio(51, 100), &Q::one());
        assert!((to_f64(&issue) - 2_019_952.941_176_470_6).abs() < 1e-6);
    }

    #[test]
    fn section_a_tables_cover_the_whole_grid() {
        let config = Config::default();
        let a = section_a(&config).unwrap();
        let grid = &config.analytic.time_to_threshold;
        let combos = grid.genesis_ids.len() * grid.attacker_shares.len() * grid.thresholds.len();
        assert_eq!(a.thresholds.len(), combos);
        assert_eq!(a.online.len(), 2 * combos * grid.online_fractions.len());
        assert_eq!(
            a.long_run.len(),
            grid.attacker_shares.len() * grid.online_fractions.len()
        );
        let never = a
            .thresholds
            .iter()
            .filter(|r| r.outcome == "never reached")
            .count();
        assert!(
            never > 0
                && a.thresholds
                    .iter()
                    .all(|r| r.years.is_some() == (r.outcome == "reached"))
        );
    }

    #[test]
    fn all_section_a_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.issuance_replicates = 100;
        for check in checks(&config).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
