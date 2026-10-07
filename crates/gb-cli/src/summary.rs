//! `SUMMARY.md`: a plain-English summary of every M1 table.
//!
//! Every number is read from the computed tables. A sentence that states a comparison or a
//! pattern is only written after the code has checked that it holds. The file contains no
//! timestamp, so a rerun at the same commit, seed and configuration produces the same bytes.

use crate::charts::{compact_number, short_count, superscript};
use gb_analytic::M1Results;
use gb_analytic::allocation::{SeatRule, absence_models};
use gb_analytic::cac::{CommitteeModel, OddsRow};
use gb_analytic::kwc_size::{LoadPolicy, SectionI, policy_c_registered};
use gb_analytic::quorum_feasibility::{AbsentSeatRow, REGISTERED, SectionH, UNREGISTERED};
use gb_analytic::quorum_tradeoff::{POOL_LAYOUT, QuorumRow, REGISTERED_LAYOUT, SeatRuleQuorumRow};
use gb_analytic::restart::{REALISTIC_COST, realistic_restart_cost_s};
use gb_analytic::time_threshold::{CAP_CONFIGURED, CAP_WITH_SAFETY_FACTOR, CapRow};
use gb_analytic::validation::Check;
use gb_analytic::witness::{CompositionRow, KwcState, SeatRuleRow};
use gb_config::Config;
use std::collections::BTreeMap;

/// The worst-case disclosure required at the top of section 1 (architect, 2026-10-06).
pub const DISCLOSURE: &str = "All M1 results assume the attacker's IDs are online 100% of the time while honest IDs are online a fraction f of the time. This is a deliberate worst case; M3 adds realistic outages for both sides.";

/// Provenance printed at the top of the summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Git commit, if known.
    pub commit: Option<String>,
    /// True when the working tree had uncommitted changes.
    pub dirty: bool,
    /// Master seed.
    pub seed: u64,
    /// SHA-256 of the resolved configuration.
    pub config_sha256: String,
}

/// Renders `SUMMARY.md`.
pub fn render(config: &Config, results: &M1Results, provenance: &Provenance) -> String {
    let mut out = String::new();
    header(&mut out, config, provenance);
    honest_majority(&mut out, config, results);
    majority_issuance(&mut out, results);
    worst_case(&mut out, config, results);
    honest_growth(&mut out, results);
    witness_chains(&mut out, config, results);
    committee(&mut out, config, results);
    restart(&mut out, results);
    hopping(&mut out, results);
    ties(&mut out, results);
    quorum_tradeoff(&mut out, config, results);
    quorum_feasibility(&mut out, config, results);
    kwc_size_tradeoff(&mut out, config, results);
    cross_checks(&mut out, results);
    closing(&mut out);
    out
}

// ----------------------------------------------------------------------------- formatting

fn line(out: &mut String, text: &str) {
    out.push_str(text);
    out.push('\n');
}

fn blank(out: &mut String) {
    out.push('\n');
}

fn table(out: &mut String, headers: &[String], rows: &[Vec<String>]) {
    line(out, &format!("| {} |", headers.join(" | ")));
    line(out, &format!("|{}", "---|".repeat(headers.len())));
    for row in rows {
        line(out, &format!("| {} |", row.join(" | ")));
    }
    blank(out);
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// Three significant digits in fixed notation, for example `97.1`, `1.98`, `0.990`.
pub(crate) fn sig3(value: f64) -> String {
    if value == 0.0 || !value.is_finite() {
        return compact_number(value);
    }
    let magnitude = libm::floor(libm::log10(value.abs())) as i32;
    let decimals = (2 - magnitude).max(0) as usize;
    let text = format!("{value:.decimals$}");
    if value.abs() >= 1_000.0 {
        compact_number(value)
    } else {
        text
    }
}

fn years(value: Option<f64>) -> String {
    value.map_or("never".to_string(), sig3)
}

/// A computed share as a percentage with three significant digits. Values just below 100%
/// are written `> 99.9%` so they are not mistaken for certainty.
pub(crate) fn pct(value: f64) -> String {
    if (0.9995..1.0).contains(&value) {
        "> 99.9%".to_string()
    } else {
        format!("{}%", sig3(100.0 * value))
    }
}

/// A multiple of T_min in words: `T_min` for 1, otherwise for example `0.5 T_min`.
pub(crate) fn t_min_multiple(x: f64) -> String {
    if x == 1.0 {
        "T_min".to_string()
    } else {
        format!("{} T_min", compact_number(x))
    }
}

/// An input share from the configuration grid, for example `5%` or `33%`.
pub(crate) fn share(value: f64) -> String {
    format!("{}%", compact_number(100.0 * value))
}

/// A share as a percentage with one decimal, for example `9.5%`.
fn pct1(value: f64) -> String {
    format!("{:.1}%", 100.0 * value)
}

/// Probability from an exact scientific string: a percentage when at least 1%, otherwise
/// `m.mm × 10ⁿ`. Values that round to 100% are written `> 99.9%`: the tables keep six
/// significant digits, so they cannot show how far below 1 such a value is.
pub(crate) fn prob(scientific: &str) -> String {
    prob_digits(scientific, 3)
}

/// [`prob`] with `digits` significant digits.
fn prob_digits(scientific: &str, digits: usize) -> String {
    let Some((mantissa, exponent)) = scientific.split_once('e') else {
        return scientific.to_string();
    };
    let (Ok(m), Ok(e)) = (mantissa.parse::<f64>(), exponent.parse::<i64>()) else {
        return scientific.to_string();
    };
    if e >= -2 {
        let value = m * libm::pow(10.0, e as f64);
        if value >= 0.9995 {
            return "> 99.9%".to_string();
        }
        let percent = 100.0 * value;
        let magnitude = libm::floor(libm::log10(percent.abs())) as i64;
        let decimals = (digits as i64 - 1 - magnitude).max(0) as usize;
        format!("{percent:.decimals$}%")
    } else {
        let decimals = digits.saturating_sub(1);
        format!("{m:.decimals$} × 10{}", superscript(e))
    }
}

/// Two probabilities printed with enough significant digits (at most six, the precision of
/// the tables) that they do not look equal when they differ.
fn prob_pair(a: &str, b: &str) -> (String, String) {
    (3..=6)
        .map(|digits| (prob_digits(a, digits), prob_digits(b, digits)))
        .find(|(x, y)| x != y)
        .unwrap_or_else(|| (prob(a), prob(b)))
}

fn distinct(values: impl Iterator<Item = f64>) -> Vec<f64> {
    let mut seen: Vec<f64> = Vec::new();
    for v in values {
        if !seen.contains(&v) {
            seen.push(v);
        }
    }
    seen
}

// ----------------------------------------------------------------------------- sections

fn header(out: &mut String, config: &Config, provenance: &Provenance) {
    line(out, "# M1 analytical baseline — summary");
    blank(out);
    let commit = match (&provenance.commit, provenance.dirty) {
        (Some(hash), false) => format!("`{hash}` (clean working tree)"),
        (Some(hash), true) => format!("`{hash}` with uncommitted changes"),
        (None, _) => "not a git repository".to_string(),
    };
    line(out, &format!("- Git commit: {commit}"));
    line(
        out,
        &format!(
            "- Seed: {} (used only by the Monte Carlo cross-checks)",
            provenance.seed
        ),
    );
    line(
        out,
        &format!(
            "- Configuration SHA-256: `{}` (`config.resolved.toml`)",
            provenance.config_sha256
        ),
    );
    blank(out);
    line(
        out,
        "These results are exact calculations: closed-form formulas and exact probabilities. They are not a simulation of the network. Seeded Monte Carlo runs appear only as cross-checks of the formulas (section 13). Every number below comes from a CSV table in this directory, and every modelling assumption is listed in `docs/ASSUMPTIONS.md`.",
    );
    blank(out);
    line(
        out,
        &format!(
            "Terms used throughout: the attacker wins a share **s** of newly issued IDs; **G** is the existing base of active IDs (default {} genesis IDs); **R** = {} new IDs per year (one every {} s); **T** is a target share of active IDs; **f** is the fraction of honest IDs that are online.",
            compact_number(config.genesis.ids.value as f64),
            compact_number(config.issuance_per_year()),
            compact_number(config.issuance.pow_id_target_interval_s.value),
        ),
    );
    blank(out);
}

fn honest_majority(out: &mut String, config: &Config, results: &M1Results) {
    line(out, "## 1. Attackers that win less than half of new IDs");
    blank(out);
    line(out, &format!("> {DISCLOSURE}"));
    blank(out);
    line(
        out,
        "Tables `A7_long_run_share.csv` and `A2_online_fraction.csv`; charts `A7_long_run_share.png`, `A5_share_trajectories.png`.",
    );
    blank(out);
    line(
        out,
        "An attacker that wins a share s of new IDs sees its share of active IDs rise towards a long-run value and never above it. If only a fraction f of honest IDs is online, applied to old and new honest IDs alike (the realistic variant), the long-run share is s / (s + f(1 − s)). If every honest ID is online, it is s.",
    );
    blank(out);
    let rows = &results.a.long_run;
    let online = distinct(rows.iter().map(|r| r.online_fraction));
    let low_f = online.iter().copied().fold(f64::INFINITY, f64::min);
    let shares: Vec<f64> = distinct(rows.iter().map(|r| r.attacker_share))
        .into_iter()
        .filter(|s| *s < 0.5)
        .collect();
    for s in &shares {
        let at = |f: f64| {
            rows.iter()
                .find(|r| r.attacker_share == *s && r.online_fraction == f)
        };
        let (Some(full), Some(low)) = (at(1.0), at(low_f)) else {
            continue;
        };
        line(
            out,
            &format!(
                "- An attacker winning {} of new IDs settles at about {} of active IDs when every honest ID is online ({}), and at about {} when {} of honest IDs are online ({}).",
                share(*s),
                pct1(full.long_run_share),
                crossing_phrase(&full.thresholds_eventually_crossed),
                pct1(low.long_run_share),
                share(low_f),
                crossing_phrase(&low.thresholds_eventually_crossed)
            ),
        );
    }
    blank(out);
    line(
        out,
        "**Long-run attacker share of active IDs** (realistic variant):",
    );
    blank(out);
    let mut headers = vec!["s".to_string()];
    let mut columns = online.clone();
    columns.sort_by(|a, b| b.total_cmp(a));
    headers.extend(columns.iter().map(|f| format!("f = {}", share(*f))));
    let body: Vec<Vec<String>> = shares
        .iter()
        .map(|s| {
            let mut row = vec![share(*s)];
            row.extend(columns.iter().map(|f| {
                rows.iter()
                    .find(|r| r.attacker_share == *s && r.online_fraction == *f)
                    .map_or("—".to_string(), |r| pct1(r.long_run_share))
            }));
            row
        })
        .collect();
    table(out, &headers, &body);
    honest_majority_times(out, config, results, &shares, low_f);
}

/// "never reaching 33%" or "eventually crossing 33% and 51%", from the A7 threshold list.
fn crossing_phrase(crossed: &str) -> String {
    if crossed == "none" {
        "never reaching 33%".to_string()
    } else {
        format!("eventually crossing {}", crossed.replace("; ", " and "))
    }
}

fn honest_majority_times(
    out: &mut String,
    config: &Config,
    results: &M1Results,
    shares: &[f64],
    low_f: f64,
) {
    let genesis = config.genesis.ids.value;
    let rows = &results.a.online;
    let find = |variant: &str, s: f64, f: f64, t: f64| {
        rows.iter().find(|r| {
            r.variant == variant
                && r.genesis_ids == genesis
                && r.attacker_share == s
                && r.online_fraction == f
                && r.threshold == t
        })
    };
    let thresholds = distinct(rows.iter().map(|r| r.threshold));
    let mid_f = if (0.7 - low_f).abs() > 1e-12 && rows.iter().any(|r| r.online_fraction == 0.7) {
        Some(0.7)
    } else {
        None
    };
    line(
        out,
        &format!(
            "**Years to reach each threshold, G = {}** (realistic variant; \"never\" means never reached):",
            short_count(genesis)
        ),
    );
    blank(out);
    let mut columns: Vec<(f64, f64)> = Vec::new();
    for t in &thresholds {
        columns.push((*t, 1.0));
        if let Some(m) = mid_f {
            columns.push((*t, m));
        }
        columns.push((*t, low_f));
    }
    let mut headers = vec!["s".to_string()];
    headers.extend(
        columns
            .iter()
            .map(|(t, f)| format!("{} at f = {}", share(*t), share(*f))),
    );
    let body: Vec<Vec<String>> = shares
        .iter()
        .map(|s| {
            let mut row = vec![share(*s)];
            row.extend(columns.iter().map(|(t, f)| {
                find("realistic", *s, *f, *t).map_or("—".to_string(), |r| years(r.years))
            }));
            row
        })
        .collect();
    table(out, &headers, &body);
    let optimistic_never = shares.iter().all(|s| {
        rows.iter()
            .filter(|r| {
                r.variant == "optimistic bound" && r.attacker_share == *s && r.threshold >= 0.5
            })
            .all(|r| r.years.is_none())
    });
    if optimistic_never {
        line(
            out,
            "Under the M1 brief's formulation, the optimistic bound, f reduces only the historical base and new honest IDs are always online. The long-run share is then exactly s, so none of these attackers ever reaches 51% or 67% (table `A2_online_fraction.csv`, variant \"optimistic bound\").",
        );
        blank(out);
    }
}

fn majority_issuance(out: &mut String, results: &M1Results) {
    line(out, "## 2. Attackers that win more than half of new IDs");
    blank(out);
    line(
        out,
        "Table `A1_time_to_threshold.csv`; chart `A1_time_to_threshold.png`. Base model: every honest ID is online.",
    );
    blank(out);
    let rows = &results.a.thresholds;
    let genesis = distinct(rows.iter().map(|r| r.genesis_ids as f64));
    let shares: Vec<f64> = distinct(rows.iter().map(|r| r.attacker_share))
        .into_iter()
        .filter(|s| *s > 0.5 && *s < 1.0)
        .collect();
    for t in distinct(rows.iter().map(|r| r.threshold))
        .into_iter()
        .filter(|t| *t > 0.5)
    {
        line(
            out,
            &format!(
                "**Years until the attacker holds {} of active IDs:**",
                share(t)
            ),
        );
        blank(out);
        let mut headers = vec!["s".to_string()];
        headers.extend(
            genesis
                .iter()
                .map(|g| format!("G = {}", short_count(*g as u64))),
        );
        let body: Vec<Vec<String>> = shares
            .iter()
            .map(|s| {
                let mut row = vec![share(*s)];
                row.extend(genesis.iter().map(|g| {
                    rows.iter()
                        .find(|r| {
                            r.attacker_share == *s && r.threshold == t && r.genesis_ids as f64 == *g
                        })
                        .map_or("—".to_string(), |r| years(r.years))
                }));
                row
            })
            .collect();
        table(out, &headers, &body);
    }
    line(
        out,
        "The time grows in proportion to G and shrinks as s moves away from T. When s equals T exactly, T is never reached in finite time.",
    );
    blank(out);
}

fn worst_case(out: &mut String, config: &Config, results: &M1Results) {
    line(
        out,
        "## 3. Worst-case bounds: an attacker that wins every new ID",
    );
    blank(out);
    line(
        out,
        "Everything in this section is a **worst-case bound**. It assumes the attacker wins 100% of new IDs and every honest ID stays online. The exact time is (T/(1−T)) × G/R, the SPEC §0 C2 floor.",
    );
    blank(out);
    let rows = &results.a.thresholds;
    let genesis = distinct(rows.iter().map(|r| r.genesis_ids as f64));
    let thresholds = distinct(rows.iter().map(|r| r.threshold));
    let mut headers = vec!["G".to_string()];
    headers.extend(thresholds.iter().map(|t| format!("years to {}", share(*t))));
    let body: Vec<Vec<String>> = genesis
        .iter()
        .map(|g| {
            let mut row = vec![short_count(*g as u64)];
            row.extend(thresholds.iter().map(|t| {
                rows.iter()
                    .find(|r| {
                        r.attacker_share == 1.0 && r.threshold == *t && r.genesis_ids as f64 == *g
                    })
                    .map_or("—".to_string(), |r| years(r.years))
            }));
            row
        })
        .collect();
    line(
        out,
        "**Fixed 30 s rate, 100% capture** (table `A1_time_to_threshold.csv`, rows s = 100%):",
    );
    blank(out);
    table(out, &headers, &body);
    genesis_floor(out, config, results);
    adaptive_cap(out, results);
}

fn genesis_floor(out: &mut String, config: &Config, results: &M1Results) {
    let rows = &results.a.genesis;
    let floors = distinct(rows.iter().map(|r| r.t_min_years));
    let online = distinct(rows.iter().map(|r| r.online_fraction));
    line(
        out,
        "**Genesis IDs to issue so that the floor holds at the fixed rate** (table `A6_genesis_to_issue.csv`, chart `A6_genesis_to_issue.png`). A 100%-capture attacker needs at least T_min to reach 51% only if the active base is at least T_min × R × 0.49/0.51. If only a fraction f of genesis IDs stays active, the number to issue is that base ÷ f:",
    );
    blank(out);
    let mut headers = vec!["active fraction f".to_string()];
    headers.extend(
        floors
            .iter()
            .map(|t| format!("T_min = {} yr", compact_number(*t))),
    );
    let mut online_sorted = online.clone();
    online_sorted.sort_by(|a, b| b.total_cmp(a));
    let body: Vec<Vec<String>> = online_sorted
        .iter()
        .map(|f| {
            let mut row = vec![share(*f)];
            row.extend(floors.iter().map(|t| {
                rows.iter()
                    .find(|r| r.t_min_years == *t && r.online_fraction == *f)
                    .map_or("—".to_string(), |r| {
                        format!("{}M", sig3(r.genesis_ids_to_issue / 1e6))
                    })
            }));
            row
        })
        .collect();
    table(out, &headers, &body);
    let default_genesis = config.genesis.ids.value as f64;
    let floor = config.issuance.min_attack_time_floor_years.value;
    if let Some(needed) = rows
        .iter()
        .find(|r| r.t_min_years == floor && r.online_fraction == 1.0)
        .map(|r| r.active_ids_needed)
    {
        line(
            out,
            &format!(
                "With {} genesis IDs issued, the {}-year floor at the fixed rate needs {} of them active, so it holds only while at least {} of genesis IDs stay active.",
                short_count(default_genesis as u64),
                compact_number(floor),
                short_count(needed.round() as u64),
                pct1(needed / default_genesis)
            ),
        );
        blank(out);
    }
}

fn adaptive_cap(out: &mut String, results: &M1Results) {
    let floor_t = results
        .a
        .safety
        .first()
        .map(|r| r.threshold)
        .unwrap_or(0.51);
    let rows: Vec<_> = results
        .a
        .cap
        .iter()
        .filter(|r| r.attacker_share == 1.0 && r.threshold == floor_t)
        .collect();
    line(
        out,
        &format!(
            "**Adaptive cap R ≤ registered IDs / (k × T_min) (SPEC §3.9, an optional variant; the fixed 30 s rate stays the default): time for a 100%-capture attacker to reach {}, in units of T_min** (table `A4_adaptive_cap.csv`, chart `A4_adaptive_cap.png`). \"Worst start\" is the fastest time over all possible start moments relative to the public checkpoint schedule.",
            share(floor_t)
        ),
    );
    blank(out);
    let model_rows = |model: &str| -> Vec<&CapRow> {
        rows.iter().copied().filter(|r| r.model == model).collect()
    };
    let at_interval = |model: &str, fraction: Option<f64>| {
        model_rows(model)
            .into_iter()
            .find(|w| w.checkpoint_interval_fraction_of_t_min == fraction)
    };
    let mut body = Vec::new();
    for r in model_rows("frozen") {
        body.push(vec![
            "cap frozen at attack start".to_string(),
            years(r.time_in_t_min),
            "—".to_string(),
            "—".to_string(),
        ]);
    }
    for r in model_rows("continuous") {
        body.push(vec![
            "recalculated continuously".to_string(),
            years(r.time_in_t_min),
            years(r.time_in_t_min),
            "—".to_string(),
        ]);
    }
    for aligned in model_rows("checkpoint aligned") {
        let fraction = aligned.checkpoint_interval_fraction_of_t_min;
        let worst = at_interval("checkpoint worst phase", fraction);
        let with_k = at_interval(CAP_WITH_SAFETY_FACTOR, fraction);
        body.push(vec![
            format!(
                "checkpoint every {} T_min",
                fraction.map_or("?".to_string(), compact_number)
            ),
            years(aligned.time_in_t_min),
            worst.map_or("—".to_string(), |w| years(w.time_in_t_min)),
            with_k.map_or("—".to_string(), |w| {
                format!(
                    "{} (k = {:.4})",
                    years(w.time_in_t_min),
                    w.safety_factor.unwrap_or(f64::NAN)
                )
            }),
        ]);
    }
    table(
        out,
        &strings(&[
            "cap recalculation",
            "start at a checkpoint, k = 1",
            "worst start, k = 1",
            "worst start, with safety factor k",
        ]),
        &body,
    );
    let holds: Vec<String> = body
        .iter()
        .filter(|row| row[2] == "—" || row[2].parse::<f64>().is_ok_and(|v| v >= 1.0))
        .filter(|row| row[1].parse::<f64>().is_ok_and(|v| v >= 1.0))
        .map(|row| row[0].clone())
        .collect();
    let holds_text = if holds.is_empty() {
        "none of these".to_string()
    } else {
        holds.join("; ")
    };
    line(
        out,
        &format!(
            "Times at or above 1.00 meet the floor. Without a safety factor (k = 1) the floor holds at every start moment only for: {holds_text}. The safety factor k for each checkpoint interval (table `A4_safety_factor.csv`):"
        ),
    );
    blank(out);
    let safety: Vec<Vec<String>> = results
        .a
        .safety
        .iter()
        .map(|r| {
            let model = match r.checkpoint_interval_fraction_of_t_min {
                Some(f) => format!("checkpoint every {} T_min", compact_number(f)),
                None => r.model.to_string(),
            };
            vec![
                model,
                sig3(r.worst_time_in_t_min_without_factor),
                format!("{:.4}", r.safety_factor),
            ]
        })
        .collect();
    table(
        out,
        &strings(&["cap", "worst time / T_min with k = 1", "safety factor k"]),
        &safety,
    );
    if let Some(configured) = model_rows(CAP_CONFIGURED).first() {
        line(
            out,
            &format!(
                "**SPEC v0.3 default:** k = {:.4} with checkpoints every {}. Its worst-start time is {} T_min, so a 100%-capture attacker cannot reach {} in less than T_min at any start phase (cross-checks `A-cap-configured-floor` and `A-cap-configured-vs-grid`). A factor k above 1 tightens the cap; below 1, the floor already holds with room to spare.",
                configured.safety_factor.unwrap_or(f64::NAN),
                configured
                    .checkpoint_interval_fraction_of_t_min
                    .map_or("?".to_string(), t_min_multiple),
                configured
                    .time_in_t_min
                    .map_or("—".to_string(), |t| format!("{t:.3}")),
                share(floor_t)
            ),
        );
        blank(out);
    }
}

fn honest_growth(out: &mut String, results: &M1Results) {
    line(out, "## 4. Honest active-base growth");
    blank(out);
    line(
        out,
        "Table `A3_honest_growth.csv`. In the architect's general form, honest active IDs grow by g per year while the attacker gains s × R. Setting g = (1 − s)R is the base model. A larger g only slows the attacker: it reaches T in finite time only if s > T·g / (R(1 − T)).",
    );
    blank(out);
    let rows = &results.a.growth;
    let thresholds = distinct(rows.iter().map(|r| r.threshold));
    let mut growth_labels: Vec<String> = Vec::new();
    for r in rows.iter().filter(|r| !r.growth.contains("base")) {
        if !growth_labels.contains(&r.growth) {
            growth_labels.push(r.growth.clone());
        }
    }
    let mut headers = vec!["growth g".to_string()];
    headers.extend(
        thresholds
            .iter()
            .map(|t| format!("minimum s to reach {}", share(*t))),
    );
    let body: Vec<Vec<String>> = growth_labels
        .iter()
        .map(|g| {
            let label = if g == "0R" {
                "0 (no growth)".to_string()
            } else {
                g.replace("R", " × R")
            };
            let mut row = vec![label];
            row.extend(thresholds.iter().map(|t| {
                rows.iter()
                    .find(|r| &r.growth == g && r.threshold == *t)
                    .map_or("—".to_string(), |r| {
                        if r.minimum_share_for_finite_time >= 1.0 {
                            "impossible (above 100%)".to_string()
                        } else if r.minimum_share_for_finite_time == 0.0 {
                            "any s > 0".to_string()
                        } else {
                            pct(r.minimum_share_for_finite_time)
                        }
                    })
            }));
            row
        })
        .collect();
    table(out, &headers, &body);
}

fn witness_chains(out: &mut String, config: &Config, results: &M1Results) {
    line(
        out,
        "## 5. Witness Chains: chance an attacker controls a KWC",
    );
    blank(out);
    line(
        out,
        "Tables `B1_kwc_probabilities.csv`, `B2_network_counts.csv`, `B3_binomial_vs_hypergeometric.csv`, `B4_kwc_compositions_10y.csv`, `B5_seat_rule_10y.csv`; charts `B1_kwc_probabilities.png`, `B4_kwc_compositions_10y.png`. The attacker controls a fraction p of registered IDs, and seats are assigned uniformly at random. A 40-node KWC is a 10-seat leader WC plus 30 subordinate seats.",
    );
    blank(out);
    line(
        out,
        "**What each state lets the attacker do.** This follows from the SPEC rules; it is not a simulation result.",
    );
    blank(out);
    table(
        out,
        &strings(&[
            "state",
            "registered quorum (7 of 10 and 21 of 30)",
            "unregistered quorum (any 27 of 40)",
            "harms it enables",
            "harms it does not enable",
        ]),
        &[
            strings(&[
                "(i) block",
                "≥ 4 leader or ≥ 10 subordinate seats",
                "≥ 14 seats",
                "stalling the KWC; censoring miners in that KWC (they can move to another KWC after the grace epoch)",
                "signing anything",
            ]),
            strings(&[
                "(ii) sign without honest members",
                "≥ 7 leader and ≥ 21 subordinate seats",
                "≥ 27 seats",
                "the same stalling and censoring",
                "making an early-signed block valid: §3.7 global validation rejects a block received before its own timestamp (within the clock tolerance δ)",
            ]),
            strings(&[
                "(iii) every seat",
                "all 40",
                "all 40",
                "stalling, censoring and entropy grinding (the entropy aggregate then contains only attacker signatures)",
                "—",
            ]),
        ],
    );
    kwc_probability_table(out, results);
    kwc_network_table(out, results);
    kwc_ten_year_table(out, results);
    seat_rule_table(out, config, results);
    kwc_model_comparison(out, results);
}

fn kwc_probability_table(out: &mut String, results: &M1Results) {
    let rows: Vec<_> = results
        .b
        .kwc
        .iter()
        .filter(|r| r.layout == "40-node" && r.model == "hypergeometric" && r.kwcs == Some(100_000))
        .collect();
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    let get = |p: f64, kind: &str, state: KwcState| {
        rows.iter()
            .find(|r| r.attacker_fraction == p && r.miner_kind == kind && r.state == state.label())
            .map_or("—".to_string(), |r| prob(&r.probability))
    };
    line(
        out,
        "**Probability that one KWC is in each state** (exact hypergeometric, 100,000 KWCs):",
    );
    blank(out);
    let body: Vec<Vec<String>> = fractions
        .iter()
        .map(|p| {
            vec![
                share(*p),
                get(*p, "registered", KwcState::Block),
                get(*p, "unregistered", KwcState::Block),
                get(*p, "registered", KwcState::Sign),
                get(*p, "unregistered", KwcState::Sign),
                get(*p, "registered", KwcState::AllSeats),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "p",
            "(i) block, registered",
            "(i) block, unregistered",
            "(ii) sign, registered",
            "(ii) sign, unregistered",
            "(iii) all seats",
        ]),
        &body,
    );
}

fn kwc_network_table(out: &mut String, results: &M1Results) {
    let rows: Vec<_> = results
        .b
        .network
        .iter()
        .filter(|r| r.layout == "40-node" && r.state == KwcState::Sign.label())
        .collect();
    let sizes = distinct(rows.iter().map(|r| r.kwcs as f64));
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    line(
        out,
        "**Expected number of KWCs in state (ii) at one moment** (= number of KWCs × per-KWC probability). The chance that at least one exists is in `B2_network_counts.csv`, with a rigorous upper bound (independence value) and lower bound (KWCs sharing no WC).",
    );
    blank(out);
    let mut headers = vec!["p".to_string()];
    for kind in ["registered", "unregistered"] {
        headers.extend(
            sizes
                .iter()
                .map(|w| format!("{kind}, {} KWCs", short_count(*w as u64))),
        );
    }
    let body: Vec<Vec<String>> = fractions
        .iter()
        .map(|p| {
            let mut row = vec![share(*p)];
            for kind in ["registered", "unregistered"] {
                row.extend(sizes.iter().map(|w| {
                    rows.iter()
                        .find(|r| {
                            r.attacker_fraction == *p && r.miner_kind == kind && r.kwcs as f64 == *w
                        })
                        .map_or("—".to_string(), |r| count(&r.expected_kwcs))
                }));
            }
            row
        })
        .collect();
    table(out, &headers, &body);
}

/// A count or rate from an exact scientific string: three significant digits from 0.01
/// upwards, `m.mm × 10ⁿ` below.
fn count(scientific: &str) -> String {
    let value: f64 = scientific.parse().unwrap_or(f64::NAN);
    if value >= 0.01 {
        sig3(value)
    } else {
        prob(scientific).replace('%', "")
    }
}

/// A count from an `f64`, written as [`count`] writes exact strings.
fn num(value: f64) -> String {
    count(&format!("{value:e}"))
}

fn kwc_ten_year_table(out: &mut String, results: &M1Results) {
    let rows = &results.b.compositions;
    let horizon = rows.first().map(|r| r.horizon_years).unwrap_or(10.0);
    let base: Vec<&CompositionRow> = rows
        .iter()
        .filter(|r| r.initial_kwcs == 100_000 && r.ban_rate_per_year == 0.0)
        .collect();
    let Some(first) = base.first() else {
        return;
    };
    line(
        out,
        &format!(
            "**KWCs able to sign without honest members over {} years** (table `B4_kwc_compositions_10y.csv`, chart `B4_kwc_compositions_10y.png`; SPEC v0.4 §10 H6). The primary measure is the expected number of **distinct episodes**: an episode starts when a change of membership moves a KWC into state (ii), and lasts while it stays there. Under the adopted allocation (SPEC §4.2) each new ID changes one existing WC, so the 4 KWCs it sits in, and one new ID in 10 completes a WC whose KWC forms while 6 others relink: about 4.7 changed compositions per new ID. With 100,000 KWCs at the start and no bans or absences, that is {} compositions. Counting every composition as an independent draw, as M1.1 did, gives an upper bound on episodes. The v0.2 count, one new KWC per 10 new IDs ({} compositions), is a comparison:",
            compact_number(horizon),
            compact_number(first.compositions),
            compact_number(first.compositions_v02_comparison)
        ),
    );
    blank(out);
    let fractions = distinct(base.iter().map(|r| r.attacker_fraction));
    let get = |p: f64, kind: &str, pick: fn(&CompositionRow) -> f64| {
        base.iter()
            .find(|r| r.attacker_fraction == p && r.miner_kind == kind)
            .map_or("—".to_string(), |r| num(pick(r)))
    };
    let body: Vec<Vec<String>> = fractions
        .iter()
        .map(|p| {
            vec![
                share(*p),
                get(*p, "registered", |r| r.expected_sign_episodes),
                get(*p, "unregistered", |r| r.expected_sign_episodes),
                get(*p, "registered", |r| {
                    r.expected_sign_compositions_upper_bound
                }),
                get(*p, "unregistered", |r| {
                    r.expected_sign_compositions_upper_bound
                }),
                get(*p, "registered", |r| r.expected_sign_v02_comparison),
                get(*p, "unregistered", |r| r.expected_sign_v02_comparison),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "p",
            "episodes, registered quorum (PoW-Tx)",
            "episodes, unregistered quorum (PoW-ID)",
            "upper bound, registered",
            "upper bound, unregistered",
            "v0.2 count, registered",
            "v0.2 count, unregistered",
        ]),
        &body,
    );
    let at = |kind: &str| {
        base.iter()
            .find(|r| r.attacker_fraction == 0.25 && r.miner_kind == kind)
    };
    if let (Some(registered), Some(unregistered)) = (at("registered"), at("unregistered")) {
        line(
            out,
            &format!(
                "Episodes are fewer than compositions because consecutive compositions of a KWC share all but one seat. At p = 25% a one-seat change enters state (ii) with {} (registered) and {} (unregistered) times the probability of a fresh draw (column `one_seat_entry_ratio`); the unregistered count is {} episodes against an upper bound of {}.",
                sig3(registered.one_seat_entry_ratio),
                sig3(unregistered.one_seat_entry_ratio),
                num(unregistered.expected_sign_episodes),
                num(unregistered.expected_sign_compositions_upper_bound)
            ),
        );
        blank(out);
    }
    let bans: Vec<f64> = distinct(rows.iter().map(|r| r.ban_rate_per_year))
        .into_iter()
        .filter(|b| *b > 0.0)
        .collect();
    let parts: Vec<String> = bans
        .iter()
        .filter_map(|ban| {
            rows.iter()
                .find(|r| {
                    r.initial_kwcs == 100_000
                        && r.ban_rate_per_year == *ban
                        && r.miner_kind == "unregistered"
                        && r.attacker_fraction == 0.25
                })
                .map(|r| {
                    format!(
                        "{} of registered IDs banned per year gives {} compositions and {} unregistered episodes at p = 25%",
                        share(*ban),
                        compact_number(r.compositions),
                        num(r.expected_sign_episodes)
                    )
                })
        })
        .collect();
    if !parts.is_empty() {
        line(
            out,
            &format!(
                "Ban sensitivities, without absences: {}. Each ban is a removal, about 4.6 changed compositions.",
                parts.join("; ")
            ),
        );
        blank(out);
    }
}

fn seat_rule_table(out: &mut String, config: &Config, results: &M1Results) {
    let rows = &results.b.seat_rule;
    let models = absence_models(config);
    let (Some(primary), Some(comparison)) = (models.first(), models.get(1)) else {
        return;
    };
    let absence = &config.analytic.absence;
    let slice = |model: &str, c: f64| -> Vec<&SeatRuleRow> {
        rows.iter()
            .filter(|r| {
                r.miner_kind == "unregistered"
                    && r.attacker_fraction == 0.25
                    && r.initial_kwcs == 100_000
                    && r.duration_model == model
                    && r.absences_per_id_per_year == c
            })
            .collect()
    };
    let median = absence.duration_scale_days * (libm::pow(2.0, 1.0 / absence.duration_shape) - 1.0);
    line(
        out,
        &format!(
            "**Seat rule (SPEC v0.4 §4.7)** (table `B5_seat_rule_10y.csv`). Going offline no longer changes seats: an absent or deactivated ID keeps its seat as an offline member, and a seat is vacated only on a ban or after a continuous absence longer than the threshold L. Under v0.3 every absence that deactivated an ID vacated its seat and the ID was re-inserted on return, about 9.3 changed compositions per absence. The absences here are illustrative until M3 supplies household profiles: c absences per ID per year, each long enough to deactivate the ID, with Lomax durations (scale {} days, shape {}: median {} days; {} of absences last longer than 30 days) and, as a comparison, exponential durations with mean {} days. At 100,000 KWCs and p = 25%, unregistered quorum, Lomax durations:",
            compact_number(absence.duration_scale_days),
            compact_number(absence.duration_shape),
            sig3(median),
            pct(primary.survival(30.0)),
            compact_number(absence.comparison_exponential_mean_days)
        ),
    );
    blank(out);
    let rates = &absence.absences_per_id_per_year;
    let mut rules: Vec<String> = Vec::new();
    for r in rows {
        if !rules.contains(&r.seat_rule) {
            rules.push(r.seat_rule.clone());
        }
    }
    let mut headers = strings(&["seat rule", "L in PoW-ID blocks", "absences that vacate"]);
    for c in rates {
        headers.push(format!(
            "c = {}: compositions (share of v0.3)",
            compact_number(*c)
        ));
        headers.push(format!("c = {}: episodes", compact_number(*c)));
    }
    let body: Vec<Vec<String>> = rules
        .iter()
        .filter_map(|rule| {
            let cells: Vec<&SeatRuleRow> = rates
                .iter()
                .filter_map(|c| {
                    slice(primary.label(), *c)
                        .into_iter()
                        .find(|r| r.seat_rule == *rule)
                })
                .collect();
            let first = cells.first()?;
            let mut row = vec![
                rule.clone(),
                first
                    .long_absence_blocks
                    .map_or("—".to_string(), compact_number),
                pct(first.vacating_absences_per_id_per_year / first.absences_per_id_per_year),
            ];
            for r in &cells {
                row.push(format!(
                    "{} ({})",
                    compact_number(r.compositions),
                    pct(r.compositions_ratio_to_v03)
                ));
                row.push(num(r.expected_sign_episodes));
            }
            Some(row)
        })
        .collect();
    table(out, &headers, &body);
    let default_days = config.offline.long_absence_threshold_s.value / 86_400.0;
    let default_rule = SeatRule::V04 {
        long_absence_days: default_days,
    }
    .label();
    let c_max = rates.iter().copied().fold(0.0, f64::max);
    let find = |model: &str| {
        slice(model, c_max)
            .into_iter()
            .find(|r| r.seat_rule == default_rule)
    };
    if let (Some(lomax), Some(exponential)) = (find(primary.label()), find(comparison.label())) {
        line(
            out,
            &format!(
                "With exponential durations fewer absences are long: at the default L = {} days, {} of absences vacate a seat against {} under Lomax, and compositions at c = {} are {} of the v0.3 count (Lomax: {}).",
                compact_number(default_days),
                pct(exponential.vacating_absences_per_id_per_year / c_max),
                pct(lomax.vacating_absences_per_id_per_year / c_max),
                compact_number(c_max),
                pct(exponential.compositions_ratio_to_v03),
                pct(lomax.compositions_ratio_to_v03)
            ),
        );
        blank(out);
    }
    let similar = rows.iter().all(|r| {
        r.compositions_ratio_to_v03 > 0.0
            && (r.episodes_ratio_to_v03 / r.compositions_ratio_to_v03 - 1.0).abs() < 0.1
    });
    if similar {
        line(
            out,
            "In every row of table B5, episodes fall by the same factor as compositions to within 10% (column `episodes_ratio_to_v03`).",
        );
        blank(out);
    }
}

fn kwc_model_comparison(out: &mut String, results: &M1Results) {
    let rows = &results.b.comparison;
    let sizes = distinct(rows.iter().map(|r| r.kwcs as f64));
    line(
        out,
        "**Binomial versus hypergeometric** (`B3_binomial_vs_hypergeometric.csv`). The hypergeometric model is exact for a finite network in which the attacker owns exactly p of the IDs. The binomial model is its infinite-network limit. Largest relative gap at each network size, over all layouts, states and p:",
    );
    blank(out);
    let body: Vec<Vec<String>> = sizes
        .iter()
        .filter_map(|w| {
            rows.iter()
                .filter(|r| r.kwcs as f64 == *w)
                .max_by(|a, b| {
                    a.relative_difference
                        .abs()
                        .total_cmp(&b.relative_difference.abs())
                })
                .map(|r| {
                    vec![
                        short_count(*w as u64),
                        format!("{:+.2}%", 100.0 * r.relative_difference),
                        format!(
                            "{}, {}, {}, p = {}",
                            r.layout,
                            r.miner_kind,
                            r.state,
                            share(r.attacker_fraction)
                        ),
                        r.absolute_difference.clone(),
                    ]
                })
        })
        .collect();
    table(
        out,
        &strings(&["KWCs", "largest relative gap", "where", "absolute gap"]),
        &body,
    );
    let sign_lower = rows
        .iter()
        .filter(|r| r.state != KwcState::Block.label())
        .all(|r| r.relative_difference <= 0.0);
    if sign_lower {
        line(
            out,
            "For states (ii) and (iii), the hypergeometric value is at or below the binomial value in every row. For blocking, the sign of the gap varies with p.",
        );
        blank(out);
    }
    let thirty: Vec<_> = results
        .b
        .kwc
        .iter()
        .filter(|r| {
            r.layout == "30-node" && r.model == "binomial" && r.state == KwcState::Sign.label()
        })
        .collect();
    let forty: Vec<_> = results
        .b
        .kwc
        .iter()
        .filter(|r| {
            r.layout == "40-node" && r.model == "binomial" && r.state == KwcState::Sign.label()
        })
        .collect();
    let compare = |kind: &str, p: f64| {
        let a = forty
            .iter()
            .find(|r| r.miner_kind == kind && r.attacker_fraction == p);
        let b = thirty
            .iter()
            .find(|r| r.miner_kind == kind && r.attacker_fraction == p);
        a.zip(b)
            .map(|(a, b)| (prob(&a.probability), prob(&b.probability)))
    };
    if let (Some((r40, r30)), Some((u40, u30))) =
        (compare("registered", 0.25), compare("unregistered", 0.25))
    {
        line(
            out,
            &format!(
                "30-node comparison (1 leader + 2 subordinate WCs; 7 of 10 and 14 of 20, or any 20 of 30), binomial, p = 25%: state (ii) has probability {r30} (registered) and {u30} (unregistered), against {r40} and {u40} for 40 nodes."
            ),
        );
        blank(out);
    }
}

/// Label of the primary committee model: the lottery with attacker IDs spread through the list.
fn primary_committee_model() -> &'static str {
    CommitteeModel::LotterySpread {
        population: 1,
        attackers: 0,
    }
    .label()
}

/// Label of the block-layout sensitivity of the lottery.
fn block_committee_model() -> &'static str {
    CommitteeModel::LotteryBlock {
        population: 1,
        attackers: 0,
    }
    .label()
}

/// Hours as a readable duration, for example `40 min`, `5.2 h` or `3.1 days`.
fn duration_hours(hours: Option<f64>) -> String {
    match hours {
        None => "never entered".to_string(),
        Some(h) if h < 1.0 => format!("{} min", sig3(60.0 * h)),
        Some(h) if h < 48.0 => format!("{} h", sig3(h)),
        Some(h) if h < 24.0 * 730.0 => format!("{} days", sig3(h / 24.0)),
        Some(h) => format!("{} years", sig3(h / (24.0 * 365.0))),
    }
}

fn committee(out: &mut String, config: &Config, results: &M1Results) {
    line(out, "## 6. Chain Allocation Committee");
    blank(out);
    let primary = primary_committee_model();
    let rows: Vec<&OddsRow> = results
        .c
        .odds
        .iter()
        .filter(|r| r.model == primary)
        .collect();
    let active = rows.first().map_or(0, |r| r.population);
    line(
        out,
        &format!(
            "Tables `C1_cac_probabilities.csv`, `C2_cac_events_per_year.csv`; chart `C1_cac_probabilities.png`. Under SPEC §4.3 a new member joins for every 10th PoW-Tx block by a lottery over the canonical active list ({} active IDs here); a draw that lands on a member moves to the next position. With the attacker's IDs spread through the list, its seat count is hypergeometric, so its expected committee share equals its share p of active IDs. Mining power plays no part. An Allocation Committee Block needs ⌈2n/3⌉ approvals; the attacker stalls with n − ⌈2n/3⌉ + 1 seats and approves alone with ⌈2n/3⌉.",
            short_count(active)
        ),
    );
    blank(out);
    let sizes = distinct(rows.iter().map(|r| r.committee_size as f64));
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    let thresholds: Vec<Vec<String>> = sizes
        .iter()
        .filter_map(|n| rows.iter().find(|r| r.committee_size as f64 == *n))
        .map(|r| {
            vec![
                r.committee_size.to_string(),
                r.approvals_needed.to_string(),
                r.stall_seats.to_string(),
            ]
        })
        .collect();
    table(
        out,
        &strings(&["committee size n", "approvals needed", "seats to stall"]),
        &thresholds,
    );
    for (label, capture) in [("stall", false), ("hold two-thirds (approve alone)", true)] {
        line(
            out,
            &format!("**Probability the attacker can {label}** (lottery):"),
        );
        blank(out);
        let mut headers = vec!["p".to_string()];
        headers.extend(sizes.iter().map(|n| format!("n = {}", compact_number(*n))));
        let body: Vec<Vec<String>> = fractions
            .iter()
            .map(|p| {
                let mut row = vec![share(*p)];
                row.extend(sizes.iter().map(|n| {
                    rows.iter()
                        .find(|r| r.attacker_fraction == *p && r.committee_size as f64 == *n)
                        .map_or("—".to_string(), |r| {
                            prob(if capture { &r.p_capture } else { &r.p_stall })
                        })
                }));
                row
            })
            .collect();
        table(out, &headers, &body);
    }
    committee_events(out, config, results);
    committee_sensitivities(out, config, results);
    committee_departures(out, results);
}

fn committee_events(out: &mut String, config: &Config, results: &M1Results) {
    let size = u64::from(config.cac.size.value);
    let primary = primary_committee_model();
    let rows: Vec<_> = results
        .c
        .events
        .iter()
        .filter(|r| r.committee_size == size && r.model == primary)
        .collect();
    let Some(first) = rows.first() else {
        return;
    };
    line(
        out,
        &format!(
            "**Stalls and captures over time at n = {size}** ({} refreshes per year, one every {} s). Primary measures: the share of time in each state and the exact number of entries into it per year; the mean episode length is the first divided by the second. Since SPEC v0.4 placement takes effect at each ID's beacon block without the committee (§4.2): the Allocation Committee Block is a record and attestation, so a stall delays that record and the compilation of approved bans, never a placement. The M1 brief's estimate (one independent composition per n refreshes) is the last column, for comparison only.",
            compact_number(first.refreshes_per_year),
            compact_number(first.seconds_per_refresh)
        ),
    );
    blank(out);
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    let body: Vec<Vec<String>> = fractions
        .iter()
        .flat_map(|p| {
            rows.iter()
                .filter(move |r| r.attacker_fraction == *p)
                .map(|r| {
                    vec![
                        share(*p),
                        r.state.to_string(),
                        prob(&r.share_of_time),
                        count(&r.entries_per_year_exact),
                        duration_hours(r.mean_episode_hours),
                        count(&r.brief_estimate_events_per_year),
                    ]
                })
        })
        .collect();
    table(
        out,
        &strings(&[
            "p",
            "state",
            "share of time in state",
            "entries per year (exact)",
            "mean episode",
            "brief's estimate, events/yr (comparison)",
        ]),
        &body,
    );
    let time_share = |text: &str| text.parse::<f64>().unwrap_or(0.0);
    let rare_more = rows
        .iter()
        .any(|r| time_share(&r.share_of_time) < 0.5 && r.ratio_exact_to_brief_estimate > 1.0);
    let common_fewer = rows
        .iter()
        .any(|r| time_share(&r.share_of_time) >= 0.5 && r.ratio_exact_to_brief_estimate < 1.0);
    if rare_more {
        let mut text = "A sliding committee changes one seat at a time. Where a state is rare, the committee enters it more often than the brief's estimate assumes".to_string();
        if common_fewer {
            text.push_str("; where it is in the state most of the time, it seldom leaves, so entries are fewer");
        }
        text.push_str(
            ". The mean-episode column shows how long the committee stays in a state once there.",
        );
        line(out, &text);
        blank(out);
    }
}

fn committee_sensitivities(out: &mut String, config: &Config, results: &M1Results) {
    let size = u64::from(config.cac.size.value);
    let find = |model: &str, mu: Option<f64>, p: f64| {
        results.c.odds.iter().find(|r| {
            r.model == model
                && r.committee_size == size
                && r.attacker_fraction == p
                && r.honest_mining_fraction == mu
        })
    };
    let primary = primary_committee_model();
    if let (Some(spread), Some(block)) = (
        find(primary, None, 0.3),
        find(block_committee_model(), None, 0.3),
    ) {
        let (stall_spread, stall_block) = prob_pair(&spread.p_stall, &block.p_stall);
        let (capture_spread, capture_block) = prob_pair(&spread.p_capture, &block.p_capture);
        line(
            out,
            &format!(
                "**Where the attacker's IDs sit in the list.** The canonical list is in registration order, so IDs won in a burst sit next to each other. If all of the attacker's IDs formed one block, a draw landing on a member would pass to a neighbour of the same type, and the seat count would be binomial instead of hypergeometric. At n = {size} and p = 30% the stall probability changes from {stall_spread} to {stall_block}, and the capture probability from {capture_spread} to {capture_block}.",
            ),
        );
        blank(out);
    }
    let mus: Vec<f64> = distinct(
        results
            .c
            .odds
            .iter()
            .filter_map(|r| r.honest_mining_fraction),
    );
    let low_mu = mus.iter().copied().fold(f64::INFINITY, f64::min);
    let old = results.c.odds.iter().find(|r| {
        r.committee_size == size
            && r.attacker_fraction == 0.25
            && r.honest_mining_fraction == Some(low_mu)
    });
    if let (Some(lottery), Some(old)) = (find(primary, None, 0.25), old) {
        line(
            out,
            &format!(
                "**Comparison with the v0.2 rule**, in which the miner of every 10th PoW-Tx block joined (rows of the tables with an honest mining fraction). An attacker that mines with all its IDs while only {} of honest IDs mine then gains seats: with 25% of active IDs it holds {} of mining IDs. At n = {size} its stall probability would be {} instead of {} under the lottery.",
                share(low_mu),
                pct1(old.attacker_share_of_population),
                prob(&old.p_stall),
                prob(&lottery.p_stall)
            ),
        );
        blank(out);
    }
}

fn committee_departures(out: &mut String, results: &M1Results) {
    let rows = &results.c.departures;
    let Some(first) = rows.first() else {
        return;
    };
    let rates = distinct(rows.iter().map(|r| r.absences_per_id_per_year));
    let c_max = rates.iter().copied().fold(0.0, f64::max);
    line(
        out,
        &format!(
            "**Departures (SPEC v0.4 §4.3)** (table `C3_cac_departures.csv`). A banned or deactivated member now leaves the committee at once, and an extra lottery draw fills its seat at the next 10th PoW-Tx block. Attacker IDs never go offline, so honest members serve shorter tenures on average and the attacker's seat share rises a little. By Little's law the share becomes p / (p + (1 − p)·r), where r is an honest member's mean tenure relative to the full tenure of n refreshes ({} h at n = {}). This is an approximation; M4 simulates the committee. Attacker share p of active IDs, c absences per honest ID per year:",
            sig3(first.tenure_hours),
            first.committee_size
        ),
    );
    blank(out);
    let mut headers = vec!["p".to_string()];
    headers.extend(
        rates
            .iter()
            .map(|c| format!("seat share, c = {}", compact_number(*c))),
    );
    headers.push("P(stall) at p".to_string());
    headers.push(format!("P(stall), c = {}", compact_number(c_max)));
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    let body: Vec<Vec<String>> = fractions
        .iter()
        .map(|p| {
            let at = |c: f64| {
                rows.iter()
                    .find(|r| r.attacker_fraction == *p && r.absences_per_id_per_year == c)
            };
            let mut row = vec![share(*p)];
            row.extend(rates.iter().map(|c| {
                at(*c).map_or("—".to_string(), |r| {
                    format!("{:.2}%", 100.0 * r.effective_attacker_share)
                })
            }));
            row.push(at(c_max).map_or("—".to_string(), |r| prob(&r.p_stall_at_p)));
            row.push(at(c_max).map_or("—".to_string(), |r| prob(&r.p_stall_at_effective_share)));
            row
        })
        .collect();
    table(out, &headers, &body);
    let quarter = rows
        .iter()
        .find(|r| r.attacker_fraction == 0.25 && r.absences_per_id_per_year == c_max);
    if let Some(r) = quarter {
        let between_absences = 24.0 * 365.0 / c_max;
        if r.tenure_hours < 0.1 * between_absences {
            line(
                out,
                &format!(
                    "At p = 25% and {} absences per ID per year the attacker's share moves from 25% to {:.2}%: a full tenure ({} h) is short compared with the time between absences ({} h).",
                    compact_number(c_max),
                    100.0 * r.effective_attacker_share,
                    sig3(r.tenure_hours),
                    compact_number(between_absences)
                ),
            );
            blank(out);
        }
    }
}

fn restart(out: &mut String, results: &M1Results) {
    line(out, "## 7. Restart attack");
    blank(out);
    line(
        out,
        "Tables `D1_restart_advantage.csv`, `D2_restart_advantage_curve.csv`; chart `D1_restart_advantage.png`. In the old design, entropy stayed fixed for the whole connection, so a miner could see its future winning steps at connection time and reconnect until one fell within a keep window W. Each reconnection costs C seconds. Advantage = expected time to an ID for a miner that stays connected ÷ expected time for the restarting miner. The realistic restart cost (SPEC v0.3 §8 S5) is the grace epoch + convergence interval + post-admission wait: 150 + 150 + 150 = 450 s at the §2 defaults. The other costs bracket it.",
    );
    blank(out);
    let body: Vec<Vec<String>> = results
        .d
        .iter()
        .map(|r| {
            let cost = if r.cost_case == REALISTIC_COST {
                format!("{} s (realistic)", compact_number(r.restart_cost_s))
            } else {
                format!("{} s", compact_number(r.restart_cost_s))
            };
            vec![
                short_count(r.competing_miners),
                cost,
                window(r.keep_window_s),
                format!("{:.1}×", r.advantage_old_design),
                window(r.optimal_keep_window_s),
                format!("{:.1}×", r.maximum_advantage_old_design),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "miners N",
            "restart cost C",
            "keep window W",
            "advantage",
            "best W",
            "best advantage",
        ]),
        &body,
    );
    let realistic: Vec<_> = results
        .d
        .iter()
        .filter(|r| r.cost_case == REALISTIC_COST && r.keep_window_s == 86_400)
        .collect();
    if let (Some(small), Some(large)) = (realistic.first(), realistic.last()) {
        line(
            out,
            &format!(
                "At the realistic cost and a one-day keep window, the old design gave a restarting miner {:.1}× the honest rate with {} competing miners and {:.1}× with {}. Its best keep window gave {:.1}× and {:.1}×.",
                small.advantage_old_design,
                short_count(small.competing_miners),
                large.advantage_old_design,
                short_count(large.competing_miners),
                small.maximum_advantage_old_design,
                large.maximum_advantage_old_design
            ),
        );
        blank(out);
    }
    line(
        out,
        "**Per-round entropy (current design): the advantage is exactly 1.** Each round's entropy is fresh and unpredictable and does not depend on what the miner did before: the header names the previous PoW-ID block, and the entropy aggregates every online member's signature. A miner gets one header per round, and abandoning it means waiting for the next block. So a connected miner wins each round with the same probability, 1/N, whatever it did before. A disconnected miner cannot win. Restarting can only remove rounds, never improve them, and never restarting is the fastest policy. The Monte Carlo check `D-per-round-entropy` (section 11) agrees.",
    );
    blank(out);
}

fn window(seconds: u64) -> String {
    let s = seconds as f64;
    if s >= 86_400.0 {
        format!("{} d", sig3(s / 86_400.0))
    } else if s >= 3_600.0 {
        format!("{} h", sig3(s / 3_600.0))
    } else {
        format!("{} s", compact_number(s))
    }
}

fn hopping(out: &mut String, results: &M1Results) {
    line(out, "## 8. Difficulty hopping");
    blank(out);
    let k = results.e.first().map_or(0, |r| r.window_blocks);
    let clamp = results
        .e
        .iter()
        .find(|r| r.clamp != "none")
        .map_or("—".to_string(), |r| r.clamp.replace('x', "×"));
    line(
        out,
        &format!(
            "Table `E1_difficulty_hopping.csv`. SPEC v0.3 §3.8 makes Variant B the default: difficulty follows the exact admitted online count, so there is no window to exploit. Variant A, a Bitcoin-style retarget every K = {k} blocks with a {clamp} clamp, is kept as the comparison. Against Variant A an attacker adds m times the honest miners for exactly one window, then leaves. Gain = the attacker's IDs per miner-second compared with Variant B. First-order formula: Variant A pays (1 + m) times Variant B's rate, a gain of m."
        ),
    );
    blank(out);
    let ratios = distinct(results.e.iter().map(|r| r.attacker_ratio));
    let body: Vec<Vec<String>> = ratios
        .iter()
        .map(|m| {
            let free = results
                .e
                .iter()
                .find(|r| r.attacker_ratio == *m && r.clamp == "none");
            let clamped = results
                .e
                .iter()
                .find(|r| r.attacker_ratio == *m && r.clamp != "none");
            vec![
                compact_number(*m),
                free.map_or("—".to_string(), |r| {
                    format!("+{}%", compact_number(r.gain_percent))
                }),
                free.map_or("—".to_string(), |r| sig3(r.attack_window_hours)),
                clamped.map_or("—".to_string(), |r| sig3(r.recovery_window_hours)),
                free.map_or("—".to_string(), |r| sig3(r.recovery_window_hours)),
                clamped.map_or("—".to_string(), |r| {
                    format!("{:.3}", r.cycle_issuance_ratio)
                }),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "m",
            "gain against Variant A",
            "hop window (h)",
            "recovery window with the clamp (h)",
            "recovery window without a clamp (h)",
            "issuance over both windows ÷ target (with the clamp)",
        ]),
        &body,
    );
    let b_checks: Vec<&Check> = results
        .checks
        .iter()
        .filter(|c| c.check.starts_with("E-mc-gain-B"))
        .collect();
    if !b_checks.is_empty() {
        let (lo, hi) = b_checks
            .iter()
            .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), c| {
                (lo.min(c.value), hi.max(c.value))
            });
        line(
            out,
            &format!(
                "The clamp only shortens the recovery window. The gain is earned before any retarget, so the clamp does not change it. Under Variant B with exact counts the first-order gain is 0; its Monte Carlo cross-checks gave gain factors between {lo:.3} and {hi:.3}. Variant B's small correction from recent block times is [P] and will be proposed and tested in M3; it is not modelled here."
            ),
        );
        blank(out);
    }
}

fn ties(out: &mut String, results: &M1Results) {
    line(out, "## 9. Same-step ties between PoW-ID blocks");
    blank(out);
    line(
        out,
        "Table `F1_tie_rate.csv`. All chains start at the same t0 and step once per second, so two miners can win at the same step. That gives two valid blocks for one height. The [P] tie-break keeps the lower block hash.",
    );
    blank(out);
    let body: Vec<Vec<String>> = results
        .f
        .iter()
        .map(|r| {
            vec![
                short_count(r.competing_miners),
                format!("{} s", compact_number(r.interval_s)),
                pct(r.tie_probability),
                compact_number(r.ties_per_year.round()),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "miners N",
            "target interval",
            "rounds ending in a tie",
            "tied rounds per year",
        ]),
        &body,
    );
}

/// Distinct quorum options of one G1 layout, in table order.
fn quorum_options<'a>(rows: &[&'a QuorumRow]) -> Vec<&'a QuorumRow> {
    let mut options: Vec<&QuorumRow> = Vec::new();
    for r in rows {
        if !options.iter().any(|o| o.quorum == r.quorum) {
            options.push(r);
        }
    }
    options
}

fn option_label(row: &QuorumRow) -> String {
    if row.spec_default && !row.quorum.starts_with("SPEC") {
        format!("{} (SPEC default)", row.quorum)
    } else {
        row.quorum.clone()
    }
}

fn quorum_tradeoff(out: &mut String, config: &Config, results: &M1Results) {
    let g = &results.g;
    let Some(kwcs) = g.quorum.iter().map(|r| r.kwcs).min() else {
        return;
    };
    line(out, "## 10. Quorum trade-off (section G)");
    blank(out);
    line(
        out,
        "Tables `G1_quorum_kwc.csv`, `G2_split_rule.csv`, `G3_cac_quorum.csv`; chart `G1_quorum_tradeoff.png`. This section changes no SPEC quorum. For each quorum fraction q it shows what an attacker holding a fraction p of the seats can do: **stall** (deny every approval), **sign without honest members**, or get **two conflicting decisions approved**. Honest members sign at most one of two conflicting proposals; the attacker signs both and may show different proposals to different members. A pool of n members with quorum k therefore allows a conflict from 2k − n attacker seats. In the registered layout each condition applies to the leader WC and to the subordinates separately. The seat condition is necessary; the attacker also has to put both proposals forward, and the proposer rights (SPEC v0.4 §4.4) decide who can: the master proposer for MOBr, registered offline requests and bans; the subordinate-only proposer for MOBu and unregistered offline requests, and bans of leader-chain members who refuse to witness newcomers; the miner for its own offline request. Since SPEC v0.4 (§4.6), two conflicting decisions that are both approved are **both rejected**, and every member who signed both has produced equivocation evidence and may be banned. A conflict therefore cancels a decision rather than enacting two.",
    );
    blank(out);
    let layouts = [POOL_LAYOUT, REGISTERED_LAYOUT];
    let at = |layout: &str| -> Vec<&QuorumRow> {
        g.quorum
            .iter()
            .filter(|r| r.layout == layout && r.kwcs == kwcs)
            .collect()
    };
    let mut thresholds = Vec::new();
    for layout in layouts {
        for o in quorum_options(&at(layout)) {
            thresholds.push(vec![
                layout.to_string(),
                option_label(o),
                o.approvals.clone(),
                o.seats_to_stall.clone(),
                o.seats_to_sign.clone(),
                o.seats_to_conflict.clone(),
            ]);
        }
    }
    line(out, "**Attacker seats each option allows:**");
    blank(out);
    table(
        out,
        &strings(&[
            "layout",
            "quorum",
            "signatures needed",
            "seats to stall",
            "seats to sign alone",
            "seats for conflicting approvals",
        ]),
        &thresholds,
    );
    line(
        out,
        "The SPEC registered default, 7 of 10 and 21 of 30, is q = 0.7 in each group. Two-thirds rounded up per group gives 7 + 20 and is shown only as a comparison.",
    );
    blank(out);
    for layout in layouts {
        let rows = at(layout);
        let options = quorum_options(&rows);
        let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
        for (title, pick) in [
            (
                "can stall",
                (|r: &QuorumRow| r.p_stall.clone()) as fn(&QuorumRow) -> String,
            ),
            ("can sign without honest members", |r: &QuorumRow| {
                r.p_sign.clone()
            }),
            (
                "can get two conflicting decisions approved",
                |r: &QuorumRow| r.p_conflict.clone(),
            ),
        ] {
            line(
                out,
                &format!(
                    "**{layout}: probability that the attacker {title}** (per KWC, exact hypergeometric, {} KWCs):",
                    short_count(kwcs)
                ),
            );
            blank(out);
            let mut headers = vec!["p".to_string()];
            headers.extend(options.iter().map(|o| option_label(o)));
            let body: Vec<Vec<String>> = fractions
                .iter()
                .map(|p| {
                    let mut row = vec![share(*p)];
                    row.extend(options.iter().map(|o| {
                        rows.iter()
                            .find(|r| r.quorum == o.quorum && r.attacker_fraction == *p)
                            .map_or("—".to_string(), |r| prob(&pick(r)))
                    }));
                    row
                })
                .collect();
            table(out, &headers, &body);
        }
    }
    quorum_counts(out, results, kwcs);
    quorum_seat_rule(out, config, results, kwcs);
    split_rule(out, results, kwcs);
    committee_quorum(out, results);
    quorum_plain_english(out, results, kwcs);
}

fn quorum_counts(out: &mut String, results: &M1Results, kwcs: u64) {
    let p = 0.25;
    let rows: Vec<&QuorumRow> = results
        .g
        .quorum
        .iter()
        .filter(|r| r.kwcs == kwcs && r.attacker_fraction == p)
        .collect();
    let Some(first) = rows.first() else {
        return;
    };
    line(
        out,
        &format!(
            "**Expected counts at p = 25%, {} KWCs.** \"Now\" is the expected number of KWCs in the state at one moment. \"Over {} years\" is the expected number of distinct episodes in the state (SPEC v0.4 §10 H6), with the composition count, the upper bound, in brackets; adopted allocation, {} compositions, binomial, no bans or absences:",
            short_count(kwcs),
            compact_number(10.0),
            compact_number(first.compositions_over_horizon)
        ),
    );
    blank(out);
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.layout.to_string(),
                option_label(r),
                count(&r.expected_kwcs_stall),
                count(&r.expected_kwcs_sign),
                count(&r.expected_kwcs_conflict),
                format!(
                    "{} ({})",
                    num(r.expected_episodes_sign),
                    num(r.expected_compositions_sign)
                ),
                format!(
                    "{} ({})",
                    num(r.expected_episodes_conflict),
                    num(r.expected_compositions_conflict)
                ),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "layout",
            "quorum",
            "stall, now",
            "sign alone, now",
            "conflict, now",
            "sign alone, over 10 years: episodes (compositions)",
            "conflict, over 10 years: episodes (compositions)",
        ]),
        &body,
    );
}

fn quorum_seat_rule(out: &mut String, config: &Config, results: &M1Results, kwcs: u64) {
    let models = absence_models(config);
    let Some(primary) = models.first() else {
        return;
    };
    let c = config
        .analytic
        .absence
        .absences_per_id_per_year
        .iter()
        .copied()
        .fold(0.0, f64::max);
    let slice: Vec<&SeatRuleQuorumRow> = results
        .g
        .seat_rule
        .iter()
        .filter(|r| {
            r.spec_default
                && r.kwcs == kwcs
                && r.attacker_fraction == 0.25
                && r.duration_model == primary.label()
                && r.absences_per_id_per_year == c
        })
        .collect();
    let (Some(pool), Some(registered)) = (
        slice.iter().find(|r| r.layout == POOL_LAYOUT),
        slice.iter().find(|r| r.layout == REGISTERED_LAYOUT),
    ) else {
        return;
    };
    line(
        out,
        &format!(
            "**Ten-year episodes under each seat rule** (`G4_quorum_10y_by_seat_rule.csv`): SPEC default quorums, p = 25%, {} KWCs at the start, {} absences per ID per year with Lomax durations. Expected distinct episodes:",
            short_count(kwcs),
            compact_number(c)
        ),
    );
    blank(out);
    let mut rules: Vec<String> = Vec::new();
    for r in &slice {
        if !rules.contains(&r.seat_rule) {
            rules.push(r.seat_rule.clone());
        }
    }
    let headers = vec![
        "seat rule".to_string(),
        format!("{}: stall", pool.approvals),
        format!("{}: sign alone", pool.approvals),
        format!("{}: conflict", pool.approvals),
        format!("{}: stall", registered.approvals),
        format!("{}: sign alone", registered.approvals),
        format!("{}: conflict", registered.approvals),
    ];
    let body: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            let mut row = vec![rule.clone()];
            for layout in [POOL_LAYOUT, REGISTERED_LAYOUT] {
                let r = slice
                    .iter()
                    .find(|r| r.layout == layout && r.seat_rule == *rule);
                for pick in [
                    |r: &SeatRuleQuorumRow| r.expected_episodes_stall,
                    |r: &SeatRuleQuorumRow| r.expected_episodes_sign,
                    |r: &SeatRuleQuorumRow| r.expected_episodes_conflict,
                ] {
                    row.push(r.map_or("—".to_string(), |r| num(pick(r))));
                }
            }
            row
        })
        .collect();
    table(out, &headers, &body);
}

fn split_rule(out: &mut String, results: &M1Results, kwcs: u64) {
    let rows: Vec<_> = results.g.split.iter().filter(|r| r.kwcs == kwcs).collect();
    let Some(first) = rows.first() else {
        return;
    };
    line(
        out,
        &format!(
            "**Split rule** (`G2_split_rule.csv`): a lower quorum for PoWit only, while decisions that global validation cannot re-check (bans, MOBu/MOBr, offline requests, committee blocks) keep two-thirds, {} voted by the full KWC. PoWit at the lower quorum ({} KWCs):",
            first.decision_approvals,
            short_count(kwcs)
        ),
    );
    blank(out);
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                format!(
                    "{} ({}; {})",
                    r.powit_quorum, r.powit_pool_approvals, r.powit_registered_approvals
                ),
                share(r.attacker_fraction),
                prob(&r.powit_pool_p_stall),
                prob(&r.powit_pool_p_sign),
                prob(&r.powit_registered_p_stall),
                prob(&r.powit_registered_p_sign),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "PoWit quorum (unregistered; registered)",
            "p",
            "unregistered PoWit: stall",
            "unregistered PoWit: sign alone",
            "registered PoWit: stall",
            "registered PoWit: sign alone",
        ]),
        &body,
    );
    line(
        out,
        &format!(
            "**Decisions at two-thirds ({}), unchanged by the split:**",
            first.decision_approvals
        ),
    );
    blank(out);
    let mut seen = Vec::new();
    let body: Vec<Vec<String>> = rows
        .iter()
        .filter(|r| {
            let fresh = !seen.contains(&r.attacker_fraction.to_bits());
            seen.push(r.attacker_fraction.to_bits());
            fresh
        })
        .map(|r| {
            vec![
                share(r.attacker_fraction),
                prob(&r.decision_p_stall),
                prob(&r.decision_p_sign),
                prob(&r.decision_p_conflict),
            ]
        })
        .collect();
    table(
        out,
        &strings(&["p", "stall", "approve alone", "two conflicting approvals"]),
        &body,
    );
    line(out, "**Which harms each threshold controls:**");
    blank(out);
    table(
        out,
        &strings(&[
            "threshold",
            "harms it controls",
            "already neutralised elsewhere",
        ]),
        &[
            strings(&[
                "PoWit quorum",
                "stalling PoWits in a KWC (its miners must move to another KWC after the grace epoch); signing valid PoWits without honest members, and so censoring",
                "invalid or early-signed blocks: every validator recomputes the hash chain and rejects a block received before its own timestamp (§3.7); two blocks at one height: the lower-hash tie-break (§3.7); two headers from one miner in a round: equivocation evidence (§3.4)",
            ]),
            strings(&[
                "decision quorum (two-thirds)",
                "false bans, MOBu/MOBr, offline requests and committee records, which rest on witnesses' observations rather than on data validators can recompute; and cancelling a decision by getting a conflicting one approved",
                "committee placements, joins and leaves: every node recomputes them and rejects a mismatch, and placement no longer waits for the committee (§4.2, §4.3); two conflicting approved decisions or committee blocks: both rejected, and those who signed both are exposed (§4.3, §4.6)",
            ]),
        ],
    );
}

fn committee_quorum(out: &mut String, results: &M1Results) {
    let rows = &results.g.cac;
    let Some(first) = rows.first() else {
        return;
    };
    let mut options: Vec<&gb_analytic::quorum_tradeoff::CacQuorumRow> = Vec::new();
    for r in rows {
        if !options.iter().any(|o| o.quorum == r.quorum) {
            options.push(r);
        }
    }
    line(
        out,
        &format!(
            "**Committee (`G3_cac_quorum.csv`)**: n = {} under the seat lottery, {} active IDs. Seats needed:",
            first.committee_size,
            short_count(first.active_ids)
        ),
    );
    blank(out);
    let thresholds: Vec<Vec<String>> = options
        .iter()
        .map(|o| {
            vec![
                if o.spec_default {
                    format!("{} (SPEC default)", o.quorum)
                } else {
                    o.quorum.clone()
                },
                o.approvals.to_string(),
                o.seats_to_stall.to_string(),
                o.seats_to_sign.to_string(),
                o.seats_to_conflict.to_string(),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "quorum",
            "approvals needed",
            "seats to stall",
            "seats to approve alone",
            "seats for conflicting blocks",
        ]),
        &thresholds,
    );
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    let mut headers = vec!["p".to_string()];
    for o in &options {
        headers.push(format!("{}: stall", o.quorum));
        headers.push(format!("{}: approve alone", o.quorum));
        headers.push(format!("{}: conflict", o.quorum));
    }
    let body: Vec<Vec<String>> = fractions
        .iter()
        .map(|p| {
            let mut row = vec![share(*p)];
            for o in &options {
                let r = rows
                    .iter()
                    .find(|r| r.quorum == o.quorum && r.attacker_fraction == *p);
                for pick in [
                    |r: &gb_analytic::quorum_tradeoff::CacQuorumRow| r.p_stall.clone(),
                    |r: &gb_analytic::quorum_tradeoff::CacQuorumRow| r.p_sign.clone(),
                    |r: &gb_analytic::quorum_tradeoff::CacQuorumRow| r.p_conflict.clone(),
                ] {
                    row.push(r.map_or("—".to_string(), |r| prob(&pick(r))));
                }
            }
            row
        })
        .collect();
    table(out, &headers, &body);
}

fn quorum_plain_english(out: &mut String, results: &M1Results, kwcs: u64) {
    let g = &results.g;
    let pool = |quorum: &str, p: f64| {
        g.quorum.iter().find(|r| {
            r.layout == POOL_LAYOUT
                && r.kwcs == kwcs
                && r.quorum == quorum
                && r.attacker_fraction == p
        })
    };
    let low = g
        .quorum
        .iter()
        .filter(|r| r.layout == POOL_LAYOUT)
        .min_by(|a, b| a.quorum_fraction.total_cmp(&b.quorum_fraction))
        .map(|r| r.quorum.clone());
    let default = g
        .quorum
        .iter()
        .find(|r| r.layout == POOL_LAYOUT && r.spec_default)
        .map(|r| r.quorum.clone());
    line(
        out,
        "**In plain English.** This section does not choose a quorum.",
    );
    blank(out);
    if let (Some(low), Some(default)) = (low, default) {
        if let (Some(l25), Some(d25), Some(l10), Some(d10)) = (
            pool(&low, 0.25),
            pool(&default, 0.25),
            pool(&low, 0.1),
            pool(&default, 0.1),
        ) {
            line(
                out,
                &format!(
                    "- **A lower quorum makes stalling harder.** In a pool of 40, stalling needs {} attacker seats at q = {low} against {} at {default}. At p = 25% the chance that a KWC can be stalled falls from {} to {}.",
                    l25.seats_to_stall.trim_start_matches("≥ "),
                    d25.seats_to_stall.trim_start_matches("≥ "),
                    prob(&d25.p_stall),
                    prob(&l25.p_stall)
                ),
            );
            line(
                out,
                &format!(
                    "- **It makes signing without honest members easier.** That needs {} seats at q = {low} against {} at {default}; at p = 25% the chance rises from {} to {}.",
                    l25.seats_to_sign.trim_start_matches("≥ "),
                    d25.seats_to_sign.trim_start_matches("≥ "),
                    prob(&d25.p_sign),
                    prob(&l25.p_sign)
                ),
            );
            line(
                out,
                &format!(
                    "- **It makes conflicting approvals much easier.** Two conflicting decisions need {} attacker seats at q = {low} against {} at {default}. At p = 10% that is possible in {} of KWCs, against {}. Under SPEC v0.4 both are then rejected, so the harm is a cancelled decision, and every member who signed both is exposed.",
                    l10.seats_to_conflict.trim_start_matches("≥ "),
                    d10.seats_to_conflict.trim_start_matches("≥ "),
                    prob(&l10.p_conflict),
                    prob(&d10.p_conflict)
                ),
            );
        }
    }
    line(
        out,
        "- **What global validation neutralises.** Every validator recomputes a PoWit's hash chain and checks its timing (§3.7), so a lower PoWit quorum cannot make an invalid or early block valid. It changes who can stall, censor or sign valid blocks. Decisions about bans, online status, offline requests and committee blocks rest on witnesses' observations, which validators cannot recompute; for those the quorum is the protection.",
    );
    let cac = g
        .cac
        .iter()
        .filter(|r| !r.spec_default)
        .min_by(|a, b| a.attacker_fraction.total_cmp(&b.attacker_fraction));
    if let Some(r) = cac {
        line(
            out,
            &format!(
                "- **The committee.** At q = {} a conflict needs {} of {} seats, and an attacker with {} of active IDs holds that many with probability {}. Placement conflicts are neutralised, because every node recomputes placement and it takes effect without the committee (§4.2), and a leader with two conflicting approved blocks has both rejected (§4.3). The committee's remaining power is over compiling bans that KWCs already approved: it can delay or omit them.",
                r.quorum,
                r.seats_to_conflict,
                r.committee_size,
                share(r.attacker_fraction),
                prob(&r.p_conflict)
            ),
        );
    }
    line(
        out,
        "- **Not considered.** A quorum at or below 50%: two disjoint groups of honest members could then approve conflicting decisions with no attacker at all. The single-member entropy stall, where one online member withholds its entropy signature, does not depend on the quorum; One Chance (§4.5) handles it, and threshold BLS entropy (SPEC §12 [P]) would remove it.",
    );
    blank(out);
}

/// The minimum uptime of an H2 or I2 row, or "not reachable" with P(fail) at full uptime.
fn minimum_uptime(minimum: Option<f64>, at_full: &str) -> String {
    minimum.map_or_else(
        || format!("not reachable ({} fail at f = 1)", prob(at_full)),
        |f| format!("{f:.4}"),
    )
}

/// An uptime rounded up to four decimals, or "not reachable".
fn uptime_up(value: Option<f64>) -> String {
    value.map_or("not reachable".to_string(), |u| {
        format!("{:.4}", libm::ceil(u * 1e4) / 1e4)
    })
}

fn quorum_feasibility(out: &mut String, config: &Config, results: &M1Results) {
    line(
        out,
        "## 11. Quorum feasibility under honest downtime (section H)",
    );
    blank(out);
    line(
        out,
        "Tables `H1_quorum_feasibility.csv`, `H2_minimum_uptime.csv`, `H3_absent_seat_share.csv`; chart `H1_quorum_feasibility.png`. A KWC can approve only when enough members sign. Each honest member is online, and signs, with probability f; the attacker holds a fraction p of the seats and its members withhold, so each seat signs with probability (1 − p)·f. Three layouts: the unregistered PoWit (any 27 of 40); the SPEC registered PoWit (7 of the leader WC's 10 and 21 of the 30 subordinates); and, for comparison, a registered PoWit valid with any 27 of 40, the validity rule of the [P] proposal to separate validity from payment (SPEC §12). The comparison's numbers equal the unregistered ones, so the gap between the two registered rules is the cost of the leader requirement.",
    );
    blank(out);
    line(
        out,
        &format!(
            "**A KWC that cannot meet quorum is a local liveness problem.** Its miners move to another KWC after the grace epoch plus admission, about {} s at the §2 defaults (SPEC §3.2), and the rest of the network continues. Miners are spread evenly over KWCs, so at any moment the share of miners affected equals the failure probability.",
            compact_number(realistic_restart_cost_s(config))
        ),
    );
    blank(out);
    line(
        out,
        "**Withholding is assumed to cost the attacker nothing.** Every row with an attacker, including H2's \"not reachable\" entries, assumes its withholding members suffer no penalty. Under SPEC §4.5–§4.6 an online member that refuses to sign after One Chance is banned; M4 models that.",
    );
    blank(out);
    feasibility_tables(out, &results.h);
    minimum_uptime_table(out, &results.h);
    absent_seat_table(out, config, &results.h);
    feasibility_plain_english(out, config, results);
}

fn feasibility_tables(out: &mut String, h: &SectionH) {
    let rows = &h.feasibility;
    let Some(first) = rows.first() else {
        return;
    };
    let kwcs = first.kwcs;
    let find = |layout: &str, p: f64, f: f64| {
        rows.iter()
            .find(|r| r.layout == layout && r.attacker_fraction == p && r.online_fraction == f)
    };
    let approvals = |layout: &str| {
        rows.iter()
            .find(|r| r.layout == layout)
            .map_or(String::new(), |r| r.approvals.clone())
    };
    let (pool, registered) = (approvals(UNREGISTERED), approvals(REGISTERED));
    line(
        out,
        &format!(
            "**Share of KWCs that cannot meet quorum, every member honest** (exact; expected failing KWCs at a network of {} KWCs):",
            short_count(kwcs)
        ),
    );
    blank(out);
    let online = distinct(rows.iter().map(|r| r.online_fraction));
    let body: Vec<Vec<String>> = online
        .iter()
        .filter_map(|f| {
            let (a, b) = (find(UNREGISTERED, 0.0, *f)?, find(REGISTERED, 0.0, *f)?);
            Some(vec![
                share(*f),
                prob(&a.p_fail),
                prob(&b.p_fail),
                b.p_leader_below_quorum
                    .as_deref()
                    .map_or("—".to_string(), prob),
                b.p_subordinates_below_quorum
                    .as_deref()
                    .map_or("—".to_string(), prob),
                num(a.expected_failing_kwcs),
                num(b.expected_failing_kwcs),
            ])
        })
        .collect();
    table(
        out,
        &[
            "f".to_string(),
            pool.clone(),
            registered.clone(),
            "leader WC below its quorum".to_string(),
            "subordinates below theirs".to_string(),
            format!("failing KWCs, {pool}"),
            format!("failing KWCs, {registered}"),
        ],
        &body,
    );
    let high: Vec<f64> = online.iter().copied().filter(|f| *f >= 0.9).collect();
    let fractions: Vec<f64> = distinct(rows.iter().map(|r| r.attacker_fraction))
        .into_iter()
        .filter(|p| *p > 0.0)
        .collect();
    if high.is_empty() || fractions.is_empty() {
        return;
    }
    line(
        out,
        "**With attacker members withholding** (share of KWCs that cannot meet quorum):",
    );
    blank(out);
    let mut headers = vec!["p".to_string()];
    for (layout, label) in [(UNREGISTERED, &pool), (REGISTERED, &registered)] {
        let _ = layout;
        headers.extend(high.iter().map(|f| format!("{label}, f = {}", share(*f))));
    }
    let body: Vec<Vec<String>> =
        fractions
            .iter()
            .map(|p| {
                let mut row = vec![share(*p)];
                for layout in [UNREGISTERED, REGISTERED] {
                    row.extend(high.iter().map(|f| {
                        find(layout, *p, *f).map_or("—".to_string(), |r| prob(&r.p_fail))
                    }));
                }
                row
            })
            .collect();
    table(out, &headers, &body);
}

fn minimum_uptime_table(out: &mut String, h: &SectionH) {
    let rows = &h.minimum_uptime;
    let targets = distinct(rows.iter().map(|r| r.failure_target));
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    let approvals = |layout: &str| {
        rows.iter()
            .find(|r| r.layout == layout)
            .map_or(String::new(), |r| r.approvals.clone())
    };
    line(
        out,
        "**Minimum honest uptime f for fewer than the target share of KWCs to fail** (`H2_minimum_uptime.csv`; exact bisection on a 10⁻⁴ grid, verified on both sides):",
    );
    blank(out);
    let mut headers = vec!["p".to_string()];
    for layout in [UNREGISTERED, REGISTERED] {
        for t in &targets {
            headers.push(format!("{}, under {}", approvals(layout), share(*t)));
        }
    }
    let body: Vec<Vec<String>> = fractions
        .iter()
        .map(|p| {
            let mut row = vec![share(*p)];
            for layout in [UNREGISTERED, REGISTERED] {
                for t in &targets {
                    row.push(
                        rows.iter()
                            .find(|r| {
                                r.layout == layout
                                    && r.attacker_fraction == *p
                                    && r.failure_target == *t
                            })
                            .map_or("—".to_string(), |r| {
                                minimum_uptime(r.minimum_online_fraction, &r.p_fail_at_full_uptime)
                            }),
                    );
                }
            }
            row
        })
        .collect();
    table(out, &headers, &body);
}

fn absent_seat_table(out: &mut String, config: &Config, h: &SectionH) {
    let models = absence_models(config);
    let Some(primary) = models.first() else {
        return;
    };
    let rows = &h.absent_seats;
    let c = config
        .analytic
        .absence
        .absences_per_id_per_year
        .iter()
        .copied()
        .fold(0.0, f64::max);
    let target = rows.iter().map(|r| r.failure_target).fold(0.0, f64::max);
    let slice: Vec<&AbsentSeatRow> = rows
        .iter()
        .filter(|r| {
            r.attacker_fraction == 0.0
                && r.failure_target == target
                && r.duration_model == primary.label()
                && r.absences_per_id_per_year == c
        })
        .collect();
    let approvals = |layout: &str| {
        slice
            .iter()
            .find(|r| r.layout == layout)
            .map_or(String::new(), |r| r.approvals.clone())
    };
    line(
        out,
        &format!(
            "**Absent IDs keep their seats (SPEC v0.4 §4.7)** (`H3_absent_seat_share.csv`). By Little's law, honest seat-holders are absent a share (c·E[min(D, L)] + a·L)/365 of the time, for c absences and a permanent departures per ID per year: a departed ID holds its seat as an offline member until L passes. The uptime needed among present members is the H2 minimum (before rounding to the grid) divided by (1 − that share). At {} absences per ID per year with Lomax durations, no attacker, under {} failing:",
            compact_number(c),
            share(target)
        ),
    );
    blank(out);
    let days = distinct(slice.iter().map(|r| r.long_absence_days));
    let departures = distinct(slice.iter().map(|r| r.departures_per_id_per_year));
    let mut body = Vec::new();
    for d in &days {
        for a in &departures {
            let find = |layout: &str| {
                slice.iter().find(|r| {
                    r.layout == layout
                        && r.long_absence_days == *d
                        && r.departures_per_id_per_year == *a
                })
            };
            let (Some(pool), Some(registered)) = (find(UNREGISTERED), find(REGISTERED)) else {
                continue;
            };
            body.push(vec![
                format!(
                    "{} d ({} blocks)",
                    compact_number(*d),
                    compact_number(pool.long_absence_blocks)
                ),
                share(*a),
                pct(pool.absent_seat_share),
                uptime_up(pool.required_ordinary_uptime),
                uptime_up(registered.required_ordinary_uptime),
            ]);
        }
    }
    table(
        out,
        &[
            "L".to_string(),
            "departures per ID per year".to_string(),
            "seats held by absent IDs".to_string(),
            format!("uptime needed, {}", approvals(UNREGISTERED)),
            format!("uptime needed, {}", approvals(REGISTERED)),
        ],
        &body,
    );
}

fn feasibility_plain_english(out: &mut String, config: &Config, results: &M1Results) {
    let h = &results.h;
    line(out, "**What this implies for L and for honest uptime.**");
    blank(out);
    let minimum = |layout: &str, p: f64, t: f64| {
        h.minimum_uptime
            .iter()
            .find(|r| r.layout == layout && r.attacker_fraction == p && r.failure_target == t)
    };
    let targets = distinct(h.minimum_uptime.iter().map(|r| r.failure_target));
    let (Some(&one), Some(&tenth)) = (
        targets.iter().max_by(|a, b| a.total_cmp(b)),
        targets.iter().min_by(|a, b| a.total_cmp(b)),
    ) else {
        return;
    };
    if let (Some(a1), Some(b1), Some(a2), Some(b2)) = (
        minimum(UNREGISTERED, 0.0, one),
        minimum(REGISTERED, 0.0, one),
        minimum(UNREGISTERED, 0.0, tenth),
        minimum(REGISTERED, 0.0, tenth),
    ) {
        if let (Some(fa1), Some(fb1), Some(fa2), Some(fb2)) = (
            a1.minimum_online_fraction,
            b1.minimum_online_fraction,
            a2.minimum_online_fraction,
            b2.minimum_online_fraction,
        ) {
            line(
                out,
                &format!(
                    "- **Without an attacker**, keeping failing KWCs under {} needs honest members online {:.4} of the time for {}, but {:.4} for {}; under {}, {:.4} against {:.4}. The leader requirement costs {} points of uptime at the {} target. The [P] single 27-of-40 rule would give registered KWCs the unregistered figures.",
                    share(one),
                    fa1,
                    a1.approvals,
                    fb1,
                    b1.approvals,
                    share(tenth),
                    fa2,
                    fb2,
                    sig3(100.0 * (fb1 - fa1)),
                    share(one)
                ),
            );
        }
    }
    let first_unreachable = |layout: &str| {
        let mut rows: Vec<_> = h
            .minimum_uptime
            .iter()
            .filter(|r| r.layout == layout && r.failure_target == one)
            .collect();
        rows.sort_by(|a, b| a.attacker_fraction.total_cmp(&b.attacker_fraction));
        rows.into_iter()
            .find(|r| r.minimum_online_fraction.is_none())
    };
    if let (Some(a), Some(b)) = (
        first_unreachable(UNREGISTERED),
        first_unreachable(REGISTERED),
    ) {
        line(
            out,
            &format!(
                "- **With attacker members withholding**, {} cannot keep failures under {} at any uptime from p = {} ({} of KWCs fail even at f = 1), and {} from p = {} ({}). These rows assume withholding is free (see above).",
                b.approvals,
                share(one),
                share(b.attacker_fraction),
                prob(&b.p_fail_at_full_uptime),
                a.approvals,
                share(a.attacker_fraction),
                prob(&a.p_fail_at_full_uptime)
            ),
        );
    }
    let models = absence_models(config);
    let c = config
        .analytic
        .absence
        .absences_per_id_per_year
        .iter()
        .copied()
        .fold(0.0, f64::max);
    let default_days = config.offline.long_absence_threshold_s.value / 86_400.0;
    if let Some(primary) = models.first() {
        let row = |layout: &str, days: f64, a: f64| {
            h.absent_seats.iter().find(|r| {
                r.layout == layout
                    && r.attacker_fraction == 0.0
                    && r.failure_target == one
                    && r.duration_model == primary.label()
                    && r.absences_per_id_per_year == c
                    && r.long_absence_days == days
                    && r.departures_per_id_per_year == a
            })
        };
        let days = distinct(h.absent_seats.iter().map(|r| r.long_absence_days));
        let departures = distinct(h.absent_seats.iter().map(|r| r.departures_per_id_per_year));
        let (Some(&shortest), Some(&longest)) = (
            days.iter().min_by(|a, b| a.total_cmp(b)),
            days.iter().max_by(|a, b| a.total_cmp(b)),
        ) else {
            return;
        };
        let middle = departures
            .iter()
            .copied()
            .filter(|a| *a > 0.0)
            .fold(f64::INFINITY, f64::min);
        if let (Some(s0), Some(l0), Some(sd), Some(ld)) = (
            row(UNREGISTERED, shortest, 0.0),
            row(UNREGISTERED, longest, 0.0),
            row(UNREGISTERED, default_days, middle),
            row(UNREGISTERED, longest, middle),
        ) && ld.absent_seat_share > 2.0 * l0.absent_seat_share
        {
            line(
                out,
                &format!(
                    "- **Temporary absences hold few seats; permanent departures dominate.** With {} absences per ID per year and no departures, absent IDs hold {} of seats at L = {} days and {} at L = {} days. A departed ID holds its seat for all of L, so with {} departures per ID per year they hold {} at L = {} days and {} at L = {} days.",
                    compact_number(c),
                    pct(s0.absent_seat_share),
                    compact_number(shortest),
                    pct(l0.absent_seat_share),
                    compact_number(longest),
                    share(middle),
                    pct(sd.absent_seat_share),
                    compact_number(default_days),
                    pct(ld.absent_seat_share),
                    compact_number(longest)
                ),
            );
        }
        if let (Some(pool), Some(registered)) = (
            row(UNREGISTERED, default_days, middle),
            row(REGISTERED, default_days, middle),
        ) {
            let unreachable_from = days
                .iter()
                .copied()
                .filter(|d| {
                    row(REGISTERED, *d, middle)
                        .is_some_and(|r| r.required_ordinary_uptime.is_none())
                })
                .fold(f64::INFINITY, f64::min);
            let mut text = format!(
                "- **At the default L = {} days** with {} departures per ID per year, the ordinary uptime needed for under {} failing is {} for {} and {} for {}.",
                compact_number(default_days),
                share(middle),
                share(one),
                uptime_up(pool.required_ordinary_uptime),
                pool.approvals,
                uptime_up(registered.required_ordinary_uptime),
                registered.approvals
            );
            if unreachable_from.is_finite() {
                text.push_str(&format!(
                    " From L = {} days, {} cannot stay under {} at any uptime.",
                    compact_number(unreachable_from),
                    registered.approvals,
                    share(one)
                ));
            }
            line(out, &text);
        }
    }
    if l_is_a_trade_off(results, one) {
        line(
            out,
            "- **So L is a trade-off.** A shorter L vacates and re-inserts more absent IDs, which adds compositions (section 5, table B5); a longer L leaves more seats with absent IDs, which needs more honest uptime (table H3). Household profiles from M3 will replace the illustrative absence inputs.",
        );
    }
    blank(out);
}

/// True when, in the tables, compositions fall (B5) and the absent seat share rises (H3) as L
/// grows, in every series.
fn l_is_a_trade_off(results: &M1Results, target: f64) -> bool {
    type Series = BTreeMap<(String, u64, u64, String, u64), Vec<(f64, f64)>>;
    let mut compositions: Series = BTreeMap::new();
    for r in &results.b.seat_rule {
        let Some(days) = r.long_absence_days else {
            continue;
        };
        compositions
            .entry((
                r.miner_kind.to_string(),
                r.attacker_fraction.to_bits(),
                r.initial_kwcs,
                r.duration_model.to_string(),
                r.absences_per_id_per_year.to_bits(),
            ))
            .or_default()
            .push((days, r.compositions));
    }
    let mut shares: Series = BTreeMap::new();
    for r in &results.h.absent_seats {
        if r.failure_target != target || r.layout != UNREGISTERED || r.attacker_fraction != 0.0 {
            continue;
        }
        shares
            .entry((
                r.duration_model.to_string(),
                r.absences_per_id_per_year.to_bits(),
                r.departures_per_id_per_year.to_bits(),
                String::new(),
                0,
            ))
            .or_default()
            .push((r.long_absence_days, r.absent_seat_share));
    }
    let monotone = |series: &mut Series, rising: bool| {
        !series.is_empty()
            && series.values_mut().all(|v| {
                v.sort_by(|a, b| a.0.total_cmp(&b.0));
                v.windows(2).all(|w| {
                    if rising {
                        w[1].1 >= w[0].1
                    } else {
                        w[1].1 <= w[0].1
                    }
                })
            })
    };
    monotone(&mut compositions, false) && monotone(&mut shares, true)
}

/// A ruler as written in the summary, for example `{1, 4, 6}`.
fn ruler(offsets: &[u64]) -> String {
    let parts: Vec<String> = offsets.iter().map(|o| o.to_string()).collect();
    format!("{{{}}}", parts.join(", "))
}

fn kwc_size_tradeoff(out: &mut String, config: &Config, results: &M1Results) {
    let grid = &config.analytic.kwc_size;
    line(out, "## 12. KWC size trade-off (section I)");
    blank(out);
    let rulers: Vec<String> = grid
        .wcs_per_kwc
        .iter()
        .zip(&grid.ring_offsets)
        .map(|(k, offsets)| format!("k = {k}: {}", ruler(offsets)))
        .collect();
    line(
        out,
        &format!(
            "Tables `I1_kwc_size_security.csv`, `I2_kwc_size_liveness.csv`, `I3_kwc_size_load.csv`, `I4_on_demand_connections.csv`. A KWC of k WCs of 10 members has 10·k members. Each size uses an optimal Golomb ruler as its ring ({}); k = 4 is the protocol's ring. Two single quorums over the whole KWC are compared: two-thirds, ⌈2n/3⌉ (27 of 40 at k = 4), and the split rule's PoWit quorum, ⌈0.51·n⌉ (SPEC §12 [P]). Probabilities are exact, hypergeometric at {} KWCs. This section does not pick a size.",
            rulers.join("; "),
            short_count(grid.comparison_kwcs)
        ),
    );
    blank(out);
    size_security_tables(out, &results.i);
    size_liveness_table(out, &results.i);
    size_load_tables(out, config, &results.i);
    on_demand_table(out, config, &results.i);
    size_plain_english(out, config, &results.i);
}

/// Sizes in table order.
fn sizes_in(rows: impl Iterator<Item = u64>) -> Vec<u64> {
    let mut sizes: Vec<u64> = Vec::new();
    for k in rows {
        if !sizes.contains(&k) {
            sizes.push(k);
        }
    }
    sizes
}

fn size_security_tables(out: &mut String, i: &SectionI) {
    let rows = &i.security;
    let sizes = sizes_in(rows.iter().map(|r| r.wcs_per_kwc));
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    let mut quorums: Vec<String> = Vec::new();
    for r in rows {
        if !quorums.contains(&r.quorum) {
            quorums.push(r.quorum.clone());
        }
    }
    for q in &quorums {
        let find = |k: u64, p: f64| {
            rows.iter()
                .find(|r| r.quorum == *q && r.wcs_per_kwc == k && r.attacker_fraction == p)
        };
        line(
            out,
            &format!(
                "**Probability that the attacker can stall a KWC, quorum {q}** (the column header gives the attacker seats that stall):"
            ),
        );
        blank(out);
        let mut headers = vec!["p".to_string()];
        headers.extend(sizes.iter().map(|k| {
            let needed = find(*k, fractions[0]).map_or(String::new(), |r| {
                format!(
                    "{} of {}",
                    r.seats_to_stall.trim_start_matches("≥ "),
                    r.members
                )
            });
            format!("k = {k} ({needed})")
        }));
        let body: Vec<Vec<String>> = fractions
            .iter()
            .map(|p| {
                let mut row = vec![share(*p)];
                row.extend(
                    sizes
                        .iter()
                        .map(|k| find(*k, *p).map_or("—".to_string(), |r| prob(&r.p_stall))),
                );
                row
            })
            .collect();
        table(out, &headers, &body);
    }
    let two_thirds = |k: u64, p: f64| {
        rows.iter()
            .find(|r| r.quorum == "2/3" && r.wcs_per_kwc == k && r.attacker_fraction == p)
    };
    line(
        out,
        "**Signing without honest members at two-thirds, p = 25%, and its ten-year episodes** (from 100,000 KWCs, no bans or absences; compositions, the upper bound, in brackets):",
    );
    blank(out);
    let body: Vec<Vec<String>> = sizes
        .iter()
        .filter_map(|k| {
            let r = two_thirds(*k, 0.25)?;
            Some(vec![
                k.to_string(),
                r.members.to_string(),
                sig3(r.compositions_per_insertion),
                prob(&r.p_sign),
                format!(
                    "{} ({})",
                    num(r.expected_episodes_sign),
                    num(r.expected_compositions_sign)
                ),
            ])
        })
        .collect();
    table(
        out,
        &strings(&[
            "k",
            "members",
            "compositions per new ID",
            "P(sign alone)",
            "episodes over 10 years (compositions)",
        ]),
        &body,
    );
}

fn size_liveness_table(out: &mut String, i: &SectionI) {
    let rows = &i.liveness;
    let sizes = sizes_in(rows.iter().map(|r| r.wcs_per_kwc));
    let target = rows.iter().map(|r| r.failure_target).fold(0.0, f64::max);
    let fractions = distinct(rows.iter().map(|r| r.attacker_fraction));
    let mut quorums: Vec<String> = Vec::new();
    for r in rows {
        if !quorums.contains(&r.quorum) {
            quorums.push(r.quorum.clone());
        }
    }
    line(
        out,
        &format!(
            "**Minimum honest uptime for under {} of KWCs failing** (`I2_kwc_size_liveness.csv`; attacker members withhold, as in section 11):",
            share(target)
        ),
    );
    blank(out);
    let mut headers = vec!["quorum".to_string(), "p".to_string()];
    headers.extend(sizes.iter().map(|k| format!("k = {k}")));
    let mut body = Vec::new();
    for q in &quorums {
        for p in &fractions {
            let mut row = vec![q.clone(), share(*p)];
            row.extend(sizes.iter().map(|k| {
                rows.iter()
                    .find(|r| {
                        r.quorum == *q
                            && r.wcs_per_kwc == *k
                            && r.attacker_fraction == *p
                            && r.failure_target == target
                    })
                    .map_or("—".to_string(), |r| match r.minimum_online_fraction {
                        Some(f) => format!("{f:.4}"),
                        None => "not reachable".to_string(),
                    })
            }));
            body.push(row);
        }
    }
    table(out, &headers, &body);
}

fn size_load_tables(out: &mut String, config: &Config, i: &SectionI) {
    let rows = &i.load;
    let sizes = sizes_in(rows.iter().map(|r| r.wcs_per_kwc));
    let grid = &config.analytic.kwc_size;
    let fastest = grid
        .registered_cadences_s
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min);
    let mut policies: Vec<String> = Vec::new();
    for r in rows {
        if !policies.contains(&r.policy) {
            policies.push(r.policy.clone());
        }
    }
    line(
        out,
        &format!(
            "**Load per node** (`I3_kwc_size_load.csv`): miners watched per node, which is also its open miner connections and its hash recomputations per second, and its steady bandwidth with registered miners exchanging every {} s, unregistered every {} s, {} bytes per exchange, no transport overhead. Policies: A, every WC hosts the SPEC capacity; B, every node watches as many miners as at the protocol size; C, the architect's rule, {} registered miners per WC (10 IDs plus the {} spare-capacity target) plus u unregistered.",
            compact_number(fastest),
            compact_number(grid.unregistered_cadence_s),
            compact_number(grid.message_bytes),
            policy_c_registered(config).map_or("—".to_string(), |n| n.to_string()),
            share(config.capacity.spare_target_fraction.value)
        ),
    );
    blank(out);
    let find = |policy: &str, k: u64| {
        rows.iter()
            .find(|r| r.policy == policy && r.wcs_per_kwc == k && r.registered_cadence_s == fastest)
    };
    let mut headers = vec!["policy".to_string()];
    headers.extend(sizes.iter().map(|k| format!("k = {k}")));
    let body: Vec<Vec<String>> = policies
        .iter()
        .map(|policy| {
            let mut row = vec![policy.clone()];
            row.extend(sizes.iter().map(|k| {
                find(policy, *k).map_or("—".to_string(), |r| {
                    format!(
                        "{} miners, {} kB/s",
                        compact_number(r.miners_watched_per_node),
                        sig3(r.bandwidth_bytes_per_s / 1_000.0)
                    )
                })
            }));
            row
        })
        .collect();
    table(out, &headers, &body);
    line(out, "**Connections and spare registered capacity:**");
    blank(out);
    let mut body = vec![
        {
            let mut row = vec!["connections per miner (KWC size)".to_string()];
            row.extend(sizes.iter().map(|k| {
                rows.iter()
                    .find(|r| r.wcs_per_kwc == *k)
                    .map_or("—".to_string(), |r| r.connections_per_miner.to_string())
            }));
            row
        },
        {
            let mut row = vec!["standing witness-peer connections per node, option 1".to_string()];
            row.extend(sizes.iter().map(|k| {
                rows.iter()
                    .find(|r| r.wcs_per_kwc == *k)
                    .map_or("—".to_string(), |r| {
                        r.peer_connections_option_1.to_string()
                    })
            }));
            row
        },
    ];
    for policy in &policies {
        let mut row = vec![format!("registered capacity ÷ registered IDs, {policy}")];
        row.extend(sizes.iter().map(|k| {
            find(policy, *k).map_or("—".to_string(), |r| {
                sig3(r.registered_capacity_per_registered_id)
            })
        }));
        body.push(row);
    }
    let mut headers = vec!["".to_string()];
    headers.extend(sizes.iter().map(|k| format!("k = {k}")));
    table(out, &headers, &body);
}

fn on_demand_table(out: &mut String, config: &Config, i: &SectionI) {
    let rows = &i.on_demand;
    let Some(policy) = rows.first().map(|r| r.policy.clone()) else {
        return;
    };
    let c = config
        .analytic
        .absence
        .absences_per_id_per_year
        .iter()
        .copied()
        .fold(0.0, f64::max);
    let changes = distinct(rows.iter().map(|r| r.session_changes_per_miner_per_day));
    let sizes = sizes_in(rows.iter().map(|r| r.wcs_per_kwc));
    line(
        out,
        &format!(
            "**Witness peer topology.** Option 1 keeps a standing connection to every member of a node's k KWCs (table above). Option 2, the architect's design [P] (SPEC §12), keeps none: the miner relays routine messages, and members connect on demand through the global directory only for One Chance, decisions, proposer duties and catch-up. Estimated on-demand connections per node per hour (opened plus accepted; `I4_on_demand_connections.csv`), policy {policy}, {} absences per member per year all treated as unannounced (the worst case for One Chance), no bans; a decision costs each member 2(n − 1)/n connections on average, averaging out the two proposers:",
            compact_number(c)
        ),
    );
    blank(out);
    let mut headers = strings(&["k", "One Chance", "catch-up"]);
    for s in &changes {
        headers.push(format!(
            "decisions, {} session changes per miner per day",
            compact_number(*s)
        ));
        headers.push(format!("total, {} changes per day", compact_number(*s)));
    }
    let body: Vec<Vec<String>> = sizes
        .iter()
        .filter_map(|k| {
            let at = |s: f64| {
                rows.iter().find(|r| {
                    r.wcs_per_kwc == *k
                        && r.policy == policy
                        && r.absences_per_id_per_year == c
                        && r.session_changes_per_miner_per_day == s
                        && r.ban_rate_per_year == 0.0
                })
            };
            let first = at(changes[0])?;
            let mut row = vec![
                k.to_string(),
                sig3(first.one_chance_per_hour),
                sig3(first.catch_up_per_hour),
            ];
            for s in &changes {
                let r = at(*s)?;
                row.push(sig3(r.decisions_per_hour));
                row.push(sig3(r.total_per_hour));
            }
            Some(row)
        })
        .collect();
    table(out, &headers, &body);
}

fn size_plain_english(out: &mut String, config: &Config, i: &SectionI) {
    line(out, "**What size buys and costs.**");
    blank(out);
    let rows = &i.security;
    let sizes = sizes_in(rows.iter().map(|r| r.wcs_per_kwc));
    let (Some(&small), Some(&large)) = (sizes.first(), sizes.last()) else {
        return;
    };
    let at = |q: &str, k: u64, p: f64| {
        rows.iter()
            .find(|r| r.quorum == q && r.wcs_per_kwc == k && r.attacker_fraction == p)
    };
    let series = |q: &str, p: f64| -> Vec<f64> {
        sizes
            .iter()
            .filter_map(|k| at(q, *k, p).map(|r| r.log10_p_stall))
            .collect()
    };
    let falls = series("2/3", 0.25).windows(2).all(|w| w[1] < w[0]);
    let high = 0.4;
    let rises_overall = match (at("2/3", small, high), at("2/3", large, high)) {
        (Some(a), Some(b)) => b.log10_p_stall > a.log10_p_stall,
        _ => false,
    };
    let strictly = series("2/3", high).windows(2).all(|w| w[1] > w[0]);
    if let (true, true, Some(a25), Some(b25), Some(a40), Some(b40)) = (
        falls,
        rises_overall,
        at("2/3", small, 0.25),
        at("2/3", large, 0.25),
        at("2/3", small, high),
        at("2/3", large, high),
    ) {
        let thresholds: Vec<String> = sizes
            .iter()
            .filter_map(|k| at("2/3", *k, 0.25))
            .map(|r| {
                let seats: f64 = r
                    .seats_to_stall
                    .trim_start_matches("≥ ")
                    .parse()
                    .unwrap_or(f64::NAN);
                format!(
                    "{} of {} ({})",
                    r.seats_to_stall.trim_start_matches("≥ "),
                    r.members,
                    pct(seats / r.members as f64)
                )
            })
            .collect();
        let mut text = format!(
            "- **Bigger groups make the one-third line sharper but do not move it.** At two-thirds, the chance an attacker can stall a KWC falls with size well below one third (p = 25%: {} at k = {small}, {} at k = {large}) and rises towards 1 well above it (p = 40%: {} at k = {small}, {} at k = {large}).",
            prob(&a25.p_stall),
            prob(&b25.p_stall),
            prob(&a40.p_stall),
            prob(&b40.p_stall)
        );
        let near: Vec<f64> = distinct(rows.iter().map(|r| r.attacker_fraction))
            .into_iter()
            .filter(|p| *p > 0.25 && *p < 0.4)
            .collect();
        let wobbles = !near.is_empty()
            && near.iter().all(|p| {
                let v = series("2/3", *p);
                !v.windows(2).all(|w| w[1] > w[0]) && !v.windows(2).all(|w| w[1] < w[0])
            });
        if !strictly || wobbles {
            let shares: Vec<String> = near.iter().map(|p| share(*p)).collect();
            text.push_str(&format!(
                " Neither trend is smooth near the line, because ⌈2n/3⌉ rounds differently at each size: stalling needs {}",
                thresholds.join(", ")
            ));
            if wobbles {
                text.push_str(&format!(
                    ", so at p = {} the odds move up and down with size",
                    shares.join(" and ")
                ));
            }
            text.push('.');
        }
        line(out, &text);
    }
    if let (Some(two), Some(low)) = (at("2/3", 4, high), at("0.51", 4, high)) {
        if prob(&low.p_stall) != prob(&two.p_stall) {
            line(
                out,
                &format!(
                    "- **A lower PoWit quorum moves the line.** At 0.51, stalling a 40-member KWC needs {} seats instead of {}, so at p = 40% the stall chance is {} instead of {}. It also allows two conflicting approvals from {} attacker seats at every size, which is why it suits PoWits only: validators recompute every PoWit, while decisions keep two-thirds (section 10).",
                    low.seats_to_stall.trim_start_matches("≥ "),
                    two.seats_to_stall.trim_start_matches("≥ "),
                    prob(&low.p_stall),
                    prob(&two.p_stall),
                    low.seats_to_conflict.trim_start_matches("≥ ")
                ),
            );
        }
    }
    let live = |k: u64| {
        i.liveness.iter().find(|r| {
            r.quorum == "2/3"
                && r.wcs_per_kwc == k
                && r.attacker_fraction == 0.0
                && r.failure_target == 0.01
        })
    };
    if let (Some(a), Some(b)) = (live(small), live(large))
        && let (Some(fa), Some(fb)) = (a.minimum_online_fraction, b.minimum_online_fraction)
    {
        let mut text = format!(
            "- **Liveness.** Without an attacker, two-thirds needs honest uptime {fa:.4} at k = {small} and {fb:.4} at k = {large} for under 1% of KWCs failing."
        );
        let mut parts = Vec::new();
        let mut quorums: Vec<String> = Vec::new();
        for r in &i.liveness {
            if !quorums.contains(&r.quorum) {
                quorums.push(r.quorum.clone());
            }
        }
        for q in &quorums {
            let fractions: Vec<f64> = distinct(i.liveness.iter().map(|r| r.attacker_fraction))
                .into_iter()
                .filter(|p| *p > 0.0)
                .collect();
            // (where, shares) groups of consecutive attacker shares with the same answer.
            let mut groups: Vec<(String, Vec<String>)> = Vec::new();
            for p in &fractions {
                let reachable: Vec<u64> = sizes
                    .iter()
                    .copied()
                    .filter(|k| {
                        i.liveness.iter().any(|r| {
                            r.quorum == *q
                                && r.wcs_per_kwc == *k
                                && r.attacker_fraction == *p
                                && r.failure_target == 0.01
                                && r.minimum_online_fraction.is_some()
                        })
                    })
                    .collect();
                let suffix = reachable
                    .first()
                    .and_then(|k| sizes.iter().position(|s| s == k))
                    .is_some_and(|start| sizes[start..] == reachable[..]);
                let where_ = if reachable.len() == sizes.len() {
                    "at every size".to_string()
                } else if reachable.is_empty() {
                    "at no size".to_string()
                } else if suffix {
                    format!("only from k = {}", reachable[0])
                } else {
                    let ks: Vec<String> = reachable.iter().map(|k| k.to_string()).collect();
                    format!("only at k = {}", ks.join(", "))
                };
                match groups.last_mut() {
                    Some((last, shares)) if *last == where_ => shares.push(share(*p)),
                    _ => groups.push((where_, vec![share(*p)])),
                }
            }
            let phrases: Vec<String> = groups
                .iter()
                .map(|(where_, shares)| {
                    let list = match shares.split_last() {
                        Some((last, rest)) if !rest.is_empty() => {
                            format!("{} and {last}", rest.join(", "))
                        }
                        _ => shares.join(""),
                    };
                    format!("at p = {list} {where_}")
                })
                .collect();
            let name = if q == "2/3" {
                "two-thirds".to_string()
            } else {
                format!("the {q} quorum")
            };
            parts.push(format!("for {name} {}", phrases.join(", ")));
        }
        if !parts.is_empty() {
            text.push_str(&format!(
                " With attacker members withholding (and no penalty), staying under 1% is possible {}.",
                parts.join("; ")
            ));
        }
        line(out, &text);
    }
    let load = |policy: &LoadPolicy, k: u64| {
        let label = policy.label(config).ok()?;
        i.load
            .iter()
            .find(|r| r.policy == label && r.wcs_per_kwc == k)
    };
    let target = 1.0 + config.capacity.spare_target_fraction.value;
    let policy_c_meets_target = i
        .load
        .iter()
        .filter(|r| r.unregistered_per_wc.is_some())
        .all(|r| r.registered_capacity_per_registered_id >= target);
    let b_label = LoadPolicy::PerNode.label(config).unwrap_or_default();
    let b_watched = distinct(
        i.load
            .iter()
            .filter(|r| r.policy == b_label)
            .map(|r| r.miners_watched_per_node),
    );
    let decisions_dominate = i
        .on_demand
        .iter()
        .filter(|r| r.session_changes_per_miner_per_day > 0.0)
        .all(|r| r.decisions_per_hour > 0.5 * r.total_per_hour);
    if let (Some(a_small), Some(a_large)) = (
        load(&LoadPolicy::PerWc, small),
        load(&LoadPolicy::PerWc, large),
    ) {
        let mut text = format!(
            "- **Load.** Under policy A a node watches {} miners at k = {small} and {} at k = {large}",
            compact_number(a_small.miners_watched_per_node),
            compact_number(a_large.miners_watched_per_node)
        );
        if b_watched.len() == 1 {
            text.push_str(&format!(
                "; policy B holds it at {}",
                compact_number(b_watched[0])
            ));
        }
        if policy_c_meets_target {
            text.push_str(&format!(
                "; policy C keeps registered witness capacity at least {} times registered IDs at every size",
                sig3(target)
            ));
        }
        text.push_str(&format!(
            ". Standing witness-peer connections under option 1 grow from {} to {}; option 2 has none, at the cost of the on-demand connections above",
            a_small.peer_connections_option_1, a_large.peer_connections_option_1
        ));
        if decisions_dominate {
            text.push_str(", which are mostly for miner session decisions");
        }
        text.push('.');
        line(out, &text);
    }
    line(
        out,
        "- **Household limits**, such as router connection tables and upload bandwidth, are to be measured in M5. This section does not pick a size.",
    );
    blank(out);
}

fn cross_checks(out: &mut String, results: &M1Results) {
    line(out, "## 13. Cross-checks");
    blank(out);
    line(
        out,
        "Table `validation.csv` lists every check with its reference, tolerance and verdict. Each check compares a result with something independent: exact substitution into the formula, a different algorithm (dynamic programming, log-space arithmetic, dense grids), or a seeded Monte Carlo simulation (agreement within the stated number of standard errors).",
    );
    blank(out);
    let mut sections: Vec<&str> = Vec::new();
    for check in &results.checks {
        if !sections.contains(&check.section) {
            sections.push(check.section);
        }
    }
    let body: Vec<Vec<String>> = sections
        .iter()
        .map(|section| {
            let checks: Vec<&Check> = results
                .checks
                .iter()
                .filter(|c| c.section == *section)
                .collect();
            let passed = checks.iter().filter(|c| c.passed).count();
            vec![section.to_string(), format!("{passed} of {}", checks.len())]
        })
        .collect();
    table(out, &strings(&["section", "checks passed"]), &body);
    let failed: Vec<&Check> = results.checks.iter().filter(|c| !c.passed).collect();
    if failed.is_empty() {
        line(out, &format!("All {} checks passed.", results.checks.len()));
    } else {
        line(
            out,
            &format!(
                "{} of {} checks **failed**:",
                failed.len(),
                results.checks.len()
            ),
        );
        for check in failed {
            line(
                out,
                &format!(
                    "- `{}`: {} (reference {}, value {})",
                    check.check, check.description, check.reference, check.value
                ),
            );
        }
    }
    blank(out);
    line(out, "**Sanity values required by the M1 brief:**");
    blank(out);
    let sanity: Vec<Vec<String>> = results
        .checks
        .iter()
        .filter(|c| c.check.starts_with("A-sanity") || c.check.starts_with("D-sanity"))
        .map(|c| {
            let value = match c.check.as_str() {
                "A-sanity-s051" if c.value == 1.0 => "no finite solution".to_string(),
                id if id.starts_with("A-sanity") => format!("{} years", sig3(c.value)),
                _ => format!("{:.1}×", c.value),
            };
            vec![
                c.check.clone(),
                c.description.clone(),
                value,
                if c.passed {
                    "pass".to_string()
                } else {
                    "FAIL".to_string()
                },
            ]
        })
        .collect();
    table(
        out,
        &strings(&["check", "what is checked", "value", "verdict"]),
        &sanity,
    );
}

fn closing(out: &mut String) {
    line(out, "## What this summary does not show");
    blank(out);
    line(
        out,
        "- No network behaviour: messages, latency, churn and adversarial timing come with the M3/M4 simulators, which must reproduce these tables first.",
    );
    line(
        out,
        "- No verdicts on the pre-registered hypotheses of SPEC §10; their thresholds are confirmed by the architect before simulation results are generated.",
    );
    line(
        out,
        "- No incentives: M1 models no rewards, payments or penalties. Sections 11 and 12 assume withholding costs the attacker nothing; M4 adds the ban rules and the [P] rule separating validity from payment.",
    );
    line(
        out,
        "- Absence rates and durations are illustrative until M3 supplies household downtime profiles.",
    );
    line(
        out,
        "- The modelling assumptions behind every number are in `docs/ASSUMPTIONS.md`; charts are in `charts/`.",
    );
    line(
        out,
        "- A short brief for a general technical audience is in `M1_PUBLIC_BRIEF.md`.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_significant_digits_in_fixed_notation() {
        assert_eq!(sig3(97.142_857), "97.1");
        assert_eq!(sig3(1.982_507), "1.98");
        assert_eq!(sig3(0.990_122), "0.990");
        assert_eq!(sig3(145.47), "145");
        assert_eq!(sig3(2_079.3), "2,079");
    }

    #[test]
    fn probabilities_use_percent_or_powers_of_ten() {
        assert_eq!(prob("4.12268e-1"), "41.2%");
        assert_eq!(prob("9.88022e-10"), "9.88 × 10⁻¹⁰");
        assert_eq!(prob("1.95e-399"), "1.95 × 10⁻³⁹⁹");
        assert_eq!(prob("1.00000e0"), "> 99.9%");
        assert_eq!(prob("9.99600e-1"), "> 99.9%");
        assert_eq!(prob("9.99400e-1"), "99.9%");
    }

    #[test]
    fn probability_pairs_gain_digits_until_they_differ() {
        assert_eq!(
            prob_pair("3.48687e-2", "3.48744e-2"),
            ("3.4869%".to_string(), "3.4874%".to_string())
        );
        assert_eq!(
            prob_pair("2.26000e-76", "2.35000e-76"),
            ("2.26 × 10⁻⁷⁶".to_string(), "2.35 × 10⁻⁷⁶".to_string())
        );
        assert_eq!(
            prob_pair("1.5e-1", "1.5e-1"),
            ("15.0%".to_string(), "15.0%".to_string())
        );
    }

    #[test]
    fn markdown_tables_have_a_separator_row() {
        let mut out = String::new();
        table(&mut out, &strings(&["a", "b"]), &[strings(&["1", "2"])]);
        assert_eq!(out, "| a | b |\n|---|---|\n| 1 | 2 |\n\n");
    }

    #[test]
    fn multiples_of_t_min_drop_a_leading_one() {
        assert_eq!(t_min_multiple(1.0), "T_min");
        assert_eq!(t_min_multiple(0.25), "0.25 T_min");
    }

    #[test]
    fn windows_are_written_in_readable_units() {
        assert_eq!(window(3_600), "1.00 h");
        assert_eq!(window(86_400), "1.00 d");
        assert_eq!(window(600), "600 s");
    }
}
