//! `SUMMARY.md`: a plain-English summary of every M1 table.
//!
//! Every number is read from the computed tables. A sentence that states a comparison or a
//! pattern is only written after the code has checked that it holds. The file contains no
//! timestamp, so a rerun at the same commit, seed and configuration produces the same bytes.

use crate::charts::{compact_number, short_count, superscript};
use gb_analytic::M1Results;
use gb_analytic::cac::{CommitteeModel, OddsRow};
use gb_analytic::quorum_tradeoff::{POOL_LAYOUT, QuorumRow, REGISTERED_LAYOUT};
use gb_analytic::restart::REALISTIC_COST;
use gb_analytic::time_threshold::{CAP_CONFIGURED, CAP_WITH_SAFETY_FACTOR, CapRow};
use gb_analytic::validation::Check;
use gb_analytic::witness::KwcState;
use gb_config::Config;

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
    witness_chains(&mut out, results);
    committee(&mut out, config, results);
    restart(&mut out, results);
    hopping(&mut out, results);
    ties(&mut out, results);
    quorum_tradeoff(&mut out, results);
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
        "These results are exact calculations: closed-form formulas and exact probabilities. They are not a simulation of the network. Seeded Monte Carlo runs appear only as cross-checks of the formulas (section 11). Every number below comes from a CSV table in this directory, and every modelling assumption is listed in `docs/ASSUMPTIONS.md`.",
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
                "**SPEC v0.3 default:** k = {:.4} with checkpoints every {} T_min. Its worst-start time is {} T_min, so a 100%-capture attacker cannot reach {} in less than T_min at any start phase (cross-checks `A-cap-configured-floor` and `A-cap-configured-vs-grid`). A factor k above 1 tightens the cap; below 1, the floor already holds with room to spare.",
                configured.safety_factor.unwrap_or(f64::NAN),
                configured
                    .checkpoint_interval_fraction_of_t_min
                    .map_or("?".to_string(), compact_number),
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

fn witness_chains(out: &mut String, results: &M1Results) {
    line(
        out,
        "## 5. Witness Chains: chance an attacker controls a KWC",
    );
    blank(out);
    line(
        out,
        "Tables `B1_kwc_probabilities.csv`, `B2_network_counts.csv`, `B3_binomial_vs_hypergeometric.csv`, `B4_kwc_compositions_10y.csv`; charts `B1_kwc_probabilities.png`, `B4_kwc_compositions_10y.png`. The attacker controls a fraction p of registered IDs, and seats are assigned uniformly at random. A 40-node KWC is a 10-seat leader WC plus 30 subordinate seats.",
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

fn kwc_ten_year_table(out: &mut String, results: &M1Results) {
    let rows = &results.b.compositions;
    let horizon = rows.first().map(|r| r.horizon_years).unwrap_or(10.0);
    let base: Vec<_> = rows
        .iter()
        .filter(|r| {
            r.initial_kwcs == 100_000
                && r.ban_rate_per_year == 0.0
                && r.deactivation_cycles_per_id_per_year == 0.0
        })
        .collect();
    let Some(first) = base.first() else {
        return;
    };
    let (compositions, v02) = (first.compositions, first.compositions_v02_comparison);
    line(
        out,
        &format!(
            "**Expected KWC compositions in state (ii) over {} years** (table `B4_kwc_compositions_10y.csv`; SPEC §10 H6 refresh model). Every composition counts as an independent draw. Under the adopted allocation (SPEC §4.2) each new ID changes one existing WC, so the 4 KWCs it sits in, and one new ID in 10 completes a WC whose KWC forms while 6 others relink: about 4.7 compositions per new ID. With 100,000 KWCs at the start, no bans and no deactivation, that is {} compositions, {} times the v0.2 count of one new KWC per 10 new IDs ({}), shown for comparison:",
            compact_number(horizon),
            compact_number(compositions),
            sig3(compositions / v02),
            compact_number(v02)
        ),
    );
    blank(out);
    let fractions = distinct(base.iter().map(|r| r.attacker_fraction));
    let body: Vec<Vec<String>> = fractions
        .iter()
        .map(|p| {
            let get = |kind: &str, v02: bool| {
                base.iter()
                    .find(|r| r.attacker_fraction == *p && r.miner_kind == kind)
                    .map_or("—".to_string(), |r| {
                        let value = if v02 {
                            r.expected_sign_capable_v02_comparison
                        } else {
                            r.expected_sign_capable
                        };
                        count(&format!("{value:e}"))
                    })
            };
            vec![
                share(*p),
                get("registered", false),
                get("unregistered", false),
                get("registered", true),
                get("unregistered", true),
            ]
        })
        .collect();
    table(
        out,
        &strings(&[
            "p",
            "registered quorum (PoW-Tx)",
            "unregistered quorum (PoW-ID)",
            "registered, v0.2 count",
            "unregistered, v0.2 count",
        ]),
        &body,
    );
    let ratio_at = |kind: &str| {
        base.iter()
            .find(|r| r.attacker_fraction == 0.25 && r.miner_kind == kind)
            .map(|r| r.one_seat_entry_ratio)
    };
    if let (Some(registered), Some(unregistered)) =
        (ratio_at("registered"), ratio_at("unregistered"))
    {
        line(
            out,
            &format!(
                "Every allocation keeps each composition a uniformly random draw, so by linearity of expectation these counts hold whatever the correlation between compositions. But most consecutive compositions share all but one seat, so one KWC staying in state (ii) across several changes is counted several times. At p = 25% a one-seat change enters state (ii) with {} (registered) and {} (unregistered) times the probability of a fresh draw (column `one_seat_entry_ratio`). M4 measures the number of distinct episodes.",
                sig3(registered),
                sig3(unregistered)
            ),
        );
        blank(out);
    }
    let sensitivity = |ban: f64, cycles: f64| {
        rows.iter()
            .find(|r| {
                r.initial_kwcs == 100_000
                    && r.ban_rate_per_year == ban
                    && r.deactivation_cycles_per_id_per_year == cycles
            })
            .map(|r| r.compositions)
    };
    let bans = distinct(rows.iter().map(|r| r.ban_rate_per_year));
    let cycles = distinct(rows.iter().map(|r| r.deactivation_cycles_per_id_per_year));
    let mut parts = Vec::new();
    for ban in bans.iter().filter(|b| **b > 0.0) {
        if let Some(c) = sensitivity(*ban, 0.0) {
            parts.push(format!(
                "{} of registered IDs banned per year gives {} compositions",
                share(*ban),
                compact_number(c)
            ));
        }
    }
    for cycle in cycles.iter().filter(|c| **c > 0.0) {
        if let Some(c) = sensitivity(0.0, *cycle) {
            parts.push(format!(
                "{} deactivation cycle{} per ID per year gives {}",
                compact_number(*cycle),
                if *cycle == 1.0 { "" } else { "s" },
                compact_number(c)
            ));
        }
    }
    if !parts.is_empty() {
        line(
            out,
            &format!(
                "Sensitivities: {}. Expected counts scale by the same factor. Under SPEC v0.3 a deactivated ID vacates its seat and a re-activated ID is re-inserted, so household downtime changes compositions (about 9.3 per cycle); the cycle rates are illustrative until M3 provides downtime profiles.",
                parts.join("; ")
            ),
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
            "Tables `C1_cac_probabilities.csv`, `C2_cac_events_per_year.csv`; chart `C1_cac_probabilities.png`. Under SPEC v0.3 §4.3 a new member joins for every 10th PoW-Tx block by a lottery over the canonical active list ({} active IDs here); a draw that lands on a member moves to the next position. With the attacker's IDs spread through the list, its seat count is hypergeometric, so its expected committee share equals its share p of active IDs. Mining power plays no part. An Allocation Committee Block needs ⌈2n/3⌉ approvals; the attacker stalls with n − ⌈2n/3⌉ + 1 seats and approves alone with ⌈2n/3⌉.",
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
            "**Stalls and captures over time at n = {size}** ({} refreshes per year, one every {} s). Primary measures: the share of time in each state and the exact number of entries into it per year; the mean episode length is the first divided by the second. Stalling is accepted for now (SPEC §4.3): allocation is deterministic, so a stalled committee delays the announcement of placements but cannot change them. The M1 brief's estimate (one independent composition per n refreshes) is the last column, for comparison only.",
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

fn quorum_tradeoff(out: &mut String, results: &M1Results) {
    let g = &results.g;
    let Some(kwcs) = g.quorum.iter().map(|r| r.kwcs).min() else {
        return;
    };
    line(out, "## 10. Quorum trade-off (section G)");
    blank(out);
    line(
        out,
        "Tables `G1_quorum_kwc.csv`, `G2_split_rule.csv`, `G3_cac_quorum.csv`; chart `G1_quorum_tradeoff.png`. This section changes no SPEC quorum. For each quorum fraction q it shows what an attacker holding a fraction p of the seats can do: **stall** (deny every approval), **sign without honest members**, or get **two conflicting decisions approved**. Honest members sign at most one of two conflicting proposals; the attacker signs both and may show different proposals to different members. A pool of n members with quorum k therefore allows a conflict from 2k − n attacker seats. In the registered layout each condition applies to the leader WC and to the subordinates separately. The seat condition is necessary; the attacker also needs a proposer turn or another way to put two proposals in front of members.",
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
            "**Expected counts at p = 25%, {} KWCs.** \"Now\" is the expected number of KWCs in the state at one moment. \"Over {} years\" is the expected number of compositions in the state under the SPEC §10 H6 refresh model and the adopted allocation ({} compositions, binomial, no bans or deactivation):",
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
                count(&format!("{:e}", r.expected_compositions_sign)),
                count(&format!("{:e}", r.expected_compositions_conflict)),
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
            "sign alone, over 10 years",
            "conflict, over 10 years",
        ]),
        &body,
    );
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
                "false or conflicting bans, MOBu/MOBr, offline requests and committee blocks, which rest on witnesses' observations rather than on data validators can recompute",
                "committee placements, joins and leaves: every node recomputes them and rejects a mismatch (§4.2, §4.3); two conflicting committee blocks from one leader: both rejected (§4.3)",
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
                    "- **It makes conflicting approvals much easier.** Two conflicting decisions need {} attacker seats at q = {low} against {} at {default}. At p = 10% that is possible in {} of KWCs, against {}.",
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
                "- **The committee.** At q = {} a conflict needs {} of {} seats, and an attacker with {} of active IDs holds that many with probability {}. Placement conflicts are neutralised, because every node recomputes placement (§4.2), and a leader with two conflicting approved blocks has both rejected (§4.3). The committee's remaining power is over compiling bans that KWCs already approved: it can delay or omit them.",
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
        "- **Not considered.** A quorum at or below 50%: two disjoint groups of honest members could then approve conflicting decisions with no attacker at all. The single-member entropy stall, where one online member withholds its entropy signature, does not depend on the quorum; One Chance (§4.5) handles it.",
    );
    blank(out);
}

fn cross_checks(out: &mut String, results: &M1Results) {
    line(out, "## 11. Cross-checks");
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
        "- The modelling assumptions behind every number are in `docs/ASSUMPTIONS.md`; charts are in `charts/`.",
    );
    line(
        out,
        "- A one-to-two-page brief for a general technical audience is in `M1_PUBLIC_BRIEF.md`.",
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
    fn windows_are_written_in_readable_units() {
        assert_eq!(window(3_600), "1.00 h");
        assert_eq!(window(86_400), "1.00 d");
        assert_eq!(window(600), "600 s");
    }
}
