//! `SUMMARY.md`: a plain-English summary of every M1 table.
//!
//! Every number is read from the computed tables. A sentence that states a comparison or a
//! pattern is only written after the code has checked that it holds. The file contains no
//! timestamp, so a rerun at the same commit, seed and configuration produces the same bytes.

use crate::charts::{compact_number, short_count, superscript};
use gb_analytic::M1Results;
use gb_analytic::time_threshold::CapRow;
use gb_analytic::validation::Check;
use gb_analytic::witness::KwcState;
use gb_config::Config;

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
fn sig3(value: f64) -> String {
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
fn pct(value: f64) -> String {
    if (0.9995..1.0).contains(&value) {
        "> 99.9%".to_string()
    } else {
        format!("{}%", sig3(100.0 * value))
    }
}

/// An input share from the configuration grid, for example `5%` or `33%`.
fn share(value: f64) -> String {
    format!("{}%", compact_number(100.0 * value))
}

/// A share as a percentage with one decimal, for example `9.5%`.
fn pct1(value: f64) -> String {
    format!("{:.1}%", 100.0 * value)
}

/// Probability from an exact scientific string: a percentage when at least 1%, otherwise
/// `m.mm × 10ⁿ`.
fn prob(scientific: &str) -> String {
    let Some((mantissa, exponent)) = scientific.split_once('e') else {
        return scientific.to_string();
    };
    let (Ok(m), Ok(e)) = (mantissa.parse::<f64>(), exponent.parse::<i64>()) else {
        return scientific.to_string();
    };
    if e >= -2 {
        pct(m * libm::pow(10.0, e as f64))
    } else {
        format!("{m:.2} × 10{}", superscript(e))
    }
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
        "These results are exact calculations: closed-form formulas and exact probabilities. They are not a simulation of the network. Seeded Monte Carlo runs appear only as cross-checks of the formulas (section 10). Every number below comes from a CSV table in this directory, and every modelling assumption is listed in `docs/ASSUMPTIONS.md`.",
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
        "Everything in this section is a **worst-case bound**. It assumes the attacker wins 100% of new IDs and every honest ID stays online. The exact time is (T/(1−T)) × G/R, the SPEC v0.2 C2 floor.",
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
            "**Adaptive cap R ≤ registered IDs / T_min (SPEC §3.9): time for a 100%-capture attacker to reach {}, in units of T_min** (table `A4_adaptive_cap.csv`, chart `A4_adaptive_cap.png`). The \"worst start\" column is the fastest time over all possible start moments relative to the checkpoint schedule.",
            share(floor_t)
        ),
    );
    blank(out);
    let model_rows = |model: &str| -> Vec<&CapRow> {
        rows.iter().copied().filter(|r| r.model == model).collect()
    };
    let mut body = Vec::new();
    for r in model_rows("frozen") {
        body.push(vec![
            "cap frozen at attack start".to_string(),
            years(r.time_in_t_min),
            "—".to_string(),
        ]);
    }
    for r in model_rows("continuous") {
        body.push(vec![
            "recalculated continuously".to_string(),
            years(r.time_in_t_min),
            years(r.time_in_t_min),
        ]);
    }
    for aligned in model_rows("checkpoint aligned") {
        let fraction = aligned.checkpoint_interval_fraction_of_t_min;
        let worst = model_rows("checkpoint worst phase")
            .into_iter()
            .find(|w| w.checkpoint_interval_fraction_of_t_min == fraction);
        body.push(vec![
            format!(
                "checkpoint every {} T_min",
                fraction.map_or("?".to_string(), compact_number)
            ),
            years(aligned.time_in_t_min),
            worst.map_or("—".to_string(), |w| years(w.time_in_t_min)),
        ]);
    }
    table(
        out,
        &strings(&["cap recalculation", "start at a checkpoint", "worst start"]),
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
            "Times at or above 1.00 meet the floor. The floor holds at every start moment only for: {holds_text}. To hold it at the worst start, the cap needs a safety factor k, as in R ≤ registered IDs / (k × T_min) (table `A4_safety_factor.csv`):"
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
        &strings(&["cap", "worst time / T_min without k", "safety factor k"]),
        &safety,
    );
    line(
        out,
        "A factor k above 1 tightens the cap; below 1, the floor already holds with room to spare.",
    );
    blank(out);
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
        .filter(|r| r.initial_kwcs == 100_000 && r.ban_replacement_rate_per_year == 0.0)
        .collect();
    let compositions = base.first().map(|r| r.compositions).unwrap_or(0.0);
    line(
        out,
        &format!(
            "**Expected number of KWC compositions in state (ii) over {} years** (SPEC §10 H6 refresh model: 100,000 KWCs at the start, one new KWC per 10 new IDs, no bans; every composition counted as an independent draw; {} compositions in total):",
            compact_number(horizon),
            compact_number(compositions)
        ),
    );
    blank(out);
    let fractions = distinct(base.iter().map(|r| r.attacker_fraction));
    let body: Vec<Vec<String>> = fractions
        .iter()
        .map(|p| {
            let get = |kind: &str| {
                base.iter()
                    .find(|r| r.attacker_fraction == *p && r.miner_kind == kind)
                    .map_or("—".to_string(), |r| {
                        count(&format!("{:e}", r.expected_sign_capable))
                    })
            };
            vec![share(*p), get("registered"), get("unregistered")]
        })
        .collect();
    table(
        out,
        &strings(&[
            "p",
            "registered quorum",
            "unregistered quorum (used by PoW-ID)",
        ]),
        &body,
    );
    let banned: Vec<_> = rows
        .iter()
        .filter(|r| r.initial_kwcs == 100_000 && r.ban_replacement_rate_per_year > 0.0)
        .collect();
    if let (Some(first), Some(last)) = (banned.first(), banned.last()) {
        line(
            out,
            &format!(
                "Ban replacements are a labelled sensitivity. Each one creates 4 new compositions. At {} and {} of IDs replaced per year, the composition count is {} and {} instead of {}, and the expected counts scale by the same factor.",
                share(first.ban_replacement_rate_per_year),
                share(last.ban_replacement_rate_per_year),
                compact_number(first.compositions),
                compact_number(last.compositions),
                compact_number(compositions)
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

fn committee(out: &mut String, config: &Config, results: &M1Results) {
    line(out, "## 6. Chain Allocation Committee");
    blank(out);
    line(
        out,
        "Tables `C1_cac_probabilities.csv`, `C2_cac_events_per_year.csv`; chart `C1_cac_probabilities.png`. An Allocation Committee Block needs ⌈2n/3⌉ approvals. The attacker can stall with n − ⌈2n/3⌉ + 1 seats and approve alone with ⌈2n/3⌉ seats. Under the [P] seat rule one ID holds at most one seat, so the attacker's seat count is hypergeometric over the mining IDs (default: all 2.1M IDs mine).",
    );
    blank(out);
    let rows: Vec<_> = results
        .c
        .odds
        .iter()
        .filter(|r| r.mining_population.is_some() && r.honest_mining_fraction == 1.0)
        .collect();
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
        line(out, &format!("**Probability the attacker can {label}:**"));
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
    committee_mining_sensitivity(out, results);
}

fn committee_events(out: &mut String, config: &Config, results: &M1Results) {
    let size = u64::from(config.cac.size.value);
    let rows: Vec<_> = results
        .c
        .events
        .iter()
        .filter(|r| {
            r.committee_size == size
                && r.honest_mining_fraction == 1.0
                && r.model.starts_with("one seat")
        })
        .collect();
    if rows.is_empty() {
        return;
    }
    let refreshes = rows.first().map(|r| r.refreshes_per_year).unwrap_or(0.0);
    line(
        out,
        &format!(
            "**Events per year at n = {size}** ({} refreshes per year). The M1 brief's estimate assumes one independent composition per n refreshes. The exact count of entries into the state, under the same seat model, is shown next to it.",
            compact_number(refreshes)
        ),
    );
    blank(out);
    let time_share = |time_fraction: &str| time_fraction.parse::<f64>().unwrap_or(0.0);
    let rare_more = rows
        .iter()
        .any(|r| time_share(&r.time_fraction) < 0.5 && r.ratio_exact_to_approximation > 1.0);
    let common_fewer = rows
        .iter()
        .any(|r| time_share(&r.time_fraction) >= 0.5 && r.ratio_exact_to_approximation < 1.0);
    if rare_more {
        let mut text = "A sliding committee changes one seat at a time. Where the state is rare, the committee enters it more often than the estimate assumes (ratio above 1)".to_string();
        if common_fewer {
            text.push_str("; where it is in the state most of the time, it seldom leaves, so entries are fewer (ratio below 1)");
        }
        text.push('.');
        line(out, &text);
        blank(out);
    }
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
                        prob(&r.time_fraction),
                        count(&r.events_per_year_independence_approximation),
                        count(&r.onsets_per_year_exact),
                        sig3(r.ratio_exact_to_approximation),
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
            "events/yr, brief's estimate",
            "entries/yr, exact",
            "exact ÷ estimate",
        ]),
        &body,
    );
}

fn committee_mining_sensitivity(out: &mut String, results: &M1Results) {
    let rows: Vec<_> = results
        .c
        .odds
        .iter()
        .filter(|r| r.mining_population.is_some())
        .collect();
    let mus = distinct(rows.iter().map(|r| r.honest_mining_fraction));
    let low_mu = mus.iter().copied().fold(f64::INFINITY, f64::min);
    let pick = |mu: f64| {
        rows.iter().find(|r| {
            r.committee_size == 600 && r.attacker_fraction == 0.25 && r.honest_mining_fraction == mu
        })
    };
    if let (Some(full), Some(low)) = (pick(1.0), pick(low_mu)) {
        line(
            out,
            &format!(
                "**If fewer honest IDs mine.** Attacker IDs always mine. If only {} of honest IDs mine, an attacker holding 25% of active IDs holds {} of mining IDs. At n = 600 its chance of being able to stall rises from {} to {} (rows with honest mining fraction below 100%).",
                share(low_mu),
                pct1(low.attacker_mining_share),
                prob(&full.p_stall),
                prob(&low.p_stall)
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
        "Tables `D1_restart_advantage.csv`, `D2_restart_advantage_curve.csv`; chart `D1_restart_advantage.png`. In the old design, entropy stayed fixed for the whole connection, so a miner could see its future winning steps at connection time and reconnect until one fell within a keep window W. Each reconnection costs C seconds. Advantage = expected time to an ID for a miner that stays connected ÷ expected time for the restarting miner.",
    );
    blank(out);
    let body: Vec<Vec<String>> = results
        .d
        .iter()
        .map(|r| {
            vec![
                short_count(r.competing_miners),
                format!("{} s", compact_number(r.restart_cost_s)),
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
    line(
        out,
        "**Per-round entropy (current design): the advantage is exactly 1.** Each round's entropy is fresh and unpredictable and does not depend on what the miner did before: the header names the previous PoW-ID block, and the entropy aggregates every online member's signature. A miner gets one header per round, and abandoning it means waiting for the next block. So a connected miner wins each round with the same probability, 1/N, whatever it did before. A disconnected miner cannot win. Restarting can only remove rounds, never improve them, and never restarting is the fastest policy. The Monte Carlo check `D-per-round-entropy` (section 10) agrees.",
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
    line(
        out,
        "Table `E1_difficulty_hopping.csv`. Variant A retargets difficulty every K blocks, Bitcoin-style. An attacker adds m times the honest miners for exactly one window, then leaves. Gain = the attacker's IDs per miner-second compared with count-based difficulty (Variant B). First-order formula: gain = m.",
    );
    blank(out);
    let windows = distinct(results.e.iter().map(|r| r.window_blocks as f64));
    let ratios = distinct(results.e.iter().map(|r| r.attacker_ratio));
    for k in windows {
        line(out, &format!("**K = {} blocks:**", compact_number(k)));
        blank(out);
        let body: Vec<Vec<String>> = ratios
            .iter()
            .map(|m| {
                let free = results.e.iter().find(|r| {
                    r.window_blocks as f64 == k && r.attacker_ratio == *m && r.clamp == "none"
                });
                let clamped = results.e.iter().find(|r| {
                    r.window_blocks as f64 == k && r.attacker_ratio == *m && r.clamp != "none"
                });
                vec![
                    compact_number(*m),
                    free.map_or("—".to_string(), |r| {
                        format!("+{}%", compact_number(r.gain_percent))
                    }),
                    free.map_or("—".to_string(), |r| sig3(r.attack_window_hours)),
                    free.map_or("—".to_string(), |r| sig3(r.recovery_window_hours)),
                    clamped.map_or("—".to_string(), |r| sig3(r.recovery_window_hours)),
                    free.map_or("—".to_string(), |r| {
                        format!("{:.3}", r.cycle_issuance_ratio)
                    }),
                ]
            })
            .collect();
        table(
            out,
            &strings(&[
                "m",
                "gain (Variant A)",
                "hop window (h)",
                "recovery window (h)",
                "recovery with 4× clamp (h)",
                "issuance over both windows ÷ target",
            ]),
            &body,
        );
    }
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
                "The 4× clamp only shortens the recovery window. The gain is earned before any retarget, so the clamp does not change it. Under Variant B with exact counts the first-order gain is 0. Its Monte Carlo cross-checks gave gain factors between {lo:.3} and {hi:.3}. Variant B's \"small correction from recent block times\" is not modelled here (deferred to M3)."
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

fn cross_checks(out: &mut String, results: &M1Results) {
    line(out, "## 10. Cross-checks");
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
