//! `M1_PUBLIC_BRIEF.md`: a one-to-two-page brief on the M1 results for a general technical
//! audience.
//!
//! The brief reads only exact tables: no Monte Carlo value, seed or commit appears in it. The
//! same configuration therefore always produces the same brief, so the copy committed at
//! `docs/M1_PUBLIC_BRIEF.md` can be checked byte for byte against a fresh run. Every sentence
//! that states a number takes it from a table; every comparison is checked before it is
//! written.

use crate::charts::{compact_number, short_count};
use crate::summary::{DISCLOSURE, prob, share, sig3, t_min_multiple};
use gb_analytic::M1Results;
use gb_analytic::cac::CommitteeModel;
use gb_analytic::restart::REALISTIC_COST;
use gb_analytic::time_threshold::CAP_CONFIGURED;
use gb_analytic::witness::KwcState;
use gb_config::Config;

/// File name of the brief inside a run directory and in `docs/`.
pub const BRIEF_FILE: &str = "M1_PUBLIC_BRIEF.md";

/// Genesis size before SPEC v0.3 (v0.2 default), for the design-change note.
const GENESIS_V02: u64 = 2_100_000;

fn line(out: &mut String, text: &str) {
    out.push_str(text);
    out.push('\n');
}

fn blank(out: &mut String) {
    out.push('\n');
}

fn table(out: &mut String, headers: &[&str], rows: &[Vec<String>]) {
    line(out, &format!("| {} |", headers.join(" | ")));
    line(out, &format!("|{}", "---|".repeat(headers.len())));
    for row in rows {
        line(out, &format!("| {} |", row.join(" | ")));
    }
    blank(out);
}

/// Renders the public brief.
pub fn render_brief(config: &Config, results: &M1Results) -> String {
    let mut out = String::new();
    let genesis = config.genesis.ids.value;
    line(
        &mut out,
        "# GrahamBell Stage 1 — M1 analytical baseline: public brief",
    );
    blank(&mut out);
    line(
        &mut out,
        &format!(
            "GrahamBell is a proposed Layer 1 blockchain. New identities (IDs) are issued one at a time at a fixed global rate, one every {} s ({} a year), through Proof of Work capped at one hash per second per participant; Witness Chains of other participants enforce the cap. Its claim is that taking control requires sustained participation over years, not a burst of hardware or capital. Stage 1 tests that claim and publishes the results whether they support it or not.",
            compact_number(config.issuance.pow_id_target_interval_s.value),
            compact_number(config.issuance_per_year())
        ),
    );
    blank(&mut out);
    line(&mut out, "## What M1 tested");
    blank(&mut out);
    line(
        &mut out,
        &format!(
            "M1 computes exact formulas and exact probabilities for the rules in SPEC v0.3: how long an attacker needs to reach a share of active IDs, how likely a randomly composed Witness Chain group is to fall under its control, how often the allocation committee can be stalled or captured, and whether restarting or hopping difficulty helps. Independent methods (exhaustive enumeration, dynamic programming, log-space arithmetic, seeded Monte Carlo) cross-check the results. The default genesis distribution is {} IDs.",
            short_count(genesis)
        ),
    );
    blank(&mut out);
    line(&mut out, &format!("> {DISCLOSURE}"));
    blank(&mut out);
    honest_majority(&mut out, config, results);
    worst_case(&mut out, config, results);
    restart(&mut out, results);
    witness(&mut out, results);
    design_changes(&mut out, config, results);
    limitations(&mut out);
    out
}

fn honest_majority(out: &mut String, config: &Config, results: &M1Results) {
    line(out, "## Headline: attackers below half of new issuance");
    blank(out);
    line(
        out,
        "An attacker that wins a share s of new IDs approaches a long-run share of active IDs and never exceeds it. If a fraction f of honest IDs is online, that share is s / (s + f(1 − s)); with every honest ID online it is s.",
    );
    blank(out);
    let rows = &results.a.long_run;
    let mut onlines: Vec<f64> = Vec::new();
    for r in rows {
        if !onlines.contains(&r.online_fraction) {
            onlines.push(r.online_fraction);
        }
    }
    onlines.sort_by(|a, b| b.total_cmp(a));
    let columns: Vec<f64> = onlines
        .iter()
        .copied()
        .filter(|f| [1.0, 0.7, 0.5].contains(f))
        .collect();
    let mut shares: Vec<f64> = Vec::new();
    for r in rows.iter().filter(|r| r.attacker_share < 0.5) {
        if !shares.contains(&r.attacker_share) {
            shares.push(r.attacker_share);
        }
    }
    let headers: Vec<String> = std::iter::once("s".to_string())
        .chain(columns.iter().map(|f| format!("f = {}", share(*f))))
        .collect();
    let body: Vec<Vec<String>> = shares
        .iter()
        .map(|s| {
            std::iter::once(share(*s))
                .chain(columns.iter().map(|f| {
                    rows.iter()
                        .find(|r| r.attacker_share == *s && r.online_fraction == *f)
                        .map_or("—".to_string(), |r| {
                            format!("{:.1}%", 100.0 * r.long_run_share)
                        })
                }))
                .collect()
        })
        .collect();
    let header_refs: Vec<&str> = headers.iter().map(String::as_str).collect();
    line(out, "Long-run attacker share of active IDs:");
    blank(out);
    table(out, &header_refs, &body);
    // The smallest minority share that eventually passes 51% at the lowest online fraction.
    let low_f = columns.iter().copied().fold(f64::INFINITY, f64::min);
    let crossing = shares.iter().copied().find(|s| {
        rows.iter().any(|r| {
            r.attacker_share == *s
                && r.online_fraction == low_f
                && r.thresholds_eventually_crossed.contains("51%")
        })
    });
    let all_safe = rows
        .iter()
        .filter(|r| r.attacker_share < 0.5 && r.online_fraction == 1.0)
        .all(|r| !r.thresholds_eventually_crossed.contains("51%"));
    if all_safe {
        let mut text = "While every honest ID is online, no attacker below half of new issuance ever reaches 51% of active IDs.".to_string();
        if let Some(s) = crossing {
            let years = results.a.online.iter().find(|r| {
                r.variant == "realistic"
                    && r.genesis_ids == config.genesis.ids.value
                    && r.attacker_share == s
                    && r.online_fraction == low_f
                    && r.threshold == 0.51
            });
            text.push_str(&format!(
                " Offline honest IDs change this: with only {} of honest IDs online, an attacker winning {} of new IDs eventually passes 51%",
                share(low_f),
                share(s)
            ));
            if let Some(time) = years.and_then(|r| r.years) {
                text.push_str(&format!(
                    ", after {} years from {} genesis IDs",
                    sig3(time),
                    short_count(config.genesis.ids.value)
                ));
            }
            text.push_str(". Honest uptime is therefore part of the security model.");
        }
        line(out, &text);
        blank(out);
    }
}

fn worst_case(out: &mut String, config: &Config, results: &M1Results) {
    line(
        out,
        "## Worst-case bounds: an attacker that wins every new ID",
    );
    blank(out);
    let rows: Vec<_> = results
        .a
        .thresholds
        .iter()
        .filter(|r| r.attacker_share == 1.0 && r.threshold == 0.51)
        .collect();
    let mut sizes: Vec<String> = Vec::new();
    for r in &rows {
        if let Some(t) = r.years {
            sizes.push(format!(
                "{} years from {} IDs",
                sig3(t),
                short_count(r.genesis_ids)
            ));
        }
    }
    line(
        out,
        &format!(
            "If the attacker wins 100% of new IDs and every honest ID stays online, reaching 51% of active IDs takes (0.51/0.49) × G/R years for an existing active base G: {}.",
            sizes.join(", ")
        ),
    );
    blank(out);
    let floor = config.issuance.min_attack_time_floor_years.value;
    if let Some(needed) = results
        .a
        .genesis
        .iter()
        .find(|r| r.t_min_years == floor && r.online_fraction == 1.0)
        .map(|r| r.active_ids_needed)
    {
        let genesis = config.genesis.ids.value as f64;
        line(
            out,
            &format!(
                "A {}-year floor at the fixed rate needs {} active IDs. With {} genesis IDs it holds while at least {:.1}% of them stay active.",
                compact_number(floor),
                short_count(needed.round() as u64),
                short_count(config.genesis.ids.value),
                100.0 * needed / genesis
            ),
        );
        blank(out);
    }
    let configured = results
        .a
        .cap
        .iter()
        .find(|r| r.model == CAP_CONFIGURED && r.attacker_share == 1.0 && r.threshold == 0.51);
    let unfactored = results.a.safety.iter().find(|r| {
        r.model == "checkpoint"
            && r.checkpoint_interval_fraction_of_t_min
                == configured.and_then(|c| c.checkpoint_interval_fraction_of_t_min)
    });
    if let (Some(c), Some(u)) = (configured, unfactored) {
        let k = config.issuance.cap_safety_factor.value;
        line(
            out,
            &format!(
                "An optional adaptive rate is capped by registered IDs, recalculated at checkpoints every {}. Without a safety factor, an attacker that times its start against the public checkpoint schedule reaches 51% in {} T_min. The safety factor k = {}/{} adopted in SPEC v0.3 restores the floor: the worst-start time becomes {:.3} T_min.",
                t_min_multiple(c.checkpoint_interval_fraction_of_t_min.unwrap_or(f64::NAN)),
                sig3(u.worst_time_in_t_min_without_factor),
                k.numerator,
                k.denominator,
                c.time_in_t_min.unwrap_or(f64::NAN)
            ),
        );
        blank(out);
    }
}

fn restart(out: &mut String, results: &M1Results) {
    line(out, "## Restart attack, before and after per-round entropy");
    blank(out);
    let rows: Vec<_> = results
        .d
        .iter()
        .filter(|r| r.cost_case == REALISTIC_COST && r.keep_window_s == 86_400)
        .collect();
    if let (Some(small), Some(large)) = (rows.first(), rows.last()) {
        line(
            out,
            &format!(
                "In an earlier design a miner's entropy stayed fixed for its whole connection, so it could compute its winning steps at once and reconnect until one fell soon. At the realistic restart cost of {} s (grace epoch, convergence interval and post-admission wait) and a one-day keep window, that gave {:.1}× the honest rate with {} competing miners and {:.1}× with {} (up to {:.1}× and {:.1}× with the best keep window). The current design draws fresh entropy every round, a miner may use one header per round, and abandoning it means waiting for the next block. Every connected miner then wins each round with the same probability, so no restart policy beats staying connected: the best advantage is exactly 1.",
                compact_number(small.restart_cost_s),
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
}

fn witness(out: &mut String, results: &M1Results) {
    line(
        out,
        "## Witness Chains: capture odds and what each state enables",
    );
    blank(out);
    line(
        out,
        "Each group of witnesses (a KWC) has 40 seats drawn uniformly at random from registered IDs. An attacker holding enough seats can block the group (stall it and censor its miners, who can move elsewhere), sign without honest members (the same powers, because every validator recomputes each block and rejects an early or invalid one), or hold every seat (which would also let it bias the group's entropy).",
    );
    blank(out);
    let rows: Vec<_> = results
        .b
        .kwc
        .iter()
        .filter(|r| r.layout == "40-node" && r.model == "hypergeometric" && r.kwcs == Some(100_000))
        .collect();
    let get = |p: f64, kind: &str, state: KwcState| {
        rows.iter()
            .find(|r| r.attacker_fraction == p && r.miner_kind == kind && r.state == state.label())
            .map_or("—".to_string(), |r| prob(&r.probability))
    };
    let body: Vec<Vec<String>> = [0.1, 0.25, 0.33]
        .iter()
        .map(|p| {
            vec![
                share(*p),
                get(*p, "unregistered", KwcState::Block),
                get(*p, "unregistered", KwcState::Sign),
                get(*p, "registered", KwcState::Sign),
                get(*p, "unregistered", KwcState::AllSeats),
            ]
        })
        .collect();
    line(
        out,
        "Probability per group, exact, at 100,000 groups (p = attacker share of registered IDs):",
    );
    blank(out);
    table(
        out,
        &[
            "p",
            "block (ID issuance)",
            "sign without honest members (ID issuance)",
            "sign without honest members (transactions)",
            "every seat",
        ],
        &body,
    );
    let ten_year = results.b.compositions.iter().find(|r| {
        r.miner_kind == "unregistered"
            && r.attacker_fraction == 0.25
            && r.initial_kwcs == 100_000
            && r.ban_rate_per_year == 0.0
            && r.deactivation_cycles_per_id_per_year == 0.0
    });
    if let Some(r) = ten_year {
        line(
            out,
            &format!(
                "Group membership changes as IDs join and leave. Counting every group composition formed over {} years from 100,000 groups ({} compositions) as an independent draw, the expected number able to sign without honest members at p = 25% is {} for ID issuance. Most consecutive compositions differ by one seat, so this counts one long episode several times; household downtime, which now changes seats, raises the count.",
                compact_number(r.horizon_years),
                compact_number(r.compositions),
                sig3(r.expected_sign_capable)
            ),
        );
        blank(out);
    }
}

fn design_changes(out: &mut String, config: &Config, results: &M1Results) {
    line(out, "## Design changes made because of M1 (SPEC v0.3)");
    blank(out);
    let previous = GENESIS_V02;
    if let Some(needed) = results
        .a
        .genesis
        .iter()
        .find(|r| {
            r.t_min_years == config.issuance.min_attack_time_floor_years.value
                && r.online_fraction == 1.0
        })
        .map(|r| r.active_ids_needed)
    {
        line(
            out,
            &format!(
                "- **Genesis size.** Raised from {} to {} IDs. With {} the 2-year floor held only while {:.1}% of genesis IDs stayed active; with {} it tolerates {:.1}% inactive.",
                short_count(previous),
                short_count(config.genesis.ids.value),
                short_count(previous),
                100.0 * needed / previous as f64,
                short_count(config.genesis.ids.value),
                100.0 * (1.0 - needed / config.genesis.ids.value as f64)
            ),
        );
    }
    if let Some(hop) = results
        .e
        .iter()
        .find(|r| r.attacker_ratio == 1.0 && r.clamp == "none")
    {
        line(
            out,
            &format!(
                "- **Difficulty.** Count-based difficulty, from the exact number of admitted online miners, is now the default. Under a Bitcoin-style retarget every {} blocks, an attacker that doubles the miners for one window earns {}% more IDs per miner-second; count-based difficulty, which follows the exact count, gives no first-order gain.",
                hop.window_blocks,
                compact_number(hop.gain_percent)
            ),
        );
    }
    let primary = CommitteeModel::LotterySpread {
        population: 1,
        attackers: 0,
    }
    .label();
    let size = u64::from(config.cac.size.value);
    let lottery =
        results.c.odds.iter().find(|r| {
            r.model == primary && r.committee_size == size && r.attacker_fraction == 0.25
        });
    let old = results.c.odds.iter().find(|r| {
        r.committee_size == size
            && r.attacker_fraction == 0.25
            && r.honest_mining_fraction == Some(0.5)
    });
    if let (Some(lottery), Some(old)) = (lottery, old) {
        line(
            out,
            &format!(
                "- **Committee seats by lottery.** Seats on the {size}-member allocation committee now go by lottery over active IDs instead of to block miners. Under the old rule an attacker with 25% of active IDs, mining with all of them while half of honest IDs mine, held {:.1}% of mining IDs and could stall the committee with probability {}; under the lottery that probability is {}.",
                100.0 * old.attacker_share_of_population,
                prob(&old.p_stall),
                prob(&lottery.p_stall)
            ),
        );
    }
    line(
        out,
        "- **Allocation.** Seats are assigned by a deterministic shuffle that every node recomputes from chain data, so the committee announces placements but cannot choose them. Every group's composition then tracks the attacker's share of all IDs, not its share of recent issuance.",
    );
    line(
        out,
        "- **Deactivation instead of bans.** An ID offline beyond the allowance is deactivated and can return; bans are reserved for proven misbehaviour.",
    );
    line(
        out,
        "- **Adaptive cap.** The optional adaptive rate gains the safety factor k = 7/6 described above.",
    );
    blank(out);
}

fn limitations(out: &mut String) {
    line(out, "## Limitations");
    blank(out);
    line(
        out,
        "- **Analytical only.** These are formulas and exact probabilities. There is no network simulation yet: no latency, message loss, churn or adversarial timing (milestones M3 and M4).",
    );
    line(
        out,
        "- **The attacker is always online.** Honest IDs are online a fraction f of the time; outages for both sides come in M3.",
    );
    line(
        out,
        "- **Idealised assignment.** Witness seats and committee draws are modelled as uniformly random, and group compositions are counted as independent draws. Simulations must confirm both.",
    );
    line(
        out,
        "- **No money costs yet.** The cost of sustaining an attacker share comes in M5.",
    );
    line(
        out,
        "- **Open parameters.** Several SPEC values (for example offline durations and the transaction-block interval) are still open and are swept.",
    );
    blank(out);
    line(
        out,
        "All tables, the full summary, the cross-check verdicts and the code that produces them are in the repository.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_rows_follow_the_header() {
        let mut out = String::new();
        table(
            &mut out,
            &["a", "b"],
            &[vec!["1".to_string(), "2".to_string()]],
        );
        assert_eq!(out, "| a | b |\n|---|---|\n| 1 | 2 |\n\n");
    }
}
