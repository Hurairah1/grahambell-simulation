//! CSV output for the M1 tables.

use anyhow::Context;
use gb_analytic::M1Results;
use gb_config::Config;
use gb_config::registry::parameter_listing;
use serde::Serialize;
use std::path::Path;

/// Writes `rows` to `path` as CSV with a header row.
pub fn write_csv<T: Serialize>(path: &Path, rows: &[T]) -> anyhow::Result<()> {
    let mut writer =
        csv::Writer::from_path(path).with_context(|| format!("creating {}", path.display()))?;
    for row in rows {
        writer.serialize(row)?;
    }
    writer.flush()?;
    Ok(())
}

/// File names of every table, in the order they are written.
pub const TABLE_FILES: &[&str] = &[
    "A1_time_to_threshold.csv",
    "A2_online_fraction.csv",
    "A3_honest_growth.csv",
    "A4_adaptive_cap.csv",
    "A4_safety_factor.csv",
    "A5_share_trajectories.csv",
    "A6_genesis_to_issue.csv",
    "A7_long_run_share.csv",
    "B1_kwc_probabilities.csv",
    "B2_network_counts.csv",
    "B3_binomial_vs_hypergeometric.csv",
    "B4_kwc_compositions_10y.csv",
    "B5_seat_rule_10y.csv",
    "C1_cac_probabilities.csv",
    "C2_cac_events_per_year.csv",
    "C3_cac_departures.csv",
    "D1_restart_advantage.csv",
    "D2_restart_advantage_curve.csv",
    "E1_difficulty_hopping.csv",
    "F1_tie_rate.csv",
    "G1_quorum_kwc.csv",
    "G2_split_rule.csv",
    "G3_cac_quorum.csv",
    "G4_quorum_10y_by_seat_rule.csv",
    "H1_quorum_feasibility.csv",
    "H2_minimum_uptime.csv",
    "H3_absent_seat_share.csv",
    "I1_kwc_size_security.csv",
    "I2_kwc_size_liveness.csv",
    "I3_kwc_size_load.csv",
    "I4_on_demand_connections.csv",
    "validation.csv",
    "parameters.csv",
];

/// Writes every M1 table, the cross-checks and the parameter listing into `dir`.
pub fn write_tables(dir: &Path, config: &Config, results: &M1Results) -> anyhow::Result<()> {
    let r = results;
    let mut written: Vec<&str> = Vec::new();
    macro_rules! table {
        ($name:literal, $rows:expr) => {{
            write_csv(&dir.join($name), $rows)?;
            written.push($name);
        }};
    }
    table!("A1_time_to_threshold.csv", &r.a.thresholds);
    table!("A2_online_fraction.csv", &r.a.online);
    table!("A3_honest_growth.csv", &r.a.growth);
    table!("A4_adaptive_cap.csv", &r.a.cap);
    table!("A4_safety_factor.csv", &r.a.safety);
    table!("A5_share_trajectories.csv", &r.a.trajectories);
    table!("A6_genesis_to_issue.csv", &r.a.genesis);
    table!("A7_long_run_share.csv", &r.a.long_run);
    table!("B1_kwc_probabilities.csv", &r.b.kwc);
    table!("B2_network_counts.csv", &r.b.network);
    table!("B3_binomial_vs_hypergeometric.csv", &r.b.comparison);
    table!("B4_kwc_compositions_10y.csv", &r.b.compositions);
    table!("B5_seat_rule_10y.csv", &r.b.seat_rule);
    table!("C1_cac_probabilities.csv", &r.c.odds);
    table!("C2_cac_events_per_year.csv", &r.c.events);
    table!("C3_cac_departures.csv", &r.c.departures);
    table!("D1_restart_advantage.csv", &r.d);
    table!("D2_restart_advantage_curve.csv", &r.d_curve);
    table!("E1_difficulty_hopping.csv", &r.e);
    table!("F1_tie_rate.csv", &r.f);
    table!("G1_quorum_kwc.csv", &r.g.quorum);
    table!("G2_split_rule.csv", &r.g.split);
    table!("G3_cac_quorum.csv", &r.g.cac);
    table!("G4_quorum_10y_by_seat_rule.csv", &r.g.seat_rule);
    table!("H1_quorum_feasibility.csv", &r.h.feasibility);
    table!("H2_minimum_uptime.csv", &r.h.minimum_uptime);
    table!("H3_absent_seat_share.csv", &r.h.absent_seats);
    table!("I1_kwc_size_security.csv", &r.i.security);
    table!("I2_kwc_size_liveness.csv", &r.i.liveness);
    table!("I3_kwc_size_load.csv", &r.i.load);
    table!("I4_on_demand_connections.csv", &r.i.on_demand);
    table!("validation.csv", &r.checks);
    table!("parameters.csv", &parameter_listing(config)?);
    anyhow::ensure!(
        written == TABLE_FILES,
        "the tables written differ from TABLE_FILES"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Row {
        name: &'static str,
        value: Option<f64>,
    }

    #[test]
    fn csv_writes_a_header_and_empty_cells_for_missing_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.csv");
        write_csv(
            &path,
            &[
                Row {
                    name: "a",
                    value: Some(1.5),
                },
                Row {
                    name: "b",
                    value: None,
                },
            ],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "name,value\na,1.5\nb,\n"
        );
    }

    #[test]
    fn table_file_names_are_unique() {
        let mut names = TABLE_FILES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TABLE_FILES.len());
    }
}
