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
    "C1_cac_probabilities.csv",
    "C2_cac_events_per_year.csv",
    "D1_restart_advantage.csv",
    "D2_restart_advantage_curve.csv",
    "E1_difficulty_hopping.csv",
    "F1_tie_rate.csv",
    "G1_quorum_kwc.csv",
    "G2_split_rule.csv",
    "G3_cac_quorum.csv",
    "validation.csv",
    "parameters.csv",
];

/// Writes every M1 table, the cross-checks and the parameter listing into `dir`.
pub fn write_tables(dir: &Path, config: &Config, results: &M1Results) -> anyhow::Result<()> {
    let a = &results.a;
    let b = &results.b;
    let c = &results.c;
    let out = |name: &str| dir.join(name);
    write_csv(&out(TABLE_FILES[0]), &a.thresholds)?;
    write_csv(&out(TABLE_FILES[1]), &a.online)?;
    write_csv(&out(TABLE_FILES[2]), &a.growth)?;
    write_csv(&out(TABLE_FILES[3]), &a.cap)?;
    write_csv(&out(TABLE_FILES[4]), &a.safety)?;
    write_csv(&out(TABLE_FILES[5]), &a.trajectories)?;
    write_csv(&out(TABLE_FILES[6]), &a.genesis)?;
    write_csv(&out(TABLE_FILES[7]), &a.long_run)?;
    write_csv(&out(TABLE_FILES[8]), &b.kwc)?;
    write_csv(&out(TABLE_FILES[9]), &b.network)?;
    write_csv(&out(TABLE_FILES[10]), &b.comparison)?;
    write_csv(&out(TABLE_FILES[11]), &b.compositions)?;
    write_csv(&out(TABLE_FILES[12]), &c.odds)?;
    write_csv(&out(TABLE_FILES[13]), &c.events)?;
    write_csv(&out(TABLE_FILES[14]), &results.d)?;
    write_csv(&out(TABLE_FILES[15]), &results.d_curve)?;
    write_csv(&out(TABLE_FILES[16]), &results.e)?;
    write_csv(&out(TABLE_FILES[17]), &results.f)?;
    write_csv(&out(TABLE_FILES[18]), &results.g.quorum)?;
    write_csv(&out(TABLE_FILES[19]), &results.g.split)?;
    write_csv(&out(TABLE_FILES[20]), &results.g.cac)?;
    write_csv(&out(TABLE_FILES[21]), &results.checks)?;
    write_csv(&out(TABLE_FILES[22]), &parameter_listing(config)?)?;
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
