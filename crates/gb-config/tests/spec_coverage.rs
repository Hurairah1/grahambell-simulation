//! Checks that every row of the SPEC §2 parameter table is covered by the configuration,
//! with matching status tags. If the SPEC gains a row, this test fails until the
//! configuration covers it.

use gb_config::registry::{SPEC_SECTION_2_ROWS, parse_spec_section_2, status_of};
use gb_config::{Config, Status};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn spec_markdown() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/SPEC.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn spec_section_2_table_is_found() {
    let rows = parse_spec_section_2(&spec_markdown());
    assert!(rows.len() >= 41, "only {} rows parsed", rows.len());
}

#[test]
fn every_spec_section_2_row_maps_to_configuration_keys() {
    let rows = parse_spec_section_2(&spec_markdown());
    for row in &rows {
        assert!(
            SPEC_SECTION_2_ROWS
                .iter()
                .any(|(name, _)| *name == row.name),
            "SPEC §2 row `{}` has no configuration mapping",
            row.name
        );
    }
}

#[test]
fn every_mapping_names_an_existing_spec_row() {
    let rows = parse_spec_section_2(&spec_markdown());
    for (name, _) in SPEC_SECTION_2_ROWS {
        assert!(
            rows.iter().any(|row| row.name == *name),
            "mapping for `{name}` refers to a row that is not in SPEC §2"
        );
    }
}

#[test]
fn configuration_status_tags_match_the_spec() {
    let config = Config::default();
    for row in parse_spec_section_2(&spec_markdown()) {
        let keys = SPEC_SECTION_2_ROWS
            .iter()
            .find(|(name, _)| *name == row.name)
            .map(|(_, keys)| *keys)
            .unwrap();
        let tags: BTreeSet<Status> = keys
            .iter()
            .map(|key| status_of(&config, key).unwrap().unwrap())
            .collect();
        assert_eq!(
            tags, row.statuses,
            "status mismatch for SPEC row `{}`",
            row.name
        );
    }
}
