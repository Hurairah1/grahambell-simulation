//! The committed test vectors must equal a fresh rendering byte for byte.

#[test]
fn committed_vectors_match_a_fresh_rendering() {
    let committed = include_str!("../vectors/protocol_v1.json");
    let fresh = gb_protocol::vectors::render().unwrap();
    assert!(
        committed == fresh,
        "vectors/protocol_v1.json is stale; regenerate it with `gb vectors`"
    );
}

#[test]
fn vector_verdicts_cover_valid_and_rejected_blocks() {
    let v = gb_protocol::vectors::generate().unwrap();
    let verdicts: Vec<&str> = v["validation"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["verdict"].as_str().unwrap())
        .collect();
    assert_eq!(
        verdicts,
        vec!["valid", "ReceivedEarly", "PowitLate", "TimestampMismatch"]
    );
}
