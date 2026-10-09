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

#[test]
fn vectors_cover_fork_choice_and_witness_equivocation() {
    let v = gb_protocol::vectors::generate().unwrap();
    let preferred: Vec<&str> = v["fork_choice"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["preferred"].as_str().unwrap())
        .collect();
    assert_eq!(preferred.len(), 3);
    assert_eq!(&preferred[..2], &["a", "a"]);
    assert_eq!(
        v["witness_equivocation"]["equivocating_seats"],
        serde_json::json!([1, 2])
    );
}
