//! Parity of the Rust exact policy with the Python reference
//! (`research/system-one/datasets/maintenance_priority.py`).
//!
//! Every hand-written item in hard-reports v3, v4 and v5 carries gold
//! readings and a label that the Python reference computed from them
//! (`decision(gold)` in the dataset scripts). The Rust `decide` must
//! reproduce every label exactly.

use serde_json::Value;
use syntriass_runtime::domain::maintenance::{decide, Reading};

const DATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../research/system-one/data"
);

fn check(set: &str) -> usize {
    let text = std::fs::read_to_string(format!("{DATA}/{set}/test_hard.jsonl")).unwrap();
    let mut n = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line).unwrap();
        let readings: Vec<Reading> = v["gold_readings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| Reading {
                key: r[0].as_str().unwrap().into(),
                value: r[1].as_f64().unwrap(),
            })
            .collect();
        assert_eq!(
            decide(&readings).label(),
            v["label"].as_str().unwrap(),
            "{set} {}",
            v["id"]
        );
        n += 1;
    }
    n
}

#[test]
fn rust_policy_matches_python_reference_on_every_labelled_item() {
    let n = check("hard-reports-v3") + check("hard-reports-v4") + check("hard-reports-v5");
    assert_eq!(n, 74 + 39 + 37);
}
