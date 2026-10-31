//! Shared test fixtures.
//!
//! FIXTURE NOTE: `expert_fixture()` is a procedure hand-written by the test
//! author from the EP-114 document text. It tests the *machinery* and gives
//! the language's expressiveness ceiling; it is not the experiment's learned
//! capability (see research/capability-learning).
#![allow(dead_code)]

use std::collections::BTreeMap;

use serde_json::Value;
use syntriass_runtime::capability::artifact::*;
use syntriass_runtime::capability::quantity::Kind;

pub const DATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../research/capability-learning/data/ir-tasks-v1"
);

pub fn rows(file: &str) -> Vec<Value> {
    std::fs::read_to_string(format!("{DATA}/{file}"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

pub fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

pub fn expert_fixture() -> Capability {
    let rule = |w: &str, o: &str| Rule {
        when: w.into(),
        outcome: o.into(),
    };
    let mut knowledge = BTreeMap::new();
    knowledge.insert("ep-114".to_string(), "655c9d192095".to_string());
    Capability {
        id: "koravi.ep114.ir-acceptance".into(),
        version: 1,
        intended_task: "Decide motor IR test acceptance per EP-114 rev C".into(),
        outcomes: s(&[
            "PASS",
            "RETEST_30D",
            "DRY_OUT",
            "REJECT",
            "INVALID_TEST",
            "OUT_OF_SCOPE",
            "INSUFFICIENT_INPUT",
        ]),
        applicability: Applicability {
            any_terms: s(&[
                "megger",
                "insulation",
                "IR",
                "megohm",
                "megohms",
                "MΩ",
                "Mohm",
                "GΩ",
                "PI",
            ]),
            min_inputs_present: 2,
        },
        procedure: Procedure {
            inputs: vec![
                InputSpec {
                    name: "kv".into(),
                    kind: Kind::Voltage,
                    cues: vec![],
                },
                InputSpec {
                    name: "ir_mohm".into(),
                    kind: Kind::Resistance,
                    cues: vec![],
                },
                InputSpec {
                    name: "temp_c".into(),
                    kind: Kind::Temperature,
                    cues: vec![],
                },
                InputSpec {
                    name: "pi".into(),
                    kind: Kind::Cued,
                    cues: s(&["PI", "polarization index", "polarisation index"]),
                },
            ],
            text_guards: vec![TextGuard {
                any_terms: s(&["transformer", "cable", "generator", "stator"]),
                outcome: "OUT_OF_SCOPE".into(),
            }],
            numeric_guards: vec![NumericGuard {
                when: "kv > 11".into(),
                outcome: "OUT_OF_SCOPE".into(),
            }],
            missing_input_outcome: "INSUFFICIENT_INPUT".into(),
            derive: vec![
                Derive {
                    name: "ir40".into(),
                    expr: "ir_mohm * 2 ^ ((temp_c - 40) / 10)".into(),
                },
                Derive {
                    name: "ir_min".into(),
                    expr: "10 * (kv + 1)".into(),
                },
            ],
            rules: vec![
                rule("temp_c < 10 or temp_c > 75", "INVALID_TEST"),
                rule("ir40 < 0.5 * ir_min", "REJECT"),
                rule("ir40 < ir_min", "DRY_OUT"),
                rule("pi < 1.5", "DRY_OUT"),
                rule("pi < 2", "RETEST_30D"),
            ],
            default_outcome: "PASS".into(),
        },
        required: Required {
            tenant: "koravi-process".into(),
            min_clearance: "restricted".into(),
            security_domain: "koravi-ot".into(),
        },
        dependencies: Dependencies {
            knowledge,
            policy_version: "ep-114-revC".into(),
            execution_model_sha256: None,
        },
        evidence_refs: s(&["ep-114", "demo-000", "demo-001"]),
        failure_conditions: s(&["inputs ambiguous", "unit not recognised"]),
        tests: rows("validation.jsonl")
            .iter()
            .map(|r| TestCase {
                id: r["id"].as_str().unwrap().into(),
                text: r["text"].as_str().unwrap().into(),
                expected: r["label"].as_str().unwrap().into(),
                source: TestSource::Expert,
                author: "expert:koravi-elec-lead".into(),
                counterexample: true,
            })
            .collect(),
        proposed_by: "user:koravi-engineer-7".into(),
    }
}
