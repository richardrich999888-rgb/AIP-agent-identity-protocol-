//! Capability engine: compilation, execution on the frozen EP-114 data,
//! lifecycle enforcement and attacks.
//!
//! FIXTURE NOTE: `expert_fixture()` is a procedure hand-written by the test
//! author from the EP-114 document text. It tests the *machinery* and gives
//! the language's expressiveness ceiling; it is not the experiment's learned
//! capability (see research/capability-learning).

use std::collections::BTreeMap;

use serde_json::Value;
use syntriass_runtime::capability::artifact::*;
use syntriass_runtime::capability::lifecycle::*;
use syntriass_runtime::capability::quantity::Kind;
use syntriass_runtime::capability::validate::*;

const DATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../research/capability-learning/data/ir-tasks-v1"
);

fn rows(file: &str) -> Vec<Value> {
    std::fs::read_to_string(format!("{DATA}/{file}"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn expert_fixture() -> Capability {
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

fn koravi_docs(d: &str) -> Option<String> {
    matches!(d, "ep-114" | "ep-090").then(|| "koravi-process".to_string())
}

#[test]
fn fixture_compiles_and_validates() {
    let r = validate(&expert_fixture(), &koravi_docs);
    assert!(r.compiled && r.evidence_scope_ok, "{r:?}");
    assert_eq!(r.failures, vec![], "validation suite must pass");
    assert!(r.passed);
}

#[test]
fn fixture_on_unseen_and_false_activation_sets() {
    // Measurement of the hand-written ceiling, recorded by the benchmark; here
    // we only require no false activation and no crash on any item.
    let cap = expert_fixture();
    let c = cap.compile().unwrap();
    let mut right = 0;
    for r in rows("test_unseen.jsonl") {
        let got = label(&cap.execute(&c, r["text"].as_str().unwrap()));
        assert!(!got.starts_with("FAILED"), "{got}");
        right += (got == r["label"].as_str().unwrap()) as usize;
    }
    assert!(
        right >= 24,
        "hand-written ceiling unexpectedly low: {right}/32"
    );
    for r in rows("false_activation.jsonl") {
        assert_eq!(
            label(&cap.execute(&c, r["text"].as_str().unwrap())),
            NOT_APPLICABLE,
            "{}",
            r["text"]
        );
    }
}

#[test]
fn self_authored_tests_do_not_count() {
    let mut cap = expert_fixture();
    for t in &mut cap.tests {
        t.author = cap.proposed_by.clone();
    }
    let r = validate(&cap, &koravi_docs);
    assert_eq!(r.expert_cases, 0);
    assert_eq!(r.self_authored_ignored, 14);
    assert!(!r.passed, "a capability must not certify itself");
}

#[test]
fn generated_tests_cannot_make_it_pass() {
    let mut cap = expert_fixture();
    for t in &mut cap.tests {
        t.source = TestSource::Generated;
    }
    assert!(!validate(&cap, &koravi_docs).passed);
}

#[test]
fn cross_tenant_evidence_fails_validation() {
    let mut cap = expert_fixture();
    cap.dependencies
        .knowledge
        .insert("tg-ir-02".into(), "daae0065d32c".into());
    let tarvel = |d: &str| {
        if d == "tg-ir-02" {
            Some("tarvel-grid".to_string())
        } else {
            koravi_docs(d)
        }
    };
    let r = validate(&cap, &tarvel);
    assert!(!r.evidence_scope_ok && !r.passed);
}

#[test]
fn a_wrong_threshold_is_caught_by_validation() {
    let mut cap = expert_fixture();
    cap.procedure.rules[4].when = "pi < 2.5".into();
    let r = validate(&cap, &koravi_docs);
    assert!(!r.passed && !r.failures.is_empty());
}

#[test]
fn compile_rejects_bad_artifacts() {
    let mut cap = expert_fixture();
    cap.procedure.rules[0].outcome = "APPROVE_TRANSFER".into();
    assert!(matches!(
        cap.compile(),
        Err(ArtifactError::UnknownOutcome(_))
    ));
    let mut cap = expert_fixture();
    cap.procedure.derive[0].expr = "ir_mohm * secret_factor".into();
    assert!(matches!(
        cap.compile(),
        Err(ArtifactError::UndefinedVariable { .. })
    ));
    let mut cap = expert_fixture();
    cap.procedure.rules[0].when = "__import__('os').system('id') < 1".into();
    assert!(matches!(cap.compile(), Err(ArtifactError::Expr { .. })));
}

fn approver() -> (String, aip_types::KeyPair) {
    (
        "user:koravi-elec-authority".into(),
        aip_crypto::generate_ed25519_keypair(),
    )
}

fn validated_record() -> Record {
    let mut rec = Record::propose(expert_fixture());
    rec.start_testing("validator", 1).unwrap();
    let rep = validate(&rec.capability, &koravi_docs);
    rec.record_validation(rep, "validator", 2).unwrap();
    assert_eq!(rec.state, State::Validated);
    rec
}

#[test]
fn full_lifecycle_requires_signed_independent_approval() {
    let mut rec = validated_record();
    let (id, kp) = approver();
    assert!(!rec.executable());
    let a = Approval::sign(
        &rec.capability_hash,
        rec.validation.as_ref().unwrap(),
        &id,
        false,
        3,
        &kp.private_key,
    )
    .unwrap();
    rec.approve(a, &kp.public_key, 3).unwrap();
    assert!(!rec.executable(), "approved is not active");
    rec.transition(State::Active, "operator", Role::Operator, 4, "go live")
        .unwrap();
    assert!(rec.executable());
    rec.transition(
        State::Suspended,
        "validator",
        Role::Validator,
        5,
        "model changed",
    )
    .unwrap();
    assert!(!rec.executable());
}

#[test]
fn proposer_cannot_approve_and_forged_signatures_fail() {
    let mut rec = validated_record();
    let kp = aip_crypto::generate_ed25519_keypair();
    let proposer = rec.capability.proposed_by.clone();
    let a = Approval::sign(
        &rec.capability_hash,
        rec.validation.as_ref().unwrap(),
        &proposer,
        false,
        3,
        &kp.private_key,
    )
    .unwrap();
    assert_eq!(
        rec.approve(a, &kp.public_key, 3),
        Err(LifecycleError::SelfApproval)
    );
    let (id, kp) = approver();
    let other = aip_crypto::generate_ed25519_keypair();
    let a = Approval::sign(
        &rec.capability_hash,
        rec.validation.as_ref().unwrap(),
        &id,
        false,
        3,
        &other.private_key,
    )
    .unwrap();
    assert_eq!(
        rec.approve(a, &kp.public_key, 3),
        Err(LifecycleError::ApprovalInvalid("signature"))
    );
}

#[test]
fn tampering_after_approval_disables_execution() {
    let mut rec = validated_record();
    let (id, kp) = approver();
    let a = Approval::sign(
        &rec.capability_hash,
        rec.validation.as_ref().unwrap(),
        &id,
        false,
        3,
        &kp.private_key,
    )
    .unwrap();
    rec.approve(a, &kp.public_key, 3).unwrap();
    rec.transition(State::Active, "operator", Role::Operator, 4, "go live")
        .unwrap();
    rec.capability.procedure.rules[1].when = "ir40 < 0".into(); // weaken REJECT after approval
    assert!(!rec.executable());
    assert_eq!(
        rec.transition(State::Suspended, "op", Role::Operator, 5, "x"),
        Err(LifecycleError::HashMismatch)
    );
}

#[test]
fn edges_and_roles_are_enforced() {
    let mut rec = Record::propose(expert_fixture());
    assert!(rec
        .transition(State::Active, "op", Role::Operator, 1, "skip")
        .is_err());
    assert!(rec
        .transition(State::Approved, "boss", Role::Approver, 1, "skip")
        .is_err());
    rec.start_testing("validator", 1).unwrap();
    let mut failing = validate(&rec.capability, &koravi_docs);
    failing.passed = false;
    rec.record_validation(failing, "validator", 2).unwrap();
    assert_eq!(rec.state, State::Rejected);
    assert!(
        rec.transition(State::Testing, "validator", Role::Validator, 3, "retry")
            .is_err(),
        "rejected is terminal"
    );
}

#[test]
fn validation_report_for_other_content_is_refused() {
    let mut rec = Record::propose(expert_fixture());
    rec.start_testing("validator", 1).unwrap();
    let mut other = expert_fixture();
    other.version = 2;
    let rep = validate(&other, &koravi_docs);
    assert_eq!(
        rec.record_validation(rep, "validator", 2),
        Err(LifecycleError::HashMismatch)
    );
}
