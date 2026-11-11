//! The scoreboard must explain the real validator without becoming a gate.
use std::path::Path;
use std::process::{Command, Output};

use serde_json::{json, Value};
use syntriass_runtime::capability::artifact::{Capability, TestCase, TestSource};
use syntriass_runtime::capability::scoreboard::{check, Scoreboard};
use syntriass_runtime::capability::suite::ExpertSuite;
use syntriass_runtime::capability::validate::{validate, CaseOrigin};

mod common;
use common::*;

fn docs(_: &str) -> Option<String> {
    Some("koravi-process".into())
}

fn board(cap: &Capability) -> Scoreboard {
    let (key, suite) = expert_suite();
    check(cap, &suite, &key.public_key, &docs)
}

fn assert_consistent(b: &Scoreboard) {
    assert_eq!(b.validation.passed, b.gates.iter().all(|g| g.passed));
    for origin in [CaseOrigin::Suite, CaseOrigin::Artifact] {
        let rows: Vec<_> = b.cases.iter().filter(|r| r.origin == origin).collect();
        let executed = rows.iter().filter(|r| r.passed.is_some()).count();
        let passed = rows.iter().filter(|r| r.passed == Some(true)).count();
        let want = if origin == CaseOrigin::Suite {
            (b.validation.expert_cases, b.validation.expert_passed)
        } else {
            (b.validation.artifact_cases, b.validation.artifact_passed)
        };
        assert_eq!((executed, passed), want);
        for row in rows.iter().filter(|r| r.passed == Some(false)) {
            assert!(b.validation.failures.iter().any(|f| f.origin == origin
                && f.id == row.id
                && f.expected == row.expected
                && Some(&f.got) == row.got.as_ref()));
            assert!(!row.input.is_empty());
            assert!(row.fired_step.is_some());
        }
    }
}

#[test]
fn real_suite_counts_counterexamples_once_and_preserves_the_validator() {
    let cap = expert_fixture();
    let (key, suite) = expert_suite();
    let mut original = validate(&cap, &suite, &key.public_key, &docs);
    let b = check(&cap, &suite, &key.public_key, &docs);
    original.wall_micros = b.validation.wall_micros;
    assert_eq!(
        original, b.validation,
        "diagnostics must not change any validation field"
    );
    assert!(b.validation.passed);
    assert_eq!(b.cases.len(), suite.cases.len());
    assert_eq!(
        b.validation.counterexamples,
        b.cases.iter().filter(|c| c.counterexample).count()
    );
    assert!(!b.activation_performed);
    assert_eq!(b.evidence_kind, "UNSIGNED_LOCAL_VALIDATION_DIAGNOSTIC");
    assert!(b
        .summary
        .contains("Signed approval and activation are still required"));
    assert_consistent(&b);
}

#[test]
fn wrong_rule_exposes_input_expected_actual_and_the_rule_that_ran() {
    let mut cap = expert_fixture();
    cap.procedure.rules[1].outcome = "PASS".into();
    let b = board(&cap);
    assert!(!b.validation.passed);
    let failed = b
        .cases
        .iter()
        .find(|r| r.expected == "REJECT" && r.passed == Some(false))
        .unwrap();
    assert_eq!(failed.got.as_deref(), Some("PASS"));
    assert_eq!(failed.fired_step.as_deref(), Some("rules[1]"));
    assert_eq!(
        failed.fired_rule.as_ref().unwrap()["when"],
        "ir40 < 0.5 * ir_min"
    );
    assert!(failed
        .review_questions
        .iter()
        .any(|q| q.field_path == "rules[].outcome"));
    assert_consistent(&b);
}

#[test]
fn missed_guard_suggests_exclusion_question_even_when_default_fires() {
    let mut cap = expert_fixture();
    cap.procedure.text_guards[0].any_terms = vec!["cables".into()];
    cap.tests.push(TestCase {
        id: "scope-boundary".into(),
        text: "Cable C-4 insulation 6.6 kV 220 megohms at 40 C, PI 2.4".into(),
        expected: "OUT_OF_SCOPE".into(),
        source: TestSource::Generated,
        author: cap.proposed_by.clone(),
        counterexample: true,
    });
    let b = board(&cap);
    let row = b.cases.last().unwrap();
    assert_eq!(row.fired_step.as_deref(), Some("default"));
    assert_eq!(row.got.as_deref(), Some("PASS"));
    assert!(row
        .review_questions
        .iter()
        .any(|q| q.field_path == "scope_exclusion_terms.*"));
    assert_consistent(&b);
}

#[test]
fn forged_signature_cannot_be_displayed_as_passing_homework() {
    let (key, mut suite) = expert_suite();
    suite.cases[0].expected = "FORGED".into();
    let b = check(&expert_fixture(), &suite, &key.public_key, &docs);
    assert!(!b.validation.passed);
    assert_eq!(b.validation.expert_cases, 0);
    assert!(b
        .cases
        .iter()
        .all(|r| r.got.is_none() && r.passed.is_none() && r.not_run_reason.is_some()));
    assert!(b.summary.contains("NOT READY"));
    assert_consistent(&b);
}

#[test]
fn wrong_trust_anchor_executes_no_expert_case() {
    let (_, suite) = expert_suite();
    let wrong = aip_crypto::generate_ed25519_keypair();
    let b = check(&expert_fixture(), &suite, &wrong.public_key, &docs);
    assert!(!b.validation.passed);
    assert!(b.cases.iter().all(|r| r.passed.is_none()));
    assert_consistent(&b);
}

#[test]
fn wrong_tenant_and_self_signed_proposal_cannot_certify() {
    let (key, suite) = expert_suite();
    for (tenant, expert) in [
        ("other-tenant", EXPERT),
        ("koravi-process", "user:koravi-engineer-7"),
    ] {
        let s = ExpertSuite::sign(
            "s",
            tenant,
            "ir",
            expert,
            suite.cases.clone(),
            &key.private_key,
        )
        .unwrap();
        let b = check(&expert_fixture(), &s, &key.public_key, &docs);
        assert!(b.validation.suite_signature_ok);
        assert!(!b.validation.suite_independent);
        assert!(b.cases.iter().all(|r| r.passed.is_none()));
        assert_consistent(&b);
    }
}

#[test]
fn missing_evidence_is_a_failed_gate_even_when_all_cases_pass() {
    let (key, suite) = expert_suite();
    let b = check(&expert_fixture(), &suite, &key.public_key, &|_| None);
    assert!(b.cases.iter().all(|r| r.passed == Some(true)));
    assert!(!b.validation.passed);
    assert!(b
        .gates
        .iter()
        .any(|g| g.name == "evidence_tenant" && !g.passed));
    assert_consistent(&b);
}

#[test]
fn too_few_cases_and_absent_counterexamples_remain_rejections() {
    let (key, suite) = expert_suite();
    for n in [1, suite.cases.len()] {
        let mut cases = suite.cases[..n].to_vec();
        for c in &mut cases {
            c.counterexample = false;
        }
        let s = ExpertSuite::sign("s", "koravi-process", "ir", EXPERT, cases, &key.private_key)
            .unwrap();
        let b = check(&expert_fixture(), &s, &key.public_key, &docs);
        assert!(!b.validation.passed);
        assert!(b
            .gates
            .iter()
            .any(|g| g.name == "minimum_counterexamples" && !g.passed));
        assert_consistent(&b);
    }
}

#[test]
fn generated_cases_never_count_as_expert_and_duplicate_ids_keep_both_rows() {
    let mut cap = expert_fixture();
    for expected in ["PASS", "REJECT"] {
        cap.tests.push(TestCase {
            id: "same-id".into(),
            text: "M-1 insulation 6.6 kV 220 megohms at 40 C, PI 2.4".into(),
            expected: expected.into(),
            source: TestSource::Expert,
            author: EXPERT.into(),
            counterexample: true,
        });
    }
    let b = board(&cap);
    let rows: Vec<_> = b
        .cases
        .iter()
        .filter(|r| r.origin == CaseOrigin::Artifact)
        .collect();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].index, rows[1].index);
    assert_eq!(b.validation.artifact_claimed_expert, 2);
    assert_eq!(b.validation.artifact_passed, 1);
    assert_eq!(b.validation.expert_cases, 14);
    assert!(!b.validation.passed);
    assert_consistent(&b);
}

#[test]
fn compile_failure_is_not_a_zero_case_pass() {
    let mut cap = expert_fixture();
    cap.procedure.rules[0].outcome = "UNKNOWN".into();
    let b = board(&cap);
    assert!(!b.validation.passed);
    assert!(b.validation.compile_error.is_some());
    assert!(b.cases.iter().all(|r| r.passed.is_none()));
    assert_consistent(&b);
}

const BIN: &str = env!("CARGO_BIN_EXE_syntriass");

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn setup(dir: &Path) -> (String, String, String) {
    let (key, suite) = expert_suite();
    let config = dir.join("config.json");
    std::fs::write(&config, json!({
        "state": dir.join("state"), "policy_version": "ep-114-revC", "security_domain": "koravi-ot", "rag_k": 4,
        "approvers": {}, "experts": {EXPERT: hex::encode(&key.public_key)},
        "python": "/unavailable/python", "sidecar_script": "/unavailable/sidecar",
        "llama_server": "/unavailable/llama-server", "profile": "none", "port": 18080,
        "q4": {"path": "/unavailable/q4", "sha256": "0".repeat(64)},
        "q8": {"path": "/unavailable/q8", "sha256": "0".repeat(64)},
    }).to_string()).unwrap();
    let config = config.to_str().unwrap().to_owned();
    let doc = format!("{DATA}/corpus/koravi-ep-114.txt");
    assert!(run(&["ingest", "--config", &config, &doc]).status.success());
    let cap = dir.join("cap.json");
    std::fs::write(&cap, serde_json::to_vec(&expert_fixture()).unwrap()).unwrap();
    let proposed = run(&[
        "cap-propose",
        "--config",
        &config,
        "--file",
        cap.to_str().unwrap(),
    ]);
    assert!(
        proposed.status.success(),
        "{}",
        String::from_utf8_lossy(&proposed.stderr)
    );
    let hash = serde_json::from_slice::<Value>(&proposed.stdout).unwrap()["hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = dir.join("suite.json");
    std::fs::write(&path, serde_json::to_vec(&suite).unwrap()).unwrap();
    (config, hash, path.to_str().unwrap().to_owned())
}

#[test]
fn cli_runs_without_models_and_does_not_validate_or_activate_stored_state() {
    let dir = tempfile::tempdir().unwrap();
    let (config, hash, suite) = setup(dir.path());
    let before = run(&["cap-list", "--config", &config]).stdout;
    let o = run(&[
        "cap-scoreboard",
        "--config",
        &config,
        "--hash",
        &hash,
        "--suite",
        &suite,
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let b: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(b["validation"]["passed"], true);
    assert_eq!(b["model_calls"], 0);
    assert_eq!(b["activation_performed"], false);
    assert_eq!(b["stored_state"], "PROPOSED");
    assert_eq!(b["stored_executable"], false);
    assert_eq!(before, run(&["cap-list", "--config", &config]).stdout);
    let record: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(record["state"], "PROPOSED");
    assert_eq!(record["executable"], false);
    let activated = run(&[
        "cap-activate",
        "--config",
        &config,
        "--hash",
        &hash,
        "--actor",
        "any",
        "--reason",
        "scoreboard passed",
    ]);
    assert!(
        !activated.status.success(),
        "passing homework must never grant activation"
    );
}

#[test]
fn cli_signature_failure_returns_three_and_retains_diagnostic_json() {
    let dir = tempfile::tempdir().unwrap();
    let (config, hash, suite) = setup(dir.path());
    let mut s: Value = serde_json::from_slice(&std::fs::read(&suite).unwrap()).unwrap();
    s["signature_hex"] = json!("00".repeat(64));
    std::fs::write(&suite, s.to_string()).unwrap();
    let o = run(&[
        "cap-scoreboard",
        "--config",
        &config,
        "--hash",
        &hash,
        "--suite",
        &suite,
    ]);
    assert_eq!(o.status.code(), Some(3));
    let b: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(b["validation"]["passed"], false);
    assert!(b["summary"].as_str().unwrap().contains("NOT READY"));
}

#[test]
fn cli_removed_expert_trust_anchor_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (config, hash, suite) = setup(dir.path());
    let mut cfg: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    cfg["experts"] = json!({});
    std::fs::write(&config, cfg.to_string()).unwrap();
    let o = run(&[
        "cap-scoreboard",
        "--config",
        &config,
        "--hash",
        &hash,
        "--suite",
        &suite,
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not a trusted expert"));
}

#[test]
fn cli_tampered_capability_is_refused_even_if_the_edited_program_would_pass() {
    let dir = tempfile::tempdir().unwrap();
    let (config, hash, suite) = setup(dir.path());
    let path = std::fs::read_dir(dir.path().join("state/capabilities"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut rec: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    // The rules still pass. Changing provenance alone must not be hidden by
    // re-hashing the edited capability and returning a fresh green display.
    rec["capability"]["intended_task"] = json!("tampered provenance");
    std::fs::write(path, rec.to_string()).unwrap();
    let o = run(&[
        "cap-scoreboard",
        "--config",
        &config,
        "--hash",
        &hash,
        "--suite",
        &suite,
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    assert!(String::from_utf8_lossy(&o.stderr).contains("content hash does not match"));
}
