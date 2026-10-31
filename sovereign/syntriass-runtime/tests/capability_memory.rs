//! Organisational capability memory (phase 3): experience is recorded, never
//! applied directly; an improvement is a new version that must pass the old
//! and new expert cases without regression, be approved, and supersede the
//! old version — which stays available for rollback.

use std::collections::BTreeMap;

use syntriass_runtime::adapters::experience_store::ExperienceLog;
use syntriass_runtime::adapters::store::FileStore;
use syntriass_runtime::capability::experience::{as_suite_case, Experience, Verification};
use syntriass_runtime::capability::lifecycle::{allowed, Role, State};
use syntriass_runtime::capability::memory::{review, upgrade_check};
use syntriass_runtime::capability::suite::ExpertSuite;
use syntriass_runtime::learning::{
    activate, approve_record, propose, rollback, transition, validate_record,
};
use syntriass_runtime::ports::CapabilityStore;
use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;
use vanian_sovereign::domain::corpus::{Classification, Document, Ident};
use vanian_sovereign::ports::CorpusStore;

mod common;
use common::*;

/// A verified field case the v1 fixture does not recognise (no applicability term).
const T024: &str = "Motor 3.3 kV at 40 C: resistance reading lost, polarization index 2.3";

fn exp(id: &str, task: &str, expected: &str, v: Verification) -> Experience {
    Experience {
        id: id.into(),
        tenant: "koravi-process".into(),
        security_domain: "koravi-ot".into(),
        classification: "restricted".into(),
        task: task.into(),
        evidence_refs: vec!["ep-114".into()],
        actions_attempted: vec![],
        observed_outcome: None,
        human_correction: None,
        expected_outcome: Some(expected.into()),
        actor: "agent:runtime".into(),
        verification: v,
        policies: vec!["ep-114-revC".into()],
        provenance: "test".into(),
    }
}

fn verified() -> Verification {
    Verification::Verified {
        verifier: EXPERT.into(),
        at_ms: 1,
    }
}

/// v2: the engineer's improvement — 'resistance' added to the applicability terms.
fn v2() -> syntriass_runtime::capability::artifact::Capability {
    let mut c = expert_fixture();
    c.version = 2;
    c.applicability.any_terms.push("resistance".into());
    c
}

fn signed(
    cases: Vec<syntriass_runtime::capability::suite::SuiteCase>,
    kp: &aip_types::KeyPair,
) -> ExpertSuite {
    ExpertSuite::sign(
        "ir/v2-regression",
        "koravi-process",
        "motor IR acceptance (EP-114 rev C)",
        EXPERT,
        cases,
        &kp.private_key,
    )
    .unwrap()
}

// ── review: experience never changes behaviour; it is compared ─────────────

#[test]
fn review_reports_disagreement_and_ignores_unverified_and_foreign_experience() {
    let v1 = expert_fixture();
    let mut foreign = exp("f", T024, "INSUFFICIENT_INPUT", verified());
    foreign.tenant = "tarvel-grid".into();
    let exps = vec![
        exp("e1", T024, "INSUFFICIENT_INPUT", verified()),
        exp(
            "e2",
            T024,
            "INSUFFICIENT_INPUT",
            Verification::SelfReported {
                agent: "agent:runtime".into(),
            },
        ),
        exp("e3", T024, "INSUFFICIENT_INPUT", Verification::Unverified),
        exp(
            "e4",
            T024,
            "INSUFFICIENT_INPUT",
            Verification::Verified {
                verifier: "agent:runtime".into(),
                at_ms: 1,
            },
        ),
        foreign,
    ];
    let r = review(&v1, &exps).unwrap();
    assert_eq!(
        (r.considered, r.skipped_unverified, r.skipped_other_tenant),
        (1, 3, 1)
    );
    assert_eq!(r.disagreements.len(), 1, "{r:?}");
    assert_eq!(r.disagreements[0].got, "NOT_APPLICABLE");
    // v2 fixes it
    assert!(review(&v2(), &exps).unwrap().disagreements.is_empty());
}

// ── upgrade check: regressions, fixes, scope ──────────────────────────────

fn regression_suite(kp: &aip_types::KeyPair) -> ExpertSuite {
    let mut cases = suite_cases("validation.jsonl");
    cases.push(
        as_suite_case(
            &exp("exp-024", T024, "INSUFFICIENT_INPUT", verified()),
            EXPERT,
            true,
        )
        .unwrap(),
    );
    signed(cases, kp)
}

#[test]
fn improvement_passes_old_and_new_cases_with_no_regression() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let r = upgrade_check(
        &expert_fixture(),
        &v2(),
        &regression_suite(&kp),
        &kp.public_key,
    );
    assert!(r.acceptable, "{:?}", r.reasons);
    assert_eq!(r.fixes.len(), 1);
    assert_eq!(r.fixes[0].case_id, "exp-024");
    assert!(r.regressions.is_empty());
    assert_eq!(r.new_passed, r.cases);
    assert_eq!(r.old_passed, r.cases - 1);
    assert!(
        r.scope_notes.iter().any(|n| n.contains("resistance")),
        "applicability change is shown to the approver"
    );
}

#[test]
fn a_version_that_breaks_an_old_case_is_a_regression() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let mut bad = v2();
    bad.procedure.default_outcome = "RETEST_30D".into();
    let r = upgrade_check(
        &expert_fixture(),
        &bad,
        &regression_suite(&kp),
        &kp.public_key,
    );
    assert!(!r.acceptable);
    assert!(!r.regressions.is_empty());
}

#[test]
fn scope_change_forged_suite_or_same_version_is_not_acceptable() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let suite = regression_suite(&kp);
    let mut wider = v2();
    wider.required.min_clearance = "internal".into();
    assert!(!upgrade_check(&expert_fixture(), &wider, &suite, &kp.public_key).acceptable);
    let mut newout = v2();
    newout.outcomes.push("SHIP_IT".into());
    assert!(!upgrade_check(&expert_fixture(), &newout, &suite, &kp.public_key).acceptable);
    let other = aip_crypto::generate_ed25519_keypair();
    assert!(!upgrade_check(&expert_fixture(), &v2(), &suite, &other.public_key).acceptable);
    assert!(
        !upgrade_check(&expert_fixture(), &expert_fixture(), &suite, &kp.public_key).acceptable
    );
}

// ── lifecycle: supersede, single active version, rollback ─────────────────

fn ingest(c: &mut SqliteCorpus, name: &str) {
    let t = std::fs::read_to_string(format!("{DATA}/corpus/{name}")).unwrap();
    let (head, body) = t.split_once('\n').unwrap();
    let f: Vec<&str> = head.splitn(4, '|').collect();
    c.ingest(&Document {
        tenant: Ident::new(f[0]).unwrap(),
        doc_id: Ident::new(f[1]).unwrap(),
        classification: Classification::parse(f[2]).unwrap(),
        title: f[3].into(),
        body: body.into(),
    })
    .unwrap();
}

fn state(store: &FileStore, h: &str) -> State {
    store
        .all()
        .unwrap()
        .into_iter()
        .find(|r| r.capability_hash == h)
        .unwrap()
        .state
}

#[test]
fn upgrade_supersedes_keeps_one_active_version_and_rolls_back() {
    let mut corpus = SqliteCorpus::in_memory().unwrap();
    ingest(&mut corpus, "koravi-ep-114.txt");
    let dir = tempfile::tempdir().unwrap();
    let mut store = FileStore::open(dir.path()).unwrap();
    let ekp = aip_crypto::generate_ed25519_keypair();
    let akp = aip_crypto::generate_ed25519_keypair();
    let experts = BTreeMap::from([(EXPERT.to_string(), ekp.public_key.clone())]);
    let suite = regression_suite(&ekp);
    let go = |cap, store: &mut FileStore| {
        let h = propose(store, &corpus, cap).unwrap();
        assert!(
            validate_record(store, &corpus, &h, &suite, &experts, "validator", 1)
                .unwrap()
                .passed
        );
        approve_record(
            store,
            &h,
            "user:koravi-elec-authority",
            &akp.private_key,
            &akp.public_key,
            false,
            2,
        )
        .unwrap();
        h
    };
    // v1 fails the regression suite's new case (that is the gap v2 fixes), so v1
    // was validated on the original suite.
    let orig = ExpertSuite::sign(
        "ir/validation",
        "koravi-process",
        "motor IR acceptance (EP-114 rev C)",
        EXPERT,
        suite_cases("validation.jsonl"),
        &ekp.private_key,
    )
    .unwrap();
    let h1 = propose(&mut store, &corpus, expert_fixture()).unwrap();
    assert!(
        validate_record(&mut store, &corpus, &h1, &orig, &experts, "validator", 1)
            .unwrap()
            .passed
    );
    approve_record(
        &mut store,
        &h1,
        "user:koravi-elec-authority",
        &akp.private_key,
        &akp.public_key,
        false,
        2,
    )
    .unwrap();
    assert!(
        activate(&mut store, &h1, "operator:koravi-ot", false, 3, "go live")
            .unwrap()
            .is_empty()
    );
    let h2 = go(v2(), &mut store);
    // A second ACTIVE version is refused unless the first is superseded.
    assert!(activate(&mut store, &h2, "operator:koravi-ot", false, 4, "x").is_err());
    assert!(transition(
        &mut store,
        &h2,
        State::Active,
        "operator:koravi-ot",
        Role::Operator,
        4,
        "x"
    )
    .is_err());
    assert_eq!(
        activate(
            &mut store,
            &h2,
            "operator:koravi-ot",
            true,
            5,
            "v2 fixes exp-024"
        )
        .unwrap(),
        vec![h1.clone()]
    );
    assert_eq!(
        (state(&store, &h1), state(&store, &h2)),
        (State::Superseded, State::Active)
    );
    // Rollback: approver only (table), target must be SUPERSEDED.
    assert!(allowed(State::Superseded, State::Active).contains(&Role::Approver));
    assert!(!allowed(State::Superseded, State::Active).contains(&Role::Operator));
    assert!(
        rollback(&mut store, &h2, "user:koravi-elec-authority", 6, "x").is_err(),
        "an active version is not a rollback target"
    );
    assert_eq!(
        rollback(
            &mut store,
            &h1,
            "user:koravi-elec-authority",
            7,
            "field issue with v2"
        )
        .unwrap(),
        vec![h2.clone()]
    );
    assert_eq!(
        (state(&store, &h1), state(&store, &h2)),
        (State::Active, State::Suspended)
    );
    let r1 = store
        .all()
        .unwrap()
        .into_iter()
        .find(|r| r.capability_hash == h1)
        .unwrap();
    assert!(
        r1.executable(),
        "rolled-back version keeps its validation and approval"
    );
}

// ── experience log: isolation and immutability ─────────────────────────────

#[test]
fn experience_log_refuses_foreign_tenant_domain_self_verification_and_rewrites() {
    let dir = tempfile::tempdir().unwrap();
    let log = ExperienceLog::open(&dir.path().join("exp.jsonl"));
    let e = exp("e1", T024, "INSUFFICIENT_INPUT", verified());
    assert!(log.record(&e, "tarvel-grid", "koravi-ot").is_err());
    assert!(log.record(&e, "koravi-process", "tarvel-ot").is_err());
    let selfv = exp(
        "e2",
        T024,
        "PASS",
        Verification::Verified {
            verifier: "agent:runtime".into(),
            at_ms: 1,
        },
    );
    assert!(log.record(&selfv, "koravi-process", "koravi-ot").is_err());
    log.record(&e, "koravi-process", "koravi-ot").unwrap();
    let mut changed = e.clone();
    changed.expected_outcome = Some("PASS".into());
    assert!(
        log.record(&changed, "koravi-process", "koravi-ot").is_err(),
        "recorded experience is immutable"
    );
    assert_eq!(log.for_tenant("koravi-process").unwrap().len(), 1);
    assert!(log.for_tenant("tarvel-grid").unwrap().is_empty());
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.path().join("exp.jsonl"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
