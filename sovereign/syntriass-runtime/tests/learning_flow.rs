//! Capability lifecycle orchestration against a real (in-memory) corpus and
//! the file store: evidence binding, trusted-expert validation, independent
//! approval, activation — and the attacks on each step.

use std::collections::BTreeMap;

use syntriass_runtime::adapters::store::FileStore;
use syntriass_runtime::capability::lifecycle::{Role, State};
use syntriass_runtime::learning::{approve_record, propose, transition, validate_record};
use syntriass_runtime::ports::CapabilityStore;
use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;
use vanian_sovereign::domain::corpus::{Classification, Document, Ident};
use vanian_sovereign::ports::CorpusStore;

mod common;
use common::*;

fn ingest(c: &mut SqliteCorpus, name: &str) -> String {
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
    hex::encode(aip_crypto::sha256(body.as_bytes()))
}

struct World {
    corpus: SqliteCorpus,
    store: FileStore,
    _dir: tempfile::TempDir,
    ep114: String,
}

fn world() -> World {
    let mut corpus = SqliteCorpus::in_memory().unwrap();
    let ep114 = ingest(&mut corpus, "koravi-ep-114.txt");
    ingest(&mut corpus, "koravi-ep-090.txt");
    ingest(&mut corpus, "tarvel-tg-ir-02.txt");
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::open(dir.path()).unwrap();
    World {
        corpus,
        store,
        _dir: dir,
        ep114,
    }
}

fn experts(pk: &[u8]) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([(EXPERT.to_string(), pk.to_vec())])
}

#[test]
fn evidence_digests_are_bound_by_the_system_not_the_proposer() {
    let mut w = world();
    let mut cap = expert_fixture();
    cap.dependencies.knowledge = BTreeMap::from([("ep-114".into(), "attacker-chosen".into())]);
    let h = propose(&mut w.store, &w.corpus, cap).unwrap();
    let rec = w
        .store
        .all()
        .unwrap()
        .into_iter()
        .find(|r| r.capability_hash == h)
        .unwrap();
    assert_eq!(rec.capability.dependencies.knowledge["ep-114"], w.ep114);
    assert_eq!(rec.state, State::Proposed);
}

#[test]
fn proposal_naming_another_tenants_document_is_refused() {
    let mut w = world();
    let mut cap = expert_fixture();
    cap.dependencies.knowledge = BTreeMap::from([("tg-ir-02".into(), String::new())]);
    assert!(propose(&mut w.store, &w.corpus, cap).is_err());
    let mut cap = expert_fixture();
    cap.dependencies.knowledge.clear();
    assert!(
        propose(&mut w.store, &w.corpus, cap).is_err(),
        "no evidence named"
    );
}

#[test]
fn full_flow_and_every_gate() {
    let mut w = world();
    let h = propose(&mut w.store, &w.corpus, expert_fixture()).unwrap();
    let (ekp, suite) = expert_suite();
    // Untrusted expert: refused before any state change.
    let stranger = aip_crypto::generate_ed25519_keypair();
    let untrusted = BTreeMap::from([("expert:someone".to_string(), stranger.public_key.clone())]);
    assert!(validate_record(
        &mut w.store,
        &w.corpus,
        &h,
        &suite,
        &untrusted,
        "validator",
        1
    )
    .is_err());
    // Cannot activate or approve before validation.
    assert!(transition(
        &mut w.store,
        &h,
        State::Active,
        "op",
        Role::Operator,
        1,
        "skip"
    )
    .is_err());
    let rep = validate_record(
        &mut w.store,
        &w.corpus,
        &h,
        &suite,
        &experts(&ekp.public_key),
        "validator",
        2,
    )
    .unwrap();
    assert!(rep.passed, "{rep:?}");
    // The proposer cannot approve its own capability.
    let pkp = aip_crypto::generate_ed25519_keypair();
    let proposer = expert_fixture().proposed_by;
    assert!(approve_record(
        &mut w.store,
        &h,
        &proposer,
        &pkp.private_key,
        &pkp.public_key,
        false,
        3
    )
    .is_err());
    // A signature that does not match the presented key fails.
    let akp = aip_crypto::generate_ed25519_keypair();
    assert!(approve_record(
        &mut w.store,
        &h,
        "user:koravi-elec-authority",
        &pkp.private_key,
        &akp.public_key,
        false,
        3
    )
    .is_err());
    approve_record(
        &mut w.store,
        &h,
        "user:koravi-elec-authority",
        &akp.private_key,
        &akp.public_key,
        false,
        4,
    )
    .unwrap();
    transition(
        &mut w.store,
        &h,
        State::Active,
        "operator",
        Role::Operator,
        5,
        "go live",
    )
    .unwrap();
    let rec = w
        .store
        .all()
        .unwrap()
        .into_iter()
        .find(|r| r.capability_hash == h)
        .unwrap();
    assert!(rec.executable());
    // Revocation is an approver decision; an operator cannot revoke.
    assert!(transition(
        &mut w.store,
        &h,
        State::Revoked,
        "operator",
        Role::Operator,
        6,
        "x"
    )
    .is_err());
    transition(
        &mut w.store,
        &h,
        State::Revoked,
        "authority",
        Role::Approver,
        6,
        "withdrawn",
    )
    .unwrap();
    let rec = w
        .store
        .all()
        .unwrap()
        .into_iter()
        .find(|r| r.capability_hash == h)
        .unwrap();
    assert!(!rec.executable());
}

#[test]
fn a_wrong_procedure_is_rejected_and_rejection_is_terminal() {
    let mut w = world();
    let mut cap = expert_fixture();
    cap.procedure.derive[1].expr = "10 * kv".into(); // drops the "+1" of EP-114 step 3
    let h = propose(&mut w.store, &w.corpus, cap).unwrap();
    let (ekp, suite) = expert_suite();
    let rep = validate_record(
        &mut w.store,
        &w.corpus,
        &h,
        &suite,
        &experts(&ekp.public_key),
        "validator",
        1,
    )
    .unwrap();
    assert!(!rep.passed && !rep.failures.is_empty());
    let rec = w
        .store
        .all()
        .unwrap()
        .into_iter()
        .find(|r| r.capability_hash == h)
        .unwrap();
    assert_eq!(rec.state, State::Rejected);
    assert!(validate_record(
        &mut w.store,
        &w.corpus,
        &h,
        &suite,
        &experts(&ekp.public_key),
        "validator",
        2
    )
    .is_err());
}
