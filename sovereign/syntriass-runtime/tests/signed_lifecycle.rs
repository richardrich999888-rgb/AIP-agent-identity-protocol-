//! Signed lifecycle actions (C2 gate: "authenticate activation and revocation").
//!
//! Before: `--actor` and `--role` were recorded as given, and a stored record
//! whose state was edited to ACTIVE executed. Each test below names one way
//! that could be abused and runs it against real source binding, a signed
//! suite, signed approval and the file store; the CLI tests run the binary.

use std::collections::BTreeMap;
use std::process::Command;

use syntriass_runtime::adapters::store::FileStore;
use syntriass_runtime::capability::action::{check_active, ActionKeys, SignedAction};
use syntriass_runtime::capability::authority::ApprovalPolicy;
use syntriass_runtime::capability::lifecycle::{LifecycleError, Record, Role, State};
use syntriass_runtime::capability::suite::ExpertSuite;
use syntriass_runtime::learning::{
    activate, activate_as, approve_record, propose, rollback_as, transition_as, validate_record,
    Actor,
};
use syntriass_runtime::ports::CapabilityStore;
use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;
use vanian_sovereign::domain::corpus::{Classification, Document, Ident};
use vanian_sovereign::ports::CorpusStore;

mod common;
use common::*;

const TENANT: &str = "koravi-process";
const DOMAIN: &str = "koravi-ot";
const OPERATOR: &str = "operator:koravi-ot";
const APPROVER: &str = "expert:approval-authority";

struct World {
    corpus: SqliteCorpus,
    store: FileStore,
    dir: tempfile::TempDir,
    expert: aip_types::KeyPair,
    approver: aip_types::KeyPair,
    operator: aip_types::KeyPair,
    operators: BTreeMap<String, Vec<u8>>,
    approvers: BTreeMap<String, Vec<u8>>,
}

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut corpus = SqliteCorpus::open(&dir.path().join("corpus.db")).unwrap();
        let text = std::fs::read_to_string(format!("{DATA}/corpus/koravi-ep-114.txt")).unwrap();
        let (_, body) = text.split_once('\n').unwrap();
        corpus
            .ingest(&Document {
                tenant: Ident::new(TENANT).unwrap(),
                doc_id: Ident::new("ep-114").unwrap(),
                classification: Classification::Restricted,
                title: "Synthetic EP-114".into(),
                body: body.into(),
            })
            .unwrap();
        let store = FileStore::open(&dir.path().join("capabilities")).unwrap();
        let (approver, operator) = (
            aip_crypto::generate_ed25519_keypair(),
            aip_crypto::generate_ed25519_keypair(),
        );
        Self {
            corpus,
            store,
            dir,
            expert: aip_crypto::generate_ed25519_keypair(),
            operators: BTreeMap::from([(OPERATOR.into(), operator.public_key.clone())]),
            approvers: BTreeMap::from([(APPROVER.into(), approver.public_key.clone())]),
            approver,
            operator,
        }
    }

    fn keys(&self) -> ActionKeys<'_> {
        ActionKeys {
            operators: &self.operators,
            approvers: &self.approvers,
            policy: None,
        }
    }

    fn ids(&self) -> Ids {
        Ids {
            operators: self.operators.clone(),
            approvers: self.approvers.clone(),
            op_sk: self.operator.private_key.clone(),
            ap_sk: self.approver.private_key.clone(),
        }
    }

    /// A validated and signed-approved version, written to the store.
    fn approved(&mut self, version: u32) -> String {
        let mut cap = expert_fixture();
        cap.version = version;
        let hash = propose(&mut self.store, &self.corpus, cap).unwrap();
        let suite = ExpertSuite::sign(
            "signed-lifecycle/validation",
            TENANT,
            "motor IR acceptance (EP-114 rev C)",
            EXPERT,
            suite_cases("validation.jsonl"),
            &self.expert.private_key,
        )
        .unwrap();
        let experts = BTreeMap::from([(EXPERT.into(), self.expert.public_key.clone())]);
        let report = validate_record(
            &mut self.store,
            &self.corpus,
            &hash,
            &suite,
            &experts,
            "validator",
            1,
        )
        .unwrap();
        assert!(report.passed, "{report:?}");
        approve_record(
            &mut self.store,
            &hash,
            APPROVER,
            &self.approver.private_key,
            &self.approver.public_key,
            false,
            2,
        )
        .unwrap();
        hash
    }

    fn record(&self, hash: &str) -> Record {
        self.store
            .all()
            .unwrap()
            .into_iter()
            .find(|r| r.capability_hash == hash)
            .unwrap()
    }

    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(self.dir.path().join("capabilities"))
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (
                    p.file_name().unwrap().to_str().unwrap().to_owned(),
                    std::fs::read(p).unwrap(),
                )
            })
            .collect()
    }

    fn key_file(&self, name: &str, id: &str, kp: &aip_types::KeyPair) -> String {
        let path = self.dir.path().join(name);
        aip_crypto::custody::create_owner_only(
            &path,
            &serde_json::to_vec(&serde_json::json!({
                "id": id, "public_hex": hex::encode(&kp.public_key), "private_hex": hex::encode(&kp.private_key)
            }))
            .unwrap(),
        )
        .unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn cli(&self, strict: bool, command: &str, args: &[&str]) -> std::process::Output {
        let unused = serde_json::json!({"path": "UNUSED_BY_LIFECYCLE", "sha256": "0".repeat(64)});
        let config = serde_json::json!({
            "state": self.dir.path(), "policy_version": "ep-114-revC", "security_domain": DOMAIN, "rag_k": 3,
            "approvers": {APPROVER: hex::encode(&self.approver.public_key)},
            "operators": {OPERATOR: hex::encode(&self.operator.public_key)},
            "require_signed_lifecycle": strict,
            "experts": {EXPERT: hex::encode(&self.expert.public_key)}, "python": "UNUSED_BY_LIFECYCLE",
            "sidecar_script": "UNUSED_BY_LIFECYCLE", "llama_server": "UNUSED_BY_LIFECYCLE",
            "profile": "none", "q4": unused, "q8": unused, "port": 18080
        });
        let path = self.dir.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        Command::new(env!("CARGO_BIN_EXE_syntriass"))
            .arg(command)
            .arg("--config")
            .arg(path)
            .args(args)
            .output()
            .unwrap()
    }
}

/// Key material owned apart from the world, so its store can be borrowed
/// mutably while an actor borrows the keys.
struct Ids {
    operators: BTreeMap<String, Vec<u8>>,
    approvers: BTreeMap<String, Vec<u8>>,
    op_sk: Vec<u8>,
    ap_sk: Vec<u8>,
}

impl Ids {
    fn keys(&self) -> ActionKeys<'_> {
        ActionKeys {
            operators: &self.operators,
            approvers: &self.approvers,
            policy: None,
        }
    }
    fn op<'a>(&'a self, keys: &'a ActionKeys<'a>) -> Actor<'a> {
        Actor::Signed {
            id: OPERATOR,
            private_key: &self.op_sk,
            keys,
        }
    }
    fn ap<'a>(&'a self, keys: &'a ActionKeys<'a>) -> Actor<'a> {
        Actor::Signed {
            id: APPROVER,
            private_key: &self.ap_sk,
            keys,
        }
    }
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ── the happy path, end to end ──────────────────────────────────────────────

#[test]
fn signed_activate_supersede_and_rollback_each_verify_at_use_time() {
    let mut w = World::new();
    let (v1, v2) = (w.approved(1), w.approved(2));
    let ids = w.ids();
    let keys = ids.keys();
    activate_as(&mut w.store, &v1, &ids.op(&keys), false, 10, "go live").unwrap();
    check_active(&w.record(&v1), &w.keys(), 11).unwrap();

    let superseded = activate_as(&mut w.store, &v2, &ids.op(&keys), true, 20, "upgrade").unwrap();
    assert_eq!(superseded, vec![v1.clone()]);
    assert_eq!(w.record(&v1).state, State::Superseded);
    check_active(&w.record(&v2), &w.keys(), 21).unwrap();
    // The supersession of v1 is itself signed, by the operator who upgraded.
    let last = w.record(&v1).history.last().cloned().unwrap();
    assert_eq!(
        (last.to, last.actor.as_str()),
        (State::Superseded, OPERATOR)
    );
    assert!(last.action.unwrap().verify(&w.operator.public_key));

    let suspended = rollback_as(&mut w.store, &v1, &ids.ap(&keys), 30, "regression").unwrap();
    assert_eq!(suspended, vec![v2.clone()]);
    assert_eq!(w.record(&v2).state, State::Suspended);
    check_active(&w.record(&v1), &w.keys(), 31).unwrap();
}

#[test]
fn the_recorded_actor_is_the_signer_never_a_caller_string() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let ids = w.ids();
    let keys = ids.keys();
    activate_as(&mut w.store, &v1, &ids.op(&keys), false, 10, "go live").unwrap();
    let last = w.record(&v1).history.last().cloned().unwrap();
    assert_eq!((last.actor.as_str(), last.role), (OPERATOR, Role::Operator));
}

// ── attacks on stored state ─────────────────────────────────────────────────

#[test]
fn a_record_hand_set_to_active_is_refused_at_use_time() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let mut r = w.record(&v1);
    r.state = State::Active;
    w.store.put(&r).unwrap();
    assert!(
        w.record(&v1).executable(),
        "the attack works against the pre-existing check"
    );
    assert_eq!(
        check_active(&w.record(&v1), &w.keys(), 10),
        Err("stored state does not follow from the recorded history")
    );
}

#[test]
fn a_legacy_unsigned_activation_does_not_satisfy_signed_lifecycle() {
    let mut w = World::new();
    let v1 = w.approved(1);
    activate(&mut w.store, &v1, "operator", false, 10, "legacy").unwrap();
    assert!(w.record(&v1).executable());
    assert_eq!(
        check_active(&w.record(&v1), &w.keys(), 11),
        Err("activation is not signed; signed lifecycle required")
    );
}

#[test]
fn a_signed_activation_copied_onto_another_record_is_refused() {
    let mut w = World::new();
    let (v1, v2) = (w.approved(1), w.approved(2));
    let ids = w.ids();
    let keys = ids.keys();
    activate_as(&mut w.store, &v1, &ids.op(&keys), false, 10, "go live").unwrap();
    let stolen = w.record(&v1).history.last().cloned().unwrap();
    let mut target = w.record(&v2);
    target.history.push(stolen);
    target.state = State::Active;
    assert_eq!(
        check_active(&target, &w.keys(), 11),
        Err("recorded transition differs from its signed action")
    );
}

#[test]
fn an_old_resume_replayed_after_a_later_suspension_is_refused() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let ids = w.ids();
    let keys = ids.keys();
    activate_as(&mut w.store, &v1, &ids.op(&keys), false, 10, "go live").unwrap();
    transition_as(
        &mut w.store,
        &v1,
        State::Suspended,
        &ids.ap(&keys),
        Role::Approver,
        20,
        "incident",
    )
    .unwrap();
    transition_as(
        &mut w.store,
        &v1,
        State::Active,
        &ids.ap(&keys),
        Role::Approver,
        30,
        "cleared",
    )
    .unwrap();
    let resume = w.record(&v1).history.last().cloned().unwrap();
    transition_as(
        &mut w.store,
        &v1,
        State::Suspended,
        &ids.ap(&keys),
        Role::Approver,
        40,
        "second incident",
    )
    .unwrap();
    // Re-append the genuine, validly signed first resume.
    let mut r = w.record(&v1);
    r.history.push(resume);
    r.state = State::Active;
    assert_eq!(
        check_active(&r, &w.keys(), 50),
        Err("signed activation is for another point in the record's history")
    );
}

#[test]
fn an_edited_reason_or_time_breaks_the_signed_activation() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let ids = w.ids();
    let keys = ids.keys();
    activate_as(&mut w.store, &v1, &ids.op(&keys), false, 10, "go live").unwrap();
    let mut r = w.record(&v1);
    r.history.last_mut().unwrap().reason = "something else".into();
    assert_eq!(
        check_active(&r, &w.keys(), 11),
        Err("recorded transition differs from its signed action")
    );
    let mut r = w.record(&v1);
    let a = r.history.last_mut().unwrap();
    a.reason = "something else".into();
    a.action.as_mut().unwrap().reason = "something else".into();
    assert_eq!(
        check_active(&r, &w.keys(), 11),
        Err("signed activation signature invalid")
    );
}

#[test]
fn removing_the_operator_from_the_trust_store_withdraws_the_activation() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let ids = w.ids();
    let keys = ids.keys();
    activate_as(&mut w.store, &v1, &ids.op(&keys), false, 10, "go live").unwrap();
    let none = BTreeMap::new();
    let without = ActionKeys {
        operators: &none,
        approvers: &w.approvers,
        policy: None,
    };
    assert_eq!(
        check_active(&w.record(&v1), &without, 11),
        Err("signer is not a configured operator")
    );
}

// ── who may sign what ───────────────────────────────────────────────────────

#[test]
fn keys_are_role_specific_and_validator_cannot_be_claimed() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let ids = w.ids();
    let keys = ids.keys();
    let before = w.files();
    // The approver key cannot activate: activation is an operator edge.
    let approver_as_operator = Actor::Signed {
        id: APPROVER,
        private_key: &ids.ap_sk,
        keys: &keys,
    };
    let e = activate_as(&mut w.store, &v1, &approver_as_operator, false, 10, "x").unwrap_err();
    assert!(
        e.to_string()
            .contains("signer is not a configured operator"),
        "{e}"
    );
    // The operator key cannot roll back or resume: those are approver edges.
    let e = transition_as(
        &mut w.store,
        &v1,
        State::Revoked,
        &ids.op(&keys),
        Role::Approver,
        10,
        "x",
    )
    .unwrap_err();
    assert!(
        e.to_string()
            .contains("signer is not a configured approver"),
        "{e}"
    );
    // No caller may sign as the runtime's validator.
    let e = transition_as(
        &mut w.store,
        &v1,
        State::Rejected,
        &ids.op(&keys),
        Role::Validator,
        10,
        "x",
    )
    .unwrap_err();
    assert!(
        e.to_string()
            .contains("validator transitions cannot be signed by a caller"),
        "{e}"
    );
    assert_eq!(w.files(), before, "a refused action wrote state");
}

#[test]
fn a_configured_id_with_the_wrong_private_key_is_refused_without_writing() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let ids = w.ids();
    let keys = ids.keys();
    let impostor = aip_crypto::generate_ed25519_keypair();
    let before = w.files();
    let forged = Actor::Signed {
        id: OPERATOR,
        private_key: &impostor.private_key,
        keys: &keys,
    };
    let e = activate_as(&mut w.store, &v1, &forged, false, 10, "x").unwrap_err();
    assert!(
        e.to_string().contains("ActionInvalid(\"signature\")"),
        "{e}"
    );
    assert_eq!(w.files(), before);
}

#[test]
fn under_strict_policy_an_approver_needs_a_current_grant_to_roll_back() {
    let mut w = World::new();
    let (v1, v2) = (w.approved(1), w.approved(2));
    let ids = w.ids();
    let keys = ids.keys();
    activate_as(&mut w.store, &v1, &ids.op(&keys), false, 10, "go live").unwrap();
    activate_as(&mut w.store, &v2, &ids.op(&keys), true, 20, "upgrade").unwrap();
    let empty = ApprovalPolicy::default(); // present but grants nothing
    let strict = ActionKeys {
        operators: &ids.operators,
        approvers: &ids.approvers,
        policy: Some(&empty),
    };
    let before = w.files();
    let e = rollback_as(&mut w.store, &v1, &ids.ap(&strict), 30, "x").unwrap_err();
    assert!(
        e.to_string().contains("no configured approval authority"),
        "{e}"
    );
    assert_eq!(
        w.files(),
        before,
        "v2 was suspended although the rollback was refused"
    );
}

#[test]
fn a_signature_check_on_the_action_itself_matches_its_fields() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let r = w.record(&v1);
    let a = SignedAction::sign(
        &r,
        State::Active,
        Role::Operator,
        OPERATOR,
        10,
        "go",
        &w.operator.private_key,
    )
    .unwrap();
    assert!(a.verify(&w.operator.public_key));
    assert!(!a.verify(&w.approver.public_key));
    let mut moved = a.clone();
    moved.to = State::Revoked;
    assert!(!moved.verify(&w.operator.public_key));
    let mut other = r.clone();
    assert_eq!(
        other.transition_signed(
            SignedAction {
                seq: 99,
                ..a.clone()
            },
            &w.operator.public_key
        ),
        Err(LifecycleError::ActionInvalid(
            "signed action is for another point in the record's history"
        ))
    );
    other.transition_signed(a, &w.operator.public_key).unwrap();
    assert_eq!(other.state, State::Active);
}

// ── atomicity of refusals (legacy and signed) ───────────────────────────────

#[test]
fn a_refused_supersession_leaves_the_current_version_active() {
    // Regression: activate() used to write the superseded version before the
    // target's own transition could fail, leaving no version active.
    let mut w = World::new();
    let (v1, v2) = (w.approved(1), w.approved(2));
    activate(&mut w.store, &v1, "operator", false, 10, "go live").unwrap();
    let mut target = w.record(&v2);
    target
        .capability
        .intended_task
        .push_str(" (edited after approval)");
    w.store.put(&target).unwrap();
    let before = w.files();
    assert!(activate(&mut w.store, &v2, "operator", true, 20, "upgrade").is_err());
    assert_eq!(w.files(), before);
    assert_eq!(w.record(&v1).state, State::Active);
}

// ── the real CLI ────────────────────────────────────────────────────────────

#[test]
fn strict_cli_refuses_an_asserted_actor_and_writes_nothing() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let before = w.files();
    let o = w.cli(
        true,
        "cap-activate",
        &["--hash", &v1, "--actor", "operator", "--reason", "x"],
    );
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("signed lifecycle required"),
        "{}",
        stderr(&o)
    );
    let o = w.cli(
        true,
        "cap-transition",
        &[
            "--hash", &v1, "--to", "ACTIVE", "--role", "operator", "--actor", "operator",
            "--reason", "x",
        ],
    );
    assert!(!o.status.success());
    assert_eq!(w.files(), before);
}

#[test]
fn strict_cli_activates_with_an_operator_key_and_refuses_a_hand_set_record() {
    let mut w = World::new();
    let (v1, v2) = (w.approved(1), w.approved(2));
    let op = w.key_file("operator.json", OPERATOR, &w.operator);
    let o = w.cli(
        true,
        "cap-activate",
        &["--hash", &v1, "--key", &op, "--reason", "go live"],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    // Make the other version look ACTIVE by editing its stored state.
    let mut r = w.record(&v2);
    r.state = State::Active;
    w.store.put(&r).unwrap();
    let list = w.cli(true, "cap-list", &[]);
    let rows: BTreeMap<String, bool> = String::from_utf8_lossy(&list.stdout)
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .map(|v| {
            (
                v["hash"].as_str().unwrap().to_owned(),
                v["executable"].as_bool().unwrap(),
            )
        })
        .collect();
    assert!(rows[&v1], "signed activation must be executable");
    assert!(!rows[&v2], "hand-set ACTIVE must not be executable");
    // The same hand-set record is still executable when the mode is off.
    let legacy = w.cli(false, "cap-list", &[]);
    assert!(String::from_utf8_lossy(&legacy.stdout)
        .lines()
        .any(|l| l.contains(&v2) && l.contains("\"executable\":true")));
}

#[test]
fn cli_refuses_both_key_and_actor() {
    let mut w = World::new();
    let v1 = w.approved(1);
    let op = w.key_file("operator.json", OPERATOR, &w.operator);
    let o = w.cli(
        false,
        "cap-activate",
        &[
            "--hash", &v1, "--key", &op, "--actor", "operator", "--reason", "x",
        ],
    );
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("give --key or --actor, not both"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn strict_cli_rollback_needs_an_approver_key() {
    let mut w = World::new();
    let (v1, v2) = (w.approved(1), w.approved(2));
    let op = w.key_file("operator.json", OPERATOR, &w.operator);
    let ap = w.key_file("approver.json", APPROVER, &w.approver);
    assert!(w
        .cli(
            true,
            "cap-activate",
            &["--hash", &v1, "--key", &op, "--reason", "a"]
        )
        .status
        .success());
    assert!(w
        .cli(
            true,
            "cap-activate",
            &["--hash", &v2, "--key", &op, "--supersede", "--reason", "b"]
        )
        .status
        .success());
    let before = w.files();
    let o = w.cli(
        true,
        "cap-rollback",
        &["--to", &v1, "--key", &op, "--reason", "c"],
    );
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("signer is not a configured approver"),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.files(), before);
    let o = w.cli(
        true,
        "cap-rollback",
        &["--to", &v1, "--key", &ap, "--reason", "c"],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(
        (w.record(&v1).state, w.record(&v2).state),
        (State::Active, State::Suspended)
    );
}
