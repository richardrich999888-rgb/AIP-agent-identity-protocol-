//! Same capability names may exist in different tenants and security domains.
//! Exercise real source binding, signed validation/approval and file persistence;
//! a lifecycle action must not displace another scope's active version.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::process::Command;

use syntriass_runtime::adapters::store::FileStore;
use syntriass_runtime::capability::lifecycle::{Record, Role, State};
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

const TENANT: &str = "koravi-process";
const DOMAIN: &str = "koravi-ot";
const FOREIGN: [(&str, &str); 2] = [("other-tenant", DOMAIN), (TENANT, "other-domain")];

struct World {
    corpus: SqliteCorpus,
    store: FileStore,
    dir: tempfile::TempDir,
    expert: aip_types::KeyPair,
    approver: aip_types::KeyPair,
    suites: Vec<ExpertSuite>,
    snapshots: RefCell<Vec<BTreeMap<String, Vec<u8>>>>,
    policies: RefCell<Vec<serde_json::Value>>,
}

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut corpus = SqliteCorpus::open(&dir.path().join("corpus.db")).unwrap();
        let text = std::fs::read_to_string(format!("{DATA}/corpus/koravi-ep-114.txt")).unwrap();
        let (_, body) = text.split_once('\n').unwrap();
        // Identical synthetic source content, separately ingested per tenant.
        for tenant in [TENANT, "other-tenant"] {
            corpus
                .ingest(&Document {
                    tenant: Ident::new(tenant).unwrap(),
                    doc_id: Ident::new("ep-114").unwrap(),
                    classification: Classification::Restricted,
                    title: "Synthetic EP-114".into(),
                    body: body.into(),
                })
                .unwrap();
        }
        let store = FileStore::open(&dir.path().join("capabilities")).unwrap();
        Self {
            corpus,
            store,
            dir,
            expert: aip_crypto::generate_ed25519_keypair(),
            approver: aip_crypto::generate_ed25519_keypair(),
            suites: vec![],
            snapshots: RefCell::new(vec![]),
            policies: RefCell::new(vec![]),
        }
    }

    fn propose(&mut self, tenant: &str, domain: &str, version: u32) -> String {
        let mut cap = expert_fixture();
        cap.required.tenant = tenant.into();
        cap.required.security_domain = domain.into();
        cap.version = version;
        propose(&mut self.store, &self.corpus, cap).unwrap()
    }

    fn approved(&mut self, tenant: &str, domain: &str, version: u32) -> String {
        let hash = self.propose(tenant, domain, version);
        let suite = ExpertSuite::sign(
            "scope-isolation/validation",
            tenant,
            "motor IR acceptance (EP-114 rev C)",
            EXPERT,
            suite_cases("validation.jsonl"),
            &self.expert.private_key,
        )
        .unwrap();
        let keys = BTreeMap::from([(EXPERT.into(), self.expert.public_key.clone())]);
        let report = validate_record(
            &mut self.store,
            &self.corpus,
            &hash,
            &suite,
            &keys,
            "validator",
            1,
        )
        .unwrap();
        assert!(report.passed, "{report:?}");
        self.suites.push(suite);
        approve_record(
            &mut self.store,
            &hash,
            "expert:approval-authority",
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

    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        let files: BTreeMap<_, _> = std::fs::read_dir(self.dir.path().join("capabilities"))
            .unwrap()
            .map(|e| {
                let path = e.unwrap().path();
                (
                    path.file_name().unwrap().to_str().unwrap().to_owned(),
                    std::fs::read(path).unwrap(),
                )
            })
            .collect();
        self.snapshots.borrow_mut().push(files.clone());
        files
    }

    fn seed_active(&mut self, hash: &str) {
        // Set up independently validated/approved active records via the pure
        // state machine, so the old orchestration bug cannot prevent the attack
        // fixture itself from containing both scopes in a shared file store.
        let mut record = self.record(hash);
        record
            .transition(
                State::Active,
                "operator",
                Role::Operator,
                3,
                "fixture setup",
            )
            .unwrap();
        self.store.put(&record).unwrap();
        assert!(record.executable());
    }

    fn assert_preserved(&self, before: &BTreeMap<String, Vec<u8>>, hash: &str) {
        let key = before.keys().find(|k| k.contains(&hash[..16])).unwrap();
        assert_eq!(
            self.snapshot()[key],
            before[key],
            "unrelated record changed"
        );
        assert_eq!(self.record(hash).state, State::Active);
    }

    fn cli(&self, command: &str, args: &[&str]) -> std::process::Output {
        self.cli_policy(command, args, None)
    }

    fn cli_policy(
        &self,
        command: &str,
        args: &[&str],
        policy: Option<&serde_json::Value>,
    ) -> std::process::Output {
        let unused = serde_json::json!({"path":"UNUSED_BY_LIFECYCLE", "sha256":"0".repeat(64)});
        let mut config = serde_json::json!({
            "state":self.dir.path(), "policy_version":"ep-114-revC", "security_domain":DOMAIN,
            "rag_k":3, "approvers":{"expert:approval-authority":hex::encode(&self.approver.public_key)},
            "experts":{EXPERT:hex::encode(&self.expert.public_key)}, "python":"UNUSED_BY_LIFECYCLE",
            "sidecar_script":"UNUSED_BY_LIFECYCLE", "llama_server":"UNUSED_BY_LIFECYCLE",
            "profile":"none", "q4":unused, "q8":unused, "port":18080
        });
        if let Some(policy) = policy {
            config["approval_policy"] = policy.clone();
            self.policies.borrow_mut().push(policy.clone());
        }
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

fn strict_policy(w: &World, hash: &str) -> serde_json::Value {
    let r = w.record(hash);
    serde_json::json!({"authorities":{"expert:approval-authority":{
        "expert_id":"expert:approval-authority",
        "public_key_sha256":hex::encode(aip_crypto::sha256(&w.approver.public_key)),
        "tenant":TENANT,"security_domain":DOMAIN,"capability_ids":[r.capability.id],
        "min_version":1,"max_version":2,"max_clearance":"restricted",
        "valid_from_ms":1,"expires_at_ms":u64::MAX,"revoked":false
    }}})
}

fn strict_approve(w: &mut World, hash: &str, policy: &serde_json::Value) {
    let mut r = w.record(hash);
    r.state = State::Validated;
    r.approval = None;
    w.store.put(&r).unwrap();
    let key = w.dir.path().join("ephemeral-key.json");
    aip_crypto::custody::create_owner_only(
        &key,
        &serde_json::to_vec(&serde_json::json!({
            "id":"expert:approval-authority", "public_hex":hex::encode(&w.approver.public_key),
            "private_hex":hex::encode(&w.approver.private_key)
        }))
        .unwrap(),
    )
    .unwrap();
    let result = w.cli_policy(
        "cap-approve",
        &["--hash", hash, "--key", key.to_str().unwrap()],
        Some(policy),
    );
    std::fs::remove_file(key).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(w.record(hash).approval.unwrap().authority_hash.is_some());
}

#[test]
fn strict_cli_approves_activates_then_refuses_revoked_authority_without_mutation() {
    let mut w = World::new();
    let hash = w.approved(TENANT, DOMAIN, 1);
    let policy = strict_policy(&w, &hash);
    strict_approve(&mut w, &hash, &policy);
    let args = [
        "--hash",
        hash.as_str(),
        "--actor",
        "operator",
        "--reason",
        "test",
    ];
    let result = w.cli_policy("cap-activate", &args, Some(&policy));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = w.cli_policy("cap-list", &[], Some(&policy));
    let row: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(row["executable"], true);
    let mut revoked = policy.clone();
    revoked["authorities"]["expert:approval-authority"]["revoked"] = true.into();
    let before = w.snapshot();
    let result = w.cli_policy("cap-list", &[], Some(&revoked));
    let row: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(row["executable"], false);
    for p in [Some(&revoked), None] {
        assert!(!w.cli_policy("cap-activate", &args, p).status.success());
        assert!(!w
            .cli_policy(
                "cap-transition",
                &[
                    "--hash", &hash, "--to", "ACTIVE", "--role", "operator", "--actor", "operator",
                    "--reason", "bypass"
                ],
                p
            )
            .status
            .success());
        assert_eq!(w.snapshot(), before);
    }
}

#[test]
fn strict_cli_rejects_below_floor_rollback_before_suspending_current() {
    let mut w = World::new();
    let old = w.approved(TENANT, DOMAIN, 1);
    let mut policy = strict_policy(&w, &old);
    strict_approve(&mut w, &old, &policy);
    w.seed_active(&old);
    let current = w.approved(TENANT, DOMAIN, 2);
    strict_approve(&mut w, &current, &policy);
    activate(&mut w.store, &current, "operator", true, 4, "upgrade").unwrap();
    policy["authorities"]["expert:approval-authority"]["min_version"] = 2.into();
    let before = w.snapshot();
    let result = w.cli_policy(
        "cap-rollback",
        &["--to", &old, "--actor", "authority", "--reason", "rollback"],
        Some(&policy),
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("version outside"));
    assert_eq!(w.snapshot(), before);
    assert_eq!(w.record(&current).state, State::Active);
}

#[test]
fn strict_cli_rejects_changed_source_and_legacy_approval() {
    let mut w = World::new();
    let hash = w.approved(TENANT, DOMAIN, 1);
    let policy = strict_policy(&w, &hash);
    let args = [
        "--hash",
        hash.as_str(),
        "--actor",
        "operator",
        "--reason",
        "test",
    ];
    let before = w.snapshot();
    let result = w.cli_policy("cap-activate", &args, Some(&policy));
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("legacy approval"));
    assert_eq!(w.snapshot(), before);
    strict_approve(&mut w, &hash, &policy);
    w.corpus
        .ingest(&Document {
            tenant: Ident::new(TENANT).unwrap(),
            doc_id: Ident::new("ep-114").unwrap(),
            classification: Classification::Restricted,
            title: "Changed synthetic source".into(),
            body: "Different limits".into(),
        })
        .unwrap();
    let before = w.snapshot();
    let result = w.cli_policy("cap-activate", &args, Some(&policy));
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("source evidence changed"));
    assert_eq!(w.snapshot(), before);
}

#[test]
fn strict_cli_denies_unauthorized_approval_without_writing_state() {
    let mut w = World::new();
    let hash = w.approved(TENANT, DOMAIN, 1);
    let mut record = w.record(&hash);
    record.state = State::Validated;
    record.approval = None;
    w.store.put(&record).unwrap();
    let policy = strict_policy(&w, &hash);
    let key = w.dir.path().join("ephemeral-key.json");
    aip_crypto::custody::create_owner_only(
        &key,
        &serde_json::to_vec(&serde_json::json!({
            "id":"expert:approval-authority", "public_hex":hex::encode(&w.approver.public_key),
            "private_hex":hex::encode(&w.approver.private_key)
        }))
        .unwrap(),
    )
    .unwrap();
    let before = w.snapshot();
    for attack in ["revoked", "expired", "tenant", "key", "empty"] {
        let mut p = policy.clone();
        let grant = &mut p["authorities"]["expert:approval-authority"];
        match attack {
            "revoked" => grant["revoked"] = true.into(),
            "expired" => grant["expires_at_ms"] = 2.into(),
            "tenant" => grant["tenant"] = "foreign".into(),
            "key" => grant["public_key_sha256"] = "0".repeat(64).into(),
            "empty" => p["authorities"] = serde_json::json!({}),
            _ => unreachable!(),
        }
        let result = w.cli_policy(
            "cap-approve",
            &["--hash", &hash, "--key", key.to_str().unwrap()],
            Some(&p),
        );
        assert!(!result.status.success(), "{attack}");
        assert_eq!(w.snapshot(), before, "{attack}");
    }
    w.corpus
        .ingest(&Document {
            tenant: Ident::new(TENANT).unwrap(),
            doc_id: Ident::new("ep-114").unwrap(),
            classification: Classification::Restricted,
            title: "Changed".into(),
            body: "Changed".into(),
        })
        .unwrap();
    let result = w.cli_policy(
        "cap-approve",
        &["--hash", &hash, "--key", key.to_str().unwrap()],
        Some(&policy),
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("source evidence changed"));
    assert_eq!(w.snapshot(), before);
    std::fs::remove_file(key).unwrap();
}

impl Drop for World {
    fn drop(&mut self) {
        let Some(root) = std::env::var_os("SYNTRIASS_LIFECYCLE_EVIDENCE") else {
            return;
        };
        let retain = || -> Result<(), Box<dyn std::error::Error>> {
            use std::os::unix::fs::PermissionsExt;
            let test = std::thread::current();
            let name = test.name().unwrap_or("unnamed-test");
            let output = std::path::PathBuf::from(root).join(format!(
                "{name}-{}",
                self.dir.path().file_name().unwrap().to_string_lossy()
            ));
            std::fs::create_dir_all(&output)?;
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))?;
            let public = serde_json::json!({
                "experts": {EXPERT:hex::encode(&self.expert.public_key)},
                "approvers": {"expert:approval-authority":hex::encode(&self.approver.public_key)},
                "test":name, "test_panicked":std::thread::panicking(),
                "scope":"synthetic lifecycle tests; not authenticated teaching approval",
            });
            aip_crypto::custody::create_owner_only(
                &output.join("public.json"),
                &serde_json::to_vec_pretty(&public)?,
            )
            .map_err(|e| format!("{e:?}"))?;
            aip_crypto::custody::create_owner_only(
                &output.join("suites.json"),
                &serde_json::to_vec_pretty(&self.suites)?,
            )
            .map_err(|e| format!("{e:?}"))?;
            aip_crypto::custody::create_owner_only(
                &output.join("policies.json"),
                &serde_json::to_vec_pretty(&*self.policies.borrow())?,
            )
            .map_err(|e| format!("{e:?}"))?;
            self.snapshot(); // Retain final bytes even when a test assertion failed.
            for (index, files) in self.snapshots.borrow().iter().enumerate() {
                let dir = output.join(format!("snapshot-{index}"));
                std::fs::create_dir(&dir)?;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
                for (name, bytes) in files {
                    aip_crypto::custody::create_owner_only(&dir.join(name), bytes)
                        .map_err(|e| format!("{e:?}"))?;
                }
            }
            Ok(())
        };
        if let Err(error) = retain() {
            if std::thread::panicking() {
                eprintln!("EVIDENCE RETENTION FAILED: {error}");
            } else {
                panic!("evidence retention failed: {error}");
            }
        }
    }
}

#[test]
fn activation_does_not_require_superseding_another_scope() {
    for (tenant, domain) in FOREIGN {
        let mut w = World::new();
        let foreign = w.approved(tenant, domain, 1);
        w.seed_active(&foreign);
        let target = w.approved(TENANT, DOMAIN, 1);
        let before = w.snapshot();
        assert!(
            activate(&mut w.store, &target, "operator", false, 4, "activate")
                .unwrap()
                .is_empty()
        );
        assert!(w.record(&target).executable());
        w.assert_preserved(&before, &foreign);
    }
}

#[test]
fn direct_transition_does_not_treat_another_scope_as_a_conflict() {
    for (tenant, domain) in FOREIGN {
        let mut w = World::new();
        let foreign = w.approved(tenant, domain, 1);
        w.seed_active(&foreign);
        let target = w.approved(TENANT, DOMAIN, 1);
        let before = w.snapshot();
        transition(
            &mut w.store,
            &target,
            State::Active,
            "operator",
            Role::Operator,
            4,
            "activate",
        )
        .unwrap();
        assert!(w.record(&target).executable());
        w.assert_preserved(&before, &foreign);
    }
}

#[test]
fn supersession_preserves_other_tenants_and_domains_byte_for_byte() {
    for (tenant, domain) in FOREIGN {
        let mut w = World::new();
        let old = w.approved(TENANT, DOMAIN, 1);
        let foreign = w.approved(tenant, domain, 1);
        w.seed_active(&old);
        w.seed_active(&foreign);
        let target = w.approved(TENANT, DOMAIN, 2);
        let before = w.snapshot();
        let displaced = activate(&mut w.store, &target, "operator", true, 4, "upgrade").unwrap();
        assert_eq!(displaced, vec![old.clone()]);
        assert_eq!(w.record(&old).state, State::Superseded);
        assert!(w.record(&target).executable());
        w.assert_preserved(&before, &foreign);
    }
}

#[test]
fn rollback_preserves_other_tenants_and_domains_byte_for_byte() {
    for (tenant, domain) in FOREIGN {
        let mut w = World::new();
        let old = w.approved(TENANT, DOMAIN, 1);
        w.seed_active(&old);
        let current = w.approved(TENANT, DOMAIN, 2);
        activate(&mut w.store, &current, "operator", true, 4, "upgrade").unwrap();
        let foreign = w.approved(tenant, domain, 1);
        w.seed_active(&foreign);
        let before = w.snapshot();
        let displaced = rollback(&mut w.store, &old, "authority", 5, "revert").unwrap();
        assert_eq!(displaced, vec![current.clone()]);
        assert_eq!(w.record(&current).state, State::Suspended);
        assert!(w.record(&old).executable());
        w.assert_preserved(&before, &foreign);
    }
}

#[test]
fn same_scope_conflicts_and_unapproved_targets_remain_refused() {
    let mut w = World::new();
    let old = w.approved(TENANT, DOMAIN, 1);
    w.seed_active(&old);
    let next = w.approved(TENANT, DOMAIN, 2);
    let unapproved = w.propose(TENANT, DOMAIN, 3);
    let before = w.snapshot();
    assert!(activate(&mut w.store, &next, "operator", false, 4, "no supersede").is_err());
    assert!(transition(
        &mut w.store,
        &next,
        State::Active,
        "operator",
        Role::Operator,
        4,
        "no supersede"
    )
    .is_err());
    assert!(activate(
        &mut w.store,
        &unapproved,
        "operator",
        true,
        4,
        "skip approval"
    )
    .is_err());
    assert!(rollback(&mut w.store, &unapproved, "authority", 4, "skip approval").is_err());
    assert_eq!(w.snapshot(), before);
}

#[test]
fn actual_cli_supersession_cannot_displace_another_tenant() {
    let mut w = World::new();
    let foreign = w.approved("other-tenant", DOMAIN, 1);
    w.seed_active(&foreign);
    let target = w.approved(TENANT, DOMAIN, 1);
    let before = w.snapshot();
    let result = w.cli(
        "cap-activate",
        &[
            "--hash",
            &target,
            "--actor",
            "operator",
            "--supersede",
            "--reason",
            "activate",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["superseded"], serde_json::json!([]));
    w.assert_preserved(&before, &foreign);
}

#[test]
fn actual_cli_rollback_cannot_suspend_another_domain() {
    let mut w = World::new();
    let old = w.approved(TENANT, DOMAIN, 1);
    w.seed_active(&old);
    let current = w.approved(TENANT, DOMAIN, 2);
    activate(&mut w.store, &current, "operator", true, 4, "upgrade").unwrap();
    let foreign = w.approved(TENANT, "other-domain", 1);
    w.seed_active(&foreign);
    let before = w.snapshot();
    let result = w.cli(
        "cap-rollback",
        &["--to", &old, "--actor", "authority", "--reason", "revert"],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["suspended"], serde_json::json!([current]));
    w.assert_preserved(&before, &foreign);
}
