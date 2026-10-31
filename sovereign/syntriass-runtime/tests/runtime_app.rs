//! End-to-end orchestration with deterministic fakes for the interpreter and
//! the model, and a real (in-memory) Sovereign corpus with its SQL ACL.

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::Value;
use syntriass_runtime::app::*;
use syntriass_runtime::capability::evidence::{EvidencePolicy, MeasurementRecord, RecordQuantity};
use syntriass_runtime::capability::lifecycle::*;
use syntriass_runtime::capability::validate::validate;
use syntriass_runtime::controller::{Refusal, Strategy, Tier};
use syntriass_runtime::domain::maintenance::Reading;
use syntriass_runtime::domain::scope::CacheScope;
use syntriass_runtime::ports::*;
use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;
use vanian_sovereign::domain::corpus::{Classification, Document, Ident, Principal};
use vanian_sovereign::ports::{ChatMessage, CorpusStore, GenerationParams, PortError};

mod common;
use common::*;

// ── fakes ───────────────────────────────────────────────────────────────

struct FakeInterp;
impl InterpreterPort for FakeInterp {
    fn interpret(&self, text: &str) -> Result<Interpretation, PortError> {
        let r = |k: &str, v: f64| Reading {
            key: k.into(),
            value: v,
        };
        Ok(match text {
            t if t.contains("P-9") => Interpretation {
                rules: vec![],
                interp: vec![r("p7_vib", 9.0)],
                interp_top_prob: 0.99,
                unregistered: vec!["P-9".into()],
                registered_codes: 0,
            },
            t if t.contains("V-12") && t.contains("G-2") => Interpretation {
                rules: vec![],
                interp: vec![r("g2_tank", 72.0)],
                interp_top_prob: 0.6,
                unregistered: vec![],
                registered_codes: 2,
            },
            t if t.contains("P-7 vibration 7.9 mm/s") => Interpretation {
                rules: vec![r("p7_vib", 7.9)],
                interp: vec![],
                interp_top_prob: 0.9,
                unregistered: vec![],
                registered_codes: 1,
            },
            _ => Interpretation {
                rules: vec![],
                interp: vec![],
                interp_top_prob: 0.1,
                unregistered: vec![],
                registered_codes: 0,
            },
        })
    }
    fn slm_request(&self, text: &str) -> Result<SlmRequest, PortError> {
        Ok(SlmRequest {
            messages: vec![ChatMessage {
                role: "user",
                content: format!("Report: {text}"),
            }],
            max_tokens: 120,
            schema: "{}".into(),
        })
    }
    fn slm_parse(&self, raw: &str) -> Result<Option<Vec<Reading>>, PortError> {
        let v: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        Ok(v["readings"].as_array().map(|a| {
            a.iter()
                .map(|p| Reading {
                    key: p[0].as_str().unwrap_or("").into(),
                    value: p[1].as_f64().unwrap_or(f64::NAN),
                })
                .collect()
        }))
    }
}

struct FakeGen {
    sha: String,
    reply: String,
    seen: RefCell<Vec<(String, String)>>, // (scope key, prompt)
}
impl ScopedGenerator for FakeGen {
    fn generate(
        &self,
        scope: &CacheScope,
        m: &[ChatMessage],
        _p: &GenerationParams,
    ) -> Result<(String, GenStats), PortError> {
        self.seen.borrow_mut().push((
            scope.key(),
            m.iter()
                .map(|x| x.content.clone())
                .collect::<Vec<_>>()
                .join("\n"),
        ));
        Ok((
            self.reply.clone(),
            GenStats {
                prompt_tokens: 10,
                completion_tokens: 5,
                ..Default::default()
            },
        ))
    }
    fn model_sha256(&self) -> String {
        self.sha.clone()
    }
}

struct FakeModels(FakeGen);
impl ModelProvider for FakeModels {
    fn configured(&self, t: Tier) -> bool {
        t == Tier::Small
    }
    fn with<'a>(
        &'a self,
        _t: Tier,
        f: &mut dyn FnMut(&dyn ScopedGenerator) -> Result<(), PortError>,
    ) -> Result<f64, PortError> {
        f(&self.0).map(|_| 0.0)
    }
    fn model_sha256(&self, _t: Tier) -> Option<String> {
        Some(self.0.sha.clone())
    }
}

struct MemStore(Vec<Record>);
impl CapabilityStore for MemStore {
    fn all(&self) -> Result<Vec<Record>, PortError> {
        Ok(self.0.clone())
    }
    fn put(&mut self, r: &Record) -> Result<(), PortError> {
        self.0.push(r.clone());
        Ok(())
    }
}

struct NullMeter;
impl Meter for NullMeter {
    fn snapshot(&self) -> Vec<(String, ResourceSnapshot)> {
        vec![]
    }
}

// ── setup ───────────────────────────────────────────────────────────────

fn ingest_file(c: &mut SqliteCorpus, name: &str) -> String {
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

fn principal(t: &str, c: Classification) -> Principal {
    Principal {
        tenant: Ident::new(t).unwrap(),
        clearance: c,
    }
}

struct World {
    corpus: SqliteCorpus,
    store: MemStore,
    approvers: BTreeMap<String, Vec<u8>>,
    instruments: BTreeMap<String, Vec<u8>>,
    audit: tempfile::NamedTempFile,
}

fn world(execution_model: Option<&str>) -> World {
    world_with(execution_model, false)
}

fn world_with(execution_model: Option<&str>, consequential: bool) -> World {
    world_full(execution_model, consequential, EvidencePolicy::Text)
}

fn world_full(
    execution_model: Option<&str>,
    consequential: bool,
    evidence: EvidencePolicy,
) -> World {
    let mut corpus = SqliteCorpus::in_memory().unwrap();
    let h = ingest_file(&mut corpus, "koravi-ep-114.txt");
    ingest_file(&mut corpus, "koravi-ep-090.txt");
    ingest_file(&mut corpus, "tarvel-tg-ir-02.txt");
    let mut cap = expert_fixture();
    cap.dependencies.knowledge.insert("ep-114".into(), h);
    cap.dependencies.execution_model_sha256 = execution_model.map(String::from);
    cap.evidence = evidence;
    let tenant_of =
        |d: &str| matches!(d, "ep-114" | "ep-090").then(|| "koravi-process".to_string());
    let mut rec = Record::propose(cap);
    rec.start_testing("validator", 1).unwrap();
    let (ekp, suite) = expert_suite();
    let rep = validate(&rec.capability, &suite, &ekp.public_key, &tenant_of);
    assert!(rep.passed, "{rep:?}");
    rec.record_validation(rep, "validator", 2).unwrap();
    let kp = aip_crypto::generate_ed25519_keypair();
    let approver = "user:koravi-elec-authority";
    let a = Approval::sign(
        &rec.capability_hash,
        rec.validation.as_ref().unwrap(),
        approver,
        consequential,
        3,
        &kp.private_key,
    )
    .unwrap();
    rec.approve(a, &kp.public_key, 3).unwrap();
    rec.transition(State::Active, "operator", Role::Operator, 4, "go live")
        .unwrap();
    let mut approvers = BTreeMap::new();
    approvers.insert(approver.to_string(), kp.public_key.clone());
    World {
        corpus,
        store: MemStore(vec![rec]),
        approvers,
        instruments: BTreeMap::new(),
        audit: tempfile::NamedTempFile::new().unwrap(),
    }
}

fn cfg(w: &World) -> Config {
    Config {
        policy_version: "ep-114-revC".into(),
        security_domain: "koravi-ot".into(),
        audit_log: w.audit.path().into(),
        rag_k: 3,
        approvers: w.approvers.clone(),
        instruments: w.instruments.clone(),
    }
}

fn models(reply: &str) -> FakeModels {
    FakeModels(FakeGen {
        sha: "model-a".into(),
        reply: reply.into(),
        seen: RefCell::new(vec![]),
    })
}

const IR_TASK: &str = "Motor M-101 rated 6.6 kV: IR 220 megohms at 40 C, PI 2.4. Decision?";

fn label(r: &Response) -> String {
    match &r.outcome {
        Outcome::Decision { label, .. } => label.clone(),
        o => format!("{o:?}"),
    }
}

// ── tests ───────────────────────────────────────────────────────────────

#[test]
fn authorized_principal_gets_the_capability_without_any_model_call() {
    let w = world(None);
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .handle(
            &principal("koravi-process", Classification::Restricted),
            IR_TASK,
        )
        .unwrap();
    assert!(matches!(r.strategy, Strategy::Capability { .. }));
    assert_eq!(label(&r), "PASS");
    assert_eq!((r.cost.model_calls, r.cost.interpreter_calls), (0, 0));
    assert!(m.0.seen.borrow().is_empty());
}

#[test]
fn other_tenant_and_lower_clearance_cannot_see_the_capability() {
    let w = world(None);
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    for p in [
        principal("tarvel-grid", Classification::Restricted),
        principal("koravi-process", Classification::Internal),
    ] {
        let r = rt.handle(&p, IR_TASK).unwrap();
        assert!(!matches!(r.strategy, Strategy::Capability { .. }), "{p:?}");
        assert!(r.capability_hash.is_none());
    }
}

#[test]
fn explicit_invocation_by_an_unauthorized_principal_is_refused() {
    let w = world(None);
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .invoke(
            &principal("tarvel-grid", Classification::Restricted),
            "koravi.ep114.ir-acceptance",
            IR_TASK,
        )
        .unwrap();
    assert!(
        matches!(
            r.outcome,
            Outcome::Refused {
                refusal: Refusal::NotPermitted { .. }
            }
        ),
        "{:?}",
        r.outcome
    );
    let r = rt
        .invoke(
            &principal("koravi-process", Classification::Restricted),
            "koravi.ep114.ir-acceptance",
            IR_TASK,
        )
        .unwrap();
    assert_eq!(label(&r), "PASS");
}

#[test]
fn untrusted_approver_makes_the_capability_invisible() {
    let w = world(None);
    let m = models("{}");
    let mut c = cfg(&w);
    c.approvers.clear();
    let rt = Runtime::new(c, &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .handle(
            &principal("koravi-process", Classification::Restricted),
            IR_TASK,
        )
        .unwrap();
    assert!(!matches!(r.strategy, Strategy::Capability { .. }));
}

#[test]
fn changed_evidence_or_policy_makes_it_stale_and_refused() {
    let mut w = world(None);
    w.corpus
        .ingest(&Document {
            tenant: Ident::new("koravi-process").unwrap(),
            doc_id: Ident::new("ep-114").unwrap(),
            classification: Classification::Restricted,
            title: "EP-114 rev D".into(),
            body: "Revised limits: minimum is 20 times (kV + 1) megohms.".into(),
        })
        .unwrap();
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .handle(
            &principal("koravi-process", Classification::Restricted),
            IR_TASK,
        )
        .unwrap();
    assert!(
        matches!(
            r.strategy,
            Strategy::Refuse(Refusal::CapabilityStale { .. })
        ),
        "{:?}",
        r.strategy
    );
    let w = world(None);
    let mut c = cfg(&w);
    c.policy_version = "ep-114-revD".into();
    let rt = Runtime::new(c, &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .handle(
            &principal("koravi-process", Classification::Restricted),
            IR_TASK,
        )
        .unwrap();
    assert!(matches!(
        r.strategy,
        Strategy::Refuse(Refusal::CapabilityStale { .. })
    ));
}

#[test]
fn model_dependent_capability_needs_revalidation_after_model_change() {
    let w = world(Some("model-old"));
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .handle(
            &principal("koravi-process", Classification::Restricted),
            IR_TASK,
        )
        .unwrap();
    match r.strategy {
        Strategy::Refuse(Refusal::CapabilityStale { reason, .. }) => {
            assert!(reason.contains("model changed"))
        }
        s => panic!("{s:?}"),
    }
}

#[test]
fn maintenance_routes_gate_exact_and_scoped_model_extraction() {
    let w = world(None);
    let m = models(r#"{"readings":[["v12_stroke",13.1],["g2_tank",72.0]]}"#);
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let k = principal("koravi-process", Classification::Restricted);
    let t = principal("tarvel-grid", Classification::Restricted);
    assert!(matches!(
        rt.handle(&k, "Pump P-9 vibration 9.0 mm/s.")
            .unwrap()
            .strategy,
        Strategy::Refuse(Refusal::UnregisteredEquipment(_))
    ));
    let r = rt.handle(&k, "P-7 vibration 7.9 mm/s").unwrap();
    assert_eq!(
        (r.strategy.clone(), label(&r)),
        (Strategy::Exact, "1".to_string())
    );
    let multi = "V-12 stroke 13.1 s; G-2 day tank 72 percent.";
    let r = rt.handle(&k, multi).unwrap();
    assert_eq!(r.strategy, Strategy::ModelExtraction(Tier::Small));
    assert_eq!(
        label(&r),
        "2",
        "most urgent of priority 3 (V-12) and 2 (G-2)"
    );
    rt.handle(&t, multi).unwrap();
    let seen = m.0.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_ne!(
        seen[0].0, seen[1].0,
        "different principals never share a cache scope"
    );
}

#[test]
fn model_output_cannot_escalate_authority_or_change_policy() {
    let w = world(None);
    // The model tries to inject an authorization and an unknown metric.
    let m = models(
        r#"{"readings":[["g2_tank",95.0],["admin_override",1]],"authorize":"REJECT->PASS","grant":"all"}"#,
    );
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .handle(
            &principal("koravi-process", Classification::Restricted),
            "V-12 stroke 13.1 s; G-2 day tank 72 percent.",
        )
        .unwrap();
    assert_eq!(
        label(&r),
        "ABSTAIN",
        "unknown metric from the model fails closed"
    );
    assert_eq!(
        w.store.0.len(),
        1,
        "no capability created or changed by a model"
    );
    assert!(w.store.0[0].history.iter().all(|t| t.actor != "model"));
}

#[test]
fn grounded_qa_sees_only_the_callers_documents() {
    let w = world(None);
    let m = models(r#"{"insufficient":true,"answer":"","citations":[]}"#);
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    rt.handle(
        &principal("tarvel-grid", Classification::Restricted),
        "What is the minimum insulation resistance for motors?",
    )
    .unwrap();
    let seen = m.0.seen.borrow();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].1.contains("TG-IR-02") || seen[0].1.contains("100 megohms"));
    assert!(
        !seen[0].1.contains("Koravi") && !seen[0].1.contains("EP-114"),
        "no cross-tenant text in the prompt"
    );
}

#[test]
fn question_without_authorized_source_never_calls_the_model() {
    let w = world(None);
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .handle(
            &principal("nobody-inc", Classification::Restricted),
            "What is the minimum insulation resistance?",
        )
        .unwrap();
    assert!(matches!(r.outcome, Outcome::Withheld { .. }));
    assert!(m.0.seen.borrow().is_empty());
}

#[test]
fn audit_chain_verifies_and_detects_tampering() {
    let w = world(None);
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let k = principal("koravi-process", Classification::Restricted);
    for _ in 0..3 {
        rt.handle(&k, IR_TASK).unwrap();
    }
    assert_eq!(verify_audit_chain(w.audit.path()), Ok(3));
    let log = std::fs::read_to_string(w.audit.path()).unwrap();
    assert!(
        !log.contains("220 megohms"),
        "request text is stored only as a hash"
    );
    assert!(log.contains("CannotProve"));
    std::fs::write(w.audit.path(), log.replacen("PASS", "REJECT", 1)).unwrap();
    assert!(verify_audit_chain(w.audit.path()).is_err());
}

#[test]
fn consequential_capabilities_are_disabled_until_aip_action_authorization_exists() {
    let w = world_with(None, true);
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let p = principal("koravi-process", Classification::Restricted);
    let r = rt.handle(&p, IR_TASK).unwrap();
    assert!(
        !matches!(r.strategy, Strategy::Capability { .. }),
        "a consequential capability must not run without AIP action authorization"
    );
    let id = w.store.0[0].capability.id.clone();
    let r = rt.invoke(&p, &id, IR_TASK).unwrap();
    match r.strategy {
        Strategy::Refuse(Refusal::NotPermitted { reason, .. }) => {
            assert!(reason.contains("consequential"))
        }
        other => panic!("expected NotPermitted, got {other:?}"),
    }
}

// ── phase 2: bounded small → large escalation ─────────────────────────────

struct TwoTier {
    small: FakeGen,
    large: FakeGen,
}
impl ModelProvider for TwoTier {
    fn configured(&self, _t: Tier) -> bool {
        true
    }
    fn with<'a>(
        &'a self,
        t: Tier,
        f: &mut dyn FnMut(&dyn ScopedGenerator) -> Result<(), PortError>,
    ) -> Result<f64, PortError> {
        match t {
            Tier::Small => f(&self.small).map(|_| 0.0),
            Tier::Large => f(&self.large).map(|_| 25.0), // simulated on-demand load
        }
    }
    fn model_sha256(&self, t: Tier) -> Option<String> {
        Some(match t {
            Tier::Small => self.small.sha.clone(),
            Tier::Large => self.large.sha.clone(),
        })
    }
}

fn gen(sha: &str, reply: &str) -> FakeGen {
    FakeGen {
        sha: sha.into(),
        reply: reply.into(),
        seen: RefCell::new(vec![]),
    }
}

#[test]
fn unparseable_small_output_escalates_once_and_charges_both_attempts() {
    let w = world(None);
    let m = TwoTier {
        small: gen("small-sha", "not json"),
        large: gen(
            "large-sha",
            r#"{"readings":[["v12_stroke",13.1],["g2_tank",72.0]]}"#,
        ),
    };
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let k = principal("koravi-process", Classification::Restricted);
    let r = rt
        .handle(&k, "V-12 stroke 13.1 s; G-2 day tank 72 percent.")
        .unwrap();
    assert_eq!(r.strategy, Strategy::ModelExtraction(Tier::Large));
    assert_eq!(label(&r), "2");
    assert_eq!(r.cost.escalations, 1);
    assert_eq!(r.cost.model_calls, 2, "the failed small attempt is charged");
    assert_eq!(
        r.cost.model_load_ms, 25.0,
        "the large model's load is charged"
    );
    let (s, l) = (m.small.seen.borrow(), m.large.seen.borrow());
    assert_eq!((s.len(), l.len()), (1, 1));
    assert_ne!(s[0].0, l[0].0, "each model has its own cache scope");
}

#[test]
fn both_tiers_failing_is_withheld_after_exactly_two_attempts() {
    let w = world(None);
    let m = TwoTier {
        small: gen("small-sha", "not json"),
        large: gen("large-sha", "still not json"),
    };
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let k = principal("koravi-process", Classification::Restricted);
    let r = rt
        .handle(&k, "V-12 stroke 13.1 s; G-2 day tank 72 percent.")
        .unwrap();
    assert!(matches!(r.outcome, Outcome::Withheld { .. }));
    assert_eq!((r.cost.model_calls, r.cost.escalations), (2, 1));
}

#[test]
fn no_authorized_source_is_not_escalated_and_capabilities_need_no_model() {
    let w = world(None);
    let m = TwoTier {
        small: gen("small-sha", "{}"),
        large: gen("large-sha", "{}"),
    };
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let r = rt
        .handle(
            &principal("nobody-inc", Classification::Restricted),
            "What is the minimum insulation resistance?",
        )
        .unwrap();
    assert!(matches!(r.outcome, Outcome::Withheld { .. }));
    assert_eq!(r.cost.escalations, 0);
    let r = rt
        .handle(
            &principal("koravi-process", Classification::Restricted),
            IR_TASK,
        )
        .unwrap();
    assert!(matches!(r.strategy, Strategy::Capability { .. }));
    assert_eq!(r.cost.model_calls, 0);
    assert!(m.small.seen.borrow().is_empty() && m.large.seen.borrow().is_empty());
}

// ── S1: evidence-bound execution ──────────────────────────────────────────

fn record(
    tenant: &str,
    instrument: &str,
    kv: &str,
    mohm: &str,
    temp: &str,
    pi: f64,
) -> MeasurementRecord {
    MeasurementRecord {
        record_id: "rec-1".into(),
        tenant: tenant.into(),
        asset_id: "M-101".into(),
        instrument_id: instrument.into(),
        taken_at_ms: 1,
        quantities: vec![
            RecordQuantity::Physical { reading: kv.into() },
            RecordQuantity::Physical {
                reading: mohm.into(),
            },
            RecordQuantity::Physical {
                reading: temp.into(),
            },
            RecordQuantity::Cued {
                cue: "PI".into(),
                value: pi,
            },
        ],
        signature_hex: String::new(),
    }
}

fn signed_world() -> (World, aip_types::KeyPair) {
    let mut w = world_full(None, false, EvidencePolicy::SignedRecord);
    let kp = aip_crypto::generate_ed25519_keypair();
    w.instruments
        .insert("megger:MIT-1025-7".into(), kp.public_key.clone());
    (w, kp)
}

#[test]
fn hypothetical_text_cannot_release_without_a_signed_record() {
    let (w, _) = signed_world();
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let k = principal("koravi-process", Classification::Restricted);
    for t in [
        IR_TASK,
        &format!("If we were to test it, we might expect: {IR_TASK}") as &str,
    ] {
        let r = rt.handle(&k, t).unwrap();
        assert!(
            matches!(r.strategy, Strategy::Capability { .. }),
            "the capability is selected by text"
        );
        assert!(
            matches!(&r.outcome, Outcome::Withheld { reason } if reason.contains("signed measurement record")),
            "{:?}",
            r.outcome
        );
        assert_eq!(r.cost.model_calls, 0);
    }
}

#[test]
fn a_verified_record_decides_and_text_numbers_are_ignored() {
    let (w, kp) = signed_world();
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let k = principal("koravi-process", Classification::Restricted);
    // Text claims a passing reading; the signed record says 9 MΩ (REJECT territory for 6.6 kV).
    let rec = record(
        "koravi-process",
        "megger:MIT-1025-7",
        "6.6 kV",
        "9 MΩ",
        "40 °C",
        2.4,
    )
    .sign(&kp.private_key)
    .unwrap();
    let r = rt.handle_with_record(&k, IR_TASK, Some(&rec)).unwrap();
    assert_eq!(
        label(&r),
        "REJECT",
        "numbers come from the record, not the text"
    );
    let good = record(
        "koravi-process",
        "megger:MIT-1025-7",
        "6.6 kV",
        "220 MΩ",
        "40 °C",
        2.4,
    )
    .sign(&kp.private_key)
    .unwrap();
    assert_eq!(
        label(&rt.handle_with_record(&k, IR_TASK, Some(&good)).unwrap()),
        "PASS"
    );
}

#[test]
fn forged_foreign_or_unregistered_records_are_rejected() {
    let (w, kp) = signed_world();
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let k = principal("koravi-process", Classification::Restricted);
    let good = record(
        "koravi-process",
        "megger:MIT-1025-7",
        "6.6 kV",
        "220 MΩ",
        "40 °C",
        2.4,
    )
    .sign(&kp.private_key)
    .unwrap();
    let mut tampered = good.clone();
    tampered.quantities[1] = RecordQuantity::Physical {
        reading: "2200 MΩ".into(),
    };
    let other_key = aip_crypto::generate_ed25519_keypair();
    let unregistered = record(
        "koravi-process",
        "megger:unknown",
        "6.6 kV",
        "220 MΩ",
        "40 °C",
        2.4,
    )
    .sign(&other_key.private_key)
    .unwrap();
    let foreign = record(
        "tarvel-grid",
        "megger:MIT-1025-7",
        "6.6 kV",
        "220 MΩ",
        "40 °C",
        2.4,
    )
    .sign(&kp.private_key)
    .unwrap();
    let wrong_signer = record(
        "koravi-process",
        "megger:MIT-1025-7",
        "6.6 kV",
        "220 MΩ",
        "40 °C",
        2.4,
    )
    .sign(&other_key.private_key)
    .unwrap();
    for (rec, why) in [
        (tampered, "BadSignature"),
        (unregistered, "UnknownInstrument"),
        (foreign, "WrongTenant"),
        (wrong_signer, "BadSignature"),
    ] {
        let r = rt.handle_with_record(&k, IR_TASK, Some(&rec)).unwrap();
        assert!(
            matches!(&r.outcome, Outcome::Withheld { reason } if reason.contains(why)),
            "{why}: {:?}",
            r.outcome
        );
    }
}

#[test]
fn conflicting_values_in_a_record_are_withheld_not_averaged() {
    let (w, kp) = signed_world();
    let m = models("{}");
    let rt = Runtime::new(cfg(&w), &w.corpus, &FakeInterp, &m, &w.store, &NullMeter);
    let k = principal("koravi-process", Classification::Restricted);
    let mut rec = record(
        "koravi-process",
        "megger:MIT-1025-7",
        "6.6 kV",
        "220 MΩ",
        "40 °C",
        2.4,
    );
    rec.quantities.push(RecordQuantity::Physical {
        reading: "150 MΩ".into(),
    });
    let rec = rec.sign(&kp.private_key).unwrap();
    let r = rt.handle_with_record(&k, IR_TASK, Some(&rec)).unwrap();
    assert!(
        matches!(r.outcome, Outcome::Withheld { .. }),
        "{:?}",
        r.outcome
    );
}
