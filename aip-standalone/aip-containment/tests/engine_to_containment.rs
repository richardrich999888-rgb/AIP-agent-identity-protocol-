//! B-3 — the real reconciler, through warrant evaluation, to the containment
//! boundary.
//!
//! # The finding
//!
//! Every existing test of the warrant and containment layers builds its
//! `Reconciliation` with `Reconciliation::fixture_default()` and assigns the
//! verdict it wants. That is legitimate for pinning the gates — it is the only
//! way to sweep verdicts — but it means the chain had never been driven by
//! `reconcile_expectation` itself. A gate can be perfectly implemented against
//! inputs the engine never produces.
//!
//! These tests close that: every `Reconciliation` below comes out of the
//! engine, from a decision point that really authorized the execution and an
//! observer that really attested the evidence. Nothing is assigned.
//!
//! # What that turns up, and why nothing here is "fixed"
//!
//! Actuation is unreachable from genuine reconciliation, today. Two gates in
//! `contain()` must both pass:
//!
//!   gate 5  `EvidenceStrength::Proven`
//!   gate 6  a *workload* violation — `UnattributedEffect`, `PhantomClaim`,
//!           `IdentityDivergence` or `LineageViolation`; `SensorIntegrityFailure`
//!           is named and refused
//!
//! The engine reaches `Proven` for exactly one result class,
//! `SensorIntegrityFailure` — a fact a third party recomputes from held bytes:
//! a signature that does not verify, a hash chain that does not link. Every
//! workload-violation class is capped at `Attested`, because the content
//! behind them is read from the observed host and is root-forgeable.
//!
//! So gates 5 and 6 are jointly unsatisfiable from engine output.
//!
//! A third closure sits behind those two, and it is the tightest of the
//! three. A `SensorIntegrityFailure` means the observer's evidence could not
//! be trusted, so the record it produces necessarily carries
//! `ObservationAvailability::Unavailable`. That caps the warrant at `Alert`
//! in `evaluate` step 4 — absence never escalates — and independently trips
//! `contain()` gate 7. The one verdict strong enough to clear the strength
//! gate is, by its own nature, a verdict about missing observation.
//!
//! (Predicted `Constrain` for that case when writing these tests; the engine
//! returned `Alert`. The assertion below records what the engine does, and
//! the reason is noted above rather than the assertion being loosened.)
//!
//! The tests record all of this as the refusal it is. They do **not**
//! manufacture a `Proven` `PhantomClaim` to make the actuator fire — that
//! verdict does not exist outside a fixture, and a test that invented one
//! would be asserting a capability the system does not have.
//!
//! This is a fail-closed system observed fully closed on its most dangerous
//! path. Whether that is the intended end state is an architectural question,
//! recorded for the Skill 16 gate rather than answered here.

#![cfg(target_os = "linux")]

use std::process::{Child, Command};

use aip_authorize::*;
use aip_containment::*;
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_core::execution_binding::collect_binding_for_pid;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_reconcile::{
    reconcile_expectation, EvidenceStrength, ExpectedSideCoverage, ObserverEvidence,
    Reconciliation, ReconciliationContext, ReconciliationResult,
};
use aip_types::{
    Action, CapabilityScope, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple,
    ScopeAction, EXECUTION_BINDING_VERSION,
};
use aip_warrant::{
    evaluate, Finding, ResponseClass, ResponseTarget, Severity, Warrant, WarrantAuthority,
    WarrantPolicy, WarrantTrustAnchors,
};

const PID: u32 = 3_900_301;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-e2e";
const PROBE_ID: &str = "probe-e2e";
const WARRANT_AUTHORITY: &str = "warrant-authority";
const CONTAINMENT_AUTHORITY: &str = "containment-authority";
const NET_CONNECT: &str = "ghost.net.connect.v1";
const REMOTE_ADDR: [u8; 4] = [10, 0, 0, 5];
const REMOTE_PORT: u16 = 443;
const ESTABLISHED: u8 = 0x01;

// ═══ The expected side — a real decision point ═══════════════════════════════
//
// Modelled on aip-reconcile/tests/action_evidence.rs, which is the reference
// for what an honest expectation looks like. Reproduced rather than shared
// because making it shared would mean putting fixture machinery on a
// published crate surface.

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn net_connect_action() -> ScopeAction {
    ScopeAction::Custom(NET_CONNECT.into())
}

fn net_connect_params() -> ActionParameters {
    ActionParameters::from_pairs([
        ("protocol", b"tcp".to_vec()),
        ("remote_addr", REMOTE_ADDR.to_vec()),
        ("remote_port", REMOTE_PORT.to_be_bytes().to_vec()),
    ])
    .unwrap()
}

fn net_scope() -> CapabilityScope {
    CapabilityScope {
        allowed: vec![net_connect_action(), ScopeAction::Standard(Action::Write)],
        denied: vec![],
    }
}

struct Expected {
    ee: ExpectedExecution,
    anchors: DecisionPointTrustAnchors,
    agent_id: String,
    agent_kp: KeyPair,
    now: u64,
}

fn fixture_binding(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: PID,
            pid_start_time_ticks: 777_000,
            boot_id: [0x3d; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v3"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

/// A genuine authorization: CFO → orchestrator → agent, the chain verified by
/// a real `DecisionPoint`, which is what mints the `ExpectedExecution`. A
/// panic here means the fixture stopped being honest, not that a test failed.
fn expected() -> Expected {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("payments-agent"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        net_scope(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(&root, &orch_kp.private_key, &agent_aid.id, net_scope()).unwrap();
    let now = root.issued_at.max(hop.issued_at) + 1;

    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    let req = AuthorizationRequest {
        agent_id: agent_aid.id.clone(),
        root_token: root,
        delegation_chain: vec![hop],
        action_kind: net_connect_action(),
        parameters: net_connect_params(),
        execution_binding: fixture_binding(&agent_aid.id),
        requested_ttl_ms: TTL,
    };
    let ee = match dp.authorize_at(&req, now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("the fixture must authorize; got {d:?}"),
    };
    Expected {
        ee,
        anchors,
        agent_id: agent_aid.id,
        agent_kp,
        now,
    }
}

// ═══ The observed side — a real collector ════════════════════════════════════

struct Observer {
    signer: CollectorSigner,
    probe: ProcfsProbe,
    anchors: ObserverTrustAnchors,
}

impl Observer {
    fn new() -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
        let mut probe = ProcfsProbe::new(PROBE_ID);
        probe.declare_source(SourceMechanism::ProcConnector);
        probe.declare_source(SourceMechanism::ProcNetTable);
        // The keypair itself is not kept: the anchors are what a verifier
        // needs, and holding the private key past this point would be an
        // invitation to re-sign something in a later edit.
        let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
        Self {
            signer,
            probe,
            anchors,
        }
    }

    fn batch(&mut self, id: u8, from: u64, to: u64, obs: Vec<ObservedExecution>) -> AttestedBatch {
        self.signer
            .attest(self.probe.batch([id; 16], from, to, obs))
            .unwrap()
    }

    fn health(&self, at: u64) -> SignedSensorHealth {
        self.signer.health(at).unwrap()
    }
}

fn process_of(ee: &ExpectedExecution) -> ObservedProcess {
    ObservedProcess {
        process: ee.execution_binding.process,
        exe_content_sha256: ee.execution_binding.exe_content_sha256,
        exe_path: ee.execution_binding.exe_path.clone(),
    }
}

fn endpoint(addr: [u8; 4], port: u16) -> SocketEndpoint {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&addr);
    SocketEndpoint {
        addr: a,
        is_v6: false,
        port,
    }
}

fn established() -> ObservedEffect {
    ObservedEffect::SocketObserved {
        protocol: SocketProtocol::Tcp,
        local: endpoint([127, 0, 0, 1], 51_000),
        remote: endpoint(REMOTE_ADDR, REMOTE_PORT),
        state: ESTABLISHED,
        inode: 90_210,
    }
}

fn claim(x: &Expected) -> AgentClaim {
    AgentClaim {
        agent_id: x.agent_id.clone(),
        claim_source: "orchestrator".into(),
        decision_id: Some(x.ee.decision_id),
    }
}

fn rctx(x: &Expected, o: &Observer, at: u64) -> ReconciliationContext {
    ReconciliationContext {
        decision_point_anchors: x.anchors.clone(),
        observer_anchors: o.anchors.clone(),
        verification_time_ms: at,
        health_max_age_ms: HEALTH_MAX_AGE,
        window_tolerance_ms: 0,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: Some(x.agent_kp.public_key.clone()),
    }
}

/// The honest evidence set: an epoch batch, then a batch inside the window
/// carrying the observed connection, then health.
fn honest_evidence(x: &Expected, o: &mut Observer) -> (ObserverEvidence, u64) {
    let now = x.now;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let c = claim(x);
    let obs = o.probe.observation_with(
        process_of(&x.ee),
        established(),
        SourceMechanism::ProcNetTable,
        Some(&c),
        now + 3_000,
    );
    let b2 = o.batch(2, now + 2_000, now + 4_000, vec![obs]);
    let at = now + 5_000;
    (
        ObserverEvidence {
            batches: vec![b1, b2],
            health: o.health(at),
        },
        at,
    )
}

// ═══ Verdicts, drawn by the engine ═══════════════════════════════════════════

/// Complete honest evidence → `VerifiedExecution` at `Attested`.
fn engine_verified_execution() -> (Reconciliation, String) {
    let x = expected();
    let mut o = Observer::new();
    let (ev, at) = honest_evidence(&x, &mut o);
    let r = reconcile_expectation(&x.ee, Some(&ev), &rctx(&x, &o, at));
    assert_eq!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "the honest scenario must verify, or this file is measuring nothing: {r:?}"
    );
    (r, x.agent_id)
}

/// The same evidence with one signed batch altered after attestation →
/// `SensorIntegrityFailure` at `Proven`. This is the only `Proven` verdict the
/// engine draws, and the reason is structural: a signature that does not
/// verify is recomputable from the bytes in hand, which is what `Proven`
/// means.
fn engine_sensor_integrity_failure() -> (Reconciliation, String) {
    let x = expected();
    let mut o = Observer::new();
    let (ev, at) = honest_evidence(&x, &mut o);
    let mut tampered = ev.clone();
    tampered.batches[1].batch.claimed_to_ms += 1;
    let r = reconcile_expectation(&x.ee, Some(&tampered), &rctx(&x, &o, at));
    assert_eq!(
        r.result,
        ReconciliationResult::SensorIntegrityFailure,
        "{r:?}"
    );
    assert_eq!(r.strength, EvidenceStrength::Proven, "{r:?}");
    (r, x.agent_id)
}

// ═══ The warrant layer, on engine output ═════════════════════════════════════

struct Keys {
    warrant: KeyPair,
    containment: KeyPair,
}

fn keys() -> Keys {
    Keys {
        warrant: generate_ed25519_keypair(),
        containment: generate_ed25519_keypair(),
    }
}

/// The most permissive policy an operator can set: autonomous containment on,
/// every result class Critical, constrain-on-attested allowed. If the chain
/// stops short even here, it is the structure stopping it, not configuration.
fn maximal_policy() -> WarrantPolicy {
    WarrantPolicy {
        autonomous_containment: true,
        allow_constrain_on_attested: true,
        ..WarrantPolicy::default()
    }
    .with_severity(ReconciliationResult::VerifiedExecution, Severity::Critical)
    .with_severity(ReconciliationResult::CannotProve, Severity::Critical)
    .with_severity(ReconciliationResult::PhantomClaim, Severity::Critical)
    .with_severity(ReconciliationResult::UnattributedEffect, Severity::Critical)
    .with_severity(ReconciliationResult::IdentityDivergence, Severity::Critical)
    .with_severity(ReconciliationResult::LineageViolation, Severity::Critical)
    .with_severity(ReconciliationResult::ContinuityFailure, Severity::Critical)
    .with_severity(
        ReconciliationResult::SensorIntegrityFailure,
        Severity::Critical,
    )
}

fn signed_warrant(k: &Keys, rec: Reconciliation, subject: &str, now: u64) -> Warrant {
    let digest = rec.digest();
    let f = Finding {
        finding_id: [0xe2; 16],
        reconciliation: rec,
        subject_agent: Some(subject.to_string()),
    };
    let w = evaluate(&f, &maximal_policy(), now).expect("engine output must yield a warrant");
    assert_eq!(
        w.reconciliation_digest, digest,
        "the warrant must be bound to the record it rests on"
    );
    WarrantAuthority::new(
        WARRANT_AUTHORITY,
        &k.warrant.private_key,
        &k.warrant.public_key,
    )
    .unwrap()
    .sign(w)
    .unwrap()
}

// ═══ The containment boundary ════════════════════════════════════════════════

/// A recording double. It never touches a process; `applied` is what it was
/// asked to do — and in this file, what it must never be asked to do.
#[derive(Default)]
struct Recorder {
    applied: Vec<(u32, ContainmentAction)>,
    released: Vec<String>,
}

impl Actuator for Recorder {
    fn mechanism(&self) -> Mechanism {
        Mechanism::TestDouble
    }
    fn apply(
        &mut self,
        target: &Attributed,
        action: ContainmentAction,
    ) -> Result<Applied, ActuationFailure> {
        self.applied.push((target.process().pid, action));
        Ok(Applied {
            mechanism: Mechanism::TestDouble,
            handle: format!("double:{}", target.process().pid),
        })
    }
    fn release(&mut self, applied: &Applied) -> Result<(), ActuationFailure> {
        self.released.push(applied.handle.clone());
        Ok(())
    }
}

/// A live process to point the containment request at, so the attribution
/// step is real rather than stubbed.
struct Target {
    child: Child,
    binding: ExecutionBinding,
}

impl Target {
    fn spawn(agent_id: &str) -> Self {
        let child = Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep");
        std::thread::sleep(std::time::Duration::from_millis(30));
        let binding = collect_binding_for_pid(agent_id, child.id()).unwrap();
        Self { child, binding }
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Drive one engine-produced verdict all the way to the containment boundary
/// and return what happened there, plus whether the actuator was touched.
fn drive(rec: Reconciliation, subject: &str) -> (ResponseClass, ResponseTarget, Outcome, bool) {
    let k = keys();
    let now = rec.verification_time_ms + 1_000;
    let warrant = signed_warrant(&k, rec, subject, now);
    let response = warrant.response;
    let target_kind = warrant.target;

    let t = Target::spawn(subject);
    let mut actuator = Recorder::default();
    let mut ledger = MemoryReplayLedger::default();
    let anchors = ContainmentAnchors {
        warrant: WarrantTrustAnchors::new().trust(WARRANT_AUTHORITY, &k.warrant.public_key),
        observer: ObserverTrustAnchors::new(),
    };
    let authority = ContainmentAuthority::new(
        CONTAINMENT_AUTHORITY,
        &k.containment.private_key,
        &k.containment.public_key,
    )
    .unwrap();
    let policy = ContainmentPolicy {
        mode: ContainmentMode::AutonomousEnabled,
        action: ContainmentAction::FreezeProcess,
        max_health_age_ms: HEALTH_MAX_AGE,
        ..ContainmentPolicy::default()
    };
    let req = ContainmentRequest {
        warrant: &warrant,
        target: &t.binding,
        observer_health: None,
        operator_ack: None,
    };
    let c = contain(
        &req,
        &policy,
        &anchors,
        &mut ledger,
        &mut actuator,
        &authority,
        now,
    )
    .expect("the record must sign");

    let touched = !actuator.applied.is_empty();
    (
        response,
        target_kind,
        c.record.record.outcome.clone(),
        touched,
    )
}

fn refusal(outcome: &Outcome) -> &Refusal {
    match outcome {
        Outcome::Refused(r) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ═══ The crossings ═══════════════════════════════════════════════════════════

#[test]
fn a_verified_execution_crosses_the_chain_and_warrants_only_observation() {
    // The clean case, end to end on engine output: a real authorization, a
    // real attested observation, the engine's own verdict, a real signed
    // warrant, a real containment decision. Nothing is asserted into being.
    let (rec, subject) = engine_verified_execution();
    assert_eq!(rec.strength, EvidenceStrength::Attested);

    let (response, target, outcome, touched) = drive(rec, &subject);
    assert_eq!(
        response,
        ResponseClass::Observe,
        "a verified execution is not a violation; the maximal policy must not \
         raise it"
    );
    assert_eq!(target, ResponseTarget::Workload);
    assert!(!touched, "the actuator must never be reached");
    assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
}

#[test]
fn the_only_proven_verdict_the_engine_draws_stops_at_the_containment_gate() {
    // The most severe verdict genuinely obtainable: SensorIntegrityFailure at
    // Proven. It clears the strength gate — and is refused by the result
    // gate, because it is an accusation about the *observer*, not about the
    // workload, and containment freezes workloads.
    let (rec, subject) = engine_sensor_integrity_failure();
    let rec_availability = rec.availability.clone();
    let (response, target, outcome, touched) = drive(rec, &subject);

    assert_eq!(
        target,
        ResponseTarget::Observer,
        "an integrity failure is about the sensor, not the agent"
    );
    // Proven raises the strength cap to Contain and the result class caps it
    // at Constrain — but the record carries `Unavailable`, because the
    // evidence that failed integrity is the evidence that would have provided
    // coverage. Step 4 of `evaluate` lowers it to Alert on that basis:
    // absence never escalates.
    assert!(
        matches!(
            rec_availability,
            aip_observe::ObservationAvailability::Unavailable { .. }
        ),
        "an integrity failure must not report coverage from the evidence that \
         failed: {rec_availability:?}"
    );
    assert_eq!(
        response,
        ResponseClass::Alert,
        "unavailable observation caps the response at Alert"
    );

    // At the containment boundary it is refused at gate 3 — the response
    // class — because the warrant says Alert. Gates 4, 5 and 6 would each
    // have refused it too (Observer target, and a result class the workload
    // gate names and rejects); gate 3 is simply the first. Asserting the
    // observed refusal rather than the one furthest down keeps this test
    // pinned to behaviour instead of to a gate ordering that may change.
    assert!(
        matches!(refusal(&outcome), Refusal::ResponseNotContain(_)),
        "got {:?}",
        refusal(&outcome)
    );
    assert!(!touched, "the actuator must never be reached");
}

#[test]
fn no_verdict_the_engine_draws_reaches_actuation() {
    // The B-3 finding, stated as a test rather than as prose.
    //
    // `contain()` requires Proven *and* a workload-violation class. The engine
    // pairs Proven with exactly one class — SensorIntegrityFailure — which the
    // result gate names and refuses. Every workload-violation class the engine
    // can reach is capped at Attested, which the strength gate refuses.
    //
    // The two gates are jointly unsatisfiable from engine output. This test
    // records that; it does not fabricate a Proven PhantomClaim to open the
    // path, because no such verdict exists outside a fixture.
    for (rec, subject) in [
        engine_verified_execution(),
        engine_sensor_integrity_failure(),
    ] {
        let described = format!("{:?}/{:?}", rec.result, rec.strength);
        let (_, _, outcome, touched) = drive(rec, &subject);
        assert!(
            !touched,
            "SECURITY (B-3): {described} reached the actuator. If this is now \
             intended, the change must be deliberate and reviewed — it is the \
             one path in this system that stops a running process."
        );
        assert!(
            matches!(outcome, Outcome::Refused(_)),
            "{described} produced {outcome:?} rather than a refusal"
        );
    }
}

#[test]
fn the_warrant_is_bound_to_the_record_the_engine_produced() {
    // The chain is only a chain if each link cites the previous one. A warrant
    // whose digest did not match its record would let a verdict be swapped
    // after evaluation.
    let (rec, subject) = engine_sensor_integrity_failure();
    let digest = rec.digest();
    let evidence = rec.evidence.clone();
    let k = keys();
    let now = rec.verification_time_ms + 1_000;
    let w = signed_warrant(&k, rec, &subject, now);

    assert_eq!(w.reconciliation_digest, digest);
    assert_eq!(
        w.evidence_refs, evidence,
        "the warrant must carry the record's citations verbatim"
    );
    assert_eq!(w.subject_agent.as_deref(), Some(subject.as_str()));
}

#[test]
fn a_reconciliation_that_travelled_as_bytes_is_refused_by_the_warrant_layer() {
    // B-9's seal, checked against a record the engine really produced rather
    // than a fixture: serialising and parsing an engine verdict strips its
    // provenance, and the warrant layer refuses it. Without this, an attacker
    // who can write JSON can write verdicts.
    let (rec, subject) = engine_sensor_integrity_failure();
    let round_tripped: Reconciliation =
        serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
    assert_eq!(
        round_tripped, rec,
        "the round trip must be faithful, or this tests the wrong thing"
    );

    let f = Finding {
        finding_id: [0xe3; 16],
        reconciliation: round_tripped,
        subject_agent: Some(subject),
    };
    assert_eq!(
        evaluate(&f, &maximal_policy(), rec.verification_time_ms + 1_000),
        Err(aip_warrant::Refusal::ReconciliationNotEngineProduced),
        "SECURITY: a deserialised verdict was accepted as engine output"
    );
}
