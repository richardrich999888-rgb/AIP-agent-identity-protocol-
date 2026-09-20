//! Adversarial tests for Ghost Stage 4 reconciliation (Skill 7 §28, cases
//! 1–22, plus the boundary cases the PR3 gap review demanded).
//!
//! Every test constructs *real* signed inputs: `ExpectedExecution` from a
//! real `DecisionPoint`, `AttestedBatch`/`SignedSensorHealth` from a real
//! `CollectorSigner`. Forgeries are made by mutating those bytes and, where a
//! forger would hold the key, by re-signing with it. No test asserts that an
//! execution happened, and no test may ever produce `VerifiedExecution`.

use aip_authorize::*;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_observe::*;
use aip_reconcile::*;
use aip_types::{
    Action, AlgorithmId, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple, ScopeAction,
    Signature, EXECUTION_BINDING_VERSION,
};

// A pid that will not exist on the test host, so a kernel event about it can
// never be accidentally anchored to a real process by `ProcfsProbe`.
const PID: u32 = 3_900_001;
const OTHER_PID: u32 = 3_900_777;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-a";
const PROBE_ID: &str = "probe-a";

// ─── Expected side (Skill 5 fixture) ───

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn binding_for(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: PID,
            pid_start_time_ticks: 433_843,
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v1"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

struct Expected {
    ee: ExpectedExecution,
    anchors: DecisionPointTrustAnchors,
    dp_id: String,
    dp_kp: KeyPair,
    agent_id: String,
    /// `ee.issued_at`; the window is `[now, now + TTL]`.
    now: u64,
}

fn expected() -> Expected {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, _agent_kp) = create_identity(provenance("payments-agent"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(
        &root,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .unwrap();
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
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: ActionParameters::from_pairs([
            ("invoice", b"INV-2026-0142".to_vec()),
            ("amount_cents", b"4820000".to_vec()),
        ])
        .unwrap(),
        execution_binding: binding_for(&agent_aid.id),
        requested_ttl_ms: TTL,
    };
    let ee = match dp.authorize_at(&req, now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("fixture must authorize, got {d:?}"),
    };
    assert_eq!(ee.valid_until, now + TTL);
    Expected {
        ee,
        anchors,
        dp_id,
        dp_kp,
        agent_id: agent_aid.id,
        now,
    }
}

fn placeholder(signer_id: &str) -> Signature {
    Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: signer_id.to_string(),
        timestamp: 0,
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: Vec::new(),
    }
}

/// A decision point's expected-side completeness statement, signed with the
/// real decision-point key. Nothing in `aip-authorize` produces these yet;
/// the test plays the producer to exercise the verifier's contract.
fn coverage_statement(
    x: &Expected,
    agent_id: &str,
    window: CoverageWindow,
    decision_ids: Vec<[u8; 16]>,
    issued_at_ms: u64,
) -> DecisionPointCoverageStatement {
    let mut s = DecisionPointCoverageStatement {
        version: DECISION_POINT_COVERAGE_VERSION,
        decision_point_id: x.dp_id.clone(),
        agent_id: agent_id.to_string(),
        window,
        decision_ids,
        issued_at_ms,
        signature: placeholder(&x.dp_id),
    };
    s.signature = sign_ed25519(&x.dp_kp.private_key, &x.dp_id, &s.signing_preimage()).unwrap();
    s
}

// ─── Observer side (Skill 6 / 6.5 fixture) ───

struct Observer {
    signer: CollectorSigner,
    probe: ProcfsProbe,
    kp: KeyPair,
    anchors: ObserverTrustAnchors,
}

impl Observer {
    /// `kernel`: the probe declares a live proc connector (kernel-pushed).
    /// `registered`: the collector runs `RegisteredOnly` with this probe
    /// provisioned for every mechanism; otherwise `Open`.
    fn new(kernel: bool, registered: bool) -> Self {
        Self::with_id(OBSERVER_ID, kernel, registered)
    }

    fn with_id(observer_id: &str, kernel: bool, registered: bool) -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(observer_id, 1, &kp.private_key, &kp.public_key).unwrap();
        if registered {
            signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
        }
        let mut probe = ProcfsProbe::new(PROBE_ID);
        probe.declare_source(if kernel {
            SourceMechanism::ProcConnector
        } else {
            SourceMechanism::ProcfsPoll
        });
        let anchors = ObserverTrustAnchors::new().trust(observer_id, 1, &kp.public_key);
        Self {
            signer,
            probe,
            kp,
            anchors,
        }
    }

    fn present(
        &mut self,
        p: ObservedProcess,
        claim: Option<&AgentClaim>,
        wall_ms: u64,
    ) -> ObservedExecution {
        self.probe
            .observation(p, ObservedEffect::ProcessPresent, claim, wall_ms)
    }

    fn batch(&mut self, id: u8, from: u64, to: u64, obs: Vec<ObservedExecution>) -> AttestedBatch {
        self.signer
            .attest(self.probe.batch([id; 16], from, to, obs))
            .unwrap()
    }

    /// A batch that also carries raw kernel events, so a test can put an
    /// **unbound** process event inside a perfectly covered window — the
    /// case where the observer saw an execution and could not identify it.
    fn batch_with_kernel(
        &mut self,
        id: u8,
        from: u64,
        to: u64,
        obs: Vec<ObservedExecution>,
        kernel: Vec<KernelLifecycleEvent>,
    ) -> AttestedBatch {
        let mut b = self.probe.batch([id; 16], from, to, obs);
        b.kernel_events = kernel;
        self.signer.attest(b).unwrap()
    }

    fn health(&self, at: u64) -> SignedSensorHealth {
        self.signer.health(at).unwrap()
    }

    fn evidence(&self, batches: Vec<AttestedBatch>, at: u64) -> ObserverEvidence {
        ObserverEvidence {
            batches,
            health: self.health(at),
        }
    }

    /// What a forger holding the collector key could do: re-sign.
    fn resign_batch(&self, mut b: AttestedBatch) -> AttestedBatch {
        b.attestation =
            sign_ed25519(&self.kp.private_key, OBSERVER_ID, &b.signing_preimage()).unwrap();
        b
    }

    fn resign_health(&self, mut h: SignedSensorHealth) -> SignedSensorHealth {
        h.attestation = sign_ed25519(
            &self.kp.private_key,
            OBSERVER_ID,
            &h.health.canonical_bytes(),
        )
        .unwrap();
        h
    }
}

fn process_of(ee: &ExpectedExecution) -> ObservedProcess {
    ObservedProcess {
        process: ee.execution_binding.process,
        exe_content_sha256: ee.execution_binding.exe_content_sha256,
        exe_path: ee.execution_binding.exe_path.clone(),

        container: None,
    }
}

fn other_process() -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: OTHER_PID,
            pid_start_time_ticks: 77,
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(b"something else entirely"),
        exe_path: "/usr/bin/other".into(),

        container: None,
    }
}

fn claim_for(x: &Expected) -> AgentClaim {
    AgentClaim {
        agent_id: x.agent_id.clone(),
        claim_source: "orchestrator".into(),
        decision_id: Some(x.ee.decision_id),
    }
}

fn exec_event(pid: u32, ts_ns: u64) -> ProcEvent {
    ProcEvent {
        kind: KernelLifecycleKind::Exec { pid, tgid: pid },
        cpu: 0,
        timestamp_ns: ts_ns,
    }
}

fn ctx(x: &Expected, o: &Observer, verification_time_ms: u64) -> ReconciliationContext {
    ReconciliationContext {
        decision_point_anchors: x.anchors.clone(),
        observer_anchors: o.anchors.clone(),
        verification_time_ms,
        health_max_age_ms: HEALTH_MAX_AGE,
        window_tolerance_ms: 0,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: None,
    }
}

/// The instant health is emitted and reconciliation runs in the standard
/// scenario: 1 s after the expectation's window closes.
fn at_of(x: &Expected) -> u64 {
    x.now + TTL + 1_000
}

/// The standard scenario: an epoch-start batch, then one contiguous batch
/// whose claimed window spans the expectation's window with 1 s slack on
/// each side, carrying `obs`.
fn covered_chain(
    x: &Expected,
    o: &mut Observer,
    obs: Vec<ObservedExecution>,
) -> Vec<AttestedBatch> {
    let now = x.now;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let b2 = o.batch(2, now - 1_000, at_of(x), obs);
    vec![b1, b2]
}

fn window_of(x: &Expected) -> CoverageWindow {
    CoverageWindow {
        from_ms: x.ee.issued_at,
        to_ms: x.ee.valid_until,
    }
}

// ═══ 1. Identity match: the ceiling is CANNOT_PROVE ═══

#[test]
fn t01_identity_match_is_cannot_prove_action_unavailable_and_never_verified_execution() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let claim = claim_for(&x);
    let obs = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnavailable);
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
    assert_eq!(r.action, ActionComparison::Unobservable);
    assert_eq!(r.temporal, TemporalComparison::WithinWindow);
    assert_eq!(
        r.availability,
        ObservationAvailability::Covered {
            window: window_of(&x)
        }
    );
    assert_eq!(
        r.decision_id,
        Some(DecisionId::from_bytes(x.ee.decision_id))
    );
    assert!(r.evidence.iter().any(|e| matches!(
        e,
        EvidenceRef::Observation {
            batch_sequence: ObserverSequence(2),
            index: 0
        }
    )));
    assert_ne!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "no observation carries action evidence; VERIFIED_EXECUTION must be unreachable"
    );
}

// ═══ 2. Expected, no observation, poll-only coverage ═══

#[test]
fn t02_poll_only_coverage_with_no_observation_is_cannot_prove_not_phantom() {
    let x = expected();
    let mut o = Observer::new(false, true);
    let at = at_of(&x);
    let filler = o.present(other_process(), None, x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![filler]);
        o.evidence(batches, at)
    };
    assert!(!ev.health.covered_by_kernel_pushed_source());

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::CoverageNotKernelPushed);
    assert_eq!(r.identity, IdentityComparison::NoReference);
    assert!(r.availability.is_covered(), "covered — by polling only");
}

/// Kernel events *present in the record* do not make the window kernel
/// covered: coverage comes from signed `covered_by`, which is the
/// intersection over the epoch. A connector that came up late covers nothing.
#[test]
fn t02b_kernel_events_in_the_record_do_not_imply_kernel_coverage() {
    let x = expected();
    let mut o = Observer::new(false, true);
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o.batch(1, now - 3_000, now - 2_000, vec![]);
    let f = o.present(other_process(), None, now - 2_000);
    let b2 = o.batch(2, now - 2_000, now - 1_000, vec![f]);
    // Connector comes up now; a kernel event lands in the third batch.
    o.probe.declare_source(SourceMechanism::ProcConnector);
    o.probe.ingest_kernel_event(exec_event(OTHER_PID, 1_000));
    let b3 = o.batch(3, now - 1_000, at, vec![]);
    let ev = o.evidence(vec![b1, b2, b3], at);
    assert!(ev.batches[2].batch.kernel_events.len() == 1);
    assert_eq!(
        ev.health.health.covered_by,
        vec![SourceMechanism::ProcfsPoll]
    );

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::CoverageNotKernelPushed);
}

// ═══ 3. PHANTOM_CLAIM and its preconditions ═══

#[test]
fn t03_phantom_claim_needs_kernel_coverage_registered_probe_and_full_chain() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let filler = o.present(other_process(), None, x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![filler]);
        o.evidence(batches, at)
    };
    assert!(ev.health.covered_by_kernel_pushed_source());
    assert_eq!(ev.health.health.probe_policy, ProbePolicy::RegisteredOnly);

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::PhantomClaim);
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.reason, ReasonCode::KernelCoverageWithNoReference);
    assert_eq!(r.identity, IdentityComparison::NoReference);
    assert_eq!(r.action, ActionComparison::Unobservable);
    assert!(r.availability.is_covered());
    // Every input the verdict rests on is referenced.
    assert!(r
        .evidence
        .iter()
        .any(|e| matches!(e, EvidenceRef::Health { .. })));
    assert_eq!(
        r.evidence
            .iter()
            .filter(|e| matches!(e, EvidenceRef::Batch { .. }))
            .count(),
        2
    );
}

/// Withholding the batch that contains the matching observation must not
/// turn a corroborated identity into a phantom. The withheld batch is
/// visible: the supplied chain no longer spans the window, or no longer
/// links to the health head.
#[test]
fn t03b_withholding_the_batch_with_the_observation_never_yields_phantom() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let now = x.now;
    let at = now + TTL + 2_000;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let claim = claim_for(&x);
    let obs = o.present(process_of(&x.ee), Some(&claim), now + 10);
    let b2 = o.batch(2, now - 1_000, now + TTL + 1_000, vec![obs]);
    let b3 = o.batch(3, now + TTL + 1_000, at, vec![]);
    let health = o.health(at);

    // Full chain: identity corroborated.
    let full = ObserverEvidence {
        batches: vec![b1.clone(), b2.clone(), b3.clone()],
        health: health.clone(),
    };
    let r = reconcile_expectation(&x.ee, Some(&full), &ctx(&x, &o, at));
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });

    // Drop b2 (keeps b1, b3): a sequence gap.
    let gap = ObserverEvidence {
        batches: vec![b1.clone(), b3.clone()],
        health: health.clone(),
    };
    let r = reconcile_expectation(&x.ee, Some(&gap), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObservationSetIncomplete);

    // Supply only the head batch: links to health, but does not span the
    // expectation's window.
    let tail = ObserverEvidence {
        batches: vec![b3.clone()],
        health: health.clone(),
    };
    let r = reconcile_expectation(&x.ee, Some(&tail), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObservationSetIncomplete);

    // Drop the head batch: chain does not end where signed health says.
    let truncated = ObserverEvidence {
        batches: vec![b1, b3.clone()],
        health: o.health(at), // still sequence 3
    };
    let r = reconcile_expectation(&x.ee, Some(&truncated), &ctx(&x, &o, at));
    assert_eq!(r.reason, ReasonCode::ObservationSetIncomplete);
    let _ = b2;
}

/// Under `Open` probe policy the collector attested bytes from a probe it
/// cannot name. Coverage and divergence statements then rest on unverified
/// provenance and are withheld.
#[test]
fn t03c_open_probe_policy_blocks_phantom_and_divergence() {
    let x = expected();
    let mut o = Observer::new(true, false);
    let at = at_of(&x);
    let filler = o.present(other_process(), None, x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![filler]);
        o.evidence(batches, at)
    };
    assert_eq!(ev.health.health.probe_policy, ProbePolicy::Open);
    assert!(ev.health.covered_by_kernel_pushed_source());

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ProvenanceUnverifiedOpenPolicy);

    let mut o = Observer::new(true, false);
    let at = at_of(&x);
    let claim = claim_for(&x);
    let mut diverged = process_of(&x.ee);
    diverged.exe_content_sha256 = sha256(b"replaced binary");
    let obs = o.present(diverged, Some(&claim), x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(
        r.identity,
        IdentityComparison::Divergent { observations: 1 }
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ProvenanceUnverifiedOpenPolicy);
}

// ═══ 4/5. Observed without expected ═══

#[test]
fn t04_observed_only_with_unknown_expected_side_is_cannot_prove() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let claim = AgentClaim {
        decision_id: None,
        ..claim_for(&x)
    };
    let obs = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };

    let target = ObservationTarget::Observation {
        batch_sequence: ObserverSequence(2),
        index: 0,
    };
    let r = reconcile_observation(&ev, target, &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ExpectedSideCompletenessUnknown);
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
    assert_eq!(r.decision_id, None);
}

#[test]
fn t05_unattributed_effect_requires_a_signed_complete_expected_side() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let stray_decision = [0x5a; 16];
    let claim = AgentClaim {
        decision_id: Some(stray_decision),
        ..claim_for(&x)
    };
    let obs = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };
    let batch_window = CoverageWindow {
        from_ms: ev.batches[1].batch.claimed_from_ms,
        to_ms: ev.batches[1].batch.claimed_to_ms,
    };
    let wide = CoverageWindow {
        from_ms: batch_window.from_ms - 1_000,
        to_ms: batch_window.to_ms + 1_000,
    };
    let target = ObservationTarget::Observation {
        batch_sequence: ObserverSequence(2),
        index: 0,
    };

    // Decision point attests: for this agent over this window, only the
    // fixture's decision exists. The observation claims a different one.
    let stmt = coverage_statement(&x, &x.agent_id, wide, vec![x.ee.decision_id], at);
    assert_eq!(stmt.verify(&x.anchors), Ok(()));
    let mut c = ctx(&x, &o, at);
    c.expected_side = ExpectedSideCoverage::Attested(Box::new(stmt.clone()));
    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.result, ReconciliationResult::UnattributedEffect);
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.reason, ReasonCode::NoExpectationAttested);
    assert_eq!(r.decision_id, Some(DecisionId::from_bytes(stray_decision)));
    assert!(r
        .evidence
        .iter()
        .any(|e| matches!(e, EvidenceRef::CoverageStatement { .. })));

    // The claimed decision *is* in the attested set: not unattributed.
    let stmt2 = coverage_statement(&x, &x.agent_id, wide, vec![stray_decision], at);
    c.expected_side = ExpectedSideCoverage::Attested(Box::new(stmt2));
    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ExpectationExistsForObservation);

    // Statement for another agent: does not cover.
    let stmt3 = coverage_statement(&x, "aip1someoneelse", wide, vec![], at);
    c.expected_side = ExpectedSideCoverage::Attested(Box::new(stmt3));
    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.reason, ReasonCode::ExpectedSideStatementDoesNotCover);

    // Statement window shorter than the batch window: does not cover.
    let narrow = CoverageWindow {
        from_ms: batch_window.from_ms + 1,
        to_ms: batch_window.to_ms,
    };
    let stmt4 = coverage_statement(&x, &x.agent_id, narrow, vec![], at);
    c.expected_side = ExpectedSideCoverage::Attested(Box::new(stmt4));
    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.reason, ReasonCode::ExpectedSideStatementDoesNotCover);

    // Tampered statement (decision list emptied after signing).
    let mut forged = stmt.clone();
    forged.decision_ids.clear();
    assert_eq!(
        forged.verify(&x.anchors),
        Err(CoverageStatementError::PayloadHashMismatch)
    );
    c.expected_side = ExpectedSideCoverage::Attested(Box::new(forged));
    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ExpectedSideStatementInvalid);

    // Statement signed by a key the verifier does not anchor.
    let mut c2 = c.clone();
    c2.decision_point_anchors = DecisionPointTrustAnchors::new();
    c2.expected_side = ExpectedSideCoverage::Attested(Box::new(stmt.clone()));
    let r = reconcile_observation(&ev, target, &c2);
    assert_eq!(r.reason, ReasonCode::ExpectedSideStatementInvalid);

    // Every signed field of the statement enters its preimage.
    let base = stmt.signing_preimage();
    let mut m = stmt.clone();
    m.agent_id.push('x');
    assert_ne!(m.signing_preimage(), base);
    let mut m = stmt.clone();
    m.window.to_ms += 1;
    assert_ne!(m.signing_preimage(), base);
    let mut m = stmt.clone();
    m.decision_ids.push([1; 16]);
    assert_ne!(m.signing_preimage(), base);
    let mut m = stmt.clone();
    m.issued_at_ms += 1;
    assert_ne!(m.signing_preimage(), base);
    let mut m = stmt.clone();
    m.decision_point_id.push('x');
    assert_ne!(m.signing_preimage(), base);
    assert_eq!(
        &base[4..4 + DECISION_POINT_COVERAGE_DOMAIN.len()],
        DECISION_POINT_COVERAGE_DOMAIN.as_bytes()
    );
}

/// An observation with no agent claim cannot be attributed to any expected
/// side, whatever the decision point attests.
#[test]
fn t05b_unclaimed_observation_is_never_unattributed_effect() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let obs = o.present(other_process(), None, x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };
    let wide = CoverageWindow {
        from_ms: 0,
        to_ms: u64::MAX / 2,
    };
    let mut c = ctx(&x, &o, at);
    c.expected_side = ExpectedSideCoverage::Attested(Box::new(coverage_statement(
        &x,
        &x.agent_id,
        wide,
        vec![],
        at,
    )));
    let r = reconcile_observation(
        &ev,
        ObservationTarget::Observation {
            batch_sequence: ObserverSequence(2),
            index: 0,
        },
        &c,
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::AttributionNotEstablished);

    let r = reconcile_observation(
        &ev,
        ObservationTarget::Observation {
            batch_sequence: ObserverSequence(2),
            index: 9,
        },
        &c,
    );
    assert_eq!(r.reason, ReasonCode::TargetNotFound);
}

// ═══ 6. IDENTITY_DIVERGENCE ═══

#[test]
fn t06_divergent_instance_under_the_same_decision_claim_is_identity_divergence() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let claim = claim_for(&x);
    let mut diverged = process_of(&x.ee);
    diverged.exe_content_sha256 = sha256(b"payments-agent binary v1 (patched)");
    let obs = o.present(diverged, Some(&claim), x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::IdentityDivergence);
    assert_eq!(
        r.strength,
        EvidenceStrength::Attested,
        "content is procfs-derived: never Proven"
    );
    assert_eq!(r.reason, ReasonCode::IdentityDiverged);
    assert_eq!(
        r.identity,
        IdentityComparison::Divergent { observations: 1 }
    );
    assert_eq!(r.action, ActionComparison::Unobservable);
}

#[test]
fn t06b_matching_and_divergent_observations_together_are_ambiguous_not_a_verdict() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let claim = claim_for(&x);
    let ok = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let mut diverged = process_of(&x.ee);
    diverged.process.pid_start_time_ticks += 1;
    let bad = o.present(diverged, Some(&claim), x.now + 20);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![ok, bad]);
        o.evidence(batches, at)
    };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::AmbiguousObservations);
    assert_eq!(
        r.identity,
        IdentityComparison::Ambiguous {
            matching: 1,
            divergent: 1
        }
    );
}

// ═══ 7. PID reuse and unbound kernel events ═══

#[test]
fn t07_pid_reuse_never_matches_and_never_phantoms() {
    let x = expected();

    // Same pid, different start ticks, no claim.
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let mut reused = process_of(&x.ee);
    reused.process.pid_start_time_ticks += 1;
    let obs = o.present(reused, None, x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::UnboundReferencesOnly);
    assert_eq!(
        r.identity,
        IdentityComparison::UnboundReferencesOnly { references: 1 }
    );

    // Same pid and ticks, different boot.
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let mut rebooted = process_of(&x.ee);
    rebooted.process.boot_id = [0x0d; 16];
    let obs = o.present(rebooted, None, x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::UnboundReferencesOnly);

    // Same tuple, different executable contents, no claim: a pid-only
    // reference. It neither matches nor diverges (no claim ties it here).
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let mut swapped = process_of(&x.ee);
    swapped.exe_content_sha256 = sha256(b"other binary");
    let obs = o.present(swapped, None, x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::UnboundReferencesOnly);
}

#[test]
fn t07b_unbound_kernel_event_about_the_expected_pid_is_cannot_prove() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let now = x.now;
    let at = at_of(&x);
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    // Exec of a pid that no longer exists: the probe cannot anchor it.
    let ev_ref = o.probe.ingest_kernel_event(exec_event(PID, 5_000));
    assert!(ev_ref.bound.is_none());
    let b2 = o.batch(2, now - 1_000, at, vec![]);
    let ev = o.evidence(vec![b1, b2], at);
    assert_eq!(ev.batches[1].batch.kernel_events.len(), 1);

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::UnboundReferencesOnly);
    assert_eq!(
        r.identity,
        IdentityComparison::UnboundReferencesOnly { references: 1 }
    );
    assert!(r.evidence.iter().any(|e| matches!(
        e,
        EvidenceRef::KernelEvent {
            batch_sequence: ObserverSequence(2),
            index: 0
        }
    )));

    // Observed-only path on the same event: identity unbound → CANNOT_PROVE.
    let r = reconcile_observation(
        &ev,
        ObservationTarget::KernelEvent {
            batch_sequence: ObserverSequence(2),
            index: 0,
        },
        &ctx(&x, &o, at),
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::UnboundReferencesOnly);
}

// ═══ 8/9. Action and parameters are unobservable ═══

#[test]
fn t08_t09_action_comparison_is_never_match_or_mismatch() {
    let x = expected();
    let mut results = Vec::new();

    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let claim = claim_for(&x);
    let obs = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };
    results.push(reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at)));
    results.push(reconcile_observation(
        &ev,
        ObservationTarget::Observation {
            batch_sequence: ObserverSequence(2),
            index: 0,
        },
        &ctx(&x, &o, at),
    ));

    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![]);
        o.evidence(batches, at)
    };
    results.push(reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at)));
    results.push(reconcile_expectation(&x.ee, None, &ctx(&x, &o, at)));

    for r in &results {
        assert_eq!(r.action, ActionComparison::Unobservable, "{r:?}");
        assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
        assert_ne!(r.result, ReconciliationResult::LineageViolation, "{r:?}");
    }
}

// ═══ 10/11. Temporal ═══

#[test]
fn t10_matching_observation_outside_the_window_is_cannot_prove_not_phantom() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o.batch(1, now - 60_000, now - 50_000, vec![]);
    let claim = claim_for(&x);
    let obs = o.present(process_of(&x.ee), Some(&claim), now - 40_000);
    let b2 = o.batch(2, now - 50_000, now - 10_000, vec![obs]);
    let b3 = o.batch(3, now - 10_000, at, vec![]);
    let ev = o.evidence(vec![b1, b2, b3], at);
    assert!(ev.health.covered_by_kernel_pushed_source());

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObservationOutsideWindow);
    assert_eq!(r.temporal, TemporalComparison::OutsideWindow);
    assert_eq!(r.identity, IdentityComparison::NoReference);
}

#[test]
fn t11_window_not_covered_by_signed_coverage_is_cannot_prove() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let now = x.now;
    let at = now + 30_000;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let b2 = o.batch(2, now - 1_000, at, vec![]); // ends before valid_until
    let ev = o.evidence(vec![b1, b2], at);

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::WindowNotCovered);
    assert_eq!(
        r.availability,
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::WindowNotCovered
        }
    );
}

#[test]
fn t11b_stale_health_is_cannot_prove() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![]);
        o.evidence(batches, at)
    };
    let late = at + HEALTH_MAX_AGE + 1;
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, late));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::HealthStale);
    assert!(matches!(
        r.availability,
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::HealthStale { .. }
        }
    ));
    assert_eq!(r.verification_time_ms, late);
}

// ═══ 12. Expected-side forgery ═══

#[test]
fn t12_tampered_or_untrusted_expectation_is_cannot_prove_never_anything_else() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![]);
        o.evidence(batches, at)
    };

    // Extend the window after signing.
    let mut forged = x.ee.clone();
    forged.valid_until += 1;
    let r = reconcile_expectation(&forged, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ExpectedSignatureInvalid);
    assert_eq!(r.identity, IdentityComparison::NoReference);
    assert_eq!(r.availability, no_observer(), "observer never consulted");

    // Swap the binding after signing.
    let mut forged = x.ee.clone();
    forged.execution_binding.exe_content_sha256 = sha256(b"anything");
    let r = reconcile_expectation(&forged, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.reason, ReasonCode::ExpectedSignatureInvalid);

    // Decision point not anchored.
    let mut c = ctx(&x, &o, at);
    c.decision_point_anchors = DecisionPointTrustAnchors::new();
    let r = reconcile_expectation(&x.ee, Some(&ev), &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ExpectedUntrustedDecisionPoint);
}

// ═══ 13. Observer forgery ═══

#[test]
fn t13_tampered_observer_bytes_are_sensor_integrity_failure_proven() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let mut ev = {
        let batches = covered_chain(&x, &mut o, vec![]);
        o.evidence(batches, at)
    };

    // Batch content altered after signing.
    let mut tampered = ev.clone();
    tampered.batches[1].batch.claimed_to_ms += 1;
    let r = reconcile_expectation(&x.ee, Some(&tampered), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    assert_eq!(r.strength, EvidenceStrength::Proven);
    assert_eq!(r.reason, ReasonCode::ObserverSignatureInvalid);

    // Health altered after signing (state upgraded by hand).
    let mut tampered = ev.clone();
    tampered.health.health.covered_by = vec![SourceMechanism::ProcConnector];
    tampered.health.health.state = ObserverState::Active;
    tampered.health.health.emitted_at_ms += 1;
    let r = reconcile_expectation(&x.ee, Some(&tampered), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    assert_eq!(r.strength, EvidenceStrength::Proven);

    // Same evidence, verifier does not anchor the observer: not an integrity
    // claim — the verifier simply cannot use it.
    let mut c = ctx(&x, &o, at);
    c.observer_anchors = ObserverTrustAnchors::new();
    let r = reconcile_expectation(&x.ee, Some(&ev), &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObserverUntrusted);

    // Observed-only path reaches the same integrity verdict.
    ev.batches[0].prev_head = [1; 32];
    let r = reconcile_observation(
        &ev,
        ObservationTarget::Observation {
            batch_sequence: ObserverSequence(2),
            index: 0,
        },
        &ctx(&x, &o, at),
    );
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    assert_eq!(r.strength, EvidenceStrength::Proven);
}

// ═══ 14/18. Degraded observer ═══

#[test]
fn t14_t18_degraded_observer_is_cannot_prove_even_with_kernel_coverage_and_silence() {
    let x = expected();
    let mut o = Observer::new(true, true);
    o.probe.enable_loss_counter();
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    o.probe.record_lost_events(3);
    let b2 = o.batch(2, now - 1_000, at, vec![]);
    assert_eq!(b2.batch.dropped_events, Some(3));
    let ev = o.evidence(vec![b1, b2], at);
    assert_eq!(ev.health.health.state, ObserverState::Degraded);

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObserverDegraded);
    assert_eq!(
        r.availability,
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::ObserverDegraded
        }
    );
}

// ═══ 15/16. Chain break, replay, fork, rollback ═══

#[test]
fn t15_replayed_batch_is_collapsed_and_flagged_not_counted_twice() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let claim = claim_for(&x);
    let obs = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let mut ev = {
        let batches = covered_chain(&x, &mut o, vec![obs]);
        o.evidence(batches, at)
    };
    let clean = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert!(!clean.replay_detected);

    ev.batches.push(ev.batches[1].clone());
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert!(r.replay_detected);
    assert_eq!(r.result, clean.result);
    assert_eq!(r.reason, clean.reason);
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
    assert_ne!(r.digest(), clean.digest(), "the flag is part of the record");
}

#[test]
fn t15b_forked_chain_signed_by_the_collector_key_is_integrity_failure_proven() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let batches = covered_chain(&x, &mut o, vec![]);
    let health = o.health(at);

    // Two different batches at the same sequence, both validly signed.
    let mut fork = batches[1].clone();
    fork.batch.claimed_to_ms += 1;
    let fork = o.resign_batch(fork);
    assert_eq!(verify_attested_batch(&fork, &o.anchors), Ok(()));
    let ev = ObserverEvidence {
        batches: vec![batches[0].clone(), batches[1].clone(), fork],
        health: health.clone(),
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    assert_eq!(r.strength, EvidenceStrength::Proven);
    assert_eq!(r.reason, ReasonCode::ObserverChainBroken);

    // A validly signed batch whose prev_head does not link.
    let mut unlinked = batches[1].clone();
    unlinked.prev_head = [7; 32];
    let unlinked = o.resign_batch(unlinked);
    let ev = ObserverEvidence {
        batches: vec![batches[0].clone(), unlinked],
        health,
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    assert_eq!(r.reason, ReasonCode::ObserverChainBroken);
}

#[test]
fn t16_health_and_chain_must_agree_on_the_head() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let b2 = o.batch(2, now - 1_000, at, vec![]);
    let health_at_2 = o.health(at);
    let b3 = o.batch(3, at, at + 1_000, vec![]);
    let health_at_3 = o.health(at + 1_000);

    // Rolled-back health with a longer chain.
    let ev = ObserverEvidence {
        batches: vec![b1.clone(), b2.clone(), b3.clone()],
        health: health_at_2,
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObservationSetIncomplete);

    // Current health with a truncated chain.
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: health_at_3,
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at + 1_000));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObservationSetIncomplete);
}

#[test]
fn t16b_batches_from_a_second_trusted_observer_are_not_merged() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let mut o2 = Observer::with_id("collector-b", true, true);
    let at = at_of(&x);
    let mut batches = covered_chain(&x, &mut o, vec![]);
    let foreign = o2.batch(1, x.now - 2_000, at, vec![]);
    batches.push(foreign);
    let ev = ObserverEvidence {
        batches,
        health: o.health(at),
    };
    let mut c = ctx(&x, &o, at);
    c.observer_anchors = c
        .observer_anchors
        .trust("collector-b", 1, &o2.kp.public_key);
    let r = reconcile_expectation(&x.ee, Some(&ev), &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::MixedObservers);
}

// ═══ 17. Continuity states ═══

#[test]
fn t17_unverified_or_recovering_continuity_is_continuity_failure_attested() {
    let x = expected();
    // One batch only: epoch start, continuity unverified.
    let mut o = Observer::new(true, true);
    let at = x.now + TTL + 1_000;
    let b1 = o.batch(1, x.now - 1_000, at, vec![]);
    let ev = o.evidence(vec![b1.clone()], at);
    assert_eq!(ev.health.health.state, ObserverState::ContinuityUnverified);
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::ContinuityFailure);
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.reason, ReasonCode::ObserverContinuityUnverified);
    assert_eq!(
        r.availability,
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::ContinuityUnverified
        }
    );

    // Probe restart after a healthy chain: recovering.
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let batches = covered_chain(&x, &mut o, vec![]);
    o.signer.note_probe_restart();
    let ev = o.evidence(batches, at);
    assert_eq!(ev.health.health.state, ObserverState::Recovering);
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::ContinuityFailure);
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.reason, ReasonCode::ObserverRecovering);
}

#[test]
fn t17b_quarantined_observer_is_integrity_failure_attested_not_proven() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let batches = covered_chain(&x, &mut o, vec![]);
    let mut h = o.health(at);
    h.health.state = ObserverState::Quarantined;
    h.health.continuity = ContinuityStatus::Broken;
    h.health.attested_coverage = None;
    h.health.covered_by.clear();
    let h = o.resign_health(h);
    assert_eq!(verify_signed_health(&h, &o.anchors), Ok(()));
    let ev = ObserverEvidence { batches, health: h };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    assert_eq!(
        r.strength,
        EvidenceStrength::Attested,
        "the collector *says* it is quarantined; nothing here was recomputed"
    );
    assert_eq!(r.reason, ReasonCode::ObserverQuarantined);
}

// ═══ 19–21. Strength by kind; no severity ═══

#[test]
fn t19_t21_strength_is_fixed_by_result_kind_and_no_severity_or_score_exists() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![]);
        o.evidence(batches, at)
    };
    let phantom = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(phantom.result, ReconciliationResult::PhantomClaim);
    assert_eq!(phantom.strength, EvidenceStrength::Attested);

    let none = reconcile_expectation(&x.ee, None, &ctx(&x, &o, at));
    assert_eq!(none.result, ReconciliationResult::CannotProve);
    assert_eq!(none.strength, EvidenceStrength::Heuristic);

    let mut tampered = ev.clone();
    tampered.batches[1].batch.claimed_from_ms += 1;
    let integrity = reconcile_expectation(&x.ee, Some(&tampered), &ctx(&x, &o, at));
    assert_eq!(
        integrity.result,
        ReconciliationResult::SensorIntegrityFailure
    );
    assert_eq!(integrity.strength, EvidenceStrength::Proven);

    for r in [&phantom, &none, &integrity] {
        let json = serde_json::to_string(r).unwrap().to_lowercase();
        for forbidden in [
            "severity",
            "confidence",
            "score",
            "risk",
            "malicious",
            "permitted",
            "authorized",
            "allowed",
            "denied",
            "revoke",
            "terminated",
            "containment",
            "isolate",
            "kill",
            "trusted\":true",
            "did_not_execute",
        ] {
            assert!(!json.contains(forbidden), "`{forbidden}` in {json}");
        }
    }
    // Strength is an ordered enum, not a number; nothing here can be
    // multiplied by a severity that does not exist.
    assert!(EvidenceStrength::Proven > EvidenceStrength::Attested);
}

// ═══ 22. Default ═══

#[test]
fn t22_no_observer_evidence_is_cannot_prove_with_no_observer_availability() {
    let x = expected();
    let o = Observer::new(true, true);
    let r = reconcile_expectation(&x.ee, None, &ctx(&x, &o, x.now));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.result, ReconciliationResult::default());
    assert_eq!(r.strength, EvidenceStrength::Heuristic);
    assert_eq!(r.reason, ReasonCode::NoObserverEvidence);
    assert_eq!(r.availability, no_observer());
    assert_eq!(r.identity, IdentityComparison::NoReference);
    assert_eq!(r.temporal, TemporalComparison::Indeterminate);
    assert_eq!(r.evidence.len(), 1, "only the expectation itself");
}

// ═══ Record: determinism and canonical encoding ═══

#[test]
fn reconciliation_is_deterministic_and_canonically_encoded() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let ev = {
        let batches = covered_chain(&x, &mut o, vec![]);
        o.evidence(batches, at)
    };
    let a = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    let b = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(a, b);
    assert_eq!(a.digest(), b.digest());

    let bytes = a.canonical_bytes();
    assert_eq!(
        &bytes[..4],
        &(RECONCILIATION_DOMAIN.len() as u32).to_le_bytes()
    );
    assert_eq!(
        &bytes[4..4 + RECONCILIATION_DOMAIN.len()],
        RECONCILIATION_DOMAIN.as_bytes()
    );

    // Every field of the record changes the encoding.
    let mut m = a.clone();
    m.result = ReconciliationResult::CannotProve;
    assert_ne!(m.canonical_bytes(), bytes);
    let mut m = a.clone();
    m.strength = EvidenceStrength::Heuristic;
    assert_ne!(m.canonical_bytes(), bytes);
    let mut m = a.clone();
    m.reason = ReasonCode::NoObserverEvidence;
    assert_ne!(m.canonical_bytes(), bytes);
    let mut m = a.clone();
    m.decision_id = None;
    assert_ne!(m.canonical_bytes(), bytes);
    let mut m = a.clone();
    m.availability = no_observer();
    assert_ne!(m.canonical_bytes(), bytes);
    let mut m = a.clone();
    m.identity = IdentityComparison::Match { observations: 1 };
    assert_ne!(m.canonical_bytes(), bytes);
    // `action` cannot be mutated from outside the crate: the positive
    // variants of `ActionComparison` require an `ActionEvidenceSeal` whose
    // constructors are `pub(crate)`, so only the engine's action-derivation
    // step can build one. Its encoding is covered by `tests/action_evidence`.
    let mut m = a.clone();
    m.temporal = TemporalComparison::WithinWindow;
    assert_ne!(m.canonical_bytes(), bytes);
    let mut m = a.clone();
    m.replay_detected = true;
    assert_ne!(m.canonical_bytes(), bytes);
    let mut m = a.clone();
    m.evidence.pop();
    assert_ne!(m.canonical_bytes(), bytes);
    let mut m = a.clone();
    m.verification_time_ms += 1;
    assert_ne!(m.canonical_bytes(), bytes);
}

/// The identifier newtypes refuse implicit conversion: a batch id cannot be
/// handed in where a decision id is expected. Checked at compile time; here
/// we only pin the explicit construction path and the correlation key.
#[test]
fn decision_id_is_the_only_correlation_key_and_is_explicitly_typed() {
    let x = expected();
    let d = DecisionId::from_bytes(x.ee.decision_id);
    assert_eq!(d.as_bytes(), &x.ee.decision_id);
    let b = BatchId::from_bytes([1; 16]);
    assert_eq!(b.as_bytes(), &[1; 16]);
    let seq = ObserverSequence(2);
    assert!(seq > ObserverSequence(1));
}

// ═══ Observation-integrity finding: a blinded observer cannot accuse ═══
// (docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md). A foreign eBPF program on a
// sampled tracepoint suppresses that tracepoint's perf submission host-wide
// with no loss accounting. Such an observer must never drive a PhantomClaim —
// a signed accusation that a claimed execution did not happen — off the back
// of the silence its own blindness produced.

/// The signed `IntegrityUnknown` state turns the strongest positive verdict
/// (PhantomClaim, reached by t03) into `CannotProve`. This is the honesty
/// half: a blinded observer says so, and the reconciler believes it.
#[test]
fn t03d_integrity_unknown_state_is_cannot_prove_never_phantom() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let filler = o.present(other_process(), None, x.now + 10);
    let mut ev = {
        let batches = covered_chain(&x, &mut o, vec![filler]);
        o.evidence(batches, at)
    };
    // Sanity: unmodified, this evidence would reach PhantomClaim.
    assert!(ev.health.covered_by_kernel_pushed_source());

    // The collector's live integrity check found a foreign tracepoint gate,
    // so it signs IntegrityUnknown. (Re-signed with the real key: the state
    // is inside the signed preimage, so this is what an honest blinded
    // collector actually emits, not a forgery.)
    ev.health.health.state = ObserverState::IntegrityUnknown;
    ev.health = o.resign_health(ev.health);
    assert!(!ev.health.covered_by_kernel_pushed_source());

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObserverIntegrityUnknown);
    assert_ne!(r.result, ReconciliationResult::PhantomClaim);
}

/// The cross-mechanism half: even with an `Active` state, kernel-pushed
/// coverage resting only on a gate-able perf tracepoint is not enough for a
/// non-occurrence statement. A single eBPF program could have blinded it, so
/// an independent facility (the connector) is required. Here the signed
/// coverage is the sched tracepoint alone — kernel-pushed, but gate-able.
#[test]
fn t03e_gate_able_tracepoint_alone_is_not_kernel_pushed_coverage() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let filler = o.present(other_process(), None, x.now + 10);
    let mut ev = {
        let batches = covered_chain(&x, &mut o, vec![filler]);
        o.evidence(batches, at)
    };
    // Replace the connector with the sched tracepoint as the sole covering
    // mechanism, and re-sign: kernel-pushed, but exposed to the eBPF gate.
    ev.health.health.covered_by = vec![SourceMechanism::SchedTracepoint];
    ev.health = o.resign_health(ev.health);

    assert!(
        !ev.health.covered_by_kernel_pushed_source(),
        "a lone gate-able tracepoint must not count as kernel-pushed coverage"
    );
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::CoverageNotKernelPushed);
    assert_ne!(r.result, ReconciliationResult::PhantomClaim);
}

// ═══ Mutation-driven regressions ═══
//
// Each test below exists because a mutation of the reconciler survived this
// suite. See `validation/mutation/CORE_MUTATION_RESULTS.json` and
// `docs/RECONCILER_VERIFIER_MUTATION_ASSURANCE.md`. They assert observable
// security properties, not the shape of the implementation.

/// R-10. I10 — an observer anchored to the *agent's own key* is not an
/// independent observer, and `verify_observer` refuses on the health record
/// before it looks at a single batch.
///
/// Why this needed its own test. Every other path into I10 runs through
/// `verify_attested_batch_independent_of_agent`, which makes the same
/// refusal per batch. So with batches present the health-level check is
/// shadowed, and deleting it changed no result anywhere in this suite. The
/// one arrangement that reaches it alone is an observer that has attested
/// nothing yet: sequence 0, no batches, a health record and nothing else.
/// That is a real deployment state — a collector that has just started — and
/// it is exactly the state in which an attacker would most like the
/// independence check to be skipped.
#[test]
fn t13d_an_observer_anchored_to_the_agents_key_is_refused_before_any_batch() {
    let x = expected();
    let o = Observer::new(true, true);
    let at = at_of(&x);

    // No batches: the collector has attested nothing, so the per-batch
    // independence check never runs and the health-level one is the only guard.
    let ev = o.evidence(vec![], at);
    assert!(ev.batches.is_empty());

    let mut c = ctx(&x, &o, at);
    // The verifier holds the agent's key — and it is the very key the
    // observer is anchored under. The "observer" is the agent.
    c.agent_public_key = Some(o.kp.public_key.clone());

    let r = reconcile_expectation(&x.ee, Some(&ev), &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(
        r.reason,
        ReasonCode::ObserverKeyIsAgentKey,
        "an observer that is the agent is not independent, batches or none"
    );

    // Control: the same evidence under a distinct agent key gets past I10 and
    // fails for an unrelated, honest reason. Without this the test above
    // would pass even if the reconciler refused everything.
    let mut c2 = ctx(&x, &o, at);
    c2.agent_public_key = Some(generate_ed25519_keypair().public_key);
    let r2 = reconcile_expectation(&x.ee, Some(&ev), &c2);
    assert_ne!(r2.reason, ReasonCode::ObserverKeyIsAgentKey);
}

/// R-21. A record read back from bytes is never the engine's own output.
///
/// `Provenance` is not serialised, so a round trip must land on
/// `Deserialized` — that is the whole of the B-9 seal. A consumer that
/// *acts* on a verdict (`aip-warrant` gate 1) requires
/// `is_engine_produced()`, so a mutation making it always true hands the
/// actuator a record anyone could have written. Downstream crates pin this;
/// nothing in `aip-reconcile`, which owns the invariant, did.
#[test]
fn t22_a_record_read_back_from_bytes_is_never_engine_produced() {
    let x = expected();
    let o = Observer::new(true, true);
    let at = at_of(&x);

    let r = reconcile_expectation(&x.ee, None, &ctx(&x, &o, at));
    assert!(r.is_engine_produced(), "the engine produced this one");
    assert_eq!(r.provenance(), Provenance::Engine);

    let json = serde_json::to_string(&r).unwrap();
    let back: Reconciliation = serde_json::from_str(&json).unwrap();

    // The round trip is faithful about the execution …
    assert_eq!(back.result, r.result);
    assert_eq!(back.reason, r.reason);
    assert_eq!(back.digest(), r.digest());
    // … and honest about itself.
    assert!(
        !back.is_engine_produced(),
        "however faithful, a deserialised record is not the engine's own output"
    );
    assert_eq!(back.provenance(), Provenance::Deserialized);
}

// ═══ `reconcile_observation` — mutation-driven regressions ═══
//
// The previous milestone's report (§9.2) predicted that the observation entry
// point would carry the same asymmetry that produced R-11b and R-12b: an
// invariant guarded on one path and bare on another. A 26-mutation matrix
// against `reconcile_observation` killed 13 and left 12 survivors. Every test
// below closes one of them.
//
// See `validation/mutation/OBSERVATION_MUTATION_RESULTS.json` and
// `docs/RECONCILE_OBSERVATION_MUTATION_ASSURANCE.md`.

/// Build a covered chain whose single observation claims `decision`, and an
/// attested expected side wide enough to cover the batch window. Returns
/// evidence, target, and a context that reaches the end of the function —
/// so a test that expects an *earlier* refusal is asserting that the refusal
/// happened, not that the fixture fell short.
fn observation_scene(
    x: &Expected,
    o: &mut Observer,
    decision: Option<[u8; 16]>,
) -> (ObserverEvidence, ObservationTarget, ReconciliationContext) {
    let at = at_of(x);
    let claim = AgentClaim {
        decision_id: decision,
        ..claim_for(x)
    };
    let obs = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let batches = covered_chain(x, o, vec![obs]);
        o.evidence(batches, at)
    };
    let w = CoverageWindow {
        from_ms: ev.batches[1].batch.claimed_from_ms - 1_000,
        to_ms: ev.batches[1].batch.claimed_to_ms + 1_000,
    };
    let mut c = ctx(x, o, at);
    c.expected_side =
        ExpectedSideCoverage::Attested(Box::new(coverage_statement(x, &x.agent_id, w, vec![], at)));
    let target = ObservationTarget::Observation {
        batch_sequence: ObserverSequence(2),
        index: 0,
    };
    (ev, target, c)
}

/// O-12 … O-16. The observer-state gate on the observation path, swept.
///
/// This is the asymmetry §9.2 predicted, and it was the largest one in the
/// repository: **five consecutive mutations survived here**. `Quarantined`
/// was covered on the expectation path (t17b) and on the lineage path
/// (lv18); `Degraded` on both (t14/t18, lv14); `IntegrityUnknown` on both
/// (t03d, lv17). On the observation path — the one entry point that can
/// produce an accusation against a workload with no expectation to check it
/// against — none of them was covered, and the gate could be deleted whole
/// without failing a single test.
///
/// Each state is asserted to its exact result, strength and reason, because
/// the three outcomes are not interchangeable: an integrity failure accuses
/// the observer, a continuity failure describes a gap, and CANNOT_PROVE
/// says the question is open.
#[test]
fn t23_observer_state_gates_the_observation_path_state_by_state() {
    let x = expected();

    // Control: an Active observer runs the whole function and reaches the
    // attributive end. Without this the sweep below would pass against a
    // reconciler that refused everything.
    let mut o = Observer::new(true, true);
    let (ev, target, c) = observation_scene(&x, &mut o, Some([0x5a; 16]));
    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.result, ReconciliationResult::UnattributedEffect);
    assert_eq!(r.reason, ReasonCode::NoExpectationAttested);

    for (state, result, strength, reason) in [
        (
            ObserverState::Quarantined,
            ReconciliationResult::SensorIntegrityFailure,
            EvidenceStrength::Attested,
            ReasonCode::ObserverQuarantined,
        ),
        (
            ObserverState::Recovering,
            ReconciliationResult::ContinuityFailure,
            EvidenceStrength::Attested,
            ReasonCode::ObserverRecovering,
        ),
        (
            ObserverState::ContinuityUnverified,
            ReconciliationResult::ContinuityFailure,
            EvidenceStrength::Attested,
            ReasonCode::ObserverContinuityUnverified,
        ),
        (
            ObserverState::Degraded,
            ReconciliationResult::CannotProve,
            EvidenceStrength::Heuristic,
            ReasonCode::ObserverDegraded,
        ),
        (
            ObserverState::IntegrityUnknown,
            ReconciliationResult::CannotProve,
            EvidenceStrength::Heuristic,
            ReasonCode::ObserverIntegrityUnknown,
        ),
    ] {
        let mut o = Observer::new(true, true);
        let (mut ev, target, c) = observation_scene(&x, &mut o, Some([0x5a; 16]));
        // The state lives inside the signed preimage, so re-signing is what
        // an honest collector in that state actually emits.
        ev.health.health.state = state;
        ev.health = o.resign_health(ev.health);

        let r = reconcile_observation(&ev, target, &c);
        assert_eq!(r.result, result, "{state:?}");
        assert_eq!(r.strength, strength, "{state:?}");
        assert_eq!(r.reason, reason, "{state:?}");
        assert_ne!(
            r.result,
            ReconciliationResult::UnattributedEffect,
            "{state:?}: an observer in this state cannot underwrite an accusation"
        );
    }
}

/// O-11. A collector clock set ahead of the verifier's cannot make a health
/// record read as fresh, on the observation path as on the expectation path.
///
/// Staleness only bounds records that are too *old*; without this check a
/// forward-set clock saturates the age computation to zero and every stale
/// record reads as current. Covered on the expectation path (t11b's sibling,
/// R-17) and nowhere here.
#[test]
fn t24_a_health_record_from_the_future_is_refused_on_the_observation_path() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let (ev, target, mut c) = observation_scene(&x, &mut o, Some([0x5a; 16]));

    // The verifier's clock is behind the collector's by more than tolerance.
    c.verification_time_ms = ev.health.health.emitted_at_ms - 1;
    c.window_tolerance_ms = 0;

    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::HealthNotYetEmitted);
    assert_ne!(r.result, ReconciliationResult::UnattributedEffect);
}

/// O-18. Under `Open` probe policy the collector attested bytes from a probe
/// it cannot name, so the mechanism label is unverified provenance and cannot
/// carry an attribution. Covered on the expectation path by t03c; on the
/// observation path the check could be deleted with no test failing.
#[test]
fn t25_open_probe_policy_blocks_attribution_on_the_observation_path() {
    let x = expected();
    let mut o = Observer::new(true, false);
    let (ev, target, c) = observation_scene(&x, &mut o, Some([0x5a; 16]));
    assert_eq!(ev.health.health.probe_policy, ProbePolicy::Open);

    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ProvenanceUnverifiedOpenPolicy);
    assert_ne!(r.result, ReconciliationResult::UnattributedEffect);

    // Control: the same scene under RegisteredOnly reaches the accusation, so
    // the refusal above is the policy and nothing else.
    let mut o = Observer::new(true, true);
    let (ev, target, c) = observation_scene(&x, &mut o, Some([0x5a; 16]));
    assert_eq!(ev.health.health.probe_policy, ProbePolicy::RegisteredOnly);
    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.result, ReconciliationResult::UnattributedEffect);
}

/// O-02. A duplicate attested batch is collapsed *and flagged* on the
/// observation path. t15 pins this on the expectation path; the observation
/// path carried the same assignment and no test read it.
///
/// The flag is not cosmetic: it is a field of the canonical record, so a
/// consumer reading a record that silently dropped a replay cannot tell the
/// difference between "one batch" and "the same batch twice".
#[test]
fn t26_a_replayed_batch_is_flagged_on_the_observation_path() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let (mut ev, target, c) = observation_scene(&x, &mut o, Some([0x5a; 16]));

    let r = reconcile_observation(&ev, target, &c);
    assert!(!r.replay_detected, "the honest chain carries no replay");
    assert_eq!(r.result, ReconciliationResult::UnattributedEffect);

    // The same batch, byte-identical, submitted twice.
    let dup = ev.batches[1].clone();
    ev.batches.push(dup);
    let r = reconcile_observation(&ev, target, &c);
    assert!(
        r.replay_detected,
        "a byte-identical duplicate is a replay and the record must say so"
    );
    // Collapsing it must not change what the evidence establishes.
    assert_eq!(r.result, ReconciliationResult::UnattributedEffect);
}

/// O-03 and O-05. A target names exactly one record. A batch sequence that is
/// not present, or a kernel-event index that is not present, is
/// `TargetNotFound` — never the nearest batch and never record zero.
///
/// t05b covered a missing *observation* index only. Substituting a different
/// record for the one the target names would let a verifier ask about one
/// event and be answered about another, which is the whole content of an
/// attribution.
///
/// **The fixture matters more than the assertion here.** A first attempt used
/// a chain whose other records did not exist, so a fallback to "the first
/// batch" or "record zero" still found nothing and still returned
/// `TargetNotFound` — the test passed and the mutation lived. Both batches
/// below therefore carry a record at index 0, and batch 2 carries a kernel
/// event, so a fallback is *observable*: it answers instead of refusing.
#[test]
fn t27_a_target_names_exactly_one_record() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let now = x.now;
    let at = at_of(&x);

    let decoy = o.present(other_process(), None, now - 1_500);
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![decoy]);
    let claim = AgentClaim {
        decision_id: Some([0x5a; 16]),
        ..claim_for(&x)
    };
    let obs = o.present(process_of(&x.ee), Some(&claim), now + 10);
    o.probe.ingest_kernel_event(exec_event(PID, 5_000));
    let b2 = o.batch(2, now - 1_000, at, vec![obs]);
    let ev = o.evidence(vec![b1, b2], at);

    // The fixture's own preconditions: a fallback would find something.
    assert!(!ev.batches[0].batch.observations.is_empty());
    assert!(!ev.batches[1].batch.observations.is_empty());
    assert_eq!(ev.batches[1].batch.kernel_events.len(), 1);

    let c = ctx(&x, &o, at);

    // A sequence the chain does not contain. Falling back to batch 1 would
    // answer about the decoy.
    let r = reconcile_observation(
        &ev,
        ObservationTarget::Observation {
            batch_sequence: ObserverSequence(99),
            index: 0,
        },
        &c,
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::TargetNotFound);

    // An observation index the batch does not contain. Falling back to
    // observation zero would answer about the authorised instance.
    let r = reconcile_observation(
        &ev,
        ObservationTarget::Observation {
            batch_sequence: ObserverSequence(2),
            index: 9,
        },
        &c,
    );
    assert_eq!(r.reason, ReasonCode::TargetNotFound);

    // A kernel-event index the batch does not contain. Batch 2 holds exactly
    // one event, so index 7 is absent and a fallback to event zero would
    // answer about it.
    let r = reconcile_observation(
        &ev,
        ObservationTarget::KernelEvent {
            batch_sequence: ObserverSequence(2),
            index: 7,
        },
        &c,
    );
    assert_eq!(r.reason, ReasonCode::TargetNotFound);

    // A sequence the chain does not contain, on the kernel-event target.
    let r = reconcile_observation(
        &ev,
        ObservationTarget::KernelEvent {
            batch_sequence: ObserverSequence(99),
            index: 0,
        },
        &c,
    );
    assert_eq!(r.reason, ReasonCode::TargetNotFound);
}

/// O-07. The record cites the observation it is about.
///
/// A reconciliation whose evidence list does not name its own target is a
/// verdict about nothing an auditor can locate. t07b asserts the
/// `KernelEvent` ref on the *expectation* path; nothing asserted it here, so
/// the push could be deleted and every existing assertion still held.
#[test]
fn t28_the_observation_record_cites_its_own_target() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let (ev, _, c) = observation_scene(&x, &mut o, Some([0x5a; 16]));

    let r = reconcile_observation(
        &ev,
        ObservationTarget::Observation {
            batch_sequence: ObserverSequence(2),
            index: 0,
        },
        &c,
    );
    assert!(
        r.evidence.iter().any(|e| matches!(
            e,
            EvidenceRef::Observation {
                batch_sequence: ObserverSequence(2),
                index: 0
            }
        )),
        "the record must name the observation it is about: {:?}",
        r.evidence
    );
}

/// O-09. The window carried into the expected-side comparison is the batch's
/// **whole** claimed window, not a point inside it.
///
/// `covers` is `from >= self.from && to <= self.to`, so collapsing the
/// observation's window to a single instant makes almost any statement cover
/// it. A decision point that attested completeness over one millisecond
/// would then settle a batch spanning seconds — and the accusation would
/// rest on a statement that never covered the period it is about.
///
/// The statement below covers the batch's start instant and stops short of
/// its end: correct behaviour refuses it, and the mutation accepts it.
#[test]
fn t29_the_expected_side_must_cover_the_whole_batch_window_not_an_instant() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let (ev, target, mut c) = observation_scene(&x, &mut o, Some([0x5a; 16]));

    let from = ev.batches[1].batch.claimed_from_ms;
    let to = ev.batches[1].batch.claimed_to_ms;
    assert!(to > from, "the fixture's batch must span a real interval");

    // Covers the opening instant and nothing more.
    let stmt = coverage_statement(
        &x,
        &x.agent_id,
        CoverageWindow {
            from_ms: from,
            to_ms: from,
        },
        vec![],
        at_of(&x),
    );
    c.expected_side = ExpectedSideCoverage::Attested(Box::new(stmt));

    let r = reconcile_observation(&ev, target, &c);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ExpectedSideStatementDoesNotCover);
    assert_ne!(
        r.result,
        ReconciliationResult::UnattributedEffect,
        "a statement covering one instant cannot settle a batch spanning an interval"
    );
}

/// O-10. Availability over the window is **computed** from the signed health
/// record, never asserted by the reconciler.
///
/// `ObservationAvailability` is a field of the canonical record and the input
/// a downstream consumer reads to decide whether a window was watched at all.
/// Hard-coding it to `Covered` would make every observation-path record claim
/// coverage the health record does not support.
#[test]
fn t30_availability_on_the_observation_path_is_computed_from_the_health_record() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let (ev, target, mut c) = observation_scene(&x, &mut o, Some([0x5a; 16]));

    // Honest: the health record covers the batch window.
    let r = reconcile_observation(&ev, target, &c);
    assert!(r.availability.is_covered());

    // The verifier's staleness bound is tighter than the health record's age,
    // so the same evidence yields an uncovered window — the health record
    // decides, not the reconciler.
    c.health_max_age_ms = 0;
    c.verification_time_ms = ev.health.health.emitted_at_ms + 10_000;
    let r = reconcile_observation(&ev, target, &c);
    assert!(
        !r.availability.is_covered(),
        "availability must follow the health record, not a constant: {:?}",
        r.availability
    );
}

// ═══ 3h. The ghost the coverage predicate used to step over ═══

/// An execution the observer **saw and could not bind** is not a dropped
/// event: the loss counter is still a counted zero, the window is still
/// gap-free, the probe still ran once. It is a hole in *attribution* rather
/// than in *coverage*, and until this test it was invisible to the verdict
/// path.
///
/// That matters for exactly one verdict. `PhantomClaim` says *the authorised
/// execution never happened*, and it is derived from the absence of any
/// reference to the expectation. An unattributable execution inside the same
/// window is a candidate that absence cannot rule out — the authorised
/// program may have been that very event, witnessed and unmeasurable. Drawing
/// "it never happened" over it would be a false accusation manufactured from
/// the observer's own blind spot.
///
/// This is not hypothetical arithmetic. On the sealed Phase-1 agent run,
/// **84 of 105 `execve` events could not be bound** — short-lived children
/// exiting before a pidfd-anchored measurement completes. A host of that
/// shape is where this verdict would have been wrong.
fn unbound_exec(pid: u32, ts_ns: u64) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessExec {
            pid,
            old_pid: pid,
            filename: "/usr/bin/something".into(),
        },
        cpu: 0,
        kernel_timestamp_ns: ts_ns,
        probe_seq: 1,
        // The whole point: seen, not measured.
        bound: None,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

#[test]
fn t03h_an_unbound_process_event_in_the_window_forbids_phantom_claim() {
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let filler = o.present(other_process(), None, x.now + 10);

    // Exactly t03's setup — which reaches PhantomClaim — except that the
    // covering batch also carries one execution the observer could not bind.
    let b1 = o.batch(1, x.now - 2_000, x.now - 1_000, vec![]);
    let b2 = o.batch_with_kernel(
        2,
        x.now - 1_000,
        at,
        vec![filler],
        vec![unbound_exec(4_242, 1_000)],
    );
    let ev = o.evidence(vec![b1, b2], at);

    // Coverage itself is impeccable by the predicate's own standards:
    // kernel-pushed and gap-free. `t03i` proves exactly that, by reaching
    // PhantomClaim from the identical setup with the unbound event removed —
    // so the refusal below is caused by the unattributable execution and by
    // nothing else.
    assert!(ev.health.covered_by_kernel_pushed_source());

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(
        r.result,
        ReconciliationResult::CannotProve,
        "an unattributable execution in the window must not become a phantom claim"
    );
    assert_eq!(r.reason, ReasonCode::CoverageUnboundProcessEvent);
}

#[test]
fn t03i_the_same_window_without_the_unbound_event_still_reaches_phantom_claim() {
    // The companion that makes t03h non-vacuous. If the predicate had simply
    // been broken, this would fail too and the tightening would be a denial
    // of service on the system's central verdict rather than a correction.
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let filler = o.present(other_process(), None, x.now + 10);

    let b1 = o.batch(1, x.now - 2_000, x.now - 1_000, vec![]);
    let b2 = o.batch_with_kernel(2, x.now - 1_000, at, vec![filler], vec![]);
    let ev = o.evidence(vec![b1, b2], at);

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::PhantomClaim);
    assert_eq!(r.reason, ReasonCode::KernelCoverageWithNoReference);
}

#[test]
fn t03j_a_bound_process_event_does_not_block_the_verdict() {
    // The rule is about *unattributable* executions, not about kernel events
    // being present at all. An execution the observer measured is accounted
    // for; it narrows nothing.
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let filler = o.present(other_process(), None, x.now + 10);

    let mut bound_event = unbound_exec(4_242, 1_000);
    bound_event.bound = Some(ObservedProcess {
        process: aip_types::ProcessInstance {
            pid: 4_242,
            pid_start_time_ticks: 900,
            boot_id: [0x11; 16],
        },
        exe_content_sha256: sha256(b"an unrelated program"),
        exe_path: "/usr/bin/something".into(),
        container: None,
    });

    let b1 = o.batch(1, x.now - 2_000, x.now - 1_000, vec![]);
    let b2 = o.batch_with_kernel(2, x.now - 1_000, at, vec![filler], vec![bound_event]);
    let ev = o.evidence(vec![b1, b2], at);

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(
        r.result,
        ReconciliationResult::PhantomClaim,
        "a measured execution is accounted for and does not withhold the verdict"
    );
}
