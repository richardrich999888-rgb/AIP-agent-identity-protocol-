//! Skill 7 corrective pass — adversarial characterization of weaknesses the
//! first Stage 4 implementation permitted.
//!
//! Every test here asserts the **required** behaviour. Each one failed against
//! the implementation at commit `362695b`; the failure is the evidence that
//! the weakness was real. None of them weakens an assertion in
//! `adversarial.rs`, which is left untouched.
//!
//! The common thread: a batch's `claimed_from_ms` / `claimed_to_ms` and its
//! `active_mechanisms` are authored by the **host-side probe**, which the
//! threat model treats as untrusted, and the collector performs no validation
//! of them beyond the registry bound. The reconciler must therefore recompute
//! coverage from the batches it holds instead of trusting a derived scalar,
//! and must anchor that coverage to a time the collector itself signed.

use aip_authorize::*;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_observe::*;
use aip_reconcile::*;
use aip_types::{
    Action, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple, ScopeAction,
    EXECUTION_BINDING_VERSION,
};

const PID: u32 = 3_900_101;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-c";
const PROBE_ID: &str = "probe-c";

// ─── Fixtures ───

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

struct Expected {
    ee: ExpectedExecution,
    anchors: DecisionPointTrustAnchors,
    agent_id: String,
    agent_kp: KeyPair,
    /// `ee.issued_at`; the authorized window is `[now, now + TTL]`.
    now: u64,
}

fn expected() -> Expected {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("payments-agent"), None).unwrap();

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
        parameters: ActionParameters::from_pairs([("invoice", b"INV-2026-0199".to_vec())]).unwrap(),
        execution_binding: ExecutionBinding {
            version: EXECUTION_BINDING_VERSION,
            agent_id: agent_aid.id.clone(),
            process: ProcessInstance {
                pid: PID,
                pid_start_time_ticks: 512_000,
                boot_id: [0x2c; 16],
            },
            exe_content_sha256: sha256(b"payments-agent binary v2"),
            exe_path: "/opt/agent/bin/payments-agent".into(),
            bound_at_ms: 1_700_000_000_000,
        },
        requested_ttl_ms: TTL,
    };
    let ee = match dp.authorize_at(&req, now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("fixture must authorize, got {d:?}"),
    };
    Expected {
        ee,
        anchors,
        agent_id: agent_aid.id,
        agent_kp,
        now,
    }
}

struct Observer {
    signer: CollectorSigner,
    probe: ProcfsProbe,
    kp: KeyPair,
    anchors: ObserverTrustAnchors,
}

impl Observer {
    fn new(kernel: bool) -> Self {
        Self::with_keypair(generate_ed25519_keypair(), kernel)
    }

    /// A collector signing with a caller-supplied key — used to model the
    /// case where the "observer" key is in fact the observed agent's key.
    fn with_keypair(kp: KeyPair, kernel: bool) -> Self {
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
        let mut probe = ProcfsProbe::new(PROBE_ID);
        probe.declare_source(if kernel {
            SourceMechanism::ProcConnector
        } else {
            SourceMechanism::ProcfsPoll
        });
        let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
        Self {
            signer,
            probe,
            kp,
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

    /// Re-sign a hand-edited health record with the collector's own key. This
    /// models a collector whose *derived* fields are wrong — a state-machine
    /// bug, or an operator who edited them — while every signature still
    /// verifies. The reconciler must not rely on a derived scalar it can
    /// recompute from the primary evidence it already holds.
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

fn ctx(x: &Expected, o: &Observer, verification_time_ms: u64) -> ReconciliationContext {
    ReconciliationContext {
        decision_point_anchors: x.anchors.clone(),
        observer_anchors: o.anchors.clone(),
        verification_time_ms,
        health_max_age_ms: HEALTH_MAX_AGE,
        window_tolerance_ms: 0,
        expected_side: ExpectedSideCoverage::Unknown,
    }
}

fn other_process() -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: 4_100_000,
            pid_start_time_ticks: 9,
            boot_id: [0x2c; 16],
        },
        exe_content_sha256: sha256(b"unrelated"),
        exe_path: "/usr/bin/unrelated".into(),
    }
}

// ═══ R1 — a hole between claimed windows is not coverage ═══

/// The collector unions batch claimed windows into `attested_coverage` and
/// never checks that they abut. A host-side probe can therefore claim two far
/// apart intervals and manufacture "coverage" over the gap between them —
/// which is exactly the interval in which the execution it wants to deny
/// would have happened. Silence inside a gap is not attested silence (I8).
#[test]
fn r1_gap_between_claimed_windows_cannot_support_phantom_claim() {
    let x = expected();
    let mut o = Observer::new(true);
    let now = x.now;
    let at = now + TTL + 1_000;
    // b1 opens the epoch (not part of attested coverage).
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    // b2 covers the first 5 s of the window, b3 the last 1 s. The 50 s
    // between them is claimed by nobody, yet the union spans the window.
    let b2 = o.batch(2, now - 1_000, now + 5_000, vec![]);
    let b3 = o.batch(3, now + 55_000, at, vec![]);
    let health = o.health(at);
    assert!(
        health
            .health
            .attested_coverage
            .unwrap()
            .covers(&CoverageWindow {
                from_ms: now,
                to_ms: now + TTL
            }),
        "precondition: the collector's union does span the window"
    );
    let ev = ObserverEvidence {
        batches: vec![b1, b2, b3],
        health,
    };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_ne!(
        r.result,
        ReconciliationResult::PhantomClaim,
        "50 s of the window was claimed by no batch: {r:?}"
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

// ═══ R2 — coverage may not extend past the observer's own signed clock ═══

/// A probe can claim a window that has not finished yet. The collector copies
/// the claim into `attested_coverage` without comparing it to its own clock,
/// so "no observation in [t, t+60s]" could be attested at t+1s — a statement
/// about the future dressed as evidence.
#[test]
fn r2_coverage_claimed_beyond_health_emission_cannot_support_phantom_claim() {
    let x = expected();
    let mut o = Observer::new(true);
    let now = x.now;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    // The probe claims to have sampled through the end of the window …
    let b2 = o.batch(2, now - 1_000, now + TTL, vec![]);
    // … but the collector signs its health only 1 s into that window.
    let emitted = now + 1_000;
    let health = o.health(emitted);
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health,
    };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, emitted));
    assert_ne!(
        r.result,
        ReconciliationResult::PhantomClaim,
        "the observer had not yet observed the end of the window: {r:?}"
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

// ═══ R3 — a health record dated after the verification time ═══

/// `availability_for` only bounds health that is too *old*. A record stamped
/// in the verifier's future saturates to "age 0" and is treated as fresh, so
/// a forward-set collector clock (or a replayed future record) silently
/// becomes usable evidence.
#[test]
fn r3_health_emitted_after_the_verification_time_is_not_usable() {
    let x = expected();
    let mut o = Observer::new(true);
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let b2 = o.batch(2, now - 1_000, at, vec![]);
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.health(at),
    };

    // The verifier's clock is a full window behind the health record.
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, now));
    assert_ne!(
        r.result,
        ReconciliationResult::PhantomClaim,
        "health is dated in the verifier's future: {r:?}"
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

// ═══ R4 — kernel coverage must be recomputable from the batches ═══

/// `covered_by` is a scalar the collector derives by intersecting
/// `active_mechanisms` over the epoch. The reconciler holds those batches and
/// must recompute the intersection rather than trust the derived field — the
/// same rule the observer already applies to chain heads, which are always
/// recomputed and never read from a field.
#[test]
fn r4_kernel_coverage_must_be_recomputed_from_the_supplied_batches() {
    let x = expected();
    let mut o = Observer::new(false); // poll-only probe
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let b2 = o.batch(2, now - 1_000, at, vec![]);
    let mut h = o.health(at);
    assert_eq!(h.health.covered_by, vec![SourceMechanism::ProcfsPoll]);
    // The derived field now disagrees with the batches it was derived from.
    h.health.covered_by = vec![SourceMechanism::ProcConnector];
    let health = o.resign_health(h);
    assert_eq!(verify_signed_health(&health, &o.anchors), Ok(()));
    assert!(health.covered_by_kernel_pushed_source());
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health,
    };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_ne!(
        r.result,
        ReconciliationResult::PhantomClaim,
        "no supplied batch declares a kernel-pushed source: {r:?}"
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::CoverageNotKernelPushed);
}

// ═══ R5 — one coverage epoch means one probe run ═══

/// `probe_run_id` changes on probe restart. The collector reacts by opening a
/// fresh coverage epoch, but that reaction lives entirely in a derived field.
/// The reconciler holds the run ids and must check them itself: a restart
/// inside the window means the window was not continuously sampled, whatever
/// the health record says.
#[test]
fn r5_probe_restart_inside_the_window_cannot_support_phantom_claim() {
    let x = expected();
    let mut o = Observer::new(true);
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let b2 = o.batch(2, now - 1_000, now + 30_000, vec![]);
    let coverage_before = o.health(now + 30_000).health.attested_coverage.unwrap();
    // The probe restarts: a new run id, no back-fill of the first run.
    let mut restarted = ProcfsProbe::new(PROBE_ID);
    restarted.declare_source(SourceMechanism::ProcConnector);
    o.probe = restarted;
    let b3 = o.batch(3, now + 30_000, at, vec![]);
    assert_ne!(b2.batch.probe_run_id, b3.batch.probe_run_id);

    // A health record whose coverage spans both runs — what the collector
    // would produce if its epoch bookkeeping were wrong.
    let mut h = o.health(at);
    h.health.state = ObserverState::Active;
    h.health.continuity = ContinuityStatus::Verified;
    h.health.attested_coverage = Some(CoverageWindow {
        from_ms: coverage_before.from_ms,
        to_ms: at,
    });
    h.health.covered_by = vec![SourceMechanism::ProcConnector];
    let health = o.resign_health(h);
    assert_eq!(verify_signed_health(&health, &o.anchors), Ok(()));
    let ev = ObserverEvidence {
        batches: vec![b1, b2, b3],
        health,
    };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_ne!(
        r.result,
        ReconciliationResult::PhantomClaim,
        "the probe restarted mid-window: {r:?}"
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

// ═══ R6 — a decision claim naming a different agent is not divergence ═══

/// `claimed_decision_id` is agent-supplied and unauthenticated. Treating it
/// alone as the link to an expectation lets any process that can register a
/// claim attach itself to *someone else's* decision and produce an
/// `IDENTITY_DIVERGENCE` against that agent. The claim carries an
/// `agent_id` in the same breath; when the two disagree the pair is
/// internally inconsistent and cannot support a verdict about either party.
#[test]
fn r6_divergence_requires_the_claim_to_name_the_expected_agent() {
    let x = expected();
    let mut o = Observer::new(true);
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let framing_claim = AgentClaim {
        agent_id: "aip1someoneelseentirely".into(),
        claim_source: "orchestrator".into(),
        decision_id: Some(x.ee.decision_id), // the victim's decision
    };
    let obs = o.probe.observation(
        other_process(),
        ObservedEffect::ProcessPresent,
        Some(&framing_claim),
        now + 10,
    );
    let b2 = o.batch(2, now - 1_000, at, vec![obs]);
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.health(at),
    };

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_ne!(
        r.result,
        ReconciliationResult::IdentityDivergence,
        "the claim names another agent; nothing here diverges from {}: {r:?}",
        x.agent_id
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}
