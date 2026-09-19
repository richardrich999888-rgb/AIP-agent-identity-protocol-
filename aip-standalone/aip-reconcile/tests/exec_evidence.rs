//! Process execution as action evidence — adversarial, FIXTURE-BASED.
//!
//! The kernel events here are constructed so every field can be controlled
//! and mutated; the live path (real `perf_event_open` on
//! `sched:sched_process_fork` / `sched_process_exec`, real processes) is in
//! `ghost-demo/tests/live_exec.rs`. These tests pin the predicate:
//!
//! ```text
//! ProcessSpawn bound to the authorized instance (the actor, anchored at fork)
//! + ProcessExec of that child, bound at exec, image hash == authorized hash
//! + child start tick within [fork − tick, exec] through the clock anchor
//! + claimed under this decision by this agent
//! + placed inside the window (collector clock, then anchor)
//! + both carrying batches inside attested coverage
//! + RegisteredOnly, Active
//! = VERIFIED_EXECUTION · Attested · Transition · SchedTracepoint
//! ```

use aip_authorize::*;
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_reconcile::*;
use aip_types::{
    CapabilityScope, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple,
    EXECUTION_BINDING_VERSION,
};

const PID: u32 = 3_900_601;
const CHILD: u32 = 3_900_602;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-x";
const PROBE_ID: &str = "probe-x";
const RUN: [u8; 16] = [0x78; 16];
const ANCHOR_BOOT_NS: u64 = 100_000_000_000;
const CLK_TCK: u32 = 100;
const TICK_NS: u64 = 10_000_000;

fn image_hash() -> [u8; 32] {
    sha256(b"/bin/sleep image contents")
}

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
    now: u64,
}

fn binding(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: PID,
            pid_start_time_ticks: 900_000,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v5"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

fn expected_for(hash: [u8; 32]) -> Expected {
    let scope = CapabilityScope {
        allowed: vec![process_exec_action()],
        denied: vec![],
    };
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("payments-agent"), None).unwrap();
    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope.clone(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(&root, &orch_kp.private_key, &agent_aid.id, scope).unwrap();
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
        action_kind: process_exec_action(),
        parameters: process_exec_parameters(hash),
        execution_binding: binding(&agent_aid.id),
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

fn expected() -> Expected {
    expected_for(image_hash())
}

struct Observer {
    signer: CollectorSigner,
    anchors: ObserverTrustAnchors,
}

impl Observer {
    fn new() -> Self {
        Self::with(true, &SourceMechanism::ALL)
    }
    fn with(registered: bool, mechanisms: &[SourceMechanism]) -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        if registered {
            signer.register_probe(PROBE_ID, mechanisms);
        }
        let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
        Self { signer, anchors }
    }
}

fn actor_of(ee: &ExpectedExecution) -> ObservedProcess {
    ObservedProcess {
        process: ee.execution_binding.process,
        exe_content_sha256: ee.execution_binding.exe_content_sha256,
        exe_path: ee.execution_binding.exe_path.clone(),
    }
}

/// The child as the probe anchors it at exec: started in the tick of the
/// fork, running the given image.
fn child_at(fork_ns: u64, hash: [u8; 32]) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: CHILD,
            pid_start_time_ticks: fork_ns / TICK_NS,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: hash,
        exe_path: "/usr/bin/sleep".into(),
    }
}

fn claim(x: &Expected) -> AgentClaim {
    AgentClaim {
        agent_id: x.agent_id.clone(),
        claim_source: "orchestrator".into(),
        decision_id: Some(x.ee.decision_id),
    }
}

fn attribution(c: Option<&AgentClaim>) -> (AgentAttribution, Option<[u8; 16]>) {
    match c {
        None => (AgentAttribution::NotEstablished, None),
        Some(c) => (
            AgentAttribution::Claimed {
                agent_id: c.agent_id.clone(),
                claim_source: c.claim_source.clone(),
            },
            c.decision_id,
        ),
    }
}

fn spawn(
    seq: u64,
    ts_ns: u64,
    child_pid: u32,
    bound: Option<ObservedProcess>,
    c: Option<&AgentClaim>,
) -> KernelLifecycleEvent {
    let (attribution, claimed_decision_id) = attribution(c);
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessSpawn {
            parent_pid: PID,
            child_pid,
            parent_comm: "agent".into(),
            child_comm: "agent".into(),
        },
        cpu: 0,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution,
        claimed_decision_id,
    }
}

fn exec(
    seq: u64,
    ts_ns: u64,
    pid: u32,
    filename: &str,
    bound: Option<ObservedProcess>,
) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessExec {
            pid,
            old_pid: pid,
            filename: filename.into(),
        },
        cpu: 1,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

#[allow(clippy::too_many_arguments)] // a fixture: every field is a knob
fn raw_batch(
    id: u8,
    from: u64,
    to: u64,
    seq: (u64, u64),
    events: Vec<KernelLifecycleEvent>,
    anchor: Option<BootClockAnchor>,
    dropped: Option<u64>,
) -> ObservationBatch {
    ObservationBatch {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        batch_id: [id; 16],
        probe_run_id: RUN,
        probe_seq_first: seq.0,
        probe_seq_last: seq.1,
        dropped_events: dropped,
        active_mechanisms: SourceMechanism::canonical_set(vec![
            SourceMechanism::PidFdAnchored,
            SourceMechanism::SchedTracepoint,
        ]),
        mechanism_integrity: Vec::new(),
        claimed_from_ms: from,
        claimed_to_ms: to,
        observations: vec![],
        kernel_events: events,
        clock_anchor: anchor,
    }
}

fn anchor_at(wall_ms: u64) -> BootClockAnchor {
    BootClockAnchor {
        realtime_ms: wall_ms,
        boottime_ns: ANCHOR_BOOT_NS,
        monotonic_ns: ANCHOR_BOOT_NS,
        clk_tck: CLK_TCK,
    }
}

fn boot_ns_for(wall_ms: u64, anchor_wall: u64) -> u64 {
    ANCHOR_BOOT_NS + (wall_ms - anchor_wall) * 1_000_000
}

fn ctx(x: &Expected, o: &Observer, at: u64) -> ReconciliationContext {
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

struct Honest {
    x: Expected,
    o: Observer,
    ev: ObserverEvidence,
    at: u64,
}

/// Epoch-start batch, then one batch `[now+2s, now+4s]` carrying the spawn
/// (placed at `fork_wall`) and, if `with_exec`, the exec 3 ms later.
#[allow(clippy::too_many_arguments)] // a fixture: every field is a knob
fn honest_with(
    x: Expected,
    mut o: Observer,
    fork_wall: u64,
    attested_at: Option<u64>,
    anchor: bool,
    c: Option<&AgentClaim>,
    with_exec: bool,
    actor: Option<ObservedProcess>,
    child_hash: [u8; 32],
) -> Honest {
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = anchor.then(|| anchor_at(anchor_wall));
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a, Some(0)),
            now - 1_000,
        )
        .unwrap();
    let fork_ns = boot_ns_for(fork_wall, anchor_wall);
    let mut events = vec![spawn(1, fork_ns, CHILD, actor, c)];
    if with_exec {
        events.push(exec(
            2,
            fork_ns + 3_000_000,
            CHILD,
            "/usr/bin/sleep",
            Some(child_at(fork_ns, child_hash)),
        ));
    }
    let last = events.len() as u64;
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now + 2_000, now + 4_000, (1, last), events, a, Some(0)),
            attested_at.unwrap_or(now + 4_000),
        )
        .unwrap();
    let at = now + 5_000;
    let health = o.signer.health(at).unwrap();
    Honest {
        x,
        o,
        ev: ObserverEvidence {
            batches: vec![b1, b2],
            health,
        },
        at,
    }
}

fn honest() -> Honest {
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let fork_wall = x.now + 3_000;
    honest_with(
        x,
        Observer::new(),
        fork_wall,
        None,
        true,
        Some(&c),
        true,
        Some(actor),
        image_hash(),
    )
}

fn reconcile(h: &Honest) -> Reconciliation {
    reconcile_expectation(&h.x.ee, Some(&h.ev), &ctx(&h.x, &h.o, h.at))
}

// ═══ Positive ═══

#[test]
fn xe01_bound_spawn_plus_exec_of_the_authorized_image_verifies_as_transition() {
    let h = honest();
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested, "never Proven");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceMatches);
    match r.action {
        ActionComparison::Match(seal) => {
            assert_eq!(seal.kind(), ActionEvidenceKind::Transition);
            assert_eq!(seal.mechanism(), SourceMechanism::SchedTracepoint);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
    let kernel_refs = r
        .evidence
        .iter()
        .filter(|e| matches!(e, EvidenceRef::KernelEvent { .. }))
        .count();
    assert_eq!(kernel_refs, 2, "fork and exec both referenced");
}

/// The kernel's `filename` is context: the digest is the image content.
#[test]
fn xe02_the_path_never_enters_the_digest_only_the_content_does() {
    // Same hash, different path → verifies.
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let mut o = Observer::new();
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a, Some(0)),
            now - 1_000,
        )
        .unwrap();
    let fork_ns = boot_ns_for(now + 3_000, anchor_wall);
    let events = vec![
        spawn(1, fork_ns, CHILD, Some(actor), Some(&c)),
        exec(
            2,
            fork_ns + 3_000_000,
            CHILD,
            "/some/other/path/to/sleep",
            Some(child_at(fork_ns, image_hash())),
        ),
    ];
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now + 2_000, now + 4_000, (1, 2), events, a, Some(0)),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at).unwrap(),
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");

    // Different content, the "right" path → mismatch.
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let h = honest_with(
        x,
        Observer::new(),
        now + 3_000,
        None,
        true,
        Some(&c),
        true,
        Some(actor),
        sha256(b"a trojaned sleep at the same path"),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceDoesNotMatch);
    match r.action {
        ActionComparison::Mismatch(seal) => {
            assert_eq!(seal.kind(), ActionEvidenceKind::Transition);
            assert_eq!(seal.mechanism(), SourceMechanism::SchedTracepoint);
        }
        other => panic!("{other:?}"),
    }
}

// ═══ Pairing ═══

#[test]
fn xe03_spawn_without_exec_is_an_attempt_not_an_execution() {
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        x.now + 3_000,
        None,
        true,
        Some(&c),
        false,
        Some(actor),
        image_hash(),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionTransitionIncomplete);
}

impl Expected {
    fn clone_for_test(&self) -> Expected {
        Expected {
            ee: self.ee.clone(),
            anchors: self.anchors.clone(),
            agent_id: self.agent_id.clone(),
            agent_kp: self.agent_kp.clone(),
            now: self.now,
        }
    }
}

#[test]
fn xe04_exec_of_another_pid_earlier_than_fork_or_recycled_child_does_not_pair() {
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let fork_ns = boot_ns_for(now + 3_000, anchor_wall);
    let recycled = ObservedProcess {
        process: ProcessInstance {
            pid: CHILD,
            // Started 5 ticks before the fork: not the forked child.
            pid_start_time_ticks: fork_ns / TICK_NS - 5,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: image_hash(),
        exe_path: "/usr/bin/sleep".into(),
    };
    let cases: [(&str, KernelLifecycleEvent); 3] = [
        (
            "other pid",
            exec(
                2,
                fork_ns + 3_000_000,
                CHILD + 7,
                "/usr/bin/sleep",
                Some(child_at(fork_ns, image_hash())),
            ),
        ),
        (
            "exec before fork",
            exec(
                2,
                fork_ns - 1,
                CHILD,
                "/usr/bin/sleep",
                Some(child_at(fork_ns, image_hash())),
            ),
        ),
        (
            "recycled pid",
            exec(
                2,
                fork_ns + 3_000_000,
                CHILD,
                "/usr/bin/sleep",
                Some(recycled),
            ),
        ),
    ];
    for (label, e) in cases {
        let mut o = Observer::new();
        let b1 = o
            .signer
            .attest_at(
                raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a, Some(0)),
                now - 1_000,
            )
            .unwrap();
        let events = vec![spawn(1, fork_ns, CHILD, Some(actor.clone()), Some(&c)), e];
        let b2 = o
            .signer
            .attest_at(
                raw_batch(2, now + 2_000, now + 4_000, (1, 2), events, a, Some(0)),
                now + 4_000,
            )
            .unwrap();
        let at = now + 5_000;
        let ev = ObserverEvidence {
            batches: vec![b1, b2],
            health: o.signer.health(at).unwrap(),
        };
        let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
        assert_ne!(
            r.result,
            ReconciliationResult::VerifiedExecution,
            "{label}: {r:?}"
        );
        assert_eq!(r.reason, ReasonCode::ActionTransitionIncomplete, "{label}");
    }
}

#[test]
fn xe05_unbound_exec_child_is_not_an_execution() {
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let fork_ns = boot_ns_for(now + 3_000, anchor_wall);
    let mut o = Observer::new();
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a, Some(0)),
            now - 1_000,
        )
        .unwrap();
    let events = vec![
        spawn(1, fork_ns, CHILD, Some(actor), Some(&c)),
        // The child exited before the probe could anchor it: unbound.
        exec(2, fork_ns + 3_000_000, CHILD, "/usr/bin/sleep", None),
    ];
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now + 2_000, now + 4_000, (1, 2), events, a, Some(0)),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at).unwrap(),
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionTransitionIncomplete);
}

// ═══ Actor binding ═══

#[test]
fn xe06_unbound_spawn_is_a_pid_reference_never_identity() {
    let x = expected();
    let c = claim(&x);
    let h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        x.now + 3_000,
        None,
        true,
        Some(&c),
        true,
        None,
        image_hash(),
    );
    let r = reconcile(&h);
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(
        r.identity,
        IdentityComparison::UnboundReferencesOnly { references: 1 }
    );
}

#[test]
fn xe07_spawn_by_another_instance_never_verifies() {
    let x = expected();
    let base = actor_of(&x.ee);
    let mut other_start = base.clone();
    other_start.process.pid_start_time_ticks += 1;
    let mut other_boot = base.clone();
    other_boot.process.boot_id = [0x5f; 16];
    let mut other_exe = base.clone();
    other_exe.exe_content_sha256 = sha256(b"another binary");
    for (label, actor) in [
        ("same pid, later start", other_start),
        ("other boot", other_boot),
        ("other executable", other_exe),
    ] {
        let x = expected();
        let c = claim(&x);
        let h = honest_with(
            x.clone_for_test(),
            Observer::new(),
            x.now + 3_000,
            None,
            true,
            Some(&c),
            true,
            Some(actor),
            image_hash(),
        );
        let r = reconcile(&h);
        assert_ne!(
            r.result,
            ReconciliationResult::VerifiedExecution,
            "{label}: {r:?}"
        );
        assert_ne!(
            r.identity,
            IdentityComparison::Match { observations: 1 },
            "{label}"
        );
    }
}

// ═══ Temporal ═══

#[test]
fn xe08_spawn_before_the_decision_precedes_authorization() {
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        x.now - 5_000,
        None,
        true,
        Some(&c),
        true,
        Some(actor.clone()),
        image_hash(),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionPrecedesAuthorization);
    assert_eq!(r.temporal, TemporalComparison::BeforeWindow);

    // Collector clock overrides a host anchor claiming "inside".
    let x = expected();
    let c = claim(&x);
    let h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        x.now + 3_000,
        Some(x.now - 100),
        true,
        Some(&c),
        true,
        Some(actor),
        image_hash(),
    );
    let r = reconcile(&h);
    assert_eq!(r.reason, ReasonCode::ActionPrecedesAuthorization, "{r:?}");
}

#[test]
fn xe09_unanchored_and_after_window_do_not_verify() {
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        x.now + 3_000,
        None,
        false,
        Some(&c),
        true,
        Some(actor.clone()),
        image_hash(),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::KernelTimeUnanchored);
    assert_eq!(r.temporal, TemporalComparison::Unanchored);

    let x = expected();
    let c = claim(&x);
    let after = x.now + TTL + 1_000;
    let mut h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        after,
        None,
        true,
        Some(&c),
        true,
        Some(actor),
        image_hash(),
    );
    h.at = h.at.max(after + 2_000);
    h.ev.health = h.o.signer.health(h.at).unwrap();
    let r = reconcile(&h);
    assert_eq!(r.reason, ReasonCode::ActionEvidenceOutsideWindow, "{r:?}");
    assert_eq!(r.temporal, TemporalComparison::AfterWindow);
}

// ═══ Claims, replay ═══

#[test]
fn xe10_spawn_claimed_under_another_decision_agent_or_nothing_does_not_verify() {
    let x = expected();
    let actor = actor_of(&x.ee);
    let other_decision = AgentClaim {
        decision_id: Some([0x5a; 16]),
        ..claim(&x)
    };
    let h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        x.now + 3_000,
        None,
        true,
        Some(&other_decision),
        true,
        Some(actor.clone()),
        image_hash(),
    );
    let r = reconcile(&h);
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnclaimed, "{r:?}");

    let x = expected();
    let other_agent = AgentClaim {
        agent_id: "aip1someoneelseentirely".into(),
        ..claim(&x)
    };
    let h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        x.now + 3_000,
        None,
        true,
        Some(&other_agent),
        true,
        Some(actor.clone()),
        image_hash(),
    );
    let r = reconcile(&h);
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");

    let x = expected();
    let h = honest_with(
        x.clone_for_test(),
        Observer::new(),
        x.now + 3_000,
        None,
        true,
        None,
        true,
        Some(actor),
        image_hash(),
    );
    let r = reconcile(&h);
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnclaimed, "{r:?}");
}

#[test]
fn xe11_replayed_batch_is_flagged_and_counted_once() {
    let h = honest();
    let mut ev = h.ev.clone();
    ev.batches.push(ev.batches[1].clone());
    let r = reconcile_expectation(&h.x.ee, Some(&ev), &ctx(&h.x, &h.o, h.at));
    assert!(r.replay_detected);
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution);
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
}

// ═══ Integrity ═══

#[test]
fn xe12_mutating_any_signed_field_of_either_event_is_an_integrity_failure() {
    let h = honest();
    type Mut = fn(&mut KernelLifecycleEvent);
    let spawn_mut: [(&str, Mut); 6] = [
        ("parent pid", |e| set_spawn(e, |s| *s.0 ^= 1)),
        ("child pid", |e| set_spawn(e, |s| *s.1 ^= 1)),
        ("parent comm", |e| set_spawn(e, |s| s.2.push('x'))),
        ("child comm", |e| set_spawn(e, |s| s.3.push('x'))),
        ("kernel timestamp", |e| e.kernel_timestamp_ns ^= 1),
        ("claimed decision", |e| {
            e.claimed_decision_id = Some([0x11; 16])
        }),
    ];
    for (label, m) in spawn_mut {
        let mut forged = h.ev.clone();
        m(&mut forged.batches[1].batch.kernel_events[0]);
        let r = reconcile_expectation(&h.x.ee, Some(&forged), &ctx(&h.x, &h.o, h.at));
        assert_eq!(
            r.result,
            ReconciliationResult::SensorIntegrityFailure,
            "spawn {label}: {r:?}"
        );
        assert_eq!(r.strength, EvidenceStrength::Proven, "{label}");
    }
    let exec_mut: [(&str, Mut); 6] = [
        ("pid", |e| set_exec(e, |s| *s.0 ^= 1)),
        ("old pid", |e| set_exec(e, |s| *s.1 ^= 1)),
        ("filename", |e| set_exec(e, |s| s.2.push('x'))),
        ("image hash", |e| {
            e.bound.as_mut().unwrap().exe_content_sha256[0] ^= 1
        }),
        ("child start", |e| {
            e.bound.as_mut().unwrap().process.pid_start_time_ticks ^= 1
        }),
        ("mechanism", |e| {
            e.mechanism = SourceMechanism::ProcConnector
        }),
    ];
    for (label, m) in exec_mut {
        let mut forged = h.ev.clone();
        m(&mut forged.batches[1].batch.kernel_events[1]);
        let r = reconcile_expectation(&h.x.ee, Some(&forged), &ctx(&h.x, &h.o, h.at));
        assert_eq!(
            r.result,
            ReconciliationResult::SensorIntegrityFailure,
            "exec {label}: {r:?}"
        );
    }
    // The anchor's CLK_TCK is signed too: it decides the start-tick check.
    let mut forged = h.ev.clone();
    forged.batches[1]
        .batch
        .clock_anchor
        .as_mut()
        .unwrap()
        .clk_tck ^= 1;
    let r = reconcile_expectation(&h.x.ee, Some(&forged), &ctx(&h.x, &h.o, h.at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
}

fn set_spawn(
    e: &mut KernelLifecycleEvent,
    f: impl FnOnce((&mut u32, &mut u32, &mut String, &mut String)),
) {
    if let KernelLifecycleKind::ProcessSpawn {
        parent_pid,
        child_pid,
        parent_comm,
        child_comm,
    } = &mut e.kind
    {
        f((parent_pid, child_pid, parent_comm, child_comm));
    } else {
        panic!("fixture event is not a spawn");
    }
}

fn set_exec(e: &mut KernelLifecycleEvent, f: impl FnOnce((&mut u32, &mut u32, &mut String))) {
    if let KernelLifecycleKind::ProcessExec {
        pid,
        old_pid,
        filename,
    } = &mut e.kind
    {
        f((pid, old_pid, filename));
    } else {
        panic!("fixture event is not an exec");
    }
}

// ═══ Provenance, loss, restart ═══

#[test]
fn xe13_unprovisioned_sched_events_are_refused_and_open_policy_does_not_verify() {
    let mut o = Observer::with(
        true,
        &[
            SourceMechanism::PidFdAnchored,
            SourceMechanism::ProcConnector,
        ],
    );
    let x = expected();
    let c = claim(&x);
    let b = raw_batch(
        2,
        x.now,
        x.now + 1,
        (1, 1),
        vec![spawn(1, 1, CHILD, Some(actor_of(&x.ee)), Some(&c))],
        None,
        Some(0),
    );
    let err = o.signer.attest_at(b, x.now + 1).unwrap_err();
    assert!(
        matches!(
            err,
            AttestError::MechanismNotProvisioned {
                mechanism: SourceMechanism::SchedTracepoint,
                ..
            }
        ),
        "{err:?}"
    );

    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let h = honest_with(
        x.clone_for_test(),
        Observer::with(false, &[]),
        x.now + 3_000,
        None,
        true,
        Some(&c),
        true,
        Some(actor),
        image_hash(),
    );
    let r = reconcile(&h);
    assert_eq!(
        r.reason,
        ReasonCode::ProvenanceUnverifiedOpenPolicy,
        "{r:?}"
    );
}

#[test]
fn xe14_loss_and_restart_block_verification() {
    let x = expected();
    let c = claim(&x);
    let actor = actor_of(&x.ee);
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let mut o = Observer::new();
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a, Some(0)),
            now - 1_000,
        )
        .unwrap();
    let fork_ns = boot_ns_for(now + 3_000, anchor_wall);
    let events = vec![
        spawn(1, fork_ns, CHILD, Some(actor), Some(&c)),
        exec(
            2,
            fork_ns + 3_000_000,
            CHILD,
            "/usr/bin/sleep",
            Some(child_at(fork_ns, image_hash())),
        ),
    ];
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now + 2_000, now + 4_000, (1, 2), events, a, Some(1)),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at).unwrap(),
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.reason, ReasonCode::ObserverDegraded, "{r:?}");

    let mut h = honest();
    h.o.signer.note_probe_restart();
    h.ev.health = h.o.signer.health(h.at).unwrap();
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::ContinuityFailure, "{r:?}");
}

// ═══ Coverage semantics ═══

/// A fork/exec stream is kernel-pushed but reaches the observer through the
/// perf-tracepoint eBPF submission gate, so a single foreign program could
/// blind it (the observation-integrity finding). It is therefore no longer
/// accepted as kernel-pushed *coverage* on its own — the coverage predicate
/// now requires a gate-independent mechanism — and, as before, it also carries
/// no exit and so fails the lifecycle check. Either way it cannot support a
/// `PHANTOM_CLAIM`; the reconcile outcome (`CoverageNotKernelPushed`, not
/// phantom) is unchanged, now defended at two layers instead of one.
#[test]
fn xe15_sched_coverage_alone_cannot_support_phantom_claim() {
    let x = expected();
    let mut o = Observer::new();
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], None, Some(0)),
            now - 1_000,
        )
        .unwrap();
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now - 1_000, at, (0, 0), vec![], None, Some(0)),
            at,
        )
        .unwrap();
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at).unwrap(),
    };
    // Sched coverage is gate-able, so it no longer counts as kernel-pushed
    // coverage on its own (the cross-mechanism requirement).
    assert!(!ev.health.covered_by_kernel_pushed_source());
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_ne!(r.result, ReconciliationResult::PhantomClaim, "{r:?}");
    assert_eq!(r.reason, ReasonCode::CoverageNotKernelPushed);
}

// ═══ Structural ═══

#[test]
fn xe16_no_caller_settable_field_and_the_record_names_the_class() {
    let h = honest();
    let r = reconcile(&h);
    let json = serde_json::to_string(&r).unwrap().to_lowercase();
    for forbidden in [
        "\"verified\":",
        "\"trusted\":",
        "kernel_verified",
        "confidence",
        "score",
        "severity",
        "risk",
    ] {
        assert!(!json.contains(forbidden), "`{forbidden}` in {json}");
    }
    assert!(json.contains("\"kind\":\"transition\""), "{json}");
    assert!(json.contains("schedtracepoint"), "{json}");
    // A socket transition and an exec transition of the same instance never
    // share a digest: distinct vocabularies.
    assert_ne!(
        process_exec_parameters(image_hash()).digest(),
        net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 5], 443)
            .unwrap()
            .digest()
    );
}
