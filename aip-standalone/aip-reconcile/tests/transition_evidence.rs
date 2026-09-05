//! Stage 7b — kernel-pushed socket-state transition evidence, adversarial.
//!
//! FIXTURE-BASED: the kernel events here are constructed, not captured, so
//! every field can be controlled and mutated. The live path — real
//! `perf_event_open` on `sock:inet_sock_set_state`, real processes — is in
//! `ghost-demo/tests/live_transition.rs`. These tests pin the predicate:
//!
//! ```text
//! bound CLOSE → SYN_SENT for the authorized instance and endpoint
//! + SYN_SENT → ESTABLISHED of the same kernel socket (sk)
//! + claimed under this decision by this agent
//! + placed inside the window (collector clock, then boot-clock anchor)
//! + both carrying batches inside attested coverage
//! + RegisteredOnly, Active
//! = VERIFIED_EXECUTION · Attested · kind Transition
//! ```
//!
//! and that every weaker or displaced set of facts is not.

use aip_authorize::*;
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_reconcile::*;
use aip_types::{
    CapabilityScope, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple, ScopeAction,
    EXECUTION_BINDING_VERSION,
};

const PID: u32 = 3_900_501;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-t";
const PROBE_ID: &str = "probe-t";
const REMOTE: [u8; 4] = [10, 0, 0, 5];
const PORT: u16 = 443;
const SK: u64 = 0xffff_9a0b_1234_5678;
const RUN: [u8; 16] = [0x77; 16];

// Boot clock: the anchor says boot-time 100 s == wall `ANCHOR_WALL`.
const ANCHOR_BOOT_NS: u64 = 100_000_000_000;

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
            boot_id: [0x4e; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v4"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
    }
}

fn expected_for(remote: [u8; 4], port: u16) -> Expected {
    let scope = CapabilityScope {
        allowed: vec![net_connect_action()],
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
        action_kind: net_connect_action(),
        parameters: net_connect_parameters(NetProtocol::Tcp, &remote, port).unwrap(),
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
    expected_for(REMOTE, PORT)
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

fn process_of(ee: &ExpectedExecution) -> ObservedProcess {
    ObservedProcess {
        process: ee.execution_binding.process,
        exe_content_sha256: ee.execution_binding.exe_content_sha256,
        exe_path: ee.execution_binding.exe_path.clone(),
    }
}

fn ep(addr: [u8; 4], port: u16) -> SocketEndpoint {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&addr);
    SocketEndpoint {
        addr: a,
        is_v6: false,
        port,
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

/// A `CLOSE → SYN_SENT` event (the `connect()` call), optionally bound.
fn syn_sent(
    seq: u64,
    ts_ns: u64,
    remote: [u8; 4],
    port: u16,
    sk: u64,
    bound: Option<ObservedProcess>,
    c: Option<&AgentClaim>,
) -> KernelLifecycleEvent {
    let (attribution, claimed_decision_id) = attribution(c);
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SockStateTracepoint,
        kind: KernelLifecycleKind::SocketState {
            protocol: SocketProtocol::Tcp,
            local: ep([127, 0, 0, 1], 0),
            remote: ep(remote, port),
            old_state: tcp_state::CLOSE,
            new_state: tcp_state::SYN_SENT,
            sk,
            current_pid: PID,
        },
        cpu: 1,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution,
        claimed_decision_id,
    }
}

/// A `SYN_SENT → ESTABLISHED` event: softirq context, never bound.
fn established(seq: u64, ts_ns: u64, remote: [u8; 4], port: u16, sk: u64) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SockStateTracepoint,
        kind: KernelLifecycleKind::SocketState {
            protocol: SocketProtocol::Tcp,
            local: ep([127, 0, 0, 1], 51_000),
            remote: ep(remote, port),
            old_state: tcp_state::SYN_SENT,
            new_state: tcp_state::ESTABLISHED,
            sk,
            current_pid: 0,
        },
        cpu: 1,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound: None,
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
    obs: Vec<ObservedExecution>,
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
            SourceMechanism::ProcNetTable,
            SourceMechanism::SockStateTracepoint,
        ]),
        claimed_from_ms: from,
        claimed_to_ms: to,
        observations: obs,
        kernel_events: events,
        clock_anchor: anchor,
    }
}

/// Anchor mapping boot-clock `ANCHOR_BOOT_NS` to wall `wall_ms`.
fn anchor_at(wall_ms: u64) -> BootClockAnchor {
    BootClockAnchor {
        realtime_ms: wall_ms,
        boottime_ns: ANCHOR_BOOT_NS,
    }
}

/// Boot-clock stamp that the anchor maps to `wall_ms`.
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

/// The honest transition scenario, parameterised.
///
/// Epoch-start batch at `now-2s`; one batch `[now+2s, now+4s]` carrying the
/// events, attested at `attested_at`, with `anchor`. The initiation is
/// stamped so the anchor places it at `syn_wall`, the completion 5 ms later.
struct Honest {
    x: Expected,
    o: Observer,
    ev: ObserverEvidence,
    at: u64,
}

#[allow(clippy::too_many_arguments)] // a fixture: every field is a knob
fn honest_with(
    x: Expected,
    mut o: Observer,
    syn_wall: u64,
    attested_at: Option<u64>,
    anchor: bool,
    c: Option<&AgentClaim>,
    completion: bool,
    bound: Option<ObservedProcess>,
) -> Honest {
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = anchor.then(|| anchor_at(anchor_wall));
    let b1 = o
        .signer
        .attest_at(
            raw_batch(
                1,
                now - 2_000,
                now - 1_000,
                (0, 0),
                vec![],
                vec![],
                a,
                Some(0),
            ),
            now - 1_000,
        )
        .unwrap();
    let syn_ns = boot_ns_for(syn_wall, anchor_wall);
    let mut events = vec![syn_sent(1, syn_ns, REMOTE, PORT, SK, bound, c)];
    if completion {
        events.push(established(2, syn_ns + 5_000_000, REMOTE, PORT, SK));
    }
    let last = events.len() as u64;
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (1, last),
                events,
                vec![],
                a,
                Some(0),
            ),
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
    let p = process_of(&x.ee);
    let syn_wall = x.now + 3_000;
    honest_with(
        x,
        Observer::new(),
        syn_wall,
        None,
        true,
        Some(&c),
        true,
        Some(p),
    )
}

fn reconcile(h: &Honest) -> Reconciliation {
    reconcile_expectation(&h.x.ee, Some(&h.ev), &ctx(&h.x, &h.o, h.at))
}

// ═══ Positive ═══

#[test]
fn tp01_bound_initiation_plus_completion_inside_the_window_verifies_as_transition() {
    let h = honest();
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested, "never Proven");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceMatches);
    match r.action {
        ActionComparison::Match(seal) => {
            assert_eq!(seal.kind(), ActionEvidenceKind::Transition);
            assert_eq!(seal.mechanism(), SourceMechanism::SockStateTracepoint);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
    // Both kernel events are referenced so a reader can re-derive the pair.
    let kernel_refs = r
        .evidence
        .iter()
        .filter(|e| matches!(e, EvidenceRef::KernelEvent { .. }))
        .count();
    assert_eq!(kernel_refs, 2);
}

// ═══ Temporal placement ═══

#[test]
fn tp02_initiation_anchored_before_the_window_precedes_authorization() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let before = x.now - 5_000;
    let h = honest_with(
        x,
        Observer::new(),
        before,
        None,
        true,
        Some(&c),
        true,
        Some(p),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionPrecedesAuthorization);
    assert_eq!(r.temporal, TemporalComparison::BeforeWindow);
    assert!(!r.action.is_observable());
}

/// The probe's anchor is a host claim. If it places the transition inside
/// the window but the collector had already signed the batch before the
/// decision existed, the collector's clock wins: the connection predates
/// the authorization whatever the host says.
#[test]
fn tp03_collector_attestation_before_the_decision_overrides_a_host_anchor() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let inside = x.now + 3_000;
    let attested_before = x.now - 100;
    let h = honest_with(
        x,
        Observer::new(),
        inside,
        Some(attested_before),
        true,
        Some(&c),
        true,
        Some(p),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionPrecedesAuthorization);
    assert_eq!(r.temporal, TemporalComparison::BeforeWindow);
}

#[test]
fn tp04_without_a_clock_anchor_kernel_time_is_not_compared_to_wall_time() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let inside = x.now + 3_000;
    let h = honest_with(
        x,
        Observer::new(),
        inside,
        None,
        false,
        Some(&c),
        true,
        Some(p),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::KernelTimeUnanchored);
    assert_eq!(r.temporal, TemporalComparison::Unanchored);
}

#[test]
fn tp05_initiation_anchored_after_the_window_does_not_verify() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let after = x.now + TTL + 1_000;
    // Health must be at/after verification; move both out.
    let mut h = honest_with(
        x,
        Observer::new(),
        after,
        None,
        true,
        Some(&c),
        true,
        Some(p),
    );
    h.at = h.at.max(after + 2_000);
    h.ev.health = h.o.signer.health(h.at).unwrap();
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceOutsideWindow);
    assert_eq!(r.temporal, TemporalComparison::AfterWindow);
}

// ═══ Completeness and pairing ═══

#[test]
fn tp06_initiation_without_completion_is_an_attempt_not_a_connection() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let inside = x.now + 3_000;
    let h = honest_with(
        x,
        Observer::new(),
        inside,
        None,
        true,
        Some(&c),
        false,
        Some(p),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionTransitionIncomplete);
}

#[test]
fn tp07_completion_of_a_different_socket_or_endpoint_does_not_pair() {
    for (label, sk, remote, port) in [
        ("other sk", SK ^ 1, REMOTE, PORT),
        ("other remote", SK, [10, 0, 0, 6], PORT),
        ("other port", SK, REMOTE, 8443),
    ] {
        let x = expected();
        let c = claim(&x);
        let p = process_of(&x.ee);
        let mut o = Observer::new();
        let now = x.now;
        let a = Some(anchor_at(now - 10_000));
        let b1 = o
            .signer
            .attest_at(
                raw_batch(
                    1,
                    now - 2_000,
                    now - 1_000,
                    (0, 0),
                    vec![],
                    vec![],
                    a,
                    Some(0),
                ),
                now - 1_000,
            )
            .unwrap();
        let syn_ns = boot_ns_for(now + 3_000, now - 10_000);
        let events = vec![
            syn_sent(1, syn_ns, REMOTE, PORT, SK, Some(p), Some(&c)),
            established(2, syn_ns + 5_000_000, remote, port, sk),
        ];
        let b2 = o
            .signer
            .attest_at(
                raw_batch(
                    2,
                    now + 2_000,
                    now + 4_000,
                    (1, 2),
                    events,
                    vec![],
                    a,
                    Some(0),
                ),
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

/// A completion that precedes its initiation in kernel time cannot be its
/// completion: pairing requires kernel-time order.
#[test]
fn tp08_completion_earlier_than_initiation_in_kernel_time_does_not_pair() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let mut o = Observer::new();
    let now = x.now;
    let a = Some(anchor_at(now - 10_000));
    let b1 = o
        .signer
        .attest_at(
            raw_batch(
                1,
                now - 2_000,
                now - 1_000,
                (0, 0),
                vec![],
                vec![],
                a,
                Some(0),
            ),
            now - 1_000,
        )
        .unwrap();
    let syn_ns = boot_ns_for(now + 3_000, now - 10_000);
    let events = vec![
        established(1, syn_ns - 1, REMOTE, PORT, SK),
        syn_sent(2, syn_ns, REMOTE, PORT, SK, Some(p), Some(&c)),
    ];
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (1, 2),
                events,
                vec![],
                a,
                Some(0),
            ),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at).unwrap(),
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.reason, ReasonCode::ActionTransitionIncomplete, "{r:?}");
}

// ═══ Instance binding ═══

#[test]
fn tp09_unbound_initiation_is_a_pid_reference_never_identity() {
    let x = expected();
    let c = claim(&x);
    let inside = x.now + 3_000;
    let h = honest_with(x, Observer::new(), inside, None, true, Some(&c), true, None);
    let r = reconcile(&h);
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(
        r.identity,
        IdentityComparison::UnboundReferencesOnly { references: 1 }
    );
}

#[test]
fn tp10_initiation_bound_to_another_instance_never_verifies() {
    let x = expected();
    let base = process_of(&x.ee);
    let mut other_start = base.clone();
    other_start.process.pid_start_time_ticks += 1;
    let mut other_boot = base.clone();
    other_boot.process.boot_id = [0x4f; 16];
    let mut other_exe = base.clone();
    other_exe.exe_content_sha256 = sha256(b"replaced binary");
    for (label, p) in [
        ("same pid, later start (PID reuse)", other_start),
        ("same pid+start, other boot (reboot)", other_boot),
        ("same tuple, other executable", other_exe),
    ] {
        let x = expected();
        let c = claim(&x);
        let inside = x.now + 3_000;
        let h = honest_with(
            x,
            Observer::new(),
            inside,
            None,
            true,
            Some(&c),
            true,
            Some(p),
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

/// The probe's binding rule, checked directly: an instance whose start tick
/// is later than the event's kernel time is not the instance that acted.
#[test]
fn tp11_start_time_rule_rejects_an_instance_started_after_the_event() {
    let mut p = process_of(&expected().ee);
    // 900_000 ticks at CLK_TCK=100 → 9_000 s of boot time.
    let tick_ns = 1_000_000_000 / 100;
    let start_ns = p.process.pid_start_time_ticks * tick_ns;
    assert!(instance_started_no_later_than(&p, start_ns));
    assert!(instance_started_no_later_than(&p, start_ns + 1));
    assert!(!instance_started_no_later_than(&p, start_ns - 1));
    p.process.pid_start_time_ticks += 1;
    assert!(!instance_started_no_later_than(&p, start_ns));
}

// ═══ Claims, replay, transplantation ═══

#[test]
fn tp12_transition_claimed_under_another_decision_or_agent_does_not_verify_this_one() {
    let x = expected();
    let p = process_of(&x.ee);
    let inside = x.now + 3_000;
    let other_decision = AgentClaim {
        decision_id: Some([0x5a; 16]),
        ..claim(&x)
    };
    let h = honest_with(
        x,
        Observer::new(),
        inside,
        None,
        true,
        Some(&other_decision),
        true,
        Some(p.clone()),
    );
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnclaimed);

    let x = expected();
    let other_agent = AgentClaim {
        agent_id: "aip1someoneelseentirely".into(),
        ..claim(&x)
    };
    let h = honest_with(
        x,
        Observer::new(),
        inside,
        None,
        true,
        Some(&other_agent),
        true,
        Some(p.clone()),
    );
    let r = reconcile(&h);
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");

    let x = expected();
    let h = honest_with(x, Observer::new(), inside, None, true, None, true, Some(p));
    let r = reconcile(&h);
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnclaimed, "{r:?}");
}

#[test]
fn tp13_replayed_batch_is_flagged_and_counted_once() {
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
fn tp14_mutating_any_signed_field_of_a_socket_event_is_an_integrity_failure() {
    let h = honest();
    type Mut = fn(&mut KernelLifecycleEvent);
    let mutations: [(&str, Mut); 12] = [
        ("protocol", |e| set_sock(e, |s| *s.0 = SocketProtocol::Tcp6)),
        ("local port", |e| set_sock(e, |s| s.1.port ^= 1)),
        ("remote addr", |e| set_sock(e, |s| s.2.addr[3] ^= 1)),
        ("remote port", |e| set_sock(e, |s| s.2.port ^= 1)),
        ("old state", |e| set_sock(e, |s| *s.3 = tcp_state::LISTEN)),
        ("new state", |e| {
            set_sock(e, |s| *s.4 = tcp_state::ESTABLISHED)
        }),
        ("sk", |e| set_sock(e, |s| *s.5 ^= 1)),
        ("current pid", |e| set_sock(e, |s| *s.6 ^= 1)),
        ("kernel timestamp", |e| e.kernel_timestamp_ns ^= 1),
        ("cpu", |e| e.cpu ^= 1),
        ("mechanism", |e| {
            e.mechanism = SourceMechanism::ProcConnector
        }),
        ("claimed decision", |e| {
            e.claimed_decision_id = Some([0x11; 16])
        }),
    ];
    for (label, m) in mutations {
        let mut forged = h.ev.clone();
        m(&mut forged.batches[1].batch.kernel_events[0]);
        let r = reconcile_expectation(&h.x.ee, Some(&forged), &ctx(&h.x, &h.o, h.at));
        assert_eq!(
            r.result,
            ReconciliationResult::SensorIntegrityFailure,
            "{label}: {r:?}"
        );
        assert_eq!(r.strength, EvidenceStrength::Proven, "{label}");
    }
    // The bound instance and the clock anchor are signed too.
    let mut forged = h.ev.clone();
    forged.batches[1].batch.kernel_events[0]
        .bound
        .as_mut()
        .unwrap()
        .process
        .pid_start_time_ticks ^= 1;
    let r = reconcile_expectation(&h.x.ee, Some(&forged), &ctx(&h.x, &h.o, h.at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    let mut forged = h.ev.clone();
    forged.batches[1]
        .batch
        .clock_anchor
        .as_mut()
        .unwrap()
        .realtime_ms ^= 1;
    let r = reconcile_expectation(&h.x.ee, Some(&forged), &ctx(&h.x, &h.o, h.at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    // And the collector's attestation clock: moving it is detected.
    let mut forged = h.ev.clone();
    forged.batches[1].attested_at_ms ^= 1;
    let r = reconcile_expectation(&h.x.ee, Some(&forged), &ctx(&h.x, &h.o, h.at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
}

type SockFields<'a> = (
    &'a mut SocketProtocol,
    &'a mut SocketEndpoint,
    &'a mut SocketEndpoint,
    &'a mut u8,
    &'a mut u8,
    &'a mut u64,
    &'a mut u32,
);

fn set_sock(e: &mut KernelLifecycleEvent, f: impl FnOnce(SockFields<'_>)) {
    if let KernelLifecycleKind::SocketState {
        protocol,
        local,
        remote,
        old_state,
        new_state,
        sk,
        current_pid,
    } = &mut e.kind
    {
        f((
            protocol,
            local,
            remote,
            old_state,
            new_state,
            sk,
            current_pid,
        ));
    } else {
        panic!("fixture event is not a socket state");
    }
}

// ═══ Provenance ═══

#[test]
fn tp15_socket_events_from_an_unprovisioned_probe_are_refused_at_attestation() {
    let mut o = Observer::with(
        true,
        &[
            SourceMechanism::PidFdAnchored,
            SourceMechanism::ProcNetTable,
            SourceMechanism::ProcConnector,
        ],
    );
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let b = raw_batch(
        2,
        x.now,
        x.now + 1,
        (1, 1),
        vec![syn_sent(1, 1, REMOTE, PORT, SK, Some(p), Some(&c))],
        vec![],
        None,
        Some(0),
    );
    let err = o.signer.attest_at(b, x.now + 1).unwrap_err();
    assert!(
        matches!(
            err,
            AttestError::MechanismNotProvisioned {
                mechanism: SourceMechanism::SockStateTracepoint,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn tp16_transition_evidence_under_open_policy_does_not_verify() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let inside = x.now + 3_000;
    let h = honest_with(
        x,
        Observer::with(false, &[]),
        inside,
        None,
        true,
        Some(&c),
        true,
        Some(p),
    );
    assert_eq!(h.ev.health.health.probe_policy, ProbePolicy::Open);
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ProvenanceUnverifiedOpenPolicy);
}

// ═══ Loss and restart ═══

#[test]
fn tp17_counted_loss_over_the_window_blocks_verification() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let mut o = Observer::new();
    let now = x.now;
    let a = Some(anchor_at(now - 10_000));
    let b1 = o
        .signer
        .attest_at(
            raw_batch(
                1,
                now - 2_000,
                now - 1_000,
                (0, 0),
                vec![],
                vec![],
                a,
                Some(0),
            ),
            now - 1_000,
        )
        .unwrap();
    let syn_ns = boot_ns_for(now + 3_000, now - 10_000);
    let events = vec![
        syn_sent(1, syn_ns, REMOTE, PORT, SK, Some(p), Some(&c)),
        established(2, syn_ns + 5_000_000, REMOTE, PORT, SK),
    ];
    // The perf ring reported one lost record over this batch.
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (1, 2),
                events,
                vec![],
                a,
                Some(1),
            ),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at).unwrap(),
    };
    assert_eq!(ev.health.health.state, ObserverState::Degraded);
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ObserverDegraded);
}

#[test]
fn tp18_probe_restart_is_continuity_failure_not_verification() {
    let mut h = honest();
    h.o.signer.note_probe_restart();
    h.ev.health = h.o.signer.health(h.at).unwrap();
    let r = reconcile(&h);
    assert_eq!(r.result, ReconciliationResult::ContinuityFailure, "{r:?}");
}

// ═══ Interaction with presence evidence ═══

/// The kernel shows the connection the table row describes was made before
/// the decision: presence evidence of that same connection must not verify.
#[test]
fn tp19_presence_of_a_connection_the_kernel_places_before_the_decision_does_not_verify() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let mut o = Observer::new();
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    // Before the decision: the connection is made (attested before too).
    let syn_ns = boot_ns_for(now - 5_000, anchor_wall);
    let early = vec![
        syn_sent(1, syn_ns, REMOTE, PORT, SK, Some(p.clone()), None),
        established(2, syn_ns + 5_000_000, REMOTE, PORT, SK),
    ];
    let b1 = o
        .signer
        .attest_at(
            raw_batch(
                1,
                now - 6_000,
                now - 4_000,
                (1, 2),
                early,
                vec![],
                a,
                Some(0),
            ),
            now - 4_000,
        )
        .unwrap();
    // Inside the window: the same connection (same local port 51000) is seen
    // in the table, claimed under the decision.
    let mut probe = ProcfsProbe::new(PROBE_ID);
    let obs = probe.observation_with(
        p.clone(),
        ObservedEffect::SocketObserved {
            protocol: SocketProtocol::Tcp,
            local: ep([127, 0, 0, 1], 51_000),
            remote: ep(REMOTE, PORT),
            state: TCP_ESTABLISHED,
            inode: 4242,
        },
        SourceMechanism::ProcNetTable,
        Some(&c),
        now + 3_000,
    );
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (3, 3),
                vec![],
                vec![obs],
                a,
                Some(0),
            ),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at).unwrap(),
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionPrecedesAuthorization);
    assert_eq!(r.temporal, TemporalComparison::BeforeWindow);
}

/// A different connection (other local port) to the same endpoint, made
/// before the decision, does not disqualify presence of a new one.
#[test]
fn tp20_a_preceding_connection_on_another_local_port_does_not_disqualify_presence() {
    let x = expected();
    let c = claim(&x);
    let p = process_of(&x.ee);
    let mut o = Observer::new();
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let syn_ns = boot_ns_for(now - 5_000, anchor_wall);
    let early = vec![
        syn_sent(1, syn_ns, REMOTE, PORT, SK, Some(p.clone()), None),
        established(2, syn_ns + 5_000_000, REMOTE, PORT, SK), // local port 51000
    ];
    let b1 = o
        .signer
        .attest_at(
            raw_batch(
                1,
                now - 6_000,
                now - 4_000,
                (1, 2),
                early,
                vec![],
                a,
                Some(0),
            ),
            now - 4_000,
        )
        .unwrap();
    let mut probe = ProcfsProbe::new(PROBE_ID);
    let obs = probe.observation_with(
        p,
        ObservedEffect::SocketObserved {
            protocol: SocketProtocol::Tcp,
            local: ep([127, 0, 0, 1], 52_000),
            remote: ep(REMOTE, PORT),
            state: TCP_ESTABLISHED,
            inode: 4243,
        },
        SourceMechanism::ProcNetTable,
        Some(&c),
        now + 3_000,
    );
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (3, 3),
                vec![],
                vec![obs],
                a,
                Some(0),
            ),
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
    assert_eq!(
        r.action.evidence_kind(),
        Some(ActionEvidenceKind::Presence),
        "presence evidence remains what it was: existence at the sample"
    );
}

// ═══ Phantom coverage is about processes, not sockets ═══

/// A live socket-state stream is kernel-pushed, but it says nothing about
/// whether a *process* existed. It must not stand in for lifecycle coverage
/// in a `PHANTOM_CLAIM`.
#[test]
fn tp21_socket_state_coverage_alone_cannot_support_phantom_claim() {
    let x = expected();
    let mut o = Observer::new();
    let now = x.now;
    let at = now + TTL + 1_000;
    let b1 = o
        .signer
        .attest_at(
            raw_batch(
                1,
                now - 2_000,
                now - 1_000,
                (0, 0),
                vec![],
                vec![],
                None,
                Some(0),
            ),
            now - 1_000,
        )
        .unwrap();
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now - 1_000, at, (0, 0), vec![], vec![], None, Some(0)),
            at,
        )
        .unwrap();
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at).unwrap(),
    };
    assert!(ev.health.covered_by_kernel_pushed_source());
    assert!(ev
        .health
        .health
        .covered_by
        .contains(&SourceMechanism::SockStateTracepoint));
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_ne!(r.result, ReconciliationResult::PhantomClaim, "{r:?}");
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::CoverageNotKernelPushed);
}

// ═══ Structural ═══

#[test]
fn tp22_no_caller_settable_field_and_kind_is_in_the_record() {
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
    assert!(json.contains("sockstatetracepoint"), "{json}");
    // The canonical encoding distinguishes presence from transition.
    let mut presence = r.clone();
    presence.action = ActionComparison::Unobservable;
    assert_ne!(presence.canonical_bytes(), r.canonical_bytes());
    let _ = ScopeAction::Custom(String::new());
}
