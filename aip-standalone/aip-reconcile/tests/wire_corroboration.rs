//! Gate 2 — wire corroboration of a kernel-reported connection, RED.
//!
//! The socket-state tracepoint says: *this instance called `connect()` and
//! the kernel later marked that socket ESTABLISHED*. The wire tap says: *a
//! SYN with these endpoints left through a device, and a SYN-ACK for it came
//! back*. They are two kernel paths (socket layer, device layer), joined by
//! the connection tuple and time. The reconciler reports whether the second
//! corroborates the first — and nothing more:
//!
//! - it never raises evidence strength: a corroborated verdict is still
//!   `Attested`, because both paths sit inside the same host's kernel;
//! - it never lowers a verdict: a missing or ambiguous wire picture is
//!   reported as such on the record, not converted into a violation, because
//!   the tap may simply not cover the path the packets took;
//! - it never stands alone: wire segments name no process, so a batch of
//!   them alone attributes nothing and verifies nothing.
//!
//! FIXTURE-BASED: events are constructed so tuples, flags, sequence numbers
//! and stamps can be mutated. The live path is `ghost-demo/tests/live_wire.rs`.

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

const PID: u32 = 3_950_501;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-w";
const PROBE_ID: &str = "probe-w";
const LOCAL: [u8; 4] = [127, 0, 0, 1];
const LOCAL_PORT: u16 = 51_000;
const REMOTE: [u8; 4] = [10, 0, 0, 5];
const PORT: u16 = 443;
const SK: u64 = 0xffff_9a0b_1234_5678;
const RUN: [u8; 16] = [0x7a; 16];
const IF_LO: u32 = 1;
const ANCHOR_BOOT_NS: u64 = 100_000_000_000;
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const ISN: u32 = 0x1234_5678;

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
        exe_content_sha256: sha256(b"payments-agent binary v5"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

fn expected() -> Expected {
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
        parameters: net_connect_parameters(NetProtocol::Tcp, &REMOTE, PORT).unwrap(),
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

struct Observer {
    signer: CollectorSigner,
    anchors: ObserverTrustAnchors,
}

impl Observer {
    fn new() -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
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

fn event(
    seq: u64,
    ts_ns: u64,
    mechanism: SourceMechanism,
    kind: KernelLifecycleKind,
) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism,
        kind,
        cpu: 1,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound: None,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

fn syn_sent(seq: u64, ts_ns: u64, bound: ObservedProcess, c: &AgentClaim) -> KernelLifecycleEvent {
    let mut e = event(
        seq,
        ts_ns,
        SourceMechanism::SockStateTracepoint,
        KernelLifecycleKind::SocketState {
            protocol: SocketProtocol::Tcp,
            local: ep(LOCAL, 0),
            remote: ep(REMOTE, PORT),
            old_state: tcp_state::CLOSE,
            new_state: tcp_state::SYN_SENT,
            sk: SK,
            current_pid: PID,
        },
    );
    e.bound = Some(bound);
    e.attribution = AgentAttribution::Claimed {
        agent_id: c.agent_id.clone(),
        claim_source: c.claim_source.clone(),
    };
    e.claimed_decision_id = c.decision_id;
    e
}

fn established(seq: u64, ts_ns: u64) -> KernelLifecycleEvent {
    event(
        seq,
        ts_ns,
        SourceMechanism::SockStateTracepoint,
        KernelLifecycleKind::SocketState {
            protocol: SocketProtocol::Tcp,
            local: ep(LOCAL, LOCAL_PORT),
            remote: ep(REMOTE, PORT),
            old_state: tcp_state::SYN_SENT,
            new_state: tcp_state::ESTABLISHED,
            sk: SK,
            current_pid: 0,
        },
    )
}

/// A wire segment from `src` to `dst`, stamped by the kernel on the realtime
/// clock. `probe_ts` is the probe's own dequeue stamp (monotonic).
#[allow(clippy::too_many_arguments)] // a fixture: every field is a knob
fn segment(
    seq: u64,
    probe_ts: u64,
    rt_ns: u64,
    direction: WireDirection,
    src: SocketEndpoint,
    dst: SocketEndpoint,
    flags: u8,
    tcp_seq: u32,
    tcp_ack: u32,
) -> KernelLifecycleEvent {
    event(
        seq,
        probe_ts,
        SourceMechanism::WireTapAfPacket,
        KernelLifecycleKind::WireSegment {
            ifindex: IF_LO,
            direction,
            protocol: SocketProtocol::Tcp,
            src,
            dst,
            flags,
            seq: tcp_seq,
            ack: tcp_ack,
            payload_len: 0,
            frame_len: 60,
            kernel_realtime_ns: rt_ns,
        },
    )
}

fn wire_syn(seq: u64, probe_ts: u64, rt_ns: u64, isn: u32) -> KernelLifecycleEvent {
    segment(
        seq,
        probe_ts,
        rt_ns,
        WireDirection::Outgoing,
        ep(LOCAL, LOCAL_PORT),
        ep(REMOTE, PORT),
        SYN,
        isn,
        0,
    )
}

fn wire_syn_ack(seq: u64, probe_ts: u64, rt_ns: u64, isn: u32) -> KernelLifecycleEvent {
    segment(
        seq,
        probe_ts,
        rt_ns,
        WireDirection::Incoming,
        ep(REMOTE, PORT),
        ep(LOCAL, LOCAL_PORT),
        SYN | ACK,
        0x9abc_def0,
        isn.wrapping_add(1),
    )
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
    tap: bool,
) -> ObservationBatch {
    let mut mechanisms = vec![
        SourceMechanism::PidFdAnchored,
        SourceMechanism::ProcNetTable,
        SourceMechanism::SockStateTracepoint,
    ];
    if tap {
        mechanisms.push(SourceMechanism::WireTapAfPacket);
    }
    ObservationBatch {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        batch_id: [id; 16],
        probe_run_id: RUN,
        probe_seq_first: seq.0,
        probe_seq_last: seq.1,
        dropped_events: dropped,
        active_mechanisms: SourceMechanism::canonical_set(mechanisms),
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
        clk_tck: 100,
    }
}

fn mono_for(wall_ms: u64, anchor_wall: u64) -> u64 {
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

/// Wire segments to place alongside the transition, given the SYN's wall
/// time in ms. Each returns the events to append.
type Wire = Box<dyn Fn(u64) -> Vec<KernelLifecycleEvent>>;

struct Scene {
    x: Expected,
    o: Observer,
    ev: ObserverEvidence,
    at: u64,
}

/// Epoch-start batch at `now-2s`; batch 2 `[now+2s, now+4s]` carrying the
/// bound initiation at `now+3s`, the completion 5 ms later, and whatever
/// wire segments `wire` produces for that SYN wall time.
fn scene(wire: Wire, tap: bool, dropped: u64, transition: bool) -> Scene {
    let x = expected();
    let c = claim(&x);
    let mut o = Observer::new();
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a, Some(0), tap),
            now - 1_000,
        )
        .unwrap();
    let syn_wall = now + 3_000;
    let syn_ns = mono_for(syn_wall, anchor_wall);
    let mut events = Vec::new();
    if transition {
        events.push(syn_sent(1, syn_ns, process_of(&x.ee), &c));
        events.push(established(2, syn_ns + 5_000_000));
    }
    events.extend(wire(syn_wall));
    let last = events.len() as u64;
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (1, last.max(1)),
                events,
                a,
                Some(dropped),
                tap,
            ),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let health = o.signer.health(at).unwrap();
    Scene {
        x,
        o,
        ev: ObserverEvidence {
            batches: vec![b1, b2],
            health,
        },
        at,
    }
}

/// One complete handshake for the transition's tuple, 1 ms and 3 ms after
/// the SYN in wall time.
fn handshake(isn: u32, offset_ms: i64) -> Wire {
    Box::new(move |syn_wall| {
        let rt = |ms: i64| ((syn_wall as i64 + offset_ms + ms) as u64) * 1_000_000;
        vec![wire_syn(10, 1, rt(1), isn), wire_syn_ack(11, 2, rt(3), isn)]
    })
}

fn none() -> Wire {
    Box::new(|_| vec![])
}

fn reconcile(s: &Scene) -> Reconciliation {
    reconcile_expectation(&s.x.ee, Some(&s.ev), &ctx(&s.x, &s.o, s.at))
}

fn kernel_refs(r: &Reconciliation) -> usize {
    r.evidence
        .iter()
        .filter(|e| matches!(e, EvidenceRef::KernelEvent { .. }))
        .count()
}

// ═══ Corroborated ═══

#[test]
fn wc01_a_syn_and_its_syn_ack_on_the_wire_corroborate_the_kernel_transition() {
    let s = scene(handshake(ISN, 0), true, 0, true);
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceMatches);
    assert_eq!(r.wire, WireCorroboration::Corroborated, "{r:?}");
    // The two socket transitions and the two wire segments are all referenced.
    assert_eq!(kernel_refs(&r), 4, "{:?}", r.evidence);
}

#[test]
fn wc02_corroboration_never_raises_strength_above_attested() {
    let s = scene(handshake(ISN, 0), true, 0, true);
    let r = reconcile(&s);
    assert_eq!(r.wire, WireCorroboration::Corroborated);
    assert_eq!(
        r.strength,
        EvidenceStrength::Attested,
        "never Proven: same host, same root"
    );
    assert_ne!(r.strength, EvidenceStrength::Proven);
}

#[test]
fn wc03_a_retransmitted_syn_is_one_handshake() {
    let w: Wire = Box::new(|syn_wall| {
        let rt = |ms: u64| (syn_wall + ms) * 1_000_000;
        vec![
            wire_syn(10, 1, rt(1), ISN),
            wire_syn(11, 2, rt(2), ISN), // same ISN again (retransmit / lo double copy)
            wire_syn_ack(12, 3, rt(3), ISN),
        ]
    });
    let r = reconcile(&scene(w, true, 0, true));
    assert_eq!(r.wire, WireCorroboration::Corroborated, "{r:?}");
}

// ═══ Not corroborated: the verdict stands, the record says why ═══

#[test]
fn wc04_without_a_declared_tap_the_wire_question_is_unavailable() {
    let s = scene(none(), false, 0, true);
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.wire, WireCorroboration::Unavailable);
    assert_eq!(kernel_refs(&r), 2);
}

#[test]
fn wc05_a_live_tap_that_saw_no_handshake_for_the_tuple_is_not_observed_not_a_violation() {
    let s = scene(none(), true, 0, true);
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.wire, WireCorroboration::NotObserved);
    assert_ne!(r.result, ReconciliationResult::LineageViolation);
    assert_ne!(r.result, ReconciliationResult::IdentityDivergence);
}

#[test]
fn wc06_a_handshake_far_from_the_transition_in_time_does_not_corroborate_it() {
    // Ten seconds earlier than the kernel transition.
    let r = reconcile(&scene(handshake(ISN, -10_000), true, 0, true));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution);
    assert_eq!(r.wire, WireCorroboration::NotObserved, "{r:?}");
    // Ten seconds later, likewise.
    let r = reconcile(&scene(handshake(ISN, 10_000), true, 0, true));
    assert_eq!(r.wire, WireCorroboration::NotObserved, "{r:?}");
}

#[test]
fn wc07_a_handshake_for_a_different_tuple_does_not_corroborate() {
    let w: Wire = Box::new(|syn_wall| {
        let rt = |ms: u64| (syn_wall + ms) * 1_000_000;
        vec![
            segment(
                10,
                1,
                rt(1),
                WireDirection::Outgoing,
                ep(LOCAL, LOCAL_PORT),
                ep(REMOTE, PORT + 1),
                SYN,
                ISN,
                0,
            ),
            segment(
                11,
                2,
                rt(3),
                WireDirection::Incoming,
                ep(REMOTE, PORT + 1),
                ep(LOCAL, LOCAL_PORT),
                SYN | ACK,
                1,
                ISN + 1,
            ),
        ]
    });
    let r = reconcile(&scene(w, true, 0, true));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution);
    assert_eq!(r.wire, WireCorroboration::NotObserved, "{r:?}");
    assert_eq!(kernel_refs(&r), 2, "the unrelated segments are not cited");
}

#[test]
fn wc08_a_syn_without_its_syn_ack_is_not_a_corroborated_handshake() {
    let w: Wire = Box::new(|syn_wall| vec![wire_syn(10, 1, (syn_wall + 1) * 1_000_000, ISN)]);
    let r = reconcile(&scene(w, true, 0, true));
    assert_eq!(r.wire, WireCorroboration::NotObserved, "{r:?}");
    // A SYN-ACK acknowledging a different ISN does not complete this SYN.
    let w: Wire = Box::new(|syn_wall| {
        let rt = |ms: u64| (syn_wall + ms) * 1_000_000;
        vec![
            wire_syn(10, 1, rt(1), ISN),
            wire_syn_ack(11, 2, rt(3), ISN + 77),
        ]
    });
    let r = reconcile(&scene(w, true, 0, true));
    assert_eq!(r.wire, WireCorroboration::NotObserved, "{r:?}");
}

#[test]
fn wc09_two_distinct_handshakes_for_the_same_tuple_in_the_window_are_ambiguous() {
    let w: Wire = Box::new(|syn_wall| {
        let rt = |ms: u64| (syn_wall + ms) * 1_000_000;
        vec![
            wire_syn(10, 1, rt(1), ISN),
            wire_syn_ack(11, 2, rt(3), ISN),
            wire_syn(12, 3, rt(200), ISN + 5_000),
            wire_syn_ack(13, 4, rt(202), ISN + 5_000),
        ]
    });
    let r = reconcile(&scene(w, true, 0, true));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution);
    assert_eq!(
        r.wire,
        WireCorroboration::Ambiguous { handshakes: 2 },
        "{r:?}"
    );
    assert_eq!(
        kernel_refs(&r),
        2,
        "ambiguous segments are not cited as corroboration"
    );
}

#[test]
fn wc10_a_batch_that_reports_loss_never_corroborates() {
    let s = scene(handshake(ISN, 0), true, 1, true);
    let r = reconcile(&s);
    assert_ne!(r.wire, WireCorroboration::Corroborated, "{r:?}");
    assert_ne!(r.strength, EvidenceStrength::Proven);
}

#[test]
fn wc11_a_segment_that_cannot_be_placed_on_the_event_clock_does_not_corroborate() {
    // The carrying batch has no clock anchor: the realtime capture stamp
    // cannot be related to the tracepoint's monotonic stamp.
    let x = expected();
    let c = claim(&x);
    let mut o = Observer::new();
    let now = x.now;
    let anchor_wall = now - 10_000;
    let b1 = o
        .signer
        .attest_at(
            raw_batch(
                1,
                now - 2_000,
                now - 1_000,
                (0, 0),
                vec![],
                None,
                Some(0),
                true,
            ),
            now - 1_000,
        )
        .unwrap();
    let syn_wall = now + 3_000;
    let syn_ns = mono_for(syn_wall, anchor_wall);
    let rt = |ms: u64| (syn_wall + ms) * 1_000_000;
    let events = vec![
        syn_sent(1, syn_ns, process_of(&x.ee), &c),
        established(2, syn_ns + 5_000_000),
        wire_syn(3, 1, rt(1), ISN),
        wire_syn_ack(4, 2, rt(3), ISN),
    ];
    // Transition batch anchored (so the verdict itself can be placed) …
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (1, 4),
                events,
                Some(anchor_at(anchor_wall)),
                Some(0),
                true,
            ),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let health = o.signer.health(at).unwrap();
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health,
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(
        r.wire,
        WireCorroboration::Corroborated,
        "same batch: anchored"
    );

    // … and now the segments arrive in a later, unanchored batch.
    let x = expected();
    let c = claim(&x);
    let mut o = Observer::new();
    let now = x.now;
    let anchor_wall = now - 10_000;
    let b1 = o
        .signer
        .attest_at(
            raw_batch(
                1,
                now - 2_000,
                now - 1_000,
                (0, 0),
                vec![],
                None,
                Some(0),
                true,
            ),
            now - 1_000,
        )
        .unwrap();
    let syn_wall = now + 3_000;
    let syn_ns = mono_for(syn_wall, anchor_wall);
    let rt = |ms: u64| (syn_wall + ms) * 1_000_000;
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 3_500,
                (1, 2),
                vec![
                    syn_sent(1, syn_ns, process_of(&x.ee), &c),
                    established(2, syn_ns + 5_000_000),
                ],
                Some(anchor_at(anchor_wall)),
                Some(0),
                true,
            ),
            now + 3_500,
        )
        .unwrap();
    let b3 = o
        .signer
        .attest_at(
            raw_batch(
                3,
                now + 3_500,
                now + 4_000,
                (3, 4),
                vec![wire_syn(3, 1, rt(1), ISN), wire_syn_ack(4, 2, rt(3), ISN)],
                None,
                Some(0),
                true,
            ),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let health = o.signer.health(at).unwrap();
    let ev = ObserverEvidence {
        batches: vec![b1, b2, b3],
        health,
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(
        r.wire,
        WireCorroboration::NotObserved,
        "unplaceable segments: {r:?}"
    );
}

// ═══ The wire never stands alone ═══

#[test]
fn wc12_wire_segments_alone_attribute_nothing_and_verify_nothing() {
    let s = scene(handshake(ISN, 0), true, 0, false);
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.identity, IdentityComparison::NoReference);
    assert_eq!(r.wire, WireCorroboration::NotEvaluated);
    assert_eq!(kernel_refs(&r), 0);
}

#[test]
fn wc13_the_wire_question_is_not_asked_without_a_transition_verdict() {
    let x = expected();
    let o = Observer::new();
    let r = reconcile_expectation(&x.ee, None, &ctx(&x, &o, x.now));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.wire, WireCorroboration::NotEvaluated);
    assert_eq!(
        WireCorroboration::default(),
        WireCorroboration::NotEvaluated
    );
}

// ═══ Record ═══

#[test]
fn wc14_record_version_five_carries_the_wire_comparison_in_its_canonical_bytes() {
    assert_eq!(RECONCILIATION_VERSION, 5);
    let r = reconcile(&scene(handshake(ISN, 0), true, 0, true));
    assert_eq!(r.version, 5);
    assert_eq!(r.wire, WireCorroboration::Corroborated);
    let mut other = r.clone();
    other.wire = WireCorroboration::NotObserved;
    assert_ne!(r.canonical_bytes(), other.canonical_bytes());
    let mut amb = r.clone();
    amb.wire = WireCorroboration::Ambiguous { handshakes: 2 };
    let mut amb3 = r.clone();
    amb3.wire = WireCorroboration::Ambiguous { handshakes: 3 };
    assert_ne!(amb.canonical_bytes(), amb3.canonical_bytes());
    let mut un = r.clone();
    un.wire = WireCorroboration::Unavailable;
    let mut ne = r.clone();
    ne.wire = WireCorroboration::NotEvaluated;
    assert_ne!(un.canonical_bytes(), ne.canonical_bytes());
}

#[test]
fn wc15_a_segment_altered_after_attestation_breaks_the_batch_signature() {
    let mut s = scene(handshake(ISN, 0), true, 0, true);
    for e in &mut s.ev.batches[1].batch.kernel_events {
        if let KernelLifecycleKind::WireSegment { flags, .. } = &mut e.kind {
            *flags ^= ACK;
        }
    }
    let r = reconcile(&s);
    assert_eq!(
        r.result,
        ReconciliationResult::SensorIntegrityFailure,
        "{r:?}"
    );
    assert_eq!(r.strength, EvidenceStrength::Proven);
    assert_eq!(r.wire, WireCorroboration::NotEvaluated);
}
