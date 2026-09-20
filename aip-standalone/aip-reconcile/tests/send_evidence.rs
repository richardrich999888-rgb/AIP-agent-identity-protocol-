//! Gate 3 — `ghost.net.send.v1`, the third action class, RED.
//!
//! ```text
//! ghost.net.send.v1
//!     parameters: protocol, remote_addr, remote_port — the ENDPOINT only
//!     observed as: sock:sock_send_length in the sender's context (anchored),
//!                  the socket's endpoints resolved from the attested
//!                  SockStateTracepoint transitions of the same `sk`
//!     evidence:    the byte count the kernel accepted — never the bytes,
//!                  never a hash of them
//!     kind:        Transition · mechanism SockSendTracepoint · Attested
//! ```
//!
//! Hash semantics, stated once: the parameter digest of a send names the
//! endpoint, exactly as a connect's does; the action *kind* is what differs.
//! The byte count is evidence context inside the signed event and is never
//! part of the digest. No payload digest exists anywhere in this class.
//!
//! FIXTURE-BASED; the live path is `ghost-demo/tests/live_send.rs`.

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

const PID: u32 = 3_960_501;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-s";
const PROBE_ID: &str = "probe-s";
const LOCAL: [u8; 4] = [127, 0, 0, 1];
const LOCAL_PORT: u16 = 51_000;
const REMOTE: [u8; 4] = [10, 0, 0, 5];
const PORT: u16 = 443;
const OTHER: [u8; 4] = [10, 0, 0, 9];
const SK: u64 = 0xffff_9a0b_1234_5678;
const RUN: [u8; 16] = [0x7b; 16];
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
        exe_content_sha256: sha256(b"payments-agent binary v6"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

fn expected_for(kind: ScopeAction, params: ActionParameters) -> Expected {
    let scope = CapabilityScope {
        allowed: vec![net_connect_action(), net_send_action()],
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
        action_kind: kind,
        parameters: params,
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

fn expected_send(remote: [u8; 4], port: u16) -> Expected {
    expected_for(
        net_send_action(),
        net_send_parameters(NetProtocol::Tcp, &remote, port).unwrap(),
    )
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

        container: None,
    }
}

fn other_instance(ee: &ExpectedExecution) -> ObservedProcess {
    let mut p = process_of(ee);
    p.process.pid_start_time_ticks += 5_000;
    p
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
    bound: Option<ObservedProcess>,
    c: Option<&AgentClaim>,
) -> KernelLifecycleEvent {
    let (attribution, claimed_decision_id) = match c {
        None => (AgentAttribution::NotEstablished, None),
        Some(c) => (
            AgentAttribution::Claimed {
                agent_id: c.agent_id.clone(),
                claim_source: c.claim_source.clone(),
            },
            c.decision_id,
        ),
    };
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism,
        kind,
        cpu: 1,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution,
        claimed_decision_id,
    }
}

#[allow(clippy::too_many_arguments)] // a fixture: every field is a knob
fn state(
    seq: u64,
    ts_ns: u64,
    sk: u64,
    remote: [u8; 4],
    port: u16,
    old: u8,
    new: u8,
    local_port: u16,
) -> KernelLifecycleEvent {
    event(
        seq,
        ts_ns,
        SourceMechanism::SockStateTracepoint,
        KernelLifecycleKind::SocketState {
            protocol: SocketProtocol::Tcp,
            local: ep(LOCAL, local_port),
            remote: ep(remote, port),
            old_state: old,
            new_state: new,
            sk,
            current_pid: 0,
        },
        None,
        None,
    )
}

fn established(seq: u64, ts_ns: u64, sk: u64, remote: [u8; 4], port: u16) -> KernelLifecycleEvent {
    state(
        seq,
        ts_ns,
        sk,
        remote,
        port,
        tcp_state::SYN_SENT,
        tcp_state::ESTABLISHED,
        LOCAL_PORT,
    )
}

fn closed(seq: u64, ts_ns: u64, sk: u64, remote: [u8; 4], port: u16) -> KernelLifecycleEvent {
    state(
        seq,
        ts_ns,
        sk,
        remote,
        port,
        tcp_state::FIN_WAIT2,
        tcp_state::CLOSE,
        LOCAL_PORT,
    )
}

fn send(
    seq: u64,
    ts_ns: u64,
    sk: u64,
    bytes: u32,
    bound: Option<ObservedProcess>,
    c: Option<&AgentClaim>,
) -> KernelLifecycleEvent {
    event(
        seq,
        ts_ns,
        SourceMechanism::SockSendTracepoint,
        KernelLifecycleKind::SocketSend {
            protocol: SocketProtocol::Tcp,
            sk,
            bytes,
            flags: 0,
            current_pid: PID,
        },
        bound,
        c,
    )
}

fn raw_batch(
    id: u8,
    from: u64,
    to: u64,
    seq: (u64, u64),
    events: Vec<KernelLifecycleEvent>,
    anchor: Option<BootClockAnchor>,
) -> ObservationBatch {
    ObservationBatch {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        batch_id: [id; 16],
        probe_run_id: RUN,
        probe_seq_first: seq.0,
        probe_seq_last: seq.1,
        dropped_events: Some(0),
        active_mechanisms: SourceMechanism::canonical_set(vec![
            SourceMechanism::PidFdAnchored,
            SourceMechanism::SockStateTracepoint,
            SourceMechanism::SockSendTracepoint,
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

/// Events for batch 2, given a function of the decision time and the
/// monotonic stamp that the anchor maps to `now + 3 s`.
type Events = Box<dyn Fn(&Expected, &AgentClaim, u64) -> Vec<KernelLifecycleEvent>>;

struct Scene {
    x: Expected,
    o: Observer,
    ev: ObserverEvidence,
    at: u64,
}

fn scene(x: Expected, events: Events) -> Scene {
    let c = claim(&x);
    let mut o = Observer::new();
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a),
            now - 1_000,
        )
        .unwrap();
    let t0 = mono_for(now + 3_000, anchor_wall);
    let evs = events(&x, &c, t0);
    let last = evs.len().max(1) as u64;
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now + 2_000, now + 4_000, (1, last), evs, a),
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

const MS: u64 = 1_000_000;

/// The honest send: the connection to REMOTE:PORT established 5 ms after
/// `t0`, then `bytes` sent on it 50 ms after, by the authorized instance
/// under the decision's claim.
fn honest(bytes: u32) -> Events {
    Box::new(move |x, c, t0| {
        vec![
            established(1, t0 + 5 * MS, SK, REMOTE, PORT),
            send(2, t0 + 50 * MS, SK, bytes, Some(process_of(&x.ee)), Some(c)),
        ]
    })
}

fn reconcile(s: &Scene) -> Reconciliation {
    reconcile_expectation(&s.x.ee, Some(&s.ev), &ctx(&s.x, &s.o, s.at))
}

// ═══ Positive ═══

#[test]
fn ss01_an_anchored_send_on_a_resolved_socket_to_the_authorized_endpoint_verifies() {
    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested, "never Proven");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceMatches);
    match r.action {
        ActionComparison::Match(seal) => {
            assert_eq!(seal.kind(), ActionEvidenceKind::Transition);
            assert_eq!(seal.mechanism(), SourceMechanism::SockSendTracepoint);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(r.temporal, TemporalComparison::WithinWindow);
    assert_eq!(
        r.wire,
        WireCorroboration::NotEvaluated,
        "a send is not a handshake"
    );
    // The send event is cited.
    assert!(r
        .evidence
        .iter()
        .any(|e| matches!(e, EvidenceRef::KernelEvent { index: 1, .. })));
}

#[test]
fn ss02_the_digest_names_the_endpoint_only_and_the_count_is_context() {
    // Same endpoint parameters as a connect; the kind is what differs.
    let p = net_send_parameters(NetProtocol::Tcp, &REMOTE, PORT).unwrap();
    let q = net_connect_parameters(NetProtocol::Tcp, &REMOTE, PORT).unwrap();
    assert_eq!(p.digest(), q.digest(), "endpoint parameters, one encoding");
    assert_ne!(net_send_action(), net_connect_action());
    assert_eq!(NET_SEND_ACTION, "ghost.net.send.v1");
    assert!(net_send_parameters(NetProtocol::Tcp, &REMOTE, 0).is_err());
    assert!(net_send_parameters(NetProtocol::Tcp6, &REMOTE, PORT).is_err());
    // Any positive byte count verifies against the same expectation.
    for bytes in [1u32, 19, 65_535, 1 << 20] {
        let r = reconcile(&scene(expected_send(REMOTE, PORT), honest(bytes)));
        assert_eq!(
            r.result,
            ReconciliationResult::VerifiedExecution,
            "{bytes}: {r:?}"
        );
    }
}

// ═══ Not the authorized action ═══

#[test]
fn ss03_a_send_to_another_endpoint_does_not_match() {
    let s = scene(expected_send(OTHER, PORT), honest(19));
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceDoesNotMatch);
    assert!(matches!(r.action, ActionComparison::Mismatch(_)));
    let s = scene(expected_send(REMOTE, PORT + 1), honest(19));
    assert_eq!(reconcile(&s).reason, ReasonCode::ActionEvidenceDoesNotMatch);
}

#[test]
fn ss04_a_send_on_a_socket_with_no_attested_transition_cannot_be_placed_on_an_endpoint() {
    let evs: Events = Box::new(|x, c, t0| {
        vec![send(
            1,
            t0 + 50 * MS,
            SK,
            19,
            Some(process_of(&x.ee)),
            Some(c),
        )]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::SendSocketUnresolved);
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution);
}

#[test]
fn ss05_a_kernel_socket_identity_reused_after_close_is_not_the_old_connection() {
    // ESTABLISHED to REMOTE, then CLOSE, then a send on the same sk: the
    // address may now belong to a different socket.
    let evs: Events = Box::new(|x, c, t0| {
        vec![
            established(1, t0 + 5 * MS, SK, REMOTE, PORT),
            closed(2, t0 + 20 * MS, SK, REMOTE, PORT),
            send(3, t0 + 50 * MS, SK, 19, Some(process_of(&x.ee)), Some(c)),
        ]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::SendSocketUnresolved);
    // A later ESTABLISHED for the reused sk names the new endpoint.
    let evs: Events = Box::new(|x, c, t0| {
        vec![
            established(1, t0 + 5 * MS, SK, REMOTE, PORT),
            closed(2, t0 + 20 * MS, SK, REMOTE, PORT),
            established(3, t0 + 30 * MS, SK, OTHER, PORT),
            send(4, t0 + 50 * MS, SK, 19, Some(process_of(&x.ee)), Some(c)),
        ]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_eq!(r.reason, ReasonCode::ActionEvidenceDoesNotMatch, "{r:?}");
    let r = reconcile(&scene(expected_send(OTHER, PORT), evs_again()));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");

    fn evs_again() -> Events {
        Box::new(|x, c, t0| {
            vec![
                established(1, t0 + 5 * MS, SK, REMOTE, PORT),
                closed(2, t0 + 20 * MS, SK, REMOTE, PORT),
                established(3, t0 + 30 * MS, SK, OTHER, PORT),
                send(4, t0 + 50 * MS, SK, 19, Some(process_of(&x.ee)), Some(c)),
            ]
        })
    }
}

#[test]
fn ss06_a_transition_later_than_the_send_does_not_name_its_endpoint() {
    let evs: Events = Box::new(|x, c, t0| {
        vec![
            send(1, t0 + 50 * MS, SK, 19, Some(process_of(&x.ee)), Some(c)),
            established(2, t0 + 60 * MS, SK, REMOTE, PORT),
        ]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_eq!(r.reason, ReasonCode::SendSocketUnresolved, "{r:?}");
}

// ═══ Attribution ═══

#[test]
fn ss07_an_unbound_send_is_a_pid_reference_never_identity() {
    let evs: Events = Box::new(|_, c, t0| {
        vec![
            established(1, t0 + 5 * MS, SK, REMOTE, PORT),
            send(2, t0 + 50 * MS, SK, 19, None, Some(c)),
        ]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::UnboundReferencesOnly);
}

#[test]
fn ss08_a_send_by_another_instance_under_the_decisions_claim_is_divergence() {
    let evs: Events = Box::new(|x, c, t0| {
        vec![
            established(1, t0 + 5 * MS, SK, REMOTE, PORT),
            send(
                2,
                t0 + 50 * MS,
                SK,
                19,
                Some(other_instance(&x.ee)),
                Some(c),
            ),
        ]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_eq!(r.result, ReconciliationResult::IdentityDivergence, "{r:?}");
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution);
}

#[test]
fn ss09_an_unclaimed_send_does_not_verify() {
    let evs: Events = Box::new(|x, _, t0| {
        vec![
            established(1, t0 + 5 * MS, SK, REMOTE, PORT),
            send(2, t0 + 50 * MS, SK, 19, Some(process_of(&x.ee)), None),
        ]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnclaimed);
}

// ═══ Time and kind ═══

#[test]
fn ss10_a_send_placed_before_the_decision_precedes_authorization() {
    let evs: Events = Box::new(|x, c, t0| {
        // 15 s before t0 is 12 s before the decision.
        let t = t0 - 15_000 * MS;
        vec![
            established(1, t + 5 * MS, SK, REMOTE, PORT),
            send(2, t + 50 * MS, SK, 19, Some(process_of(&x.ee)), Some(c)),
        ]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionPrecedesAuthorization);
    assert_eq!(r.temporal, TemporalComparison::BeforeWindow);
}

#[test]
fn ss11_a_connect_expectation_is_not_satisfied_by_a_send_nor_a_send_by_a_connect() {
    // Connect expected, only a send (plus the completion) observed.
    let x = expected_for(
        net_connect_action(),
        net_connect_parameters(NetProtocol::Tcp, &REMOTE, PORT).unwrap(),
    );
    let r = reconcile(&scene(x, honest(19)));
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    // Send expected, only the connect transition observed (bound initiation).
    let evs: Events = Box::new(|x, c, t0| {
        vec![
            event(
                1,
                t0,
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
                Some(process_of(&x.ee)),
                Some(c),
            ),
            established(2, t0 + 5 * MS, SK, REMOTE, PORT),
        ]
    });
    let r = reconcile(&scene(expected_send(REMOTE, PORT), evs));
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

#[test]
fn ss12_a_zero_byte_send_is_not_a_send() {
    let r = reconcile(&scene(expected_send(REMOTE, PORT), honest(0)));
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

// ═══ Tamper ═══

#[test]
fn ss13_a_byte_count_altered_after_attestation_breaks_the_batch_signature() {
    let mut s = scene(expected_send(REMOTE, PORT), honest(19));
    for e in &mut s.ev.batches[1].batch.kernel_events {
        if let KernelLifecycleKind::SocketSend { bytes, .. } = &mut e.kind {
            *bytes += 1;
        }
    }
    let r = reconcile(&s);
    assert_eq!(
        r.result,
        ReconciliationResult::SensorIntegrityFailure,
        "{r:?}"
    );
    assert_eq!(r.strength, EvidenceStrength::Proven);
}
