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

use std::{fs, io::Write, process::Command};

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

fn exported_bundle(s: &Scene) -> (serde_json::Value, serde_json::Value) {
    let dp_key = s.x.anchors.get(&s.x.ee.decision_point_id).unwrap().to_vec();
    let observer_key =
        s.o.anchors
            .get(
                &s.ev.health.health.observer_id,
                s.ev.health.health.key_version,
            )
            .unwrap()
            .to_vec();
    assert_ne!(
        dp_key, observer_key,
        "collector and decision point use independent keys"
    );
    let dp_id = s.x.ee.decision_point_id.clone();
    let observer_id = s.ev.health.health.observer_id.clone();
    let observer_version = s.ev.health.health.key_version;
    let bundle = serde_json::json!({
        "bundle_version": 1,
        "evidence_origin": "SYNTHETIC_TEST_FIXTURE",
        "expected_execution": s.x.ee,
        "observer_batches": s.ev.batches,
        "signed_sensor_health": s.ev.health,
        "trust_anchors": {
            "decision_point": {"id": dp_id, "public_key": dp_key},
            "observer": {"id": observer_id, "key_version": observer_version, "public_key": observer_key},
            "agent_public_key": s.x.agent_kp.public_key
        },
        "verification_context": {"verification_time_ms":s.at, "health_max_age_ms":HEALTH_MAX_AGE, "window_tolerance_ms":0, "expected_side_coverage":"unknown"}
    });
    let anchors = serde_json::json!({
        "decision_point": {"id": dp_id, "public_key": dp_key.iter().map(|b| format!("{b:02x}")).collect::<String>()},
        "observer": {"id": observer_id, "key_version": observer_version, "public_key": observer_key.iter().map(|b| format!("{b:02x}")).collect::<String>()}
    });
    (bundle, anchors)
}

fn invoke_evidence_cli(bundle: &str, anchors: &str) -> (serde_json::Value, bool) {
    let dir = std::env::temp_dir().join(format!(
        "aip-evidence-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    let bundle_path = dir.join("bundle.json");
    let anchors_path = dir.join("anchors.json");
    fs::write(&bundle_path, bundle).unwrap();
    fs::write(&anchors_path, anchors).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_aip-evidence-verify"))
        .args([
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--anchors",
            anchors_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "CLI did not emit JSON: {e}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    fs::remove_dir_all(dir).unwrap();
    (report, output.status.success())
}

fn degraded_scene() -> Scene {
    let mut s = scene(expected_send(REMOTE, PORT), honest(19));
    let previous = s.ev.batches.last().unwrap().batch.probe_seq_last;
    let mut loss = raw_batch(
        3,
        s.x.now + 4_000,
        s.x.now + 4_500,
        (previous + 1, previous + 1),
        vec![],
        None,
    );
    loss.dropped_events = Some(1);
    s.ev.batches
        .push(s.o.signer.attest_at(loss, s.x.now + 4_500).unwrap());
    s.ev.health = s.o.signer.health(s.at).unwrap();
    s
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
            boot_id: [0x4e; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v6"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

fn expected_for(kind: ScopeAction, params: ActionParameters) -> Expected {
    expected_for_ttl(kind, params, TTL)
}

fn expected_for_ttl(kind: ScopeAction, params: ActionParameters, ttl_ms: u64) -> Expected {
    authorize_for(
        kind,
        params,
        ttl_ms,
        vec![net_connect_action(), net_send_action()],
    )
    .unwrap_or_else(|d| panic!("fixture must authorize, got {d:?}"))
}

fn authorize_for(
    kind: ScopeAction,
    params: ActionParameters,
    ttl_ms: u64,
    allowed: Vec<ScopeAction>,
) -> Result<Expected, Denial> {
    let scope = CapabilityScope {
        allowed,
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
        requested_ttl_ms: ttl_ms,
    };
    match dp.authorize_at(&req, now) {
        Decision::Authorized(ee) => Ok(Expected {
            ee: *ee,
            anchors,
            agent_id: agent_aid.id,
            agent_kp,
            now,
        }),
        Decision::Denied(d) => Err(d),
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
        signer.register_probe(
            PROBE_ID,
            &[
                SourceMechanism::PidFdAnchored,
                SourceMechanism::SockStateTracepoint,
                SourceMechanism::SockSendTracepoint,
            ],
        );
        let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
        Self { signer, anchors }
    }

    fn open_policy() -> Self {
        let kp = generate_ed25519_keypair();
        let signer = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
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
        cgroup: aip_observe::CgroupSample::NotSampled,
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
    scene_with_observer(x, events, Observer::new())
}

fn scene_with_observer(x: Expected, events: Events, mut o: Observer) -> Scene {
    let c = claim(&x);
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
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceDoesNotMatch);
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
    assert_eq!(r.reason, ReasonCode::IdentityDiverged, "{r:?}");
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
    assert_eq!(r.reason, ReasonCode::ObserverSignatureInvalid, "{r:?}");
}

#[test]
fn ss14_offline_verifier_reconciles_signed_records_and_emits_json_report() {
    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let (bundle, _) = exported_bundle(&s);
    let offline_ee: ExpectedExecution =
        serde_json::from_value(bundle["expected_execution"].clone()).unwrap();
    let offline_batches: Vec<AttestedBatch> =
        serde_json::from_value(bundle["observer_batches"].clone()).unwrap();
    let offline_health: SignedSensorHealth =
        serde_json::from_value(bundle["signed_sensor_health"].clone()).unwrap();
    let trust = &bundle["trust_anchors"];
    let dp_id = trust["decision_point"]["id"].as_str().unwrap();
    let dp_key: Vec<u8> =
        serde_json::from_value(trust["decision_point"]["public_key"].clone()).unwrap();
    let observer_id = trust["observer"]["id"].as_str().unwrap();
    let observer_version = trust["observer"]["key_version"].as_u64().unwrap() as u32;
    let observer_key: Vec<u8> =
        serde_json::from_value(trust["observer"]["public_key"].clone()).unwrap();
    let agent_key: Vec<u8> = serde_json::from_value(trust["agent_public_key"].clone()).unwrap();
    let dp_anchors = DecisionPointTrustAnchors::new().trust(dp_id, &dp_key);
    let observer_anchors =
        ObserverTrustAnchors::new().trust(observer_id, observer_version, &observer_key);
    assert_eq!(
        verify_expected_execution_for_agent(&offline_ee, &dp_anchors, &agent_key),
        Ok(())
    );
    for batch in &offline_batches {
        assert_eq!(
            verify_attested_batch_independent_of_agent(batch, &observer_anchors, &agent_key),
            Ok(())
        );
    }
    assert_eq!(
        verify_signed_health(&offline_health, &observer_anchors),
        Ok(())
    );
    // Reconciliation consumes only the signed records and trust anchors. It
    // does not call the agent or the code which generated the fixture events.
    let offline_evidence = ObserverEvidence {
        batches: offline_batches.clone(),
        health: offline_health.clone(),
    };
    let offline_context = ReconciliationContext {
        decision_point_anchors: dp_anchors,
        observer_anchors: observer_anchors.clone(),
        verification_time_ms: bundle["verification_context"]["verification_time_ms"]
            .as_u64()
            .unwrap(),
        health_max_age_ms: bundle["verification_context"]["health_max_age_ms"]
            .as_u64()
            .unwrap(),
        window_tolerance_ms: bundle["verification_context"]["window_tolerance_ms"]
            .as_u64()
            .unwrap(),
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: Some(agent_key),
    };
    let r = reconcile_expectation(&offline_ee, Some(&offline_evidence), &offline_context);
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.reason, ReasonCode::ActionEvidenceMatches);
    let report = serde_json::json!({
        "agent_id": s.x.agent_id,
        "decision_id": s.x.ee.decision_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "authorized_action": NET_SEND_ACTION,
        "authorized_parameters": {"protocol":"tcp", "remote_addr":"10.0.0.5", "remote_port":443},
        "execution_binding": s.x.ee.execution_binding,
        "observer_id": s.ev.health.health.observer_id,
        "probe_id": s.ev.batches.last().unwrap().batch.probe_id,
        "evidence_batch_sequences": s.ev.batches.iter().map(|b| b.sequence).collect::<Vec<_>>(),
        "signature_verification": {"expected_execution":"verified_offline", "attested_batches":"verified_offline", "signed_sensor_health":"verified_offline"},
        "offline_input_bundle": bundle,
        "observer_evidence_present": true,
        "observation_availability": serde_json::to_value(&r.availability).unwrap(),
        "observer_health": format!("{:?}", s.ev.health.health.state),
        "reconciliation": serde_json::to_value(&r).unwrap(),
        "evidence_origin": "SYNTHETIC_TEST_FIXTURE",
        "live_kernel_observation": false
    });
    assert_eq!(report["reconciliation"]["result"], "VerifiedExecution");
    assert_eq!(report["reconciliation"]["strength"], "Attested");
    println!("AIP_SNIFFER_DOG_E2E_REPORT={report}");
}

#[test]
fn ss15_expired_action_is_not_reconciled_as_execution() {
    let x = expected_for_ttl(
        net_send_action(),
        net_send_parameters(NetProtocol::Tcp, &REMOTE, PORT).unwrap(),
        1_000,
    );
    let r = reconcile(&scene(x, honest(19)));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ObservationOutsideWindow, "{r:?}");
}

#[test]
fn ss16_missing_observer_evidence_remains_conservative() {
    let x = expected_send(REMOTE, PORT);
    let o = Observer::new();
    let r = reconcile_expectation(&x.ee, None, &ctx(&x, &o, x.now + 5_000));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::NoObserverEvidence, "{r:?}");
}

#[test]
fn ss17_untrusted_observer_key_is_not_accepted() {
    let mut s = scene(expected_send(REMOTE, PORT), honest(19));
    s.o.anchors = ObserverTrustAnchors::new();
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ObserverUntrusted, "{r:?}");
}

#[test]
fn ss18_degraded_observer_health_suppresses_positive_result() {
    let mut s = scene(expected_send(REMOTE, PORT), honest(19));
    let previous = s.ev.batches.last().unwrap().batch.probe_seq_last;
    let mut loss = raw_batch(
        3,
        s.x.now + 4_000,
        s.x.now + 4_500,
        (previous + 1, previous + 1),
        vec![],
        None,
    );
    loss.dropped_events = Some(1);
    s.ev.batches
        .push(s.o.signer.attest_at(loss, s.x.now + 4_500).unwrap());
    s.ev.health = s.o.signer.health(s.at).unwrap();
    assert_eq!(
        s.ev.health.health.state,
        aip_observe::ObserverState::Degraded
    );
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ObserverDegraded, "{r:?}");
}

#[test]
fn ss19_open_probe_policy_does_not_upgrade_synthetic_provenance() {
    let s = scene_with_observer(
        expected_send(REMOTE, PORT),
        honest(19),
        Observer::open_policy(),
    );
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(
        r.reason,
        ReasonCode::ProvenanceUnverifiedOpenPolicy,
        "{r:?}"
    );
}

#[test]
fn ss20_decision_point_rejects_an_action_outside_authority_scope() {
    let denial = authorize_for(
        ScopeAction::Custom("ghost.file.erase.v1".into()),
        ActionParameters::empty(),
        TTL,
        vec![net_send_action()],
    )
    .err()
    .expect("out-of-scope action must not receive an ExpectedExecution");
    assert_eq!(denial.reason, DenialReason::ActionOutOfScope);
    // No ExpectedExecution exists for a denied request, so passing one to the
    // reconciler would require fabricating a signed authorization.
}

#[test]
fn cli_accepts_a_valid_export_and_retains_fixture_provenance() {
    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let (bundle, anchors) = exported_bundle(&s);
    let (report, success) = invoke_evidence_cli(&bundle.to_string(), &anchors.to_string());
    assert!(success, "{report}");
    assert_eq!(report["status"], "INPUTS_VERIFIED");
    assert_eq!(report["reconciliation_result"], "VerifiedExecution");
    assert_eq!(report["evidence_strength"], "Attested");
    assert_eq!(report["reason_code"], "ActionEvidenceMatches");
    assert_eq!(report["evidence_origin"], "SYNTHETIC_TEST_FIXTURE");
    assert_eq!(report["evidence_origin_is_self_asserted"], true);
}

/// Explicit opt-in export for users who want to transfer the synthetic fixture
/// to an offline verifier. Normal test runs never create persistent files.
#[test]
#[ignore = "manual exporter; set AIP_SNIFFER_DOG_EXPORT_DIR (see OFFLINE_EVIDENCE_VERIFIER.md)"]
fn export_synthetic_bundle_to_user_directory() {
    let output_dir = std::env::var_os("AIP_SNIFFER_DOG_EXPORT_DIR")
        .map(std::path::PathBuf::from)
        .expect("set AIP_SNIFFER_DOG_EXPORT_DIR to the chosen output directory");
    fs::create_dir_all(&output_dir)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", output_dir.display()));

    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let (bundle, anchors) = exported_bundle(&s);
    assert_eq!(bundle["evidence_origin"], "SYNTHETIC_TEST_FIXTURE");
    let files = [
        (
            "evidence-bundle.json",
            serde_json::to_vec_pretty(&bundle).unwrap(),
        ),
        (
            "trusted-anchors.json",
            serde_json::to_vec_pretty(&anchors).unwrap(),
        ),
    ];

    // create_new is atomic with respect to an existing file and never
    // overwrites user data. Roll back only files created by this invocation
    // if the second create or either write fails.
    let mut created = Vec::new();
    let result = (|| -> std::io::Result<()> {
        for (name, contents) in &files {
            let path = output_dir.join(name);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            created.push(path);
            file.write_all(contents)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        for path in created {
            let _ = fs::remove_file(path);
        }
        panic!("export failed; existing files were preserved: {error}");
    }
    println!("Exported synthetic fixture:");
    println!("  {}", output_dir.join("evidence-bundle.json").display());
    println!("  {}", output_dir.join("trusted-anchors.json").display());
}

#[test]
fn cli_rejects_tampered_authorization_and_observer_batch() {
    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let (bundle, anchors) = exported_bundle(&s);
    let mut bad_authorization = bundle.clone();
    let sig_byte = bad_authorization["expected_execution"]["decision_sig"]["payload_hash"][0]
        .as_u64()
        .unwrap() as u8;
    bad_authorization["expected_execution"]["decision_sig"]["payload_hash"][0] =
        serde_json::json!(sig_byte ^ 1);
    let (report, success) =
        invoke_evidence_cli(&bad_authorization.to_string(), &anchors.to_string());
    assert!(!success);
    assert_eq!(report["status"], "REJECTED");
    assert_eq!(
        report["signature_verification"]["expected_execution"]["verified"],
        false
    );

    let mut bad_batch = bundle;
    bad_batch["observer_batches"][1]["batch"]["probe_id"] = serde_json::json!("substituted-probe");
    let (report, success) = invoke_evidence_cli(&bad_batch.to_string(), &anchors.to_string());
    assert!(!success);
    assert_eq!(report["status"], "REJECTED");
    assert_eq!(
        report["signature_verification"]["observer_batches"][1],
        false
    );
}

#[test]
fn cli_rejects_untrusted_decision_point_and_observer_keys() {
    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let (base, base_anchors) = exported_bundle(&s);
    let mut untrusted_dp_bundle = base.clone();
    let mut untrusted_dp_anchors = base_anchors.clone();
    let wrong_dp = generate_ed25519_keypair().public_key;
    untrusted_dp_bundle["trust_anchors"]["decision_point"]["public_key"] =
        serde_json::json!(wrong_dp);
    untrusted_dp_anchors["decision_point"]["public_key"] =
        untrusted_dp_bundle["trust_anchors"]["decision_point"]["public_key"].clone();
    let (report, success) = invoke_evidence_cli(
        &untrusted_dp_bundle.to_string(),
        &untrusted_dp_anchors.to_string(),
    );
    assert!(!success);
    assert_eq!(report["status"], "REJECTED");
    assert_eq!(
        report["signature_verification"]["expected_execution"]["verified"],
        false
    );

    let mut untrusted_observer_bundle = base;
    let mut untrusted_observer_anchors = base_anchors;
    let wrong_observer = generate_ed25519_keypair().public_key;
    untrusted_observer_bundle["trust_anchors"]["observer"]["public_key"] =
        serde_json::json!(wrong_observer);
    untrusted_observer_anchors["observer"]["public_key"] =
        untrusted_observer_bundle["trust_anchors"]["observer"]["public_key"].clone();
    let (report, success) = invoke_evidence_cli(
        &untrusted_observer_bundle.to_string(),
        &untrusted_observer_anchors.to_string(),
    );
    assert!(!success);
    assert_eq!(report["status"], "REJECTED");
    assert_eq!(
        report["signature_verification"]["observer_batches"][0],
        false
    );
}

#[test]
fn cli_rejects_a_missing_external_trust_anchor() {
    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let (bundle, mut anchors) = exported_bundle(&s);
    anchors.as_object_mut().unwrap().remove("observer");
    let (report, success) = invoke_evidence_cli(&bundle.to_string(), &anchors.to_string());
    assert!(!success);
    assert_eq!(report["status"], "REJECTED");
    assert!(report["error"]
        .as_str()
        .unwrap()
        .contains("external trust anchor"));
}

#[test]
fn cli_keeps_missing_evidence_conservative() {
    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let (mut bundle, anchors) = exported_bundle(&s);
    bundle["observer_batches"] = serde_json::json!([]);
    let (report, success) = invoke_evidence_cli(&bundle.to_string(), &anchors.to_string());
    assert!(!success);
    assert_eq!(report["status"], "INCOMPLETE");
    assert_eq!(report["reconciliation_result"], "CannotProve");
}

#[test]
fn cli_reports_degraded_signed_health_without_upgrading_the_result() {
    let s = degraded_scene();
    let (bundle, anchors) = exported_bundle(&s);
    let (report, success) = invoke_evidence_cli(&bundle.to_string(), &anchors.to_string());
    assert!(success, "the signed input records are authentic: {report}");
    assert_eq!(report["status"], "INPUTS_VERIFIED");
    assert_eq!(report["reconciliation_result"], "CannotProve");
    assert_eq!(report["reason_code"], "ObserverDegraded");
}

#[test]
fn cli_rejects_malformed_bundle_json_with_a_json_report() {
    let s = scene(expected_send(REMOTE, PORT), honest(19));
    let (_, anchors) = exported_bundle(&s);
    let (report, success) = invoke_evidence_cli("{malformed", &anchors.to_string());
    assert!(!success);
    assert_eq!(report["status"], "REJECTED");
    assert!(report["error"]
        .as_str()
        .unwrap()
        .contains("malformed bundle"));
}
