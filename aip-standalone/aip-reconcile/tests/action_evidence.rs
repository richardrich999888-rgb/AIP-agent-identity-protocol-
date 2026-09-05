//! Stage 7 — action-level evidence. Adversarial tests written **before** the
//! implementation, against the engine at `2c58771`.
//!
//! FIXTURE-BASED. Every observation here is constructed in the test rather
//! than read from a live kernel table; the live path is exercised by the
//! `ghost-demo` crate. These tests pin what must and must not verify.
//!
//! What was red against the pre-implementation engine: only the positive
//! path (`p1_*`, `p2_*`) — `VERIFIED_EXECUTION` was unreachable, so an honest,
//! complete evidence set still produced `CANNOT_PROVE`. Every negative case
//! passed trivially for the same reason; they are pinned here so the new
//! capability cannot over-reach.
//!
//! The action class under test is a TCP connection: authorized as the custom
//! scope action `ghost.net.connect.v1` with parameters
//! `(protocol, remote_addr, remote_port)`, observed as an ESTABLISHED row of
//! the kernel socket table joined to the instance's open descriptors under a
//! pidfd anchor (`SourceMechanism::ProcNetTable`). This is socket-level
//! metadata read through procfs (I23): polled, host-root-forgeable, capped at
//! `Attested`. No payload, no packets, no connect() event exist here.

use aip_authorize::*;
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_observe::*;
use aip_reconcile::*;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u32};
use aip_types::{
    Action, CapabilityScope, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple,
    ScopeAction, EXECUTION_BINDING_VERSION,
};

const PID: u32 = 3_900_301;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-e";
const PROBE_ID: &str = "probe-e";

/// The action vocabulary as raw constructions — deliberately not via a
/// helper, so these tests compile against the pre-implementation crate and
/// so the helper added later must reproduce exactly these bytes.
const NET_CONNECT: &str = "ghost.net.connect.v1";

fn net_connect_action() -> ScopeAction {
    ScopeAction::Custom(NET_CONNECT.into())
}

fn net_connect_params(protocol: &str, addr: &[u8], port: u16) -> ActionParameters {
    ActionParameters::from_pairs([
        ("protocol", protocol.as_bytes().to_vec()),
        ("remote_addr", addr.to_vec()),
        ("remote_port", port.to_be_bytes().to_vec()),
    ])
    .unwrap()
}

const REMOTE_ADDR: [u8; 4] = [10, 0, 0, 5];
const REMOTE_PORT: u16 = 443;
const ESTABLISHED: u8 = 0x01;
const LISTEN: u8 = 0x0a;
const SYN_SENT: u8 = 0x02;

// ─── Fixtures ───

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
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

fn binding(agent_id: &str) -> ExecutionBinding {
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
    }
}

/// Authorize `action`/`params` for the fixture agent and binding.
fn expected_for(action: ScopeAction, params: ActionParameters) -> Expected {
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
        action_kind: action,
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

fn expected() -> Expected {
    expected_for(
        net_connect_action(),
        net_connect_params("tcp", &REMOTE_ADDR, REMOTE_PORT),
    )
}

struct Observer {
    signer: CollectorSigner,
    probe: ProcfsProbe,
    kp: KeyPair,
    anchors: ObserverTrustAnchors,
}

impl Observer {
    fn new() -> Self {
        Self::with(generate_ed25519_keypair(), true, &SourceMechanism::ALL)
    }

    fn with(kp: KeyPair, registered: bool, mechanisms: &[SourceMechanism]) -> Self {
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        if registered {
            signer.register_probe(PROBE_ID, mechanisms);
        }
        let mut probe = ProcfsProbe::new(PROBE_ID);
        probe.declare_source(SourceMechanism::ProcConnector);
        probe.declare_source(SourceMechanism::ProcNetTable);
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

fn socket(protocol: SocketProtocol, remote: [u8; 4], port: u16, state: u8) -> ObservedEffect {
    ObservedEffect::SocketObserved {
        protocol,
        local: endpoint([127, 0, 0, 1], 51_000),
        remote: endpoint(remote, port),
        state,
        inode: 90_210,
    }
}

fn established() -> ObservedEffect {
    socket(SocketProtocol::Tcp, REMOTE_ADDR, REMOTE_PORT, ESTABLISHED)
}

fn claim(x: &Expected) -> AgentClaim {
    AgentClaim {
        agent_id: x.agent_id.clone(),
        claim_source: "orchestrator".into(),
        decision_id: Some(x.ee.decision_id),
    }
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

/// The honest scenario: an epoch-start batch, then one batch inside the
/// authorized window carrying `effects` observed on `process` under `claim`
/// via the socket-table mechanism. Health is emitted just after that batch.
fn scenario(
    x: &Expected,
    o: &mut Observer,
    process: ObservedProcess,
    effects: Vec<ObservedEffect>,
    claim: Option<&AgentClaim>,
) -> (ObserverEvidence, u64) {
    let now = x.now;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let obs: Vec<ObservedExecution> = effects
        .into_iter()
        .map(|e| {
            o.probe.observation_with(
                process.clone(),
                e,
                SourceMechanism::ProcNetTable,
                claim,
                now + 3_000,
            )
        })
        .collect();
    let b2 = o.batch(2, now + 2_000, now + 4_000, obs);
    let at = now + 5_000;
    (
        ObserverEvidence {
            batches: vec![b1, b2],
            health: o.health(at),
        },
        at,
    )
}

fn not_verified(r: &Reconciliation) {
    assert_ne!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "must not verify: {r:?}"
    );
    assert!(!r.action.is_observable() || r.result != ReconciliationResult::VerifiedExecution);
}

// ═══ Positive path — RED before implementation ═══

/// Complete, honest evidence: DP-signed expectation for a TCP connection to
/// 10.0.0.5:443; a collector-attested, socket-table observation of the
/// authorized instance holding an ESTABLISHED socket to exactly that tuple,
/// inside the window, claimed under this decision by this agent, from a
/// registered probe, on an Active observer. This — and only this — is
/// `VERIFIED_EXECUTION`, at `Attested` (procfs-read content, never `Proven`).
#[test]
fn p1_complete_evidence_for_a_tcp_connection_verifies_at_attested() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let (ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![established()], Some(&c));

    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
    assert!(r.action.is_observable());
    assert_eq!(r.temporal, TemporalComparison::WithinWindow);
    assert!(r.evidence.iter().any(|e| matches!(
        e,
        EvidenceRef::Observation {
            batch_sequence: ObserverSequence(2),
            index: 0
        }
    )));
}

/// The same evidence with an unrelated extra socket (a DNS lookup, say) on
/// the same instance: the authorized connection is still verified; the extra
/// socket is not this expectation's business.
#[test]
fn p2_unrelated_extra_sockets_do_not_block_verification() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let (ev, at) = scenario(
        &x,
        &mut o,
        process_of(&x.ee),
        vec![
            socket(SocketProtocol::Udp, [10, 0, 0, 53], 53, 0x07),
            established(),
            socket(SocketProtocol::Tcp, [10, 0, 0, 9], 80, ESTABLISHED),
        ],
        Some(&c),
    );
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested);
}

// ═══ 1–2. No action evidence ═══

#[test]
fn n01_expectation_with_process_but_no_action_evidence_is_cannot_prove() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let (ev, at) = scenario(
        &x,
        &mut o,
        process_of(&x.ee),
        vec![ObservedEffect::ProcessPresent],
        Some(&c),
    );
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
    assert!(!r.action.is_observable());
}

/// A socket that is not an established connection — LISTEN, SYN_SENT — is
/// not evidence of a connection to the remote.
#[test]
fn n02_non_established_socket_states_are_not_connection_evidence() {
    for state in [
        LISTEN, SYN_SENT, 0x06, /* TIME_WAIT */
        0x08, /* CLOSE_WAIT */
    ] {
        let x = expected();
        let mut o = Observer::new();
        let c = claim(&x);
        let (ev, at) = scenario(
            &x,
            &mut o,
            process_of(&x.ee),
            vec![socket(SocketProtocol::Tcp, REMOTE_ADDR, REMOTE_PORT, state)],
            Some(&c),
        );
        let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
        not_verified(&r);
        assert_eq!(
            r.result,
            ReconciliationResult::CannotProve,
            "state {state:#x}"
        );
    }
}

// ═══ 3, 7, 8. Wrong action / parameters / kind ═══

#[test]
fn n03_correct_process_different_remote_does_not_verify() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let (ev, at) = scenario(
        &x,
        &mut o,
        process_of(&x.ee),
        vec![socket(
            SocketProtocol::Tcp,
            [10, 0, 0, 6],
            REMOTE_PORT,
            ESTABLISHED,
        )],
        Some(&c),
    );
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
}

#[test]
fn n07_same_action_label_different_parameter_digest_does_not_verify() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    // Right remote, wrong port; and right port, v6 protocol.
    for effect in [
        socket(SocketProtocol::Tcp, REMOTE_ADDR, 8443, ESTABLISHED),
        socket(SocketProtocol::Tcp6, REMOTE_ADDR, REMOTE_PORT, ESTABLISHED),
    ] {
        let (ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![effect], Some(&c));
        let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
        not_verified(&r);
        assert_eq!(r.result, ReconciliationResult::CannotProve);
        o = Observer::new();
    }
}

/// The parameters are exactly the connection tuple but the authorized
/// action is `Write`: a matching digest under the wrong kind is nothing.
#[test]
fn n08_correct_parameter_digest_but_wrong_action_kind_does_not_verify() {
    let x = expected_for(
        ScopeAction::Standard(Action::Write),
        net_connect_params("tcp", &REMOTE_ADDR, REMOTE_PORT),
    );
    let mut o = Observer::new();
    let c = claim(&x);
    let (ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![established()], Some(&c));
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert!(!r.action.is_observable(), "no observable class for Write");
}

// ═══ 4, 5, 6, 19. Wrong process instance ═══

#[test]
fn n04_n05_n06_n19_correct_connection_on_a_different_instance_does_not_verify() {
    let x = expected();
    let base = process_of(&x.ee);

    let mut other_exe = base.clone();
    other_exe.exe_content_sha256 = sha256(b"impostor binary");
    let mut other_start = base.clone();
    other_start.process.pid_start_time_ticks += 1;
    let mut other_boot = base.clone();
    other_boot.process.boot_id = [0x3e; 16];
    let mut other_pid = base.clone();
    other_pid.process.pid += 1;

    for (label, p) in [
        ("same exe, other pid", other_pid),
        ("same pid, later start", other_start),
        ("same pid+start, other boot", other_boot),
        ("same instance tuple, other exe", other_exe),
    ] {
        let mut o = Observer::new();
        let c = claim(&x);
        let (ev, at) = scenario(&x, &mut o, p, vec![established()], Some(&c));
        let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
        not_verified(&r);
        assert_ne!(
            r.identity,
            IdentityComparison::Match { observations: 1 },
            "{label}: {r:?}"
        );
    }
}

// ═══ 9. Agent-signed observer ═══

#[test]
fn n09_action_evidence_attested_only_by_the_agent_never_verifies() {
    let x = expected();
    let mut o = Observer::with(x.agent_kp.clone(), true, &SourceMechanism::ALL);
    let c = claim(&x);
    let (ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![established()], Some(&c));
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObserverKeyIsAgentKey);
}

// ═══ 10. Host-fabricated evidence under unverified provenance ═══

/// Under `Open` probe policy the collector attested bytes from a probe it
/// cannot name, so nothing about the mechanism label is verified.
#[test]
fn n10_fabricated_evidence_under_open_provenance_does_not_verify() {
    let x = expected();
    let mut o = Observer::with(generate_ed25519_keypair(), false, &[]);
    let c = claim(&x);
    let (ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![established()], Some(&c));
    assert_eq!(ev.health.health.probe_policy, ProbePolicy::Open);
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ProvenanceUnverifiedOpenPolicy);
}

// ═══ 11, 18. Cross-decision transplantation ═══

#[test]
fn n11_n18_evidence_claimed_under_another_decision_does_not_verify_this_one() {
    let x = expected();
    let mut o = Observer::new();
    let other = AgentClaim {
        decision_id: Some([0x5a; 16]),
        ..claim(&x)
    };
    let (ev, at) = scenario(
        &x,
        &mut o,
        process_of(&x.ee),
        vec![established()],
        Some(&other),
    );
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    // The instance was observed; nothing ties this connection to *this*
    // decision.
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });

    // And with no claim at all.
    let mut o = Observer::new();
    let (ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![established()], None);
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

// ═══ 12. Unregistered mechanism ═══

#[test]
fn n12_socket_table_evidence_from_an_unprovisioned_mechanism_is_refused_at_attestation() {
    let x = expected();
    let mut o = Observer::with(
        generate_ed25519_keypair(),
        true,
        &[SourceMechanism::ProcfsPoll, SourceMechanism::ProcConnector],
    );
    let c = claim(&x);
    let obs = o.probe.observation_with(
        process_of(&x.ee),
        established(),
        SourceMechanism::ProcNetTable,
        Some(&c),
        x.now + 3_000,
    );
    let err = o
        .signer
        .attest(
            o.probe
                .batch([2u8; 16], x.now + 2_000, x.now + 4_000, vec![obs]),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestError::MechanismNotProvisioned {
                mechanism: SourceMechanism::ProcNetTable,
                ..
            }
        ),
        "{err:?}"
    );
}

// ═══ 13, 14. Lost evidence, restart ═══

#[test]
fn n13_counted_loss_around_the_action_is_cannot_prove() {
    let x = expected();
    let mut o = Observer::new();
    o.probe.enable_loss_counter();
    let c = claim(&x);
    let now = x.now;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    o.probe.record_lost_events(2);
    let obs = o.probe.observation_with(
        process_of(&x.ee),
        established(),
        SourceMechanism::ProcNetTable,
        Some(&c),
        now + 3_000,
    );
    let b2 = o.batch(2, now + 2_000, now + 4_000, vec![obs]);
    let at = now + 5_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.health(at),
    };
    assert_eq!(ev.health.health.state, ObserverState::Degraded);
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObserverDegraded);
}

#[test]
fn n14_observer_restart_around_the_action_is_not_verification() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let (mut ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![established()], Some(&c));
    o.signer.note_probe_restart();
    ev.health = o.health(at);
    assert_eq!(ev.health.health.state, ObserverState::Recovering);
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::ContinuityFailure);
}

// ═══ 15. Mutation of every signed field of the action evidence ═══

#[test]
fn n15_mutating_any_signed_field_of_the_action_observation_is_an_integrity_failure() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let (ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![established()], Some(&c));

    type Mut = fn(&mut ObservedExecution);
    let mutations: [(&str, Mut); 11] = [
        ("protocol", |o| {
            set_socket(o, |s| *s.0 = SocketProtocol::Tcp6)
        }),
        ("remote addr", |o| set_socket(o, |s| s.2.addr[3] ^= 1)),
        ("remote port", |o| set_socket(o, |s| s.2.port ^= 1)),
        ("state", |o| set_socket(o, |s| *s.3 = LISTEN)),
        ("inode", |o| set_socket(o, |s| *s.4 ^= 1)),
        ("local port", |o| set_socket(o, |s| s.1.port ^= 1)),
        ("pid", |o| o.observed.process.pid ^= 1),
        ("start ticks", |o| {
            o.observed.process.pid_start_time_ticks ^= 1
        }),
        ("exe hash", |o| o.observed.exe_content_sha256[0] ^= 1),
        ("mechanism", |o| o.mechanism = SourceMechanism::ProcfsPoll),
        ("claimed decision", |o| {
            o.claimed_decision_id = Some([0x11; 16]);
        }),
    ];
    for (label, m) in mutations {
        let mut forged = ev.clone();
        m(&mut forged.batches[1].batch.observations[0]);
        let r = reconcile_expectation(&x.ee, Some(&forged), &ctx(&x, &o, at));
        assert_eq!(
            r.result,
            ReconciliationResult::SensorIntegrityFailure,
            "{label}: {r:?}"
        );
        assert_eq!(r.strength, EvidenceStrength::Proven, "{label}");
    }
    // Attribution is signed too.
    let mut forged = ev.clone();
    forged.batches[1].batch.observations[0].attribution = AgentAttribution::Claimed {
        agent_id: "aip1someoneelse".into(),
        claim_source: "orchestrator".into(),
    };
    let r = reconcile_expectation(&x.ee, Some(&forged), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
}

type SocketFields<'a> = (
    &'a mut SocketProtocol,
    &'a mut SocketEndpoint,
    &'a mut SocketEndpoint,
    &'a mut u8,
    &'a mut u64,
);

fn set_socket(o: &mut ObservedExecution, f: impl FnOnce(SocketFields<'_>)) {
    if let ObservedEffect::SocketObserved {
        protocol,
        local,
        remote,
        state,
        inode,
    } = &mut o.effect
    {
        f((protocol, local, remote, state, inode));
    } else {
        panic!("fixture effect is not a socket");
    }
}

// ═══ 16. Domain separation of the parameter digest ═══

/// The parameter digest is domain-tagged (`GHOST/ActionParameters/v1`). The
/// same `(key, value)` pairs encoded under any other domain, or with no
/// domain, must not reproduce it — so no other signed object's digest can be
/// presented as a parameter match.
#[test]
fn n16_parameter_digest_is_domain_separated() {
    let params = net_connect_params("tcp", &REMOTE_ADDR, REMOTE_PORT);
    let genuine = params.digest();
    for domain in [
        "GHOST/ExpectedExecution/v1",
        "SYNTRIASS/GHOST/OBSERVED_EXECUTION/v1",
        "GHOST/ActionParameters/v2",
        "",
    ] {
        let mut buf = Vec::new();
        if !domain.is_empty() {
            put_domain(&mut buf, domain);
        }
        put_u32(&mut buf, 3);
        for (k, v) in [
            ("protocol", b"tcp".to_vec()),
            ("remote_addr", REMOTE_ADDR.to_vec()),
            ("remote_port", REMOTE_PORT.to_be_bytes().to_vec()),
        ] {
            put_str(&mut buf, k);
            put_bytes(&mut buf, &v);
        }
        assert_ne!(sha256(&buf), genuine, "domain {domain:?}");
    }
    // And the bytes are injective in the tuple.
    assert_ne!(
        net_connect_params("tcp", &REMOTE_ADDR, 444).digest(),
        genuine
    );
    assert_ne!(
        net_connect_params("tcp", &[10, 0, 0, 6], REMOTE_PORT).digest(),
        genuine
    );
    assert_ne!(
        net_connect_params("tcp6", &REMOTE_ADDR, REMOTE_PORT).digest(),
        genuine
    );
}

// ═══ 17. Cross-agent transplantation ═══

#[test]
fn n17_evidence_claimed_by_a_different_agent_does_not_verify() {
    let x = expected();
    let mut o = Observer::new();
    let other = AgentClaim {
        agent_id: "aip1someoneelseentirely".into(),
        ..claim(&x)
    };
    let (ev, at) = scenario(
        &x,
        &mut o,
        process_of(&x.ee),
        vec![established()],
        Some(&other),
    );
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

// ═══ 20. Window manipulation ═══

#[test]
fn n20_action_observed_outside_the_authorized_window_does_not_verify() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let now = x.now;
    // Batch claimed entirely before the window opens.
    let b1 = o.batch(1, now - 20_000, now - 10_000, vec![]);
    let obs = o.probe.observation_with(
        process_of(&x.ee),
        established(),
        SourceMechanism::ProcNetTable,
        Some(&c),
        now - 5_000,
    );
    let b2 = o.batch(2, now - 10_000, now - 1_000, vec![obs]);
    let at = now + 5_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.health(at),
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.temporal, TemporalComparison::OutsideWindow);

    // Batch claimed straddling past the window's end.
    let mut o = Observer::new();
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let obs = o.probe.observation_with(
        process_of(&x.ee),
        established(),
        SourceMechanism::ProcNetTable,
        Some(&c),
        now + TTL + 500,
    );
    let b2 = o.batch(2, now + 1_000, now + TTL + 1_000, vec![obs]);
    let at = now + TTL + 2_000;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.health(at),
    };
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    not_verified(&r);
}

// ═══ Structural: the caller cannot supply the verdict ═══

/// `Reconciliation` has no `verified`, `trusted`, `observed`, `kernel_verified`
/// or scalar field a caller could set; the positive action variant needs a
/// seal only the engine can build.
#[test]
fn caller_cannot_assert_verification_through_the_record() {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let (ev, at) = scenario(&x, &mut o, process_of(&x.ee), vec![established()], Some(&c));
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    let json = serde_json::to_string(&r).unwrap().to_lowercase();
    for forbidden in [
        "\"verified\":",
        "\"trusted\":",
        "\"observed\":true",
        "kernel_verified",
        "confidence",
        "score",
        "severity",
        "risk",
    ] {
        assert!(!json.contains(forbidden), "`{forbidden}` in {json}");
    }
    // Re-signing the health with a different, unanchored key is not a path
    // to a verdict either.
    let stranger = generate_ed25519_keypair();
    let mut forged = ev.clone();
    forged.health.attestation = sign_ed25519(
        &stranger.private_key,
        OBSERVER_ID,
        &forged.health.health.canonical_bytes(),
    )
    .unwrap();
    let r = reconcile_expectation(&x.ee, Some(&forged), &ctx(&x, &o, at));
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    let _ = o.kp;
}
