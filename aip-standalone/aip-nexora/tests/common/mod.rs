//! A real end-to-end scenario the NEXORA tests build proofs from.
//!
//! Nothing here is a stub: a real issuer delegates to a real agent, a real
//! decision point authorises a `ghost.net.connect.v1`, a real collector
//! attests kernel socket-state events for the authorised instance, and the
//! repository's own reconciler produces the verdict. The NEXORA tests then
//! package exactly that and try to break the package.

#![allow(dead_code)] // each test file uses a different part of the scenario

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

pub const PID: u32 = 4_100_777;
pub const TTL: u64 = 60_000;
pub const MAX_TTL: u64 = 3_600_000;
pub const HEALTH_MAX_AGE: u64 = 3_600_000;
pub const OBSERVER_ID: &str = "collector-n";
pub const PROBE_ID: &str = "probe-n";
pub const REMOTE: [u8; 4] = [10, 0, 0, 5];
pub const PORT: u16 = 443;
pub const SK: u64 = 0xffff_1234_abcd_0001;
pub const RUN: [u8; 16] = [0x5b; 16];
const ANCHOR_BOOT_NS: u64 = 100_000_000_000;

pub fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

pub fn binding(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: PID,
            pid_start_time_ticks: 910_000,
            boot_id: [0x3c; 16],
        },
        exe_content_sha256: sha256(b"nexora-scenario agent binary"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
    }
}

/// The authority chain, the decision point, the expectation and the keys a
/// verifier needs to check them.
pub struct Authorized {
    pub ee: ExpectedExecution,
    pub dp_anchors: DecisionPointTrustAnchors,
    pub dp_id: String,
    pub agent_id: String,
    pub agent_kp: KeyPair,
    pub root: aip_types::ScopedToken,
    pub chain: Vec<aip_types::DelegationToken>,
    pub issuer_keys: std::collections::HashMap<String, Vec<u8>>,
    pub now: u64,
}

pub fn authorized() -> Authorized {
    authorized_for(REMOTE, PORT)
}

pub fn authorized_for(remote: [u8; 4], port: u16) -> Authorized {
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
    let dp_anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);
    let req = AuthorizationRequest {
        agent_id: agent_aid.id.clone(),
        root_token: root.clone(),
        delegation_chain: vec![hop.clone()],
        action_kind: net_connect_action(),
        parameters: net_connect_parameters(NetProtocol::Tcp, &remote, port).unwrap(),
        execution_binding: binding(&agent_aid.id),
        requested_ttl_ms: TTL,
    };
    let ee = match dp.authorize_at(&req, now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("fixture must authorize, got {d:?}"),
    };
    let mut issuer_keys = std::collections::HashMap::new();
    issuer_keys.insert(cfo_id.clone(), cfo_kp.public_key.clone());
    issuer_keys.insert(orch_aid.id.clone(), orch_kp.public_key.clone());
    Authorized {
        ee,
        dp_anchors,
        dp_id,
        agent_id: agent_aid.id,
        agent_kp,
        root,
        chain: vec![hop],
        issuer_keys,
        now,
    }
}

pub struct Observer {
    pub signer: CollectorSigner,
    pub anchors: ObserverTrustAnchors,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl Observer {
    pub fn new() -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
        let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
        Self {
            signer,
            anchors,
            public_key: kp.public_key,
            private_key: kp.private_key,
        }
    }
}

impl Default for Observer {
    fn default() -> Self {
        Self::new()
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

fn process_of(ee: &ExpectedExecution) -> ObservedProcess {
    ObservedProcess {
        process: ee.execution_binding.process,
        exe_content_sha256: ee.execution_binding.exe_content_sha256,
        exe_path: ee.execution_binding.exe_path.clone(),
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

fn boot_ns_for(wall_ms: u64, anchor_wall: u64) -> u64 {
    ANCHOR_BOOT_NS + (wall_ms - anchor_wall) * 1_000_000
}

#[allow(clippy::too_many_arguments)]
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
            SourceMechanism::ProcNetTable,
            SourceMechanism::SockStateTracepoint,
        ]),
        claimed_from_ms: from,
        claimed_to_ms: to,
        observations: vec![],
        kernel_events: events,
        clock_anchor: anchor,
    }
}

/// The whole scenario: authorisation, observation, and the verdict the
/// repository's own reconciler produced over them.
pub struct Scenario {
    pub a: Authorized,
    pub o: Observer,
    pub evidence: ObserverEvidence,
    pub reconciliation: Reconciliation,
    pub at: u64,
}

impl Scenario {
    /// The verifier context this scenario reconciles under.
    pub fn ctx(&self) -> ReconciliationContext {
        ReconciliationContext {
            decision_point_anchors: self.a.dp_anchors.clone(),
            observer_anchors: self.o.anchors.clone(),
            verification_time_ms: self.at,
            health_max_age_ms: HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            expected_side: ExpectedSideCoverage::Unknown,
            agent_public_key: Some(self.a.agent_kp.public_key.clone()),
        }
    }
}

/// A `VERIFIED_EXECUTION · Attested` scenario: the authorised instance
/// initiates and completes the authorised connection, inside the window,
/// under attested kernel-pushed coverage.
pub fn verified_execution() -> Scenario {
    let a = authorized();
    let mut o = Observer::new();
    let now = a.now;
    let anchor_wall = now - 10_000;
    let anchor = Some(anchor_at(anchor_wall));
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], anchor),
            now - 1_000,
        )
        .unwrap();
    let syn_wall = now + 3_000;
    let syn_ns = boot_ns_for(syn_wall, anchor_wall);
    let claim = AgentClaim {
        agent_id: a.agent_id.clone(),
        claim_source: "orchestrator".into(),
        decision_id: Some(a.ee.decision_id),
    };
    let events = vec![
        KernelLifecycleEvent {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: PROBE_ID.into(),
            mechanism: SourceMechanism::SockStateTracepoint,
            kind: KernelLifecycleKind::SocketState {
                protocol: SocketProtocol::Tcp,
                local: ep([127, 0, 0, 1], 0),
                remote: ep(REMOTE, PORT),
                old_state: tcp_state::CLOSE,
                new_state: tcp_state::SYN_SENT,
                sk: SK,
                current_pid: PID,
            },
            cpu: 1,
            kernel_timestamp_ns: syn_ns,
            probe_seq: 1,
            bound: Some(process_of(&a.ee)),
            attribution: AgentAttribution::Claimed {
                agent_id: claim.agent_id.clone(),
                claim_source: claim.claim_source.clone(),
            },
            claimed_decision_id: claim.decision_id,
        },
        KernelLifecycleEvent {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: PROBE_ID.into(),
            mechanism: SourceMechanism::SockStateTracepoint,
            kind: KernelLifecycleKind::SocketState {
                protocol: SocketProtocol::Tcp,
                local: ep([127, 0, 0, 1], 51_000),
                remote: ep(REMOTE, PORT),
                old_state: tcp_state::SYN_SENT,
                new_state: tcp_state::ESTABLISHED,
                sk: SK,
                current_pid: 0,
            },
            cpu: 1,
            kernel_timestamp_ns: syn_ns + 5_000_000,
            probe_seq: 2,
            bound: None,
            attribution: AgentAttribution::NotEstablished,
            claimed_decision_id: None,
        },
    ];
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now + 2_000, now + 4_000, (1, 2), events, anchor),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let health = o.signer.health(at).unwrap();
    let evidence = ObserverEvidence {
        batches: vec![b1, b2],
        health,
    };
    let mut s = Scenario {
        a,
        o,
        evidence,
        reconciliation: Reconciliation {
            version: RECONCILIATION_VERSION,
            result: ReconciliationResult::CannotProve,
            strength: EvidenceStrength::Heuristic,
            reason: ReasonCode::NoObserverEvidence,
            decision_id: None,
            availability: aip_observe::no_observer(),
            identity: IdentityComparison::NoReference,
            action: ActionComparison::Unobservable,
            temporal: TemporalComparison::Indeterminate,
            lineage: LineageComparison::NotEvaluated,
            wire: WireCorroboration::NotEvaluated,
            replay_detected: false,
            evidence: vec![],
            verification_time_ms: at,
        },
        at,
    };
    s.reconciliation = reconcile_expectation(&s.a.ee, Some(&s.evidence), &s.ctx());
    assert_eq!(
        s.reconciliation.result,
        ReconciliationResult::VerifiedExecution,
        "the shared scenario must be a verified execution: {:?}",
        s.reconciliation.reason
    );
    assert_eq!(s.reconciliation.strength, EvidenceStrength::Attested);
    s
}

/// The same authorisation with **no** observer evidence at all: the
/// reconciler's default answer, `CANNOT_PROVE`.
pub fn cannot_prove() -> Scenario {
    let mut s = verified_execution();
    s.reconciliation = reconcile_expectation(&s.a.ee, None, &s.ctx());
    assert_eq!(
        s.reconciliation.result,
        ReconciliationResult::CannotProve,
        "no observer evidence must reconcile as CANNOT_PROVE"
    );
    s
}

// ─── Components other gates attach to a package ───

/// A signed continuity report from `observer_id`, under a key of its own.
/// The break it names is immaterial to the binding tests; what matters is
/// whose record it is.
pub fn continuity_report_of(observer_id: &str) -> aip_observe::SignedContinuityReport {
    let kp = generate_ed25519_keypair();
    let report = aip_observe::ContinuityReport {
        version: OBSERVE_PROTOCOL_VERSION,
        observer_id: observer_id.to_string(),
        key_version: 1,
        continuity_break: aip_observe::ContinuityBreak::ArchiveTruncated {
            resumed_sequence: 3,
            archived_sequence: 2,
        },
        resumed_sequence: Some(3),
        archived_sequence: Some(2),
        archived_head: Some([0x11; 32]),
        policy: aip_observe::ContinuityPolicy::Strict,
        refused: false,
        emitted_at_ms: 1_700_000_100_000,
    };
    let signature =
        aip_crypto::sign_ed25519(&kp.private_key, observer_id, &report.canonical_bytes()).unwrap();
    aip_observe::SignedContinuityReport { report, signature }
}

/// A signed warrant resting on `rec`, for `subject`. The response class is
/// whatever the engine decides; these tests never need it to be Contain.
pub fn warrant_for(rec: &Reconciliation, subject: Option<&str>) -> aip_warrant::Warrant {
    let kp = generate_ed25519_keypair();
    let finding = aip_warrant::Finding {
        finding_id: [0xa1; 16],
        reconciliation: rec.clone(),
        subject_agent: subject.map(str::to_string),
    };
    let w = aip_warrant::evaluate(
        &finding,
        &aip_warrant::WarrantPolicy::default(),
        rec.verification_time_ms + 1,
    )
    .unwrap();
    aip_warrant::WarrantAuthority::new("warrant-authority", &kp.private_key, &kp.public_key)
        .unwrap()
        .sign(w)
        .unwrap()
}

/// Commit `rec` to a fresh log and return the inclusion proof plus the
/// anchors that verify its head.
pub fn commit(
    rec: &Reconciliation,
) -> (
    aip_nexora::ProofObject,
    aip_nexora::NexoraTrustAnchors,
) {
    let kp = generate_ed25519_keypair();
    let signer = aip_nexora::NexoraSigner::new("nexora-1", 1, &kp.private_key, &kp.public_key)
        .unwrap();
    let mut log = aip_nexora::CommitmentLog::new([0x7a; 16]);
    let index = log.append(aip_nexora::LeafKind::Reconciliation, &rec.canonical_bytes());
    let head = log.head(&signer, 1_700_000_200_000).unwrap();
    let proof = log.proof_for(index, &head).unwrap();
    let anchors = aip_nexora::NexoraTrustAnchors::new().trust("nexora-1", 1, &kp.public_key);
    (proof, anchors)
}
