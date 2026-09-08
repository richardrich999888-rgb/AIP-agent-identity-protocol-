//! Phase C2 — `LINEAGE_VIOLATION` reachability, RED.
//!
//! The reconciler answers a lineage question about one decision: does the
//! kernel-observed ancestry of the authorized instance contradict the
//! lineage its own signed claims assert? A violation is reachable **only**
//! when both sides are complete:
//!
//! Observed side:
//!
//! - a `LineageEdge` (bound fork + bound exec, start verified) whose child
//!   is the authorized instance, carried by a batch inside attested
//!   coverage under a registered probe;
//! - the parent instance attributed to exactly one agent P through a
//!   decision-point-signed expectation whose binding matches it.
//!
//! Claimed side:
//!
//! - the decision's authority chain, supplied as tokens matching the
//!   expectation's `AuthorityRef`, verified by `aip_core`, in standing at
//!   the decision time, none of it revoked — giving the delegators D;
//! - the agent's identity document with a lineage proof that verifies
//!   against the parent document's key — giving the identity parent A.
//!
//! Violation iff P ∉ D and P ≠ A and P ≠ the agent itself. Anything missing
//! is `CANNOT_PROVE` with the gap named; any ambiguity is ambiguity. Nothing
//! here is a policy about who *should* spawn whom: it is a contradiction
//! between what was observed and what was signed.

use std::collections::HashMap;

use aip_authorize::*;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_reconcile::*;
use aip_types::{
    Action, AgentIdentityDocument, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple,
    ScopeAction, ScopedToken, EXECUTION_BINDING_VERSION,
};

const PARENT_PID: u32 = 5_200_001;
const CHILD_PID: u32 = 5_200_002;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-lv";
const PROBE_ID: &str = "probe-lv";
const RUN: [u8; 16] = [0x5b; 16];
const ANCHOR_BOOT_NS: u64 = 300_000_000_000;
const CLK_TCK: u32 = 100;
const TICK_NS: u64 = 10_000_000;

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn binding(agent_id: &str, pid: u32, start_ticks: u64, image: &[u8]) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: start_ticks,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: sha256(image),
        exe_path: "/opt/agent/bin/image".into(),
        bound_at_ms: 1_700_000_000_000,
    }
}

fn process_of(b: &ExecutionBinding) -> ObservedProcess {
    ObservedProcess {
        process: b.process,
        exe_content_sha256: b.exe_content_sha256,
        exe_path: b.exe_path.clone(),
    }
}

/// Principals: CFO (root issuer), orchestrator (holds the root, delegates to
/// the child, and is the child's identity parent), the child agent, and a
/// rogue agent with its own root authority but no relation to the child.
struct World {
    cfo_id: String,
    orch: AgentIdentityDocument,
    child: AgentIdentityDocument,
    child_kp: KeyPair,
    rogue: AgentIdentityDocument,
    root: ScopedToken,
    child_chain: DecisionAuthority,
    rogue_root: ScopedToken,
    keys: HashMap<String, Vec<u8>>,
    dp: DecisionPoint,
    anchors: DecisionPointTrustAnchors,
    now: u64,
}

fn world() -> World {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch, orch_kp) = create_identity(provenance("orch"), None).unwrap();
    let (child, child_kp) =
        create_identity(provenance("child"), Some((&orch.id, &orch_kp.private_key))).unwrap();
    let (rogue, rogue_kp) = create_identity(provenance("rogue"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(&root, &orch_kp.private_key, &child.id, scope_submitter()).unwrap();
    let rogue_root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &rogue.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let now = root.issued_at.max(hop.issued_at).max(rogue_root.issued_at) + 1;

    let mut keys = HashMap::new();
    keys.insert(cfo_id.clone(), cfo_kp.public_key.clone());
    keys.insert(orch.id.clone(), orch_kp.public_key.clone());
    keys.insert(rogue.id.clone(), rogue_kp.public_key.clone());

    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("dp"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch.id, &orch_kp.public_key)
        .trust_issuer(&rogue.id, &rogue_kp.public_key);
    let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    World {
        cfo_id,
        orch,
        child,
        child_kp,
        rogue,
        root: root.clone(),
        child_chain: DecisionAuthority {
            root,
            chain: vec![hop],
        },
        rogue_root,
        keys,
        dp,
        anchors,
        now,
    }
}

impl World {
    fn expect(
        &self,
        agent_id: &str,
        root: &ScopedToken,
        chain: &[aip_types::DelegationToken],
        action: ScopeAction,
        b: ExecutionBinding,
    ) -> ExpectedExecution {
        let req = AuthorizationRequest {
            agent_id: agent_id.to_string(),
            root_token: root.clone(),
            delegation_chain: chain.to_vec(),
            action_kind: action,
            parameters: ActionParameters::empty(),
            execution_binding: b,
            requested_ttl_ms: TTL,
        };
        match self.dp.authorize_at(&req, self.now) {
            Decision::Authorized(ee) => *ee,
            Decision::Denied(d) => panic!("fixture must authorize: {d:?}"),
        }
    }

    fn child_expectation(&self, b: ExecutionBinding) -> ExpectedExecution {
        self.expect(
            &self.child.id,
            &self.child_chain.root,
            &self.child_chain.chain,
            ScopeAction::Standard(Action::Write),
            b,
        )
    }

    fn orch_expectation(&self, b: ExecutionBinding) -> ExpectedExecution {
        self.expect(
            &self.orch.id,
            &self.root,
            &[],
            ScopeAction::Standard(Action::Delegate),
            b,
        )
    }

    fn rogue_expectation(&self, b: ExecutionBinding) -> ExpectedExecution {
        self.expect(
            &self.rogue.id,
            &self.rogue_root,
            &[],
            ScopeAction::Standard(Action::Delegate),
            b,
        )
    }

    fn ctx(&self, o: &Observer, at: u64) -> ReconciliationContext {
        ReconciliationContext {
            decision_point_anchors: self.anchors.clone(),
            observer_anchors: o.anchors.clone(),
            verification_time_ms: at,
            health_max_age_ms: HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            expected_side: ExpectedSideCoverage::Unknown,
            agent_public_key: Some(self.child_kp.public_key.clone()),
        }
    }
}

struct Observer {
    signer: CollectorSigner,
    anchors: ObserverTrustAnchors,
    kp: aip_types::KeyPair,
}

impl Observer {
    fn new(registered: bool) -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        if registered {
            signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
        }
        let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
        Self {
            signer,
            anchors,
            kp,
        }
    }

    /// Re-sign a health record the test has edited. The state lives inside
    /// the signed preimage, so this is what an honest collector in that
    /// state actually emits — not a forgery.
    fn resign_health(&self, mut h: SignedSensorHealth) -> SignedSensorHealth {
        h.attestation = aip_crypto::sign_ed25519(
            &self.kp.private_key,
            OBSERVER_ID,
            &h.health.canonical_bytes(),
        )
        .unwrap();
        h
    }
}

fn spawn(
    seq: u64,
    ts_ns: u64,
    parent_pid: u32,
    child_pid: u32,
    bound: Option<ObservedProcess>,
) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessSpawn {
            parent_pid,
            child_pid,
            parent_comm: "orch".into(),
            child_comm: "orch".into(),
        },
        cpu: 0,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

fn exec(seq: u64, ts_ns: u64, pid: u32, bound: Option<ObservedProcess>) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessExec {
            pid,
            old_pid: pid,
            filename: "/opt/agent/bin/image".into(),
        },
        cpu: 1,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
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
            SourceMechanism::SchedTracepoint,
        ]),
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

/// The whole observed scene: `parent` (bound) forks `child_pid`, which
/// execs as `child` (bound), inside one attested batch after an epoch batch.
struct Scene {
    o: Observer,
    ev: ObserverEvidence,
    at: u64,
    fork_ns: u64,
}

fn scene(
    w: &World,
    mut o: Observer,
    parent: Option<ObservedProcess>,
    child: Option<ObservedProcess>,
    with_exec: bool,
) -> Scene {
    let now = w.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let b1 = o
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a),
            now - 1_000,
        )
        .unwrap();
    let fork_ns = boot_ns_for(now + 3_000, anchor_wall);
    let mut events = vec![spawn(1, fork_ns, PARENT_PID, CHILD_PID, parent)];
    if with_exec {
        events.push(exec(2, fork_ns + 3_000_000, CHILD_PID, child));
    }
    let last = events.len() as u64;
    let b2 = o
        .signer
        .attest_at(
            raw_batch(2, now + 2_000, now + 4_000, (1, last), events, a),
            now + 4_000,
        )
        .unwrap();
    let at = now + 5_000;
    let health = o.signer.health(at).unwrap();
    Scene {
        o,
        ev: ObserverEvidence {
            batches: vec![b1, b2],
            health,
        },
        at,
        fork_ns,
    }
}

/// Child start tick as the probe would anchor it at exec: the fork tick.
fn child_start_ticks(w: &World) -> u64 {
    let anchor_wall = w.now - 10_000;
    boot_ns_for(w.now + 3_000, anchor_wall) / TICK_NS
}

fn child_binding(w: &World) -> ExecutionBinding {
    binding(&w.child.id, CHILD_PID, child_start_ticks(w), b"child image")
}

fn parent_binding(agent_id: &str) -> ExecutionBinding {
    binding(agent_id, PARENT_PID, 2_000_000, b"orchestrator image")
}

struct Case {
    w: World,
    ee: ExpectedExecution,
    scene: Scene,
    peers: Vec<ExpectedExecution>,
}

/// The default scene: the child instance, spawned by an instance the
/// decision point attributes to `spawner`, authorized through cfo → orch →
/// child, whose identity parent is orch.
fn case(spawner: Spawner) -> Case {
    let w = world();
    let cb = child_binding(&w);
    let ee = w.child_expectation(cb.clone());
    let (pb, peer) = match spawner {
        Spawner::Orch => {
            let pb = parent_binding(&w.orch.id);
            (pb.clone(), w.orch_expectation(pb))
        }
        Spawner::Rogue => {
            let pb = parent_binding(&w.rogue.id);
            (pb.clone(), w.rogue_expectation(pb))
        }
    };
    let sc = scene(
        &w,
        Observer::new(true),
        Some(process_of(&pb)),
        Some(process_of(&cb)),
        true,
    );
    Case {
        w,
        ee,
        scene: sc,
        peers: vec![peer],
    }
}

enum Spawner {
    Orch,
    Rogue,
}

fn inputs<'a>(
    c: &'a Case,
    authority: Option<&'a DecisionAuthority>,
    identity: Option<IdentityLineageInput<'a>>,
    revoked: &'a [[u8; 16]],
) -> LineageInputs<'a> {
    LineageInputs {
        peer_expectations: &c.peers,
        authority,
        issuer_keys: &c.w.keys,
        revoked_jtis: revoked,
        identity,
    }
}

fn full<'a>(c: &'a Case) -> LineageInputs<'a> {
    inputs(
        c,
        Some(&c.w.child_chain),
        Some(IdentityLineageInput {
            child: &c.w.child,
            parent: &c.w.orch,
        }),
        &[],
    )
}

fn run(c: &Case, li: &LineageInputs<'_>) -> Reconciliation {
    reconcile_lineage(
        &c.ee,
        Some(&c.scene.ev),
        &c.w.ctx(&c.scene.o, c.scene.at),
        li,
    )
}

// ═══ the violation, and the two ways the same scene is consistent ═══

/// lv01 — complete evidence on both sides, and they contradict: the kernel
/// shows the child instance spawned by an instance the decision point
/// attributes to the rogue; the child's authority chain names cfo and orch;
/// its identity parent is orch. The rogue is on neither side.
#[test]
fn lv01_contradiction_with_complete_evidence_is_lineage_violation() {
    let c = case(Spawner::Rogue);
    let r = run(&c, &full(&c));
    assert_eq!(r.result, ReconciliationResult::LineageViolation, "{r:?}");
    assert_eq!(
        r.strength,
        EvidenceStrength::Attested,
        "never Proven: procfs-bound instances"
    );
    assert_eq!(r.reason, ReasonCode::LineageContradicted);
    assert_eq!(r.lineage, LineageComparison::Contradicted);
    // Traceable: the fork and exec events and the peer decision are cited.
    let kernel_refs = r
        .evidence
        .iter()
        .filter(|e| matches!(e, EvidenceRef::KernelEvent { .. }))
        .count();
    assert_eq!(kernel_refs, 2);
    assert!(r.evidence.iter().any(|e| matches!(
        e,
        EvidenceRef::Expected { decision_id, .. } if decision_id.as_bytes() == &c.peers[0].decision_id
    )));
    assert_eq!(r.version, RECONCILIATION_VERSION);
}

/// lv02 — the spawner is a delegator on the child's chain: consistent. No
/// violation, and no positive class either — the record says what was
/// established and stops.
#[test]
fn lv02_spawner_on_the_delegation_chain_is_consistent() {
    let c = case(Spawner::Orch);
    let r = run(&c, &full(&c));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageConsistent);
    assert_eq!(
        r.lineage,
        LineageComparison::Consistent {
            via: LineageLink::Delegator
        }
    );
}

/// lv03 — the spawner is not on the chain but is the identity parent (the
/// key that endorsed the child's key at creation): consistent by identity.
#[test]
fn lv03_spawner_that_is_the_identity_parent_is_consistent() {
    // Authority for the child comes straight from the CFO (no orch hop), but
    // orch created the child's identity and spawned its process.
    let (w, direct) = world_with_direct_root();
    let cb = child_binding(&w);
    let ee = w.expect(
        &w.child.id,
        &direct,
        &[],
        ScopeAction::Standard(Action::Write),
        cb.clone(),
    );
    let pb = parent_binding(&w.orch.id);
    let peer = w.orch_expectation(pb.clone());
    let sc = scene(
        &w,
        Observer::new(true),
        Some(process_of(&pb)),
        Some(process_of(&cb)),
        true,
    );
    let c = Case {
        w,
        ee,
        scene: sc,
        peers: vec![peer],
    };
    let authority = DecisionAuthority {
        root: direct,
        chain: vec![],
    };
    let li = inputs(
        &c,
        Some(&authority),
        Some(IdentityLineageInput {
            child: &c.w.child,
            parent: &c.w.orch,
        }),
        &[],
    );
    let r = run(&c, &li);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageConsistent);
    assert_eq!(
        r.lineage,
        LineageComparison::Consistent {
            via: LineageLink::IdentityParent
        }
    );
}

/// A world plus a root token issued by the CFO directly to the child.
fn world_with_direct_root() -> (World, ScopedToken) {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch, orch_kp) = create_identity(provenance("orch"), None).unwrap();
    let (child, child_kp) =
        create_identity(provenance("child"), Some((&orch.id, &orch_kp.private_key))).unwrap();
    let (rogue, rogue_kp) = create_identity(provenance("rogue"), None).unwrap();
    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(&root, &orch_kp.private_key, &child.id, scope_submitter()).unwrap();
    let rogue_root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &rogue.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let direct = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &child.id,
        scope_submitter(),
        Some(3_600_000),
    )
    .unwrap();
    let now = [
        root.issued_at,
        hop.issued_at,
        rogue_root.issued_at,
        direct.issued_at,
    ]
    .into_iter()
    .max()
    .unwrap()
        + 1;
    let mut keys = HashMap::new();
    keys.insert(cfo_id.clone(), cfo_kp.public_key.clone());
    keys.insert(orch.id.clone(), orch_kp.public_key.clone());
    keys.insert(rogue.id.clone(), rogue_kp.public_key.clone());
    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("dp"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch.id, &orch_kp.public_key)
        .trust_issuer(&rogue.id, &rogue_kp.public_key);
    let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);
    (
        World {
            cfo_id,
            orch,
            child,
            child_kp,
            rogue,
            root: root.clone(),
            child_chain: DecisionAuthority {
                root,
                chain: vec![hop],
            },
            rogue_root,
            keys,
            dp,
            anchors,
            now,
        },
        direct,
    )
}

// ═══ incompleteness: every missing piece is CANNOT_PROVE with its gap ═══

/// lv04 — forged parent: the spawner's expectation is signed by a decision
/// point the verifier does not anchor (or by the agent's own key). The
/// parent is then unattributed; the scene is otherwise the violation scene.
#[test]
fn lv04_forged_parent_attribution_leaves_the_parent_unattributed() {
    let mut c = case(Spawner::Rogue);
    // Re-sign the rogue's expectation under an unanchored decision point.
    let fake_kp = generate_ed25519_keypair();
    let fake_dp = DecisionPoint::new(
        derive_aip_id(&fake_kp.public_key, &provenance("fake-dp")),
        &fake_kp.private_key,
        &fake_kp.public_key,
        MAX_TTL,
    )
    .unwrap()
    .trust_issuer(&c.w.cfo_id, &c.w.keys[&c.w.cfo_id]);
    let req = AuthorizationRequest {
        agent_id: c.w.rogue.id.clone(),
        root_token: c.w.rogue_root.clone(),
        delegation_chain: vec![],
        action_kind: ScopeAction::Standard(Action::Delegate),
        parameters: ActionParameters::empty(),
        execution_binding: parent_binding(&c.w.rogue.id),
        requested_ttl_ms: TTL,
    };
    let forged = fake_dp
        .authorize_at(&req, c.w.now)
        .expected()
        .unwrap()
        .clone();
    c.peers = vec![forged];
    let r = run(&c, &full(&c));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::LineageParentUnattributed);
    assert_eq!(r.lineage, LineageComparison::Incomplete);
}

/// lv05 — forged child: the exec'd child instance is not the authorized
/// instance (another start tick, or another image). No edge is about this
/// decision; nothing is concluded.
#[test]
fn lv05_a_child_that_is_not_the_authorized_instance_is_no_evidence() {
    let w = world();
    let cb = child_binding(&w);
    let ee = w.child_expectation(cb.clone());
    let pb = parent_binding(&w.rogue.id);
    let peer = w.rogue_expectation(pb.clone());
    let mut other = process_of(&cb);
    other.exe_content_sha256 = sha256(b"another image");
    let sc = scene(
        &w,
        Observer::new(true),
        Some(process_of(&pb)),
        Some(other),
        true,
    );
    let c = Case {
        w,
        ee,
        scene: sc,
        peers: vec![peer],
    };
    let r = run(&c, &full(&c));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageEvidenceUnavailable);
    assert_eq!(r.lineage, LineageComparison::Incomplete);
}

/// lv06 — transplanted delegation: the tokens supplied as the decision's
/// authority do not match the expectation's `AuthorityRef` (another
/// chain, or a chain ending at another agent). Authority side incomplete.
#[test]
fn lv06_transplanted_delegation_is_not_this_decisions_authority() {
    let c = case(Spawner::Rogue);
    let other_chain = DecisionAuthority {
        root: c.w.rogue_root.clone(),
        chain: vec![],
    };
    let li = inputs(
        &c,
        Some(&other_chain),
        Some(IdentityLineageInput {
            child: &c.w.child,
            parent: &c.w.orch,
        }),
        &[],
    );
    let r = run(&c, &li);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageAuthorityUnavailable);
    assert_eq!(r.lineage, LineageComparison::Incomplete);
}

/// lv07 — valid identity but invalid authority: a hop rewritten after
/// signing. Authority side incomplete; never a violation.
#[test]
fn lv07_valid_identity_with_invalid_authority_is_incomplete() {
    let c = case(Spawner::Rogue);
    let mut forged = c.w.child_chain.clone();
    forged.chain[0].expires_at = forged.chain[0].expires_at.map(|e| e + 1);
    let li = inputs(
        &c,
        Some(&forged),
        Some(IdentityLineageInput {
            child: &c.w.child,
            parent: &c.w.orch,
        }),
        &[],
    );
    let r = run(&c, &li);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageAuthorityUnavailable);
}

/// lv08 — process lineage without identity lineage: no identity document,
/// or a document whose proof does not verify against the offered parent.
/// The claimed side is incomplete; the same scene that is a violation with
/// complete evidence is CANNOT_PROVE here.
#[test]
fn lv08_process_lineage_without_identity_lineage_is_incomplete() {
    let c = case(Spawner::Rogue);
    let li = inputs(&c, Some(&c.w.child_chain), None, &[]);
    let r = run(&c, &li);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageIdentityUnavailable);
    assert_eq!(r.lineage, LineageComparison::Incomplete);

    // A proof that does not verify against the offered parent document.
    let li = inputs(
        &c,
        Some(&c.w.child_chain),
        Some(IdentityLineageInput {
            child: &c.w.child,
            parent: &c.w.rogue,
        }),
        &[],
    );
    let r = run(&c, &li);
    assert_eq!(r.reason, ReasonCode::LineageIdentityUnavailable);
}

/// lv09 — identity lineage without authority lineage: no chain supplied.
#[test]
fn lv09_identity_lineage_without_authority_lineage_is_incomplete() {
    let c = case(Spawner::Rogue);
    let li = inputs(
        &c,
        None,
        Some(IdentityLineageInput {
            child: &c.w.child,
            parent: &c.w.orch,
        }),
        &[],
    );
    let r = run(&c, &li);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageAuthorityUnavailable);
}

/// lv10 — ambiguous parent: two agents' decision-point-signed expectations
/// name bindings matching the parent instance. Ambiguity, never a verdict.
#[test]
fn lv10_ambiguous_parent_is_ambiguity() {
    let mut c = case(Spawner::Rogue);
    // The orchestrator's expectation, but with the rogue's process as binding.
    let pb_rogue = parent_binding(&c.w.rogue.id);
    let mut same_process_other_agent = pb_rogue.clone();
    same_process_other_agent.agent_id = c.w.orch.id.clone();
    let orch_peer = c.w.orch_expectation(same_process_other_agent);
    c.peers.push(orch_peer);
    let r = run(&c, &full(&c));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageParentAmbiguous);
    assert_eq!(
        r.lineage,
        LineageComparison::Ambiguous {
            parent_candidates: 2
        }
    );
}

/// lv11 — missing parent evidence: the fork's parent was not anchored (no
/// bound parent), or the fork has no exec. No edge exists.
#[test]
fn lv11_missing_parent_evidence_is_no_edge() {
    let w = world();
    let cb = child_binding(&w);
    let ee = w.child_expectation(cb.clone());
    let pb = parent_binding(&w.rogue.id);
    let peer = w.rogue_expectation(pb.clone());
    let sc = scene(&w, Observer::new(true), None, Some(process_of(&cb)), true);
    let c = Case {
        w,
        ee,
        scene: sc,
        peers: vec![peer],
    };
    let r = run(&c, &full(&c));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageEvidenceUnavailable);

    let w = world();
    let cb = child_binding(&w);
    let ee = w.child_expectation(cb.clone());
    let pb = parent_binding(&w.rogue.id);
    let peer = w.rogue_expectation(pb.clone());
    let sc = scene(&w, Observer::new(true), Some(process_of(&pb)), None, false);
    let c = Case {
        w,
        ee,
        scene: sc,
        peers: vec![peer],
    };
    let r = run(&c, &full(&c));
    assert_eq!(r.reason, ReasonCode::LineageEvidenceUnavailable);
}

/// lv12 — revoked parent / revoked delegation: a revoked token anywhere on
/// the child's chain removes the authority side from evidence. The same
/// scene that would be consistent (lv02) is CANNOT_PROVE, and the violation
/// scene is CANNOT_PROVE too — revocation is never turned into a verdict.
#[test]
fn lv12_revoked_authority_is_incomplete_never_a_verdict() {
    let c = case(Spawner::Orch);
    let revoked = [c.w.child_chain.chain[0].jti];
    let li = inputs(
        &c,
        Some(&c.w.child_chain),
        Some(IdentityLineageInput {
            child: &c.w.child,
            parent: &c.w.orch,
        }),
        &revoked,
    );
    let r = run(&c, &li);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageAuthorityUnavailable);

    let c = case(Spawner::Rogue);
    let revoked = [c.w.root.jti];
    let li = inputs(
        &c,
        Some(&c.w.child_chain),
        Some(IdentityLineageInput {
            child: &c.w.child,
            parent: &c.w.orch,
        }),
        &revoked,
    );
    let r = run(&c, &li);
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageAuthorityUnavailable);
}

/// lv13 — duplicated child attribution: another agent's decision-point-
/// signed expectation names the child instance too. Two agents claim one
/// instance; ambiguity, never a verdict.
#[test]
fn lv13_duplicated_child_attribution_is_ambiguity() {
    let mut c = case(Spawner::Rogue);
    let mut cb_other = child_binding(&c.w);
    cb_other.agent_id = c.w.orch.id.clone();
    let other_claim = c.w.orch_expectation(cb_other);
    c.peers.push(other_claim);
    let r = run(&c, &full(&c));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::LineageChildAmbiguous);
    assert!(matches!(r.lineage, LineageComparison::Ambiguous { .. }));
}

// ═══ observer gates apply to lineage exactly as to actions ═══

/// lv14 — an unregistered (Open policy) probe, a degraded observer, an edge
/// outside attested coverage: none reaches a verdict.
#[test]
fn lv14_observer_gates_apply() {
    // Open policy.
    let w = world();
    let cb = child_binding(&w);
    let ee = w.child_expectation(cb.clone());
    let pb = parent_binding(&w.rogue.id);
    let peer = w.rogue_expectation(pb.clone());
    let sc = scene(
        &w,
        Observer::new(false),
        Some(process_of(&pb)),
        Some(process_of(&cb)),
        true,
    );
    let c = Case {
        w,
        ee,
        scene: sc,
        peers: vec![peer],
    };
    let r = run(&c, &full(&c));
    assert_ne!(r.result, ReconciliationResult::LineageViolation);
    assert_eq!(r.reason, ReasonCode::ProvenanceUnverifiedOpenPolicy);

    // Degraded observer: loss reported in the events batch.
    let c = case(Spawner::Rogue);
    let mut degraded = Observer::new(true);
    let now = c.w.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
    let b1 = degraded
        .signer
        .attest_at(
            raw_batch(1, now - 2_000, now - 1_000, (0, 0), vec![], a),
            now - 1_000,
        )
        .unwrap();
    let pb = parent_binding(&c.w.rogue.id);
    let cb = child_binding(&c.w);
    let fork_ns = c.scene.fork_ns;
    let mut lossy = raw_batch(
        2,
        now + 2_000,
        now + 4_000,
        (1, 2),
        vec![
            spawn(1, fork_ns, PARENT_PID, CHILD_PID, Some(process_of(&pb))),
            exec(2, fork_ns + 3_000_000, CHILD_PID, Some(process_of(&cb))),
        ],
        a,
    );
    lossy.dropped_events = Some(7);
    let b2 = degraded.signer.attest_at(lossy, now + 4_000).unwrap();
    let at = now + 5_000;
    let health = degraded.signer.health(at).unwrap();
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health,
    };
    let r = reconcile_lineage(&c.ee, Some(&ev), &c.w.ctx(&degraded, at), &full(&c));
    assert_ne!(r.result, ReconciliationResult::LineageViolation);
    assert_eq!(r.reason, ReasonCode::ObserverDegraded);
}

/// lv15 — the guard: a `LineageViolation` can leave `finish` only with
/// `lineage == Contradicted` at `Attested`. The record carries the lineage
/// comparison in its canonical bytes since record v4 (Gate 2 raised the
/// record to v5 for the wire comparison; the lineage field stays).
#[test]
fn lv15_record_carries_lineage_and_version_four() {
    // The lineage comparison entered the record at v4.
    const _: () = assert!(RECONCILIATION_VERSION >= 4);
    let c = case(Spawner::Rogue);
    let r = run(&c, &full(&c));
    let mut other = r.clone();
    other.lineage = LineageComparison::NotEvaluated;
    assert_ne!(r.canonical_bytes(), other.canonical_bytes());
    assert_ne!(r.digest(), other.digest());
}

/// lv16 — a plain expectation reconciliation never evaluates lineage and
/// never emits the class: the two entry points are separate questions.
#[test]
fn lv16_expectation_reconciliation_does_not_evaluate_lineage() {
    let c = case(Spawner::Rogue);
    let r = reconcile_expectation(&c.ee, Some(&c.scene.ev), &c.w.ctx(&c.scene.o, c.scene.at));
    assert_eq!(r.lineage, LineageComparison::NotEvaluated);
    assert_ne!(r.result, ReconciliationResult::LineageViolation);
}

/// R-12b. `reconcile_lineage` gates on observer state exactly as
/// `reconcile_expectation` does, and `IntegrityUnknown` is one of the states
/// that stops it.
///
/// Why this needed its own test. lv14 already covers `Degraded` on the
/// lineage path and t03d covers `IntegrityUnknown` on the expectation path,
/// so deleting the `IntegrityUnknown` arm *from the lineage gate alone*
/// changed no result in this suite. A blinded collector — one whose own
/// integrity check found a foreign tracepoint gate — would then have gone on
/// to support a `LineageViolation`, which is an accusation about a workload
/// resting on an observer that has said it cannot vouch for what it saw.
#[test]
fn lv17_integrity_unknown_blocks_lineage_exactly_as_it_blocks_an_action() {
    let c = case(Spawner::Rogue);

    // Sanity: this scene reaches a lineage violation when the observer is sound.
    let sound = reconcile_lineage(
        &c.ee,
        Some(&c.scene.ev),
        &c.w.ctx(&c.scene.o, c.scene.at),
        &full(&c),
    );
    assert_eq!(sound.result, ReconciliationResult::LineageViolation);

    // The collector's live integrity check found a foreign tracepoint gate,
    // so it signs IntegrityUnknown. The state is inside the signed preimage,
    // so re-signing is what an honest blinded collector actually emits.
    let mut ev = c.scene.ev.clone();
    ev.health.health.state = ObserverState::IntegrityUnknown;
    ev.health = c.scene.o.resign_health(ev.health);

    let r = reconcile_lineage(
        &c.ee,
        Some(&ev),
        &c.w.ctx(&c.scene.o, c.scene.at),
        &full(&c),
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObserverIntegrityUnknown);
    assert_ne!(
        r.result,
        ReconciliationResult::LineageViolation,
        "a blinded observer must not underwrite an accusation about ancestry"
    );
}

/// R-11b. A quarantined observer stops `reconcile_lineage` exactly as it
/// stops `reconcile_expectation`: `SensorIntegrityFailure` at `Attested`,
/// and never a statement about the workload's ancestry.
///
/// Why this needed its own test. t17b covers `Quarantined` on the
/// expectation path and lv14 covers `Degraded` on the lineage path, so
/// deleting the `Quarantined` arm from the lineage gate alone changed no
/// result in this suite. A quarantined collector is one that has been
/// *proven* to have forked its own record — the strongest statement the
/// system makes against an observer — and it must not go on to underwrite
/// an accusation against a workload.
#[test]
fn lv18_a_quarantined_observer_stops_lineage_and_accuses_only_itself() {
    let c = case(Spawner::Rogue);

    let sound = reconcile_lineage(
        &c.ee,
        Some(&c.scene.ev),
        &c.w.ctx(&c.scene.o, c.scene.at),
        &full(&c),
    );
    assert_eq!(sound.result, ReconciliationResult::LineageViolation);

    let mut ev = c.scene.ev.clone();
    ev.health.health.state = ObserverState::Quarantined;
    ev.health = c.scene.o.resign_health(ev.health);

    let r = reconcile_lineage(
        &c.ee,
        Some(&ev),
        &c.w.ctx(&c.scene.o, c.scene.at),
        &full(&c),
    );
    assert_eq!(r.result, ReconciliationResult::SensorIntegrityFailure);
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.reason, ReasonCode::ObserverQuarantined);
    assert_ne!(
        r.result,
        ReconciliationResult::LineageViolation,
        "a collector proven to have forked its own record accuses nobody else"
    );
}
