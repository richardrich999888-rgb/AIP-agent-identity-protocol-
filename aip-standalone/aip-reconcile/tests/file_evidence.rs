//! Gate 4 — `ghost.fs.write.v1`, one filesystem action, RED.
//!
//! ```text
//! ghost.fs.write.v1
//!     parameters:  path — the absolute path, exactly as authorized (raw bytes)
//!     observed as: a fanotify FAN_CLOSE_WRITE event whose kernel-created pidfd
//!                  bound the writer, resolved by the probe to the kernel's
//!                  current path of the object and its (dev, ino)
//!     evidence:    that a write to that path was completed by that instance;
//!                  nothing about the content
//!     kind:        Transition · mechanism Fanotify · Attested
//! ```
//!
//! The five states the mandate names, each pinned below:
//!
//! | state | record |
//! |---|---|
//! | OBSERVED | `VERIFIED_EXECUTION · Attested · Match(Fanotify, Transition)` (fw01) |
//! | NOT OBSERVED | `CANNOT_PROVE · ActionEvidenceUnavailable` — the instance was seen, no write to the path was (fw03) |
//! | AMBIGUOUS | `CANNOT_PROVE · AmbiguousObservations` — two instances, one claim (fw04) |
//! | LOSS | `CANNOT_PROVE · ObserverDegraded` — the queue overflowed in the window (fw05) |
//! | UNAVAILABLE | no observer / mechanism not provisioned / `Open` policy (fw06) |
//!
//! Hash semantics: the digest is over the path bytes only. A path is a name
//! the kernel resolved for the object when the event was read, in the
//! probe's mount namespace; the object's `(dev, ino)` is signed context. No
//! content digest exists in this class.
//!
//! FIXTURE-BASED; the live path is `ghost-demo/tests/live_file.rs`.

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

const PID: u32 = 3_970_501;
const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const HEALTH_MAX_AGE: u64 = 3_600_000;
const OBSERVER_ID: &str = "collector-f";
const PROBE_ID: &str = "probe-f";
const PATH: &str = "/srv/out/report.csv";
const OTHER_PATH: &str = "/srv/out/other.csv";
const DEV: u64 = 65_024;
const INO: u64 = 1_884_732;
const RUN: [u8; 16] = [0x7c; 16];
const ANCHOR_BOOT_NS: u64 = 100_000_000_000;
const FAN_MODIFY: u64 = 0x02;
const FAN_CLOSE_WRITE: u64 = 0x08;
const MS: u64 = 1_000_000;

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
        exe_content_sha256: sha256(b"payments-agent binary v7"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
    }
}

fn expected_write(path: &str) -> Expected {
    let scope = CapabilityScope {
        allowed: vec![fs_write_action()],
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
        action_kind: fs_write_action(),
        parameters: fs_write_parameters(path).unwrap(),
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

fn other_instance(ee: &ExpectedExecution) -> ObservedProcess {
    let mut p = process_of(ee);
    p.process.pid_start_time_ticks += 5_000;
    p
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

#[allow(clippy::too_many_arguments)] // a fixture: every field is a knob
fn write_event(
    seq: u64,
    ts_ns: u64,
    mask: u64,
    path: &str,
    deleted: bool,
    ino: u64,
    bound: Option<ObservedProcess>,
    c: Option<&AgentClaim>,
) -> KernelLifecycleEvent {
    let (attribution, claimed_decision_id) = attribution(c);
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::Fanotify,
        kind: KernelLifecycleKind::FileEvent {
            mask,
            pid: PID,
            path: path.into(),
            deleted,
            dev: DEV,
            ino,
        },
        cpu: 0,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution,
        claimed_decision_id,
    }
}

fn presence(seq: u64, p: ObservedProcess, c: Option<&AgentClaim>, wall: u64) -> ObservedExecution {
    let (attribution, claimed_decision_id) = attribution(c);
    ObservedExecution {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        observed: p,
        attribution,
        effect: ObservedEffect::ProcessPresent,
        mechanism: SourceMechanism::PidFdAnchored,
        claimed_decision_id,
        host_wall_clock_ms: wall,
        probe_monotonic_ns: seq,
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
            SourceMechanism::Fanotify,
        ]),
        claimed_from_ms: from,
        claimed_to_ms: to,
        observations: obs,
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

type Events = Box<dyn Fn(&Expected, &AgentClaim, u64) -> Vec<KernelLifecycleEvent>>;

struct Scene {
    x: Expected,
    o: Observer,
    ev: ObserverEvidence,
    at: u64,
}

/// Epoch-start batch; batch 2 `[now+2s, now+4s]` carrying a presence
/// observation of the authorized instance (so identity is always in
/// question) plus whatever `events` yields for `t0` (the stamp the anchor
/// maps to `now + 3 s`).
fn scene_with(x: Expected, o: Observer, events: Events, dropped: u64) -> Scene {
    let c = claim(&x);
    let mut o = o;
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
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
    let t0 = mono_for(now + 3_000, anchor_wall);
    let evs = events(&x, &c, t0);
    let obs = vec![presence(100, process_of(&x.ee), Some(&c), now + 3_000)];
    let last = evs.len().max(1) as u64;
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (1, last.max(100)),
                evs,
                obs,
                a,
                Some(dropped),
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

fn scene(x: Expected, events: Events) -> Scene {
    scene_with(x, Observer::new(), events, 0)
}

fn honest() -> Events {
    Box::new(|x, c, t0| {
        vec![write_event(
            1,
            t0 + 50 * MS,
            FAN_MODIFY | FAN_CLOSE_WRITE,
            PATH,
            false,
            INO,
            Some(process_of(&x.ee)),
            Some(c),
        )]
    })
}

fn none() -> Events {
    Box::new(|_, _, _| vec![])
}

fn reconcile(s: &Scene) -> Reconciliation {
    reconcile_expectation(&s.x.ee, Some(&s.ev), &ctx(&s.x, &s.o, s.at))
}

// ═══ OBSERVED ═══

#[test]
fn fw01_observed_a_completed_write_to_the_authorized_path_by_the_bound_instance_verifies() {
    let r = reconcile(&scene(expected_write(PATH), honest()));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested, "never Proven");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceMatches);
    match r.action {
        ActionComparison::Match(seal) => {
            assert_eq!(seal.kind(), ActionEvidenceKind::Transition);
            assert_eq!(seal.mechanism(), SourceMechanism::Fanotify);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(r.temporal, TemporalComparison::WithinWindow);
    assert_eq!(r.wire, WireCorroboration::NotEvaluated);
    assert!(r
        .evidence
        .iter()
        .any(|e| matches!(e, EvidenceRef::KernelEvent { index: 0, .. })));
}

#[test]
fn fw02_the_digest_is_the_path_bytes_and_nothing_else() {
    assert_eq!(FS_WRITE_ACTION, "ghost.fs.write.v1");
    let a = fs_write_parameters(PATH).unwrap();
    let b = fs_write_parameters(PATH).unwrap();
    assert_eq!(a.digest(), b.digest());
    assert_ne!(
        a.digest(),
        fs_write_parameters("/srv/out/report.csv/")
            .unwrap()
            .digest()
    );
    assert_ne!(
        a.digest(),
        fs_write_parameters(OTHER_PATH).unwrap().digest()
    );
    assert!(fs_write_parameters("relative/path").is_err());
    assert!(fs_write_parameters("").is_err());
    assert!(fs_write_parameters("/srv/out/re\0port").is_err());
    assert_ne!(fs_write_action(), net_connect_action());
    // The inode is signed context, never in the digest: a different inode at
    // the same path (the file was replaced) still verifies.
    let evs: Events = Box::new(|x, c, t0| {
        vec![write_event(
            1,
            t0 + 50 * MS,
            FAN_CLOSE_WRITE,
            PATH,
            false,
            INO + 1,
            Some(process_of(&x.ee)),
            Some(c),
        )]
    });
    let r = reconcile(&scene(expected_write(PATH), evs));
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
}

// ═══ NOT OBSERVED ═══

#[test]
fn fw03_not_observed_the_instance_was_seen_and_no_write_to_the_path_was() {
    let r = reconcile(&scene(expected_write(PATH), none()));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnavailable);
    assert_eq!(r.identity, IdentityComparison::Match { observations: 1 });
    assert_ne!(
        r.result,
        ReconciliationResult::PhantomClaim,
        "silence is not non-execution"
    );
}

// ═══ AMBIGUOUS ═══

#[test]
fn fw04_ambiguous_two_instances_write_the_path_under_one_claim() {
    let evs: Events = Box::new(|x, c, t0| {
        vec![
            write_event(
                1,
                t0 + 50 * MS,
                FAN_CLOSE_WRITE,
                PATH,
                false,
                INO,
                Some(process_of(&x.ee)),
                Some(c),
            ),
            write_event(
                2,
                t0 + 60 * MS,
                FAN_CLOSE_WRITE,
                PATH,
                false,
                INO,
                Some(other_instance(&x.ee)),
                Some(c),
            ),
        ]
    });
    let r = reconcile(&scene(expected_write(PATH), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::AmbiguousObservations);
}

// ═══ LOSS ═══

#[test]
fn fw05_loss_a_queue_overflow_in_the_window_degrades_the_verdict() {
    let s = scene_with(expected_write(PATH), Observer::new(), honest(), 1);
    let r = reconcile(&s);
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::ObserverDegraded);
}

// ═══ UNAVAILABLE ═══

#[test]
fn fw06_unavailable_no_observer_unprovisioned_probe_or_open_policy() {
    let x = expected_write(PATH);
    let o = Observer::new();
    let r = reconcile_expectation(&x.ee, None, &ctx(&x, &o, x.now));
    assert_eq!(r.result, ReconciliationResult::CannotProve);
    assert_eq!(r.reason, ReasonCode::NoObserverEvidence);
    // A probe not provisioned for fanotify cannot even get its batch signed.
    let mut o = Observer::with(true, &[SourceMechanism::PidFdAnchored]);
    let b = raw_batch(1, 1, 2, (0, 0), vec![], vec![], None, Some(0));
    assert!(o.signer.attest(b).is_err());
    // Under Open policy the label is unverified provenance.
    let s = scene_with(
        expected_write(PATH),
        Observer::with(false, &[]),
        honest(),
        0,
    );
    let r = reconcile(&s);
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ProvenanceUnverifiedOpenPolicy);
}

// ═══ Not the authorized action ═══

#[test]
fn fw07_a_write_to_another_path_does_not_match() {
    let evs: Events = Box::new(|x, c, t0| {
        vec![write_event(
            1,
            t0 + 50 * MS,
            FAN_CLOSE_WRITE,
            OTHER_PATH,
            false,
            INO,
            Some(process_of(&x.ee)),
            Some(c),
        )]
    });
    let r = reconcile(&scene(expected_write(PATH), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceDoesNotMatch);
    assert!(matches!(r.action, ActionComparison::Mismatch(_)));
}

#[test]
fn fw08_a_modify_without_a_close_write_is_a_write_in_progress_not_a_completed_write() {
    let evs: Events = Box::new(|x, c, t0| {
        vec![write_event(
            1,
            t0 + 50 * MS,
            FAN_MODIFY,
            PATH,
            false,
            INO,
            Some(process_of(&x.ee)),
            Some(c),
        )]
    });
    let r = reconcile(&scene(expected_write(PATH), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnavailable);
}

#[test]
fn fw09_a_path_the_kernel_reported_as_deleted_cannot_be_placed_on_an_authorized_path() {
    let evs: Events = Box::new(|x, c, t0| {
        vec![write_event(
            1,
            t0 + 50 * MS,
            FAN_CLOSE_WRITE,
            PATH,
            true,
            INO,
            Some(process_of(&x.ee)),
            Some(c),
        )]
    });
    let r = reconcile(&scene(expected_write(PATH), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::FilePathUnresolved);
}

// ═══ Attribution ═══

#[test]
fn fw10_an_unbound_write_is_a_pid_reference_never_identity() {
    let evs: Events = Box::new(|_, c, t0| {
        vec![write_event(
            1,
            t0 + 50 * MS,
            FAN_CLOSE_WRITE,
            PATH,
            false,
            INO,
            None,
            Some(c),
        )]
    });
    let r = reconcile(&scene(expected_write(PATH), evs));
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

#[test]
fn fw11_a_write_by_another_instance_under_the_claim_is_divergence_when_it_is_the_only_writer() {
    // No presence of the bound instance here: the only reference is the
    // other instance's claimed write.
    let x = expected_write(PATH);
    let c = claim(&x);
    let mut o = Observer::new();
    let now = x.now;
    let anchor_wall = now - 10_000;
    let a = Some(anchor_at(anchor_wall));
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
    let t0 = mono_for(now + 3_000, anchor_wall);
    let b2 = o
        .signer
        .attest_at(
            raw_batch(
                2,
                now + 2_000,
                now + 4_000,
                (1, 1),
                vec![write_event(
                    1,
                    t0 + 50 * MS,
                    FAN_CLOSE_WRITE,
                    PATH,
                    false,
                    INO,
                    Some(other_instance(&x.ee)),
                    Some(&c),
                )],
                vec![],
                a,
                Some(0),
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
    assert_eq!(r.result, ReconciliationResult::IdentityDivergence, "{r:?}");
}

#[test]
fn fw12_an_unclaimed_write_does_not_verify() {
    let evs: Events = Box::new(|x, _, t0| {
        vec![write_event(
            1,
            t0 + 50 * MS,
            FAN_CLOSE_WRITE,
            PATH,
            false,
            INO,
            Some(process_of(&x.ee)),
            None,
        )]
    });
    let r = reconcile(&scene(expected_write(PATH), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnclaimed);
}

// ═══ Time, kind, tamper ═══

#[test]
fn fw13_a_write_placed_before_the_decision_precedes_authorization() {
    let evs: Events = Box::new(|x, c, t0| {
        vec![write_event(
            1,
            t0 - 15_000 * MS,
            FAN_CLOSE_WRITE,
            PATH,
            false,
            INO,
            Some(process_of(&x.ee)),
            Some(c),
        )]
    });
    let r = reconcile(&scene(expected_write(PATH), evs));
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionPrecedesAuthorization);
    assert_eq!(r.temporal, TemporalComparison::BeforeWindow);
}

#[test]
fn fw14_a_connect_or_send_expectation_is_not_satisfied_by_a_file_write() {
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
        parameters: net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 5], 443).unwrap(),
        execution_binding: binding(&agent_aid.id),
        requested_ttl_ms: TTL,
    };
    let ee = match dp.authorize_at(&req, now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("{d:?}"),
    };
    let x = Expected {
        ee,
        anchors,
        agent_id: agent_aid.id,
        agent_kp,
        now,
    };
    let r = reconcile(&scene(x, honest()));
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

#[test]
fn fw15_a_path_altered_after_attestation_breaks_the_batch_signature() {
    let mut s = scene(expected_write(OTHER_PATH), honest());
    for e in &mut s.ev.batches[1].batch.kernel_events {
        if let KernelLifecycleKind::FileEvent { path, .. } = &mut e.kind {
            *path = OTHER_PATH.into();
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
