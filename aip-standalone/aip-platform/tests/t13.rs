//! Skill 19 — T13, driven through the real engine.
//!
//! # The attack
//!
//! An `ExpectedExecution` authorizes agent A, execution E1, on platform P. The
//! execution actually runs on platform Q. A self-reported `platform_id = P`
//! must not be sufficient, and the system must reach a correct disposition
//! from what it can actually observe.
//!
//! # The finding these tests record
//!
//! The host-level case was **already closed** before Skill 19. The reconciler
//! compares the whole `ProcessInstance`, and `boot_id` — host-scoped, measured
//! by the probe from `/proc/sys/kernel/random/boot_id`, never claimed by the
//! agent — is part of it. An execution measured on a different host-boot than
//! the one authorized yields `IdentityDivergence`.
//!
//! The property was undocumented and unexercised, which is indistinguishable
//! from absent to anyone reading the audit. These tests are the exercise. No
//! reconciler change was needed and none was made.
//!
//! # Fixture provenance
//!
//! The scenario machinery below is reproduced from
//! `aip-reconcile/tests/action_evidence.rs`, which is the reference for what
//! an honest expectation and an honest observation look like. Reproduced
//! rather than shared because sharing it would mean putting fixture machinery
//! on a published crate surface.

#![allow(dead_code)]

use aip_authorize::*;
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_reconcile::*;
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
        container: None,
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

// ═══ T13 — the platform-substitution attack, against the real engine ═══

use aip_platform::*;
use aip_system::{HardwareId, PlatformId};

const PLATFORM_P: &str = "tail:N123AB";
const PLATFORM_Q: &str = "tail:N456CD";
const BOOT_P: [u8; 16] = [0x11; 16];
const BOOT_Q: [u8; 16] = [0x22; 16];

mod support;

fn platform(v: &str) -> PlatformId {
    PlatformId::parse(v).expect("valid platform id")
}

/// A verified `ObservedBoot`, produced the only way one can be.
fn observed(boot: [u8; 16]) -> ObservedBoot {
    let (batch, anchors) = support::attested_batch_on(boot);
    ObservedBoot::from_attested(&batch, &anchors)
        .expect("an anchored observer's batch must verify")
        .expect("the batch carries an observation")
}

/// A registry asserting that boot P is platform P and boot Q is platform Q.
fn deployment_registry() -> PlatformRegistry {
    PlatformRegistry::new()
        .register(
            BOOT_P,
            HostRegistration {
                platform_id: platform(PLATFORM_P),
                hardware_id: Some(HardwareId::parse("mod:EC-02").unwrap()),
                registered_from_ms: 0,
                registered_until_ms: None,
            },
        )
        .unwrap()
        .register(
            BOOT_Q,
            HostRegistration {
                platform_id: platform(PLATFORM_Q),
                hardware_id: Some(HardwareId::parse("mod:EC-09").unwrap()),
                registered_from_ms: 0,
                registered_until_ms: None,
            },
        )
        .unwrap()
}

/// Reconcile an execution the observer measured on `observed_boot`, against an
/// expectation bound to the fixture's own host.
fn reconcile_on_host(observed_boot: [u8; 16]) -> Reconciliation {
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let mut proc = process_of(&x.ee);
    proc.process.boot_id = observed_boot;
    let (ev, at) = scenario(&x, &mut o, proc, vec![established()], Some(&c));
    reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at))
}

/// The boot id the fixture's `ExpectedExecution` is bound to.
fn authorized_boot() -> [u8; 16] {
    expected().ee.execution_binding.process.boot_id
}

// ─── 1-2. The attack itself ───

#[test]
fn t13_01_authorized_on_p_executed_on_q_is_an_identity_divergence() {
    // The core T13 case. Same pid, same start ticks, same executable hash —
    // only the host-boot differs, which is exactly what distinguishes one
    // machine from another.
    let r = reconcile_on_host([0x99; 16]);

    assert_eq!(
        r.result,
        ReconciliationResult::IdentityDivergence,
        "SECURITY (T13): an execution measured on a different host than the \
         one authorized was not reported as a divergence. Got {r:?}"
    );
    assert!(
        matches!(r.identity, IdentityComparison::Divergent { .. }),
        "the divergence must be an identity comparison, not an incidental \
         failure elsewhere: {:?}",
        r.identity
    );
    // And it is not silently upgraded: observed content is root-forgeable, so
    // it stays at Attested.
    assert_eq!(r.strength, EvidenceStrength::Attested);
}

#[test]
fn t13_02_the_same_host_still_verifies() {
    // The control. Without it, t13_01 would be satisfied by an engine that
    // diverges on everything.
    let r = reconcile_on_host(authorized_boot());
    assert_eq!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "the honest case must still verify, or t13_01 proves nothing: {r:?}"
    );
    assert!(matches!(r.identity, IdentityComparison::Match { .. }));
}

#[test]
fn t13_03_a_self_reported_platform_cannot_establish_the_binding() {
    // The agent claims platform P. Nothing observed it. The disposition must
    // be NotEvaluated — a claim by the thing being described is not evidence
    // about it.
    let claimed = PlatformBinding::resolve(
        [0xE1; 16],
        None, // nothing measured
        Some(&platform(PLATFORM_P)),
        &deployment_registry(),
        1_000,
    );
    assert_eq!(
        claimed.disposition(),
        &PlatformDisposition::NotEvaluated,
        "SECURITY (T13): a self-reported platform produced a binding"
    );
    assert!(
        !claimed.disposition().asserts_platform(),
        "SECURITY (T13): a self-report asserted where the execution ran"
    );
    // The method that would have been used is not even independent.
    assert!(!BindingMethod::SelfDeclared.is_independent());
}

// ─── 3-4. Platform and hardware resolution ───

#[test]
fn t13_04_an_observed_boot_registered_to_another_platform_is_a_mismatch() {
    // T13 at the platform layer: authorized for P, observed on a host the
    // verifier registered as Q.
    let b = PlatformBinding::resolve(
        [0xE1; 16],
        Some(observed(BOOT_Q)),
        Some(&platform(PLATFORM_P)),
        &deployment_registry(),
        1_000,
    );
    match b.disposition() {
        PlatformDisposition::Mismatch {
            authorized,
            observed,
        } => {
            assert_eq!(authorized.as_str(), PLATFORM_P);
            assert_eq!(observed.as_str(), PLATFORM_Q);
        }
        other => panic!("SECURITY (T13): expected a mismatch, got {other:?}"),
    }
    assert!(!b.disposition().asserts_platform());
}

#[test]
fn t13_05_an_observed_boot_registered_to_the_authorized_platform_binds() {
    let b = PlatformBinding::resolve(
        [0xE1; 16],
        Some(observed(BOOT_P)),
        Some(&platform(PLATFORM_P)),
        &deployment_registry(),
        1_000,
    );
    match b.disposition() {
        PlatformDisposition::Bound {
            platform_id,
            hardware_id,
            method,
        } => {
            assert_eq!(platform_id.as_str(), PLATFORM_P);
            assert_eq!(hardware_id.as_ref().unwrap().as_str(), "mod:EC-02");
            assert_eq!(
                *method,
                BindingMethod::DeploymentRegistry,
                "the registry is the strongest method this build can produce"
            );
        }
        other => panic!("expected a binding, got {other:?}"),
    }
    assert!(b.disposition().asserts_platform());
}

#[test]
fn t13_06_an_unregistered_host_is_unknown_not_wrong() {
    // The verifier has not spoken about this host. That is not an accusation,
    // and it is distinct from having looked and found nothing.
    let b = PlatformBinding::resolve(
        [0xE1; 16],
        Some(observed([0xEE; 16])),
        Some(&platform(PLATFORM_P)),
        &deployment_registry(),
        1_000,
    );
    assert_eq!(b.disposition(), &PlatformDisposition::Unregistered);
    assert!(!b.disposition().asserts_platform());
    assert_ne!(
        b.disposition(),
        &PlatformDisposition::NotEvaluated,
        "SECURITY: 'unregistered' and 'not evaluated' must stay distinct — \
         summing them turns a blind spot into a clean bill of health"
    );
}

// ─── 7-9. PID reuse, observer disagreement, NEXORA ───

#[test]
fn t13_07_pid_reuse_on_another_host_does_not_inherit_the_binding() {
    // Case 12 of the matrix, and the sharpest version of T13: an attacker
    // arranges for the *same pid and the same start ticks* on a different
    // machine. Only boot_id separates them, and the kernel generates it per
    // boot — the host cannot choose another machine's.
    let x = expected();
    let mut o = Observer::new();
    let c = claim(&x);
    let mut proc = process_of(&x.ee);
    // Deliberately identical pid and start ticks; different machine.
    assert_eq!(proc.process.pid, x.ee.execution_binding.process.pid);
    assert_eq!(
        proc.process.pid_start_time_ticks,
        x.ee.execution_binding.process.pid_start_time_ticks
    );
    proc.process.boot_id = [0x77; 16];

    let (ev, at) = scenario(&x, &mut o, proc, vec![established()], Some(&c));
    let r = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));

    assert_eq!(
        r.result,
        ReconciliationResult::IdentityDivergence,
        "SECURITY (T13): a process replayed on another host with the same pid \
         and start ticks inherited the original binding. Got {r:?}"
    );
}

#[test]
fn t13_08_the_observer_seeing_a_different_platform_is_a_divergence_not_a_pass() {
    // Case 22. The observer is honest and reports what it measured; the
    // measurement disagrees with the authorization. The disposition must
    // reflect the disagreement rather than defaulting to the claim.
    let r = reconcile_on_host(BOOT_Q);
    assert_eq!(r.result, ReconciliationResult::IdentityDivergence);
    assert!(
        !matches!(r.identity, IdentityComparison::Match { .. }),
        "SECURITY: a measurement disagreeing with the authorization compared \
         as a match"
    );

    // And at the platform layer the same facts resolve to a named mismatch.
    let b = PlatformBinding::resolve(
        [0xE1; 16],
        Some(observed(BOOT_Q)),
        Some(&platform(PLATFORM_P)),
        &deployment_registry(),
        1_000,
    );
    assert!(matches!(
        b.disposition(),
        PlatformDisposition::Mismatch { .. }
    ));
}

#[test]
fn t13_09_a_binding_digest_commits_to_the_platform_it_resolved() {
    // Case 24 — the NEXORA question, answered without changing NEXORA. A
    // binding travelling in a proof package is committed to by its digest, so
    // a package carrying a mismatched platform identity cannot present a
    // binding that resolves to a different one.
    //
    // NEXORA itself is untouched: this is the property a future integration
    // would rely on, asserted here rather than by modifying the proof format
    // speculatively.
    let reg = deployment_registry();
    let on_p = PlatformBinding::resolve([0xE1; 16], Some(observed(BOOT_P)), None, &reg, 1_000);
    let on_q = PlatformBinding::resolve([0xE1; 16], Some(observed(BOOT_Q)), None, &reg, 1_000);
    assert_ne!(
        on_p.digest(),
        on_q.digest(),
        "SECURITY: two bindings resolving to different platforms shared a \
         digest, so a proof package could substitute one for the other"
    );
    // The digest is over domain-separated bytes, not a bare concatenation.
    // `put_domain` length-prefixes the tag, so the encoding leads with a u32
    // length and then the tag — not with the tag text. An earlier draft of
    // this assertion checked for the text at offset zero and failed; the
    // assertion was wrong, not the encoding.
    let bytes = on_p.canonical_bytes();
    let tag = PLATFORM_BINDING_DOMAIN.as_bytes();
    assert_eq!(
        &bytes[..4],
        &(tag.len() as u32).to_le_bytes(),
        "the encoding must lead with the domain tag's length prefix"
    );
    assert_eq!(
        &bytes[4..4 + tag.len()],
        tag,
        "the domain tag must be the first element of the encoding, so a \
         signature over one object type can never verify over another"
    );
}
