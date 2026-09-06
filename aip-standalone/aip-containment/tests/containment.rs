//! Skill 9 / Gate 9 — the containment boundary, RED.
//!
//! The only path to actuation:
//!
//! ```text
//! signed Warrant (Contain, Proven, workload violation, cited, covered,
//!                 autonomous, unprotected, bound to a subject)
//!   + ExecutionBinding of the target (agent + pid + start ticks + boot id
//!                 + executable contents), attributed live through a pidfd
//!   + current signed observer health from the cited observer, Active
//!   + ContainmentPolicy with the mode explicitly enabled
//!   + an unconsumed warrant id
//!   ↓
//! ContainmentDecision → Actuator → signed ContainmentRecord
//! ```
//!
//! Every attempt — refused, advisory, applied, failed, released — is a
//! signed record under the containment authority's own key. A raw
//! reconciliation, a severity, a strength, a boolean or a pid can never
//! reach an actuator: the function signature does not accept them. The
//! actuator here is a recording double; the real cgroup v2 freezer is
//! exercised in `live_freeze.rs`.

#![cfg(target_os = "linux")]

use std::process::{Child, Command};

use aip_containment::*;
use aip_core::execution_binding::collect_binding_for_pid;
use aip_crypto::generate_ed25519_keypair;
use aip_observe::{
    CollectorSigner, CoverageWindow, ObservationAvailability, ObserverAttestor,
    ObserverTrustAnchors, ProcfsProbe, SignedSensorHealth, UnavailableReason,
};
use aip_reconcile::{
    ActionComparison, DecisionId, DecisionPointId, EvidenceRef, EvidenceStrength,
    IdentityComparison, LineageComparison, ObserverId, ObserverSequence, ReasonCode,
    Reconciliation, ReconciliationResult, TemporalComparison, WireCorroboration,
    RECONCILIATION_VERSION,
};
use aip_types::{ExecutionBinding, KeyPair};
use aip_warrant::{
    evaluate, Finding, ProtectedIdentitySet, ResponseClass, Severity, Warrant, WarrantAuthority,
    WarrantPolicy, WarrantTrustAnchors,
};

const NOW: u64 = 1_700_003_000_000;
const AGENT: &str = "aip1agent";
const OBSERVER: &str = "obs-1";
const WARRANT_AUTHORITY: &str = "warrant-authority";
const CONTAINMENT_AUTHORITY: &str = "containment-authority";

// ═══ fixtures ═══

struct Keys {
    warrant: KeyPair,
    containment: KeyPair,
    observer: KeyPair,
}

fn keys() -> Keys {
    Keys {
        warrant: generate_ed25519_keypair(),
        containment: generate_ed25519_keypair(),
        observer: generate_ed25519_keypair(),
    }
}

fn anchors(k: &Keys) -> ContainmentAnchors {
    ContainmentAnchors {
        warrant: WarrantTrustAnchors::new().trust(WARRANT_AUTHORITY, &k.warrant.public_key),
        observer: ObserverTrustAnchors::new().trust(OBSERVER, 1, &k.observer.public_key),
    }
}

fn authority(k: &Keys) -> ContainmentAuthority {
    ContainmentAuthority::new(
        CONTAINMENT_AUTHORITY,
        &k.containment.private_key,
        &k.containment.public_key,
    )
    .unwrap()
}

fn evidence() -> Vec<EvidenceRef> {
    vec![
        EvidenceRef::Expected {
            decision_point_id: DecisionPointId("aip1dp".into()),
            decision_id: DecisionId::from_bytes([0x11; 16]),
        },
        EvidenceRef::Health {
            observer_id: ObserverId(OBSERVER.into()),
            sequence: ObserverSequence(2),
            emitted_at_ms: NOW - 1_000,
        },
    ]
}

fn record(
    result: ReconciliationResult,
    strength: EvidenceStrength,
    availability: ObservationAvailability,
    evidence: Vec<EvidenceRef>,
) -> Reconciliation {
    {
        let mut r = Reconciliation::fixture_default();
        r.version = RECONCILIATION_VERSION;
        r.result = result;
        r.strength = strength;
        r.reason = ReasonCode::ActionEvidenceUnavailable;
        r.decision_id = Some(DecisionId::from_bytes([0x11; 16]));
        r.availability = availability;
        r.identity = IdentityComparison::NoReference;
        r.action = ActionComparison::Unobservable;
        r.temporal = TemporalComparison::Indeterminate;
        r.lineage = LineageComparison::NotEvaluated;
        r.wire = WireCorroboration::NotEvaluated;
        r.replay_detected = false;
        r.evidence = evidence;
        r.verification_time_ms = NOW - 1;
        r
    }
}

fn covered() -> ObservationAvailability {
    ObservationAvailability::Covered {
        window: CoverageWindow {
            from_ms: NOW - 60_000,
            to_ms: NOW,
        },
    }
}

fn proven_phantom() -> Reconciliation {
    record(
        ReconciliationResult::PhantomClaim,
        EvidenceStrength::Proven,
        covered(),
        evidence(),
    )
}

fn warrant_for(k: &Keys, rec: Reconciliation, subject: Option<&str>) -> Warrant {
    let policy = WarrantPolicy {
        autonomous_containment: true,
        ..WarrantPolicy::default()
    }
    .with_severity(ReconciliationResult::PhantomClaim, Severity::Critical)
    .with_severity(ReconciliationResult::CannotProve, Severity::Critical)
    .with_severity(ReconciliationResult::ContinuityFailure, Severity::Critical)
    .with_severity(
        ReconciliationResult::SensorIntegrityFailure,
        Severity::Critical,
    );
    let f = Finding {
        finding_id: [0xf1; 16],
        reconciliation: rec,
        subject_agent: subject.map(str::to_string),
    };
    let w = evaluate(&f, &policy, NOW - 10_000).unwrap();
    WarrantAuthority::new(
        WARRANT_AUTHORITY,
        &k.warrant.private_key,
        &k.warrant.public_key,
    )
    .unwrap()
    .sign(w)
    .unwrap()
}

/// A Contain warrant on a Proven PhantomClaim, bound to `AGENT`.
fn contain_warrant(k: &Keys) -> Warrant {
    let w = warrant_for(k, proven_phantom(), Some(AGENT));
    assert_eq!(
        w.response,
        ResponseClass::Contain,
        "fixture must be Contain"
    );
    w
}

/// Current signed health from `OBSERVER`: Active after two contiguous
/// batches.
fn active_health(k: &Keys, at: u64) -> SignedSensorHealth {
    let mut s =
        CollectorSigner::new(OBSERVER, 1, &k.observer.private_key, &k.observer.public_key).unwrap();
    let mut probe = ProcfsProbe::new("p");
    for i in 1..=2u8 {
        s.attest_at(
            probe.batch([i; 16], NOW - 50_000, NOW - 40_000, vec![]),
            NOW - 30_000,
        )
        .unwrap();
    }
    let h = s.health(at).unwrap();
    assert_eq!(h.health.state, aip_observe::ObserverState::Active);
    h
}

/// A live target: a child that sleeps. Its binding is what the decision
/// point would have signed and the observer measured.
struct Target {
    child: Child,
    binding: ExecutionBinding,
}

impl Target {
    fn spawn() -> Self {
        let child = Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep");
        std::thread::sleep(std::time::Duration::from_millis(30));
        let binding = collect_binding_for_pid(AGENT, child.id()).unwrap();
        Self { child, binding }
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn enabled_policy() -> ContainmentPolicy {
    ContainmentPolicy {
        mode: ContainmentMode::AutonomousEnabled,
        action: ContainmentAction::FreezeProcess,
        ..ContainmentPolicy::default()
    }
}

/// A recording double. It never touches a process; `applied` is what it was
/// asked to do.
#[derive(Default)]
struct Recorder {
    applied: Vec<(u32, ContainmentAction)>,
    released: Vec<String>,
    fail_next: Option<ActuationFailure>,
}

impl Actuator for Recorder {
    fn mechanism(&self) -> Mechanism {
        Mechanism::TestDouble
    }
    fn apply(
        &mut self,
        target: &Attributed,
        action: ContainmentAction,
    ) -> Result<Applied, ActuationFailure> {
        if let Some(f) = self.fail_next.take() {
            return Err(f);
        }
        self.applied.push((target.process().pid, action));
        Ok(Applied {
            mechanism: Mechanism::TestDouble,
            handle: format!("double:{}", target.process().pid),
        })
    }
    fn release(&mut self, applied: &Applied) -> Result<(), ActuationFailure> {
        self.released.push(applied.handle.clone());
        Ok(())
    }
}

struct Rig {
    k: Keys,
    anchors: ContainmentAnchors,
    authority: ContainmentAuthority,
    ledger: MemoryReplayLedger,
    actuator: Recorder,
}

fn rig() -> Rig {
    let k = keys();
    let anchors = anchors(&k);
    let authority = authority(&k);
    Rig {
        k,
        anchors,
        authority,
        ledger: MemoryReplayLedger::default(),
        actuator: Recorder::default(),
    }
}

fn run(
    r: &mut Rig,
    warrant: &Warrant,
    target: &ExecutionBinding,
    health: Option<&SignedSensorHealth>,
    policy: &ContainmentPolicy,
) -> Containment {
    let req = ContainmentRequest {
        warrant,
        target,
        observer_health: health,
        operator_ack: None,
    };
    contain(
        &req,
        policy,
        &r.anchors,
        &mut r.ledger,
        &mut r.actuator,
        &r.authority,
        NOW,
    )
    .unwrap()
}

fn refused(c: &Containment) -> &Refusal {
    match &c.record.record.outcome {
        Outcome::Refused(r) => r,
        other => panic!("expected refusal, got {other:?}"),
    }
}

// ═══ The gate holds under every prohibited input (skill §22 tests 1–7) ═══

#[test]
fn c01_heuristic_correlated_attested_cannot_contain() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    for strength in [
        EvidenceStrength::Heuristic,
        EvidenceStrength::Correlated,
        EvidenceStrength::Attested,
    ] {
        let w = warrant_for(
            &r.k,
            record(
                ReconciliationResult::PhantomClaim,
                strength,
                covered(),
                evidence(),
            ),
            Some(AGENT),
        );
        assert_ne!(w.response, ResponseClass::Contain);
        let c = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
        assert!(
            matches!(refused(&c), Refusal::ResponseNotContain(_)),
            "{strength:?}: {:?}",
            c.record.record.outcome
        );
        assert!(!c.actuated());
    }
    assert!(
        r.actuator.applied.is_empty(),
        "the actuator was never called"
    );
}

#[test]
fn c02_cannot_prove_observation_unavailable_and_observer_results_cannot_contain() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let cases = vec![
        record(
            ReconciliationResult::CannotProve,
            EvidenceStrength::Proven,
            covered(),
            evidence(),
        ),
        record(
            ReconciliationResult::PhantomClaim,
            EvidenceStrength::Proven,
            ObservationAvailability::Unavailable {
                reason: UnavailableReason::ObserverDegraded,
            },
            evidence(),
        ),
        record(
            ReconciliationResult::ContinuityFailure,
            EvidenceStrength::Proven,
            covered(),
            evidence(),
        ),
        record(
            ReconciliationResult::SensorIntegrityFailure,
            EvidenceStrength::Proven,
            covered(),
            evidence(),
        ),
        record(
            ReconciliationResult::PhantomClaim,
            EvidenceStrength::Proven,
            covered(),
            vec![],
        ),
    ];
    for rec in cases {
        let w = warrant_for(&r.k, rec.clone(), Some(AGENT));
        let c = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
        assert!(
            !c.actuated(),
            "{:?}: {:?}",
            rec.result,
            c.record.record.outcome
        );
        assert!(matches!(c.record.record.outcome, Outcome::Refused(_)));
    }
    assert!(r.actuator.applied.is_empty());
}

#[test]
fn c03_a_forged_contain_warrant_is_refused_even_when_every_field_says_contain() {
    // An attacker who cannot reach the warrant engine builds the fields by
    // hand: Contain, Proven, autonomous, cited, covered — and signs under
    // another key, or does not sign at all, or alters one byte after
    // signing.
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let good = contain_warrant(&r.k);

    let other = generate_ed25519_keypair();
    let forged = WarrantAuthority::new(WARRANT_AUTHORITY, &other.private_key, &other.public_key)
        .unwrap()
        .sign(Warrant {
            signature: None,
            ..good.clone()
        })
        .unwrap();
    let c = run(&mut r, &forged, &t.binding, Some(&h), &enabled_policy());
    assert!(matches!(refused(&c), Refusal::WarrantInvalid(_)));

    let unsigned = Warrant {
        signature: None,
        ..good.clone()
    };
    let c = run(&mut r, &unsigned, &t.binding, Some(&h), &enabled_policy());
    assert!(matches!(refused(&c), Refusal::WarrantInvalid(_)));

    // Every security field mutated after signing (skill test 9 / 18).
    type Mutation = Box<dyn Fn(&mut Warrant)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|w| w.valid_until = Some(NOW + 10_000_000_000)),
        Box::new(|w| w.issued_at = NOW - 1),
        Box::new(|w| w.response = ResponseClass::Contain),
        Box::new(|w| w.evidence_strength = EvidenceStrength::Proven),
        Box::new(|w| w.autonomous = true),
        Box::new(|w| w.protected = false),
        Box::new(|w| w.observation_unavailable = false),
        Box::new(|w| w.subject_agent = Some("aip1someoneelse".into())),
        Box::new(|w| w.evidence_refs.clear()),
        Box::new(|w| w.reconciliation_digest[0] ^= 1),
        Box::new(|w| w.warrant_id[0] ^= 1),
        Box::new(|w| w.policy_version += 1),
    ];
    for (i, m) in mutations.iter().enumerate() {
        let mut w = good.clone();
        m(&mut w);
        if w == good {
            continue; // the mutation was a no-op on this fixture
        }
        let c = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
        assert!(
            matches!(refused(&c), Refusal::WarrantInvalid(_)),
            "mutation {i} passed: {:?}",
            c.record.record.outcome
        );
    }
    assert!(r.actuator.applied.is_empty());
}

#[test]
fn c04_an_expired_or_not_yet_valid_warrant_is_refused() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    let expired_at = w.valid_until.unwrap() + 1;
    let req = ContainmentRequest {
        warrant: &w,
        target: &t.binding,
        observer_health: Some(&h),
        operator_ack: None,
    };
    let c = contain(
        &req,
        &enabled_policy(),
        &r.anchors,
        &mut r.ledger,
        &mut r.actuator,
        &r.authority,
        expired_at,
    )
    .unwrap();
    assert!(matches!(refused(&c), Refusal::WarrantExpired { .. }));
    let c = contain(
        &req,
        &enabled_policy(),
        &r.anchors,
        &mut r.ledger,
        &mut r.actuator,
        &r.authority,
        w.issued_at - 1,
    )
    .unwrap();
    assert!(matches!(refused(&c), Refusal::WarrantNotYetValid { .. }));
    assert!(r.actuator.applied.is_empty());
}

// ═══ Target binding (skill §9, §15, §22 tests 11 and 17; mandate: wrong
// PID, PID reuse, cross-agent transplant, ambiguous attribution) ═══

#[test]
fn c05_a_warrant_for_agent_a_does_not_contain_agent_b_and_an_unbound_warrant_contains_nobody() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    let mut other = t.binding.clone();
    other.agent_id = "aip1agentB".into();
    let c = run(&mut r, &w, &other, Some(&h), &enabled_policy());
    assert!(matches!(refused(&c), Refusal::SubjectMismatch { .. }));

    let unbound = warrant_for(&r.k, proven_phantom(), None);
    let c = run(&mut r, &unbound, &t.binding, Some(&h), &enabled_policy());
    assert!(matches!(refused(&c), Refusal::SubjectUnbound));
    assert!(r.actuator.applied.is_empty());
}

#[test]
fn c06_wrong_pid_reused_pid_wrong_boot_and_wrong_executable_are_attribution_refusals() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    let p = enabled_policy();

    // Wrong pid: nobody there.
    let mut b = t.binding.clone();
    b.process.pid = 4_000_000;
    let c = run(&mut r, &w, &b, Some(&h), &p);
    assert!(matches!(
        refused(&c),
        Refusal::Attribution(AttributionFailure::ProcessNotVisible { .. })
    ));

    // PID reuse: the number is live, the instance the binding names is not.
    let mut b = t.binding.clone();
    b.process.pid_start_time_ticks -= 1;
    let c = run(&mut r, &w, &b, Some(&h), &p);
    assert!(matches!(
        refused(&c),
        Refusal::Attribution(AttributionFailure::InstanceMismatch { .. })
    ));

    // Another boot.
    let mut b = t.binding.clone();
    b.process.boot_id[0] ^= 1;
    let c = run(&mut r, &w, &b, Some(&h), &p);
    assert!(matches!(
        refused(&c),
        Refusal::Attribution(AttributionFailure::BootMismatch)
    ));

    // Same instance, different executable contents claimed.
    let mut b = t.binding.clone();
    b.exe_content_sha256[0] ^= 1;
    let c = run(&mut r, &w, &b, Some(&h), &p);
    assert!(matches!(
        refused(&c),
        Refusal::Attribution(AttributionFailure::ExecutableMismatch)
    ));

    // The containment process itself, and init, are never targets.
    let mut b = t.binding.clone();
    b.process.pid = std::process::id();
    let c = run(&mut r, &w, &b, Some(&h), &p);
    assert!(matches!(
        refused(&c),
        Refusal::Attribution(AttributionFailure::SelfTarget)
    ));
    let mut b = t.binding.clone();
    b.process.pid = 1;
    let c = run(&mut r, &w, &b, Some(&h), &p);
    assert!(matches!(
        refused(&c),
        Refusal::Attribution(AttributionFailure::InitTarget)
    ));
    assert!(r.actuator.applied.is_empty());
}

// ═══ Operator controls and protection (skill §10, §11, §22 tests 12–13;
// mandate: protected component, operator disabled) ═══

#[test]
fn c07_the_default_policy_is_advisory_and_advisory_never_actuates() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    let p = ContainmentPolicy::default();
    assert_eq!(p.mode, ContainmentMode::Advisory);
    assert_eq!(p.action, ContainmentAction::AdvisoryOnly);
    let c = run(&mut r, &w, &t.binding, Some(&h), &p);
    assert!(matches!(c.record.record.outcome, Outcome::Advisory));
    assert!(!c.actuated());
    assert!(c.hold.is_none());
    assert!(r.actuator.applied.is_empty());
    // Advisory consumed nothing: the same warrant can still be acted on
    // once an operator enables the mode.
    assert!(!r.ledger.is_consumed(&w.warrant_id));
    // Every gate still ran: the decision names the attributed target.
    assert_eq!(c.record.record.decision.target.process, t.binding.process);
}

#[test]
fn c08_operator_enabled_requires_an_acknowledgement_naming_this_warrant() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    let p = ContainmentPolicy {
        mode: ContainmentMode::OperatorEnabled,
        action: ContainmentAction::FreezeProcess,
        ..ContainmentPolicy::default()
    };
    let c = run(&mut r, &w, &t.binding, Some(&h), &p);
    assert!(matches!(
        refused(&c),
        Refusal::OperatorAcknowledgementMissing
    ));
    let wrong = OperatorAcknowledgement {
        operator_id: "op".into(),
        warrant_id: [0xee; 16],
        acknowledged_at_ms: NOW,
    };
    let req = ContainmentRequest {
        warrant: &w,
        target: &t.binding,
        observer_health: Some(&h),
        operator_ack: Some(&wrong),
    };
    let c = contain(
        &req,
        &p,
        &r.anchors,
        &mut r.ledger,
        &mut r.actuator,
        &r.authority,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        refused(&c),
        Refusal::OperatorAcknowledgementMismatch
    ));
    assert!(r.actuator.applied.is_empty());
    let right = OperatorAcknowledgement {
        operator_id: "op".into(),
        warrant_id: w.warrant_id,
        acknowledged_at_ms: NOW,
    };
    let req = ContainmentRequest {
        warrant: &w,
        target: &t.binding,
        observer_health: Some(&h),
        operator_ack: Some(&right),
    };
    let c = contain(
        &req,
        &p,
        &r.anchors,
        &mut r.ledger,
        &mut r.actuator,
        &r.authority,
        NOW,
    )
    .unwrap();
    assert!(c.actuated(), "{:?}", c.record.record.outcome);
    assert_eq!(r.actuator.applied.len(), 1);
}

#[test]
fn c09_a_protected_identity_is_never_autonomously_contained() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    // Protected at the containment policy.
    let p = ContainmentPolicy {
        protected: ProtectedIdentitySet::new().protect_agent(AGENT),
        ..enabled_policy()
    };
    let c = run(&mut r, &w, &t.binding, Some(&h), &p);
    assert!(matches!(refused(&c), Refusal::Protected { .. }));
    // The observer cited by the evidence is protected: containment would
    // rest on infrastructure the policy shields.
    let p = ContainmentPolicy {
        protected: ProtectedIdentitySet::new().protect_observer(OBSERVER),
        ..enabled_policy()
    };
    let c = run(&mut r, &w, &t.binding, Some(&h), &p);
    assert!(matches!(refused(&c), Refusal::Protected { .. }));
    // Protected upstream: the warrant engine already capped the response,
    // so the warrant is not Contain; and a Contain warrant that somehow
    // carries `protected` is refused on that flag alone.
    let mut flagged = contain_warrant(&r.k);
    flagged.protected = true;
    let flagged = WarrantAuthority::new(
        WARRANT_AUTHORITY,
        &r.k.warrant.private_key,
        &r.k.warrant.public_key,
    )
    .unwrap()
    .sign(Warrant {
        signature: None,
        ..flagged
    })
    .unwrap();
    let c = run(&mut r, &flagged, &t.binding, Some(&h), &enabled_policy());
    assert!(matches!(refused(&c), Refusal::WarrantMarkedProtected));
    assert!(r.actuator.applied.is_empty());
}

#[test]
fn c10_a_warrant_issued_without_autonomous_enablement_never_actuates() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let mut w = contain_warrant(&r.k);
    w.autonomous = false;
    let w = WarrantAuthority::new(
        WARRANT_AUTHORITY,
        &r.k.warrant.private_key,
        &r.k.warrant.public_key,
    )
    .unwrap()
    .sign(Warrant {
        signature: None,
        ..w
    })
    .unwrap();
    let c = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
    assert!(matches!(refused(&c), Refusal::WarrantNotAutonomous));
    assert!(r.actuator.applied.is_empty());
}

// ═══ Observer degradation at containment time (mandate: observer degraded)
// ═══

#[test]
fn c11_containment_needs_current_active_health_from_the_cited_observer() {
    let mut r = rig();
    let t = Target::spawn();
    let w = contain_warrant(&r.k);
    let p = enabled_policy();

    let c = run(&mut r, &w, &t.binding, None, &p);
    assert!(matches!(refused(&c), Refusal::ObserverHealthMissing));

    // Stale.
    let old = active_health(&r.k, NOW - p.max_health_age_ms - 1);
    let c = run(&mut r, &w, &t.binding, Some(&old), &p);
    assert!(matches!(refused(&c), Refusal::ObserverHealthStale { .. }));

    // Not Active: a restarted collector is Recovering.
    let mut s = CollectorSigner::new(
        OBSERVER,
        1,
        &r.k.observer.private_key,
        &r.k.observer.public_key,
    )
    .unwrap();
    let mut probe = ProcfsProbe::new("p");
    s.attest_at(
        probe.batch([1; 16], NOW - 50_000, NOW - 40_000, vec![]),
        NOW - 30_000,
    )
    .unwrap();
    s.note_probe_restart();
    let recovering = s.health(NOW).unwrap();
    assert_ne!(recovering.health.state, aip_observe::ObserverState::Active);
    let c = run(&mut r, &w, &t.binding, Some(&recovering), &p);
    assert!(matches!(refused(&c), Refusal::ObserverNotActive(_)));

    // Under a key the anchors do not hold.
    let other = generate_ed25519_keypair();
    let mut s = CollectorSigner::new(OBSERVER, 1, &other.private_key, &other.public_key).unwrap();
    for i in 1..=2u8 {
        s.attest_at(
            probe.batch([i + 5; 16], NOW - 50_000, NOW - 40_000, vec![]),
            NOW - 30_000,
        )
        .unwrap();
    }
    let untrusted = s.health(NOW).unwrap();
    let c = run(&mut r, &w, &t.binding, Some(&untrusted), &p);
    assert!(matches!(refused(&c), Refusal::ObserverHealthUntrusted(_)));

    // From an observer the evidence never cited.
    let stranger_key = generate_ed25519_keypair();
    r.anchors.observer = r
        .anchors
        .observer
        .clone()
        .trust("obs-2", 1, &stranger_key.public_key);
    let mut s = CollectorSigner::new(
        "obs-2",
        1,
        &stranger_key.private_key,
        &stranger_key.public_key,
    )
    .unwrap();
    for i in 1..=2u8 {
        s.attest_at(
            probe.batch([i + 9; 16], NOW - 50_000, NOW - 40_000, vec![]),
            NOW - 30_000,
        )
        .unwrap();
    }
    let stranger = s.health(NOW).unwrap();
    let c = run(&mut r, &w, &t.binding, Some(&stranger), &p);
    assert!(matches!(refused(&c), Refusal::ObserverNotCited { .. }));
    assert!(r.actuator.applied.is_empty());
}

// ═══ Replay, idempotency, failure (skill §12–§14, §22 tests 14–15) ═══

#[test]
fn c12_a_consumed_warrant_is_never_a_second_authorization() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    let c = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
    assert!(c.actuated());
    assert!(r.ledger.is_consumed(&w.warrant_id));
    let again = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
    assert!(matches!(refused(&again), Refusal::Replayed { .. }));
    assert_eq!(r.actuator.applied.len(), 1, "one action, not two");
}

#[test]
fn c13_the_replay_ledger_survives_a_restart_on_disk() {
    let dir = std::env::temp_dir().join(format!("ghost-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("consumed.warrants");
    {
        let mut l = FileReplayLedger::open(&path).unwrap();
        assert!(!l.is_consumed(&[7; 16]));
        l.consume(&[7; 16]).unwrap();
        assert!(l.is_consumed(&[7; 16]));
    }
    let l = FileReplayLedger::open(&path).unwrap();
    assert!(l.is_consumed(&[7; 16]), "consumed state is durable");
    assert!(!l.is_consumed(&[8; 16]));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn c14_an_actuation_failure_fails_open_is_recorded_and_escalates_nothing() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    r.actuator.fail_next = Some(ActuationFailure::Stage {
        stage: "freeze".into(),
        reason: "simulated".into(),
    });
    let c = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
    assert!(matches!(c.record.record.outcome, Outcome::Failed(_)));
    assert!(!c.actuated());
    assert!(c.hold.is_none());
    // The record carries the warrant's strength verbatim: a failed action
    // is not evidence of anything about the workload.
    assert_eq!(
        c.record.record.decision.evidence_strength,
        w.evidence_strength
    );
    assert_eq!(
        c.record.record.decision.reconciliation_result,
        w.reconciliation_result
    );
    // The warrant was consumed by the decision, so the failure is not
    // retried destructively by default.
    assert!(r.ledger.is_consumed(&w.warrant_id));
    let again = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
    assert!(matches!(refused(&again), Refusal::Replayed { .. }));
    verify_containment_record(
        &c.record,
        &ContainmentTrustAnchors::new().trust(CONTAINMENT_AUTHORITY, &r.k.containment.public_key),
    )
    .unwrap();
}

// ═══ Accountability (skill §18, §19, §21) ═══

#[test]
fn c15_every_attempt_is_a_signed_domain_separated_record_a_third_party_can_read() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    let ca =
        ContainmentTrustAnchors::new().trust(CONTAINMENT_AUTHORITY, &r.k.containment.public_key);

    // Refused.
    let c = run(
        &mut r,
        &w,
        &t.binding,
        Some(&h),
        &ContainmentPolicy::default(),
    );
    verify_containment_record(&c.record, &ca).unwrap();
    // Applied.
    let c = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
    assert!(c.actuated());
    verify_containment_record(&c.record, &ca).unwrap();
    let d = &c.record.record.decision;
    assert_eq!(d.warrant_id, w.warrant_id);
    assert_eq!(d.warrant_digest, aip_crypto::sha256(&w.signing_preimage()));
    assert_eq!(d.reconciliation_digest, w.reconciliation_digest);
    assert_eq!(d.reconciliation_result, ReconciliationResult::PhantomClaim);
    assert_eq!(d.evidence_strength, EvidenceStrength::Proven);
    assert_eq!(d.evidence_refs, w.evidence_refs);
    assert_eq!(d.target.agent_id, AGENT);
    assert_eq!(d.target.process, t.binding.process);
    assert_eq!(d.target.exe_content_sha256, t.binding.exe_content_sha256);
    assert_eq!(d.action, ContainmentAction::FreezeProcess);
    assert_eq!(d.mode, ContainmentMode::AutonomousEnabled);
    assert!(d.warrant_autonomous);
    assert_eq!(d.decided_at_ms, NOW);
    assert!(matches!(
        c.record.record.outcome,
        Outcome::Applied {
            mechanism: Mechanism::TestDouble,
            ..
        }
    ));
    assert!(CONTAINMENT_DOMAIN.starts_with("SYNTRIASS/GHOST/"));
    let pre = c.record.record.canonical_bytes();
    assert!(pre
        .windows(CONTAINMENT_DOMAIN.len())
        .any(|x| x == CONTAINMENT_DOMAIN.as_bytes()));

    // Tampered after signing: refused.
    let mut tampered = c.record.clone();
    tampered.record.outcome = Outcome::Advisory;
    assert!(verify_containment_record(&tampered, &ca).is_err());
    let mut tampered = c.record.clone();
    tampered.record.decision.target.process.pid += 1;
    assert!(verify_containment_record(&tampered, &ca).is_err());
    let mut tampered = c.record.clone();
    tampered.record.decision.evidence_strength = EvidenceStrength::Heuristic;
    assert!(verify_containment_record(&tampered, &ca).is_err());
    // Under the warrant authority's key instead of a distinct one: refused.
    let same_key = ContainmentAuthority::new(
        CONTAINMENT_AUTHORITY,
        &r.k.warrant.private_key,
        &r.k.warrant.public_key,
    )
    .unwrap();
    let signed_by_warrant_key = same_key.sign(c.record.record.clone()).unwrap();
    let ca2 = ContainmentTrustAnchors::new().trust(CONTAINMENT_AUTHORITY, &r.k.warrant.public_key);
    assert!(verify_containment_record(&signed_by_warrant_key, &ca2).is_ok());
    assert!(matches!(
        verify_containment_record_distinct(
            &signed_by_warrant_key,
            &ca2,
            &[&r.k.warrant.public_key]
        ),
        Err(RecordVerifyError::KeyIsAnotherAuthority)
    ));
    // Serde round trip, and no forbidden vocabulary.
    let json = serde_json::to_string(&c.record).unwrap();
    let back: SignedContainmentRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c.record);
    let lower = json.to_lowercase();
    for word in ["trusted", "confidence", "score", "malicious", "risk"] {
        assert!(!lower.contains(word), "{word} in {json}");
    }
}

#[test]
fn c16_release_thaws_through_the_same_hold_and_is_recorded() {
    let mut r = rig();
    let t = Target::spawn();
    let h = active_health(&r.k, NOW);
    let w = contain_warrant(&r.k);
    let c = run(&mut r, &w, &t.binding, Some(&h), &enabled_policy());
    let hold = c.hold.expect("applied containment holds the target");
    let rec = release(hold, &mut r.actuator, &r.authority, NOW + 5_000).unwrap();
    assert!(matches!(rec.record.outcome, Outcome::Released { .. }));
    assert_eq!(rec.record.decision.warrant_id, w.warrant_id);
    assert_eq!(r.actuator.released.len(), 1);
    verify_containment_record(
        &rec,
        &ContainmentTrustAnchors::new().trust(CONTAINMENT_AUTHORITY, &r.k.containment.public_key),
    )
    .unwrap();
}

// ═══ Closed action set, no shell (skill §16, §17, §22 test 16) ═══

#[test]
fn c17_the_action_set_is_closed_and_carries_no_command() {
    // The enum has exactly the actions the product supports. A string, a
    // path or a command line is not constructible as an action.
    let all = ContainmentAction::ALL;
    assert_eq!(all.len(), 2);
    assert!(all.contains(&ContainmentAction::AdvisoryOnly));
    assert!(all.contains(&ContainmentAction::FreezeProcess));
    let json = serde_json::to_string(&ContainmentAction::FreezeProcess).unwrap();
    assert_eq!(json, "\"FreezeProcess\"");
    // Codes are distinct.
    let mut codes: Vec<u8> = all.iter().map(|a| a.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), all.len());
}

#[test]
fn c18_policy_and_mode_vocabulary() {
    assert_eq!(ContainmentMode::default(), ContainmentMode::Advisory);
    assert_eq!(ContainmentPolicy::default().max_health_age_ms, 30_000);
    assert!(ContainmentPolicy::default().protected.is_empty());
    assert_eq!(CONTAINMENT_VERSION, 1);
    let json = serde_json::to_string(&ContainmentPolicy::default())
        .unwrap()
        .to_lowercase();
    assert!(!json.contains("trusted"));
    assert!(!json.contains("confidence"));
}
