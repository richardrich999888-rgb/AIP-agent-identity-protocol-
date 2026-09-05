//! Skill 8 — warrant engine, RED (adversarial matrix of §23 plus the
//! property-style sweeps of §24).
//!
//! The engine consumes the reconciler's typed record, an operator-declared
//! severity, and explicit policy, and returns a response class. Containment
//! requires `EvidenceStrength::Proven` structurally; the default policy is
//! advisory; nothing here actuates anything.

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_observe::{CoverageWindow, ObservationAvailability, UnavailableReason};
use aip_reconcile::{
    ActionComparison, DecisionId, DecisionPointId, EvidenceRef, EvidenceStrength,
    IdentityComparison, ReasonCode, Reconciliation, ReconciliationResult, TemporalComparison,
    RECONCILIATION_VERSION,
};
use aip_types::KeyPair;
use aip_warrant::*;

const NOW: u64 = 1_700_000_900_000;

fn covered() -> ObservationAvailability {
    ObservationAvailability::Covered {
        window: CoverageWindow {
            from_ms: NOW - 60_000,
            to_ms: NOW,
        },
    }
}

fn unavailable(reason: UnavailableReason) -> ObservationAvailability {
    ObservationAvailability::Unavailable { reason }
}

fn evidence() -> Vec<EvidenceRef> {
    vec![EvidenceRef::Expected {
        decision_point_id: DecisionPointId("aip1dp".into()),
        decision_id: DecisionId::from_bytes([0x11; 16]),
    }]
}

fn record(
    result: ReconciliationResult,
    strength: EvidenceStrength,
    availability: ObservationAvailability,
    evidence: Vec<EvidenceRef>,
) -> Reconciliation {
    Reconciliation {
        version: RECONCILIATION_VERSION,
        result,
        strength,
        reason: ReasonCode::ActionEvidenceUnavailable,
        decision_id: Some(DecisionId::from_bytes([0x11; 16])),
        availability,
        identity: IdentityComparison::NoReference,
        action: ActionComparison::Unobservable,
        temporal: TemporalComparison::Indeterminate,
        replay_detected: false,
        evidence,
        verification_time_ms: NOW - 1,
    }
}

fn finding(rec: Reconciliation) -> Finding {
    Finding {
        finding_id: [0xf1; 16],
        reconciliation: rec,
        subject_agent: Some("aip1agent".into()),
    }
}

fn autonomous() -> WarrantPolicy {
    WarrantPolicy {
        autonomous_containment: true,
        ..WarrantPolicy::default()
    }
}

fn eval(rec: Reconciliation, policy: &WarrantPolicy) -> Warrant {
    evaluate(&finding(rec), policy, NOW).expect("well-formed input")
}

fn all_results() -> [ReconciliationResult; 8] {
    use ReconciliationResult::*;
    [
        VerifiedExecution,
        UnattributedEffect,
        PhantomClaim,
        IdentityDivergence,
        LineageViolation,
        SensorIntegrityFailure,
        ContinuityFailure,
        CannotProve,
    ]
}

fn all_strengths() -> [EvidenceStrength; 4] {
    use EvidenceStrength::*;
    [Heuristic, Correlated, Attested, Proven]
}

fn all_severities() -> [Severity; 4] {
    use Severity::*;
    [Low, Medium, High, Critical]
}

fn all_unavailable() -> Vec<UnavailableReason> {
    vec![
        UnavailableReason::NoObserver,
        UnavailableReason::ObserverDegraded,
        UnavailableReason::ObserverRecovering,
        UnavailableReason::ContinuityUnverified,
        UnavailableReason::ObserverQuarantined,
        UnavailableReason::WindowNotCovered,
        UnavailableReason::HealthStale {
            newest_ms: NOW - 10,
            required_ms: NOW,
        },
    ]
}

/// A policy that declares every result `Critical`, so severity never masks
/// what strength and policy decide in the gate tests.
fn critical_everywhere(mut p: WarrantPolicy) -> WarrantPolicy {
    for r in all_results() {
        p.severity = p.severity.with(r, Severity::Critical);
    }
    p
}

// ─── default posture ───

/// w01 — the default policy is advisory: autonomous containment off,
/// constrain-on-attested off, no protected identities, a positive validity.
#[test]
fn w01_default_policy_is_advisory() {
    let p = WarrantPolicy::default();
    assert!(!p.autonomous_containment);
    assert!(!p.allow_constrain_on_attested);
    assert!(p.protected.is_empty());
    assert!(p.validity_ms > 0);
    assert!(p.version > 0);
}

// ─── the evidence-strength gate ───

/// w02 — the §23 matrix: sub-Proven strength never reaches Contain whatever
/// the severity; Attested reaches Constrain only by explicit policy; Proven
/// reaches Contain only with autonomous containment enabled.
#[test]
fn w02_strength_gate_matrix() {
    let p = critical_everywhere(autonomous());
    let r = |s| record(ReconciliationResult::UnattributedEffect, s, covered(), evidence());

    let w = eval(r(EvidenceStrength::Heuristic), &p);
    assert_eq!(w.severity, Severity::Critical);
    assert_eq!(w.response, ResponseClass::Alert);

    let w = eval(r(EvidenceStrength::Correlated), &p);
    assert_eq!(w.response, ResponseClass::Alert);

    let w = eval(r(EvidenceStrength::Attested), &p);
    assert_ne!(w.response, ResponseClass::Contain);
    assert_eq!(w.response, ResponseClass::Alert, "constrain needs explicit policy");
    let mut p2 = p.clone();
    p2.allow_constrain_on_attested = true;
    let w = eval(r(EvidenceStrength::Attested), &p2);
    assert_eq!(w.response, ResponseClass::Constrain);
    assert_ne!(w.response, ResponseClass::Contain);

    let w = eval(r(EvidenceStrength::Proven), &p);
    assert_eq!(w.response, ResponseClass::Contain);
    assert_eq!(w.target, ResponseTarget::Workload);
    assert_eq!(w.evidence_strength, EvidenceStrength::Proven);
}

/// w03 — `CANNOT_PROVE` is not maliciousness: whatever severity is declared
/// and whatever strength the record carries, at most Alert.
#[test]
fn w03_cannot_prove_never_contains() {
    let p = critical_everywhere(autonomous());
    for s in all_strengths() {
        let w = eval(
            record(ReconciliationResult::CannotProve, s, covered(), evidence()),
            &p,
        );
        assert!(w.response <= ResponseClass::Alert, "{s:?} → {:?}", w.response);
    }
}

/// w04 — `OBSERVATION_UNAVAILABLE` in any form caps at Alert, even for a
/// record that claims Proven strength on a workload violation.
#[test]
fn w04_observation_unavailable_never_contains() {
    let p = critical_everywhere(autonomous());
    for reason in all_unavailable() {
        for result in all_results() {
            let w = eval(
                record(
                    result,
                    EvidenceStrength::Proven,
                    unavailable(reason.clone()),
                    evidence(),
                ),
                &p,
            );
            assert!(
                w.response <= ResponseClass::Alert,
                "{result:?} under {reason:?} → {:?}",
                w.response
            );
            assert!(w.observation_unavailable);
        }
    }
}

/// w05 — `CONTINUITY_FAILURE` is loss of assurance, not execution: Alert at
/// most, and it is about the observer, not the workload.
#[test]
fn w05_continuity_failure_is_alert_about_the_observer() {
    let p = critical_everywhere(autonomous());
    for s in all_strengths() {
        let w = eval(
            record(ReconciliationResult::ContinuityFailure, s, covered(), evidence()),
            &p,
        );
        assert!(w.response <= ResponseClass::Alert);
        assert_eq!(w.target, ResponseTarget::Observer);
    }
}

/// w06 — a proven `SENSOR_INTEGRITY_FAILURE` is about the sensor: its
/// target is the observer and it may reach Constrain (of the observer) but
/// never Contain, and never anything against the workload.
#[test]
fn w06_sensor_integrity_failure_never_contains_the_workload() {
    let mut p = critical_everywhere(autonomous());
    p.allow_constrain_on_attested = true;
    for s in all_strengths() {
        let w = eval(
            record(
                ReconciliationResult::SensorIntegrityFailure,
                s,
                covered(),
                evidence(),
            ),
            &p,
        );
        assert_eq!(w.target, ResponseTarget::Observer);
        assert_ne!(w.response, ResponseClass::Contain);
    }
    let w = eval(
        record(
            ReconciliationResult::SensorIntegrityFailure,
            EvidenceStrength::Proven,
            covered(),
            evidence(),
        ),
        &p,
    );
    assert_eq!(w.response, ResponseClass::Constrain);
}

/// w07 — protected identities (agent, decision point, observer named in the
/// evidence) are never autonomously contained; the warrant says why.
#[test]
fn w07_protected_identities_are_never_contained() {
    let base = critical_everywhere(autonomous());
    let proven = || {
        record(
            ReconciliationResult::UnattributedEffect,
            EvidenceStrength::Proven,
            covered(),
            evidence(),
        )
    };
    // Control: contains without protection.
    assert_eq!(eval(proven(), &base).response, ResponseClass::Contain);

    let mut p = base.clone();
    p.protected = p.protected.protect_agent("aip1agent");
    let w = eval(proven(), &p);
    assert_ne!(w.response, ResponseClass::Contain);
    assert!(w.protected);

    let mut p = base.clone();
    p.protected = p.protected.protect_decision_point("aip1dp");
    let w = eval(proven(), &p);
    assert_ne!(w.response, ResponseClass::Contain);
    assert!(w.protected);

    let mut p = base.clone();
    p.protected = p.protected.protect_observer("collector-x");
    let rec = record(
        ReconciliationResult::UnattributedEffect,
        EvidenceStrength::Proven,
        covered(),
        vec![EvidenceRef::Health {
            observer_id: aip_reconcile::ObserverId("collector-x".into()),
            sequence: aip_reconcile::ObserverSequence(3),
            emitted_at_ms: NOW - 5,
        }],
    );
    let w = eval(rec, &p);
    assert_ne!(w.response, ResponseClass::Contain);
    assert!(w.protected);
}

/// w08 — Proven + Critical with autonomous containment disabled is not
/// containment. The default policy is that policy.
#[test]
fn w08_operator_enablement_is_required() {
    let p = critical_everywhere(WarrantPolicy::default());
    let w = eval(
        record(
            ReconciliationResult::UnattributedEffect,
            EvidenceStrength::Proven,
            covered(),
            evidence(),
        ),
        &p,
    );
    assert_ne!(w.response, ResponseClass::Contain);
    assert!(!w.autonomous);
}

/// w09 — a finding with no evidence reference is capped at Alert whatever
/// else holds; a containment-capable warrant must cite evidence.
#[test]
fn w09_uncited_findings_cap_at_alert() {
    let p = critical_everywhere(autonomous());
    let w = eval(
        record(
            ReconciliationResult::UnattributedEffect,
            EvidenceStrength::Proven,
            covered(),
            vec![],
        ),
        &p,
    );
    assert!(w.response <= ResponseClass::Alert);
    assert!(w.evidence_refs.is_empty());
}

/// w10 — a verified execution warrants no response: it is `Observe`.
#[test]
fn w10_verified_execution_is_observe() {
    let p = critical_everywhere(autonomous());
    let w = eval(
        record(
            ReconciliationResult::VerifiedExecution,
            EvidenceStrength::Attested,
            covered(),
            evidence(),
        ),
        &p,
    );
    assert_eq!(w.response, ResponseClass::Observe);
}

// ─── orthogonality ───

/// w11 — severity and strength are separate fields set from separate
/// sources; changing one never changes the other, and the response depends
/// on the pair, never on a product.
#[test]
fn w11_severity_and_strength_are_orthogonal() {
    let r = |s| record(ReconciliationResult::PhantomClaim, s, covered(), evidence());
    for sev in all_severities() {
        let p = WarrantPolicy::default()
            .with_severity(ReconciliationResult::PhantomClaim, sev);
        for s in all_strengths() {
            let w = eval(r(s), &p);
            assert_eq!(w.severity, sev, "severity comes from policy alone");
            assert_eq!(w.evidence_strength, s, "strength comes from the record alone");
        }
    }
    // Same strength, different severities: strength untouched.
    let p_low = WarrantPolicy::default().with_severity(ReconciliationResult::PhantomClaim, Severity::Low);
    let p_crit = WarrantPolicy::default()
        .with_severity(ReconciliationResult::PhantomClaim, Severity::Critical);
    let a = eval(r(EvidenceStrength::Attested), &p_low);
    let b = eval(r(EvidenceStrength::Attested), &p_crit);
    assert_eq!(a.evidence_strength, b.evidence_strength);
    assert_ne!(a.severity, b.severity);
}

/// w12 — the properties of §24, swept exhaustively over every result,
/// strength, severity, availability, policy switch, protection and
/// evidence presence:
///   Contain ⇒ Proven ∧ autonomous ∧ ¬protected ∧ cited ∧ covered ∧
///             workload-violation result;
///   sub-Proven ⇒ ¬Contain; unavailable ⇒ ¬Contain; CANNOT_PROVE ⇒ ¬Contain;
///   protected ⇒ ¬Contain; Constrain on Attested ⇒ policy allowed it.
#[test]
fn w12_containment_properties_hold_everywhere() {
    let availabilities: Vec<ObservationAvailability> = std::iter::once(covered())
        .chain(all_unavailable().into_iter().map(unavailable))
        .collect();
    let mut contain_seen = 0;
    for result in all_results() {
        for strength in all_strengths() {
            for sev in all_severities() {
                for avail in &availabilities {
                    for autonomous_on in [false, true] {
                        for constrain_on in [false, true] {
                            for protect in [false, true] {
                                for cited in [false, true] {
                                    let mut p = WarrantPolicy::default().with_severity(result, sev);
                                    p.autonomous_containment = autonomous_on;
                                    p.allow_constrain_on_attested = constrain_on;
                                    if protect {
                                        p.protected = p.protected.protect_agent("aip1agent");
                                    }
                                    let ev = if cited { evidence() } else { vec![] };
                                    let w = eval(record(result, strength, avail.clone(), ev), &p);
                                    let unavailable = !matches!(
                                        avail,
                                        ObservationAvailability::Covered { .. }
                                    );
                                    if w.response == ResponseClass::Contain {
                                        contain_seen += 1;
                                        assert_eq!(strength, EvidenceStrength::Proven);
                                        assert!(autonomous_on);
                                        assert!(!protect);
                                        assert!(cited);
                                        assert!(!unavailable);
                                        assert!(matches!(
                                            result,
                                            ReconciliationResult::UnattributedEffect
                                                | ReconciliationResult::PhantomClaim
                                                | ReconciliationResult::IdentityDivergence
                                                | ReconciliationResult::LineageViolation
                                        ));
                                        assert_eq!(w.target, ResponseTarget::Workload);
                                    }
                                    if strength < EvidenceStrength::Proven {
                                        assert_ne!(w.response, ResponseClass::Contain);
                                    }
                                    if unavailable || protect || !cited {
                                        assert!(w.response <= ResponseClass::Alert);
                                    }
                                    if result == ReconciliationResult::CannotProve {
                                        assert!(w.response <= ResponseClass::Alert);
                                    }
                                    if w.response == ResponseClass::Constrain
                                        && strength == EvidenceStrength::Attested
                                    {
                                        assert!(constrain_on);
                                    }
                                    // Never a product of the two axes.
                                    assert_eq!(w.severity, sev);
                                    assert_eq!(w.evidence_strength, strength);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(contain_seen > 0, "the gate is reachable when every condition holds");
}

// ─── authenticity ───

struct Keys {
    warrant: KeyPair,
    other: KeyPair,
}

fn keys() -> Keys {
    Keys {
        warrant: generate_ed25519_keypair(),
        other: generate_ed25519_keypair(),
    }
}

fn signed() -> (Warrant, WarrantTrustAnchors, Keys) {
    let k = keys();
    let authority =
        WarrantAuthority::new("warrant-authority-1", &k.warrant.private_key, &k.warrant.public_key)
            .unwrap();
    let w = eval(
        record(
            ReconciliationResult::UnattributedEffect,
            EvidenceStrength::Proven,
            covered(),
            evidence(),
        ),
        &critical_everywhere(autonomous()),
    );
    let w = authority.sign(w).unwrap();
    let anchors = WarrantTrustAnchors::new().trust("warrant-authority-1", &k.warrant.public_key);
    (w, anchors, k)
}

/// w13 — a signed warrant verifies against its anchor; an unsigned one does
/// not; an untrusted authority does not; and every security-relevant field
/// is under the signature.
#[test]
fn w13_every_security_field_is_under_the_signature() {
    let (w, anchors, _) = signed();
    assert_eq!(verify_warrant(&w, &anchors), Ok(()));
    assert!(w.valid_until.is_some());

    let mut unsigned = w.clone();
    unsigned.signature = None;
    assert_eq!(verify_warrant(&unsigned, &anchors), Err(WarrantVerifyError::Unsigned));

    let untrusted = WarrantTrustAnchors::new();
    assert!(matches!(
        verify_warrant(&w, &untrusted),
        Err(WarrantVerifyError::UntrustedAuthority(_))
    ));

    let mutations: Vec<(&str, Box<dyn Fn(&mut Warrant)>)> = vec![
        ("finding_id", Box::new(|m| m.finding_id[0] ^= 1)),
        ("warrant_id", Box::new(|m| m.warrant_id[0] ^= 1)),
        ("result", Box::new(|m| m.reconciliation_result = ReconciliationResult::CannotProve)),
        ("reconciliation_digest", Box::new(|m| m.reconciliation_digest[0] ^= 1)),
        ("strength", Box::new(|m| m.evidence_strength = EvidenceStrength::Heuristic)),
        ("severity", Box::new(|m| m.severity = Severity::Low)),
        ("response", Box::new(|m| m.response = ResponseClass::Alert)),
        ("target", Box::new(|m| m.target = ResponseTarget::Observer)),
        ("policy_version", Box::new(|m| m.policy_version += 1)),
        ("issued_at", Box::new(|m| m.issued_at += 1)),
        ("valid_until", Box::new(|m| m.valid_until = m.valid_until.map(|v| v + 86_400_000))),
        ("valid_until_none", Box::new(|m| m.valid_until = None)),
        ("evidence_refs", Box::new(|m| m.evidence_refs.clear())),
        ("evidence_ref_content", Box::new(|m| {
            m.evidence_refs[0] = EvidenceRef::Expected {
                decision_point_id: DecisionPointId("aip1dp".into()),
                decision_id: DecisionId::from_bytes([0x12; 16]),
            }
        })),
        ("subject", Box::new(|m| m.subject_agent = None)),
        ("protected", Box::new(|m| m.protected = true)),
        ("autonomous", Box::new(|m| m.autonomous = false)),
        ("observation_unavailable", Box::new(|m| m.observation_unavailable = true)),
    ];
    for (name, mutate) in mutations {
        let mut m = w.clone();
        mutate(&mut m);
        assert_eq!(
            verify_warrant(&m, &anchors),
            Err(WarrantVerifyError::SignatureInvalid),
            "mutating `{name}` must break the signature"
        );
    }
}

/// w14 — the warrant authority is a distinct key holder: an anchor whose
/// key is the decision point's, an observer's or the agent's key is refused.
#[test]
fn w14_warrant_key_must_not_be_another_authoritys_key() {
    let (w, anchors, k) = signed();
    let disjoint = verify_warrant_distinct(&w, &anchors, &[&k.other.public_key]);
    assert_eq!(disjoint, Ok(()));
    let shared = verify_warrant_distinct(&w, &anchors, &[&k.warrant.public_key]);
    assert_eq!(shared, Err(WarrantVerifyError::KeyIsAnotherAuthority));
}

/// w15 — a warrant issued at `now` with the policy's validity is valid from
/// `issued_at` to `valid_until`; the engine refuses a policy with zero
/// validity rather than issuing an unbounded or inverted window.
#[test]
fn w15_temporal_range_is_explicit_and_bounded() {
    let (w, _, _) = signed();
    assert_eq!(w.issued_at, NOW);
    assert_eq!(w.valid_until, Some(NOW + WarrantPolicy::default().validity_ms));
    assert!(w.is_valid_at(NOW));
    assert!(w.is_valid_at(NOW + WarrantPolicy::default().validity_ms));
    assert!(!w.is_valid_at(NOW + WarrantPolicy::default().validity_ms + 1));
    assert!(!w.is_valid_at(NOW - 1));

    let mut p = autonomous();
    p.validity_ms = 0;
    let rec = record(
        ReconciliationResult::UnattributedEffect,
        EvidenceStrength::Proven,
        covered(),
        evidence(),
    );
    assert_eq!(
        evaluate(&finding(rec), &p, NOW).unwrap_err(),
        Refusal::InvalidPolicy("validity_ms must be positive".into())
    );
}

/// w16 — malformed input never becomes containment: an unsupported record
/// version is refused outright; a policy version of zero is refused.
#[test]
fn w16_malformed_input_is_refused_not_escalated() {
    let mut rec = record(
        ReconciliationResult::UnattributedEffect,
        EvidenceStrength::Proven,
        covered(),
        evidence(),
    );
    rec.version = RECONCILIATION_VERSION + 1;
    assert!(matches!(
        evaluate(&finding(rec), &autonomous(), NOW).unwrap_err(),
        Refusal::UnsupportedReconciliationVersion(_)
    ));
    let mut p = autonomous();
    p.version = 0;
    let rec = record(
        ReconciliationResult::UnattributedEffect,
        EvidenceStrength::Proven,
        covered(),
        evidence(),
    );
    assert!(matches!(
        evaluate(&finding(rec), &p, NOW).unwrap_err(),
        Refusal::InvalidPolicy(_)
    ));
}

/// w17 — the warrant is traceable: it carries the record's digest and its
/// evidence references verbatim, and the response class is an enum whose
/// serialization names no boolean and no score.
#[test]
fn w17_warrant_is_traceable_and_carries_no_scalar() {
    let (w, _, _) = signed();
    let rec = record(
        ReconciliationResult::UnattributedEffect,
        EvidenceStrength::Proven,
        covered(),
        evidence(),
    );
    assert_eq!(w.reconciliation_digest, rec.digest());
    assert_eq!(w.evidence_refs, evidence());
    let v = serde_json::to_value(&w).unwrap();
    let mut keys = Vec::new();
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    out.push(k.clone());
                    walk(v, out);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    walk(&v, &mut keys);
    for k in &keys {
        let lk = k.to_ascii_lowercase();
        for f in ["score", "confiden", "trust", "reputation", "should_kill", "kill"] {
            assert!(!lk.contains(f), "forbidden key `{k}`");
        }
    }
    let _ = sha256(b"warrants sign canonical bytes, never json");
}

/// w18 — no actuation anywhere in the crate: the source contains none of
/// the actuation identifiers Skill 8 §20 forbids.
#[test]
fn w18_crate_contains_no_actuation() {
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/policy.rs"),
        include_str!("../src/warrant.rs"),
    ];
    let forbidden = [
        "SIGKILL", "kill(", "libc::kill", "cgroup", "freeze", "iptables", "nftables", "XDP",
        "xdp", "setsockopt", "unshare", "ptrace",
    ];
    for (i, src) in sources.iter().enumerate() {
        for f in forbidden {
            assert!(!src.contains(f), "source #{i} contains `{f}`");
        }
    }
}

/// w19 — the warrant signing domain is distinct from every other signed
/// domain in the repository and is the first, length-prefixed element of the
/// preimage.
#[test]
fn w19_domain_is_distinct_and_leads_the_preimage() {
    assert_eq!(WARRANT_DOMAIN, "SYNTRIASS/GHOST/WARRANT/v1");
    assert_ne!(WARRANT_DOMAIN, aip_reconcile::RECONCILIATION_DOMAIN);
    let (w, _, _) = signed();
    let bytes = w.signing_preimage();
    let mut expected = Vec::new();
    aip_types::canonical::put_domain(&mut expected, WARRANT_DOMAIN);
    assert!(bytes.starts_with(&expected));
}
