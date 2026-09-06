//! Gate 5 / Phase H — g5d: the strength ceiling any supporting tier of
//! application, database or proxy records would live under
//! (`APPLICATION_LOG_SENSOR_DECISION.md` §4). Such records can be at most
//! `Correlated`; `Correlated` never leaves `Alert`, whatever the severity
//! and whatever the result class claims. w02–w04 in `warrant.rs` pin the
//! full matrix; this test pins the ceiling by name so the decision document
//! has one executable anchor.

use aip_crypto::sha256;
use aip_observe::{CoverageWindow, ObservationAvailability};
use aip_reconcile::{
    ActionComparison, DecisionId, DecisionPointId, EvidenceRef, EvidenceStrength,
    IdentityComparison, LineageComparison, ReasonCode, Reconciliation, ReconciliationResult,
    TemporalComparison, WireCorroboration, RECONCILIATION_VERSION,
};
use aip_warrant::*;

const NOW: u64 = 1_700_000_900_000;

fn record(result: ReconciliationResult, strength: EvidenceStrength) -> Reconciliation {
    {
        let mut r = Reconciliation::fixture_default();
        r.version = RECONCILIATION_VERSION;
        r.result = result;
        r.strength = strength;
        r.reason = ReasonCode::ActionEvidenceMatches;
        r.decision_id = Some(DecisionId::from_bytes([0x11; 16]));
        r.availability = ObservationAvailability::Covered {
            window: CoverageWindow {
                from_ms: NOW - 60_000,
                to_ms: NOW,
            },
        };
        r.identity = IdentityComparison::NoReference;
        r.action = ActionComparison::Unobservable;
        r.temporal = TemporalComparison::Indeterminate;
        r.lineage = LineageComparison::NotEvaluated;
        r.wire = WireCorroboration::NotEvaluated;
        r.replay_detected = false;
        r.evidence = vec![EvidenceRef::Expected {
            decision_point_id: DecisionPointId("aip1dp".into()),
            decision_id: DecisionId::from_bytes([0x11; 16]),
        }];
        r.verification_time_ms = NOW - 1;
        r
    }
}

#[test]
fn g5d_correlated_evidence_never_leaves_alert_under_any_severity_or_policy() {
    assert!(EvidenceStrength::Heuristic < EvidenceStrength::Correlated);
    assert!(EvidenceStrength::Correlated < EvidenceStrength::Attested);
    assert!(EvidenceStrength::Attested < EvidenceStrength::Proven);
    let mut p = WarrantPolicy {
        autonomous_containment: true,
        allow_constrain_on_attested: true,
        ..WarrantPolicy::default()
    };
    for r in [
        ReconciliationResult::VerifiedExecution,
        ReconciliationResult::UnattributedEffect,
        ReconciliationResult::PhantomClaim,
        ReconciliationResult::IdentityDivergence,
        ReconciliationResult::LineageViolation,
        ReconciliationResult::SensorIntegrityFailure,
        ReconciliationResult::ContinuityFailure,
        ReconciliationResult::CannotProve,
    ] {
        p.severity = p.severity.with(r, Severity::Critical);
    }
    let _ = sha256(b"anchor");
    for result in [
        ReconciliationResult::UnattributedEffect,
        ReconciliationResult::IdentityDivergence,
        ReconciliationResult::LineageViolation,
        ReconciliationResult::PhantomClaim,
    ] {
        for strength in [EvidenceStrength::Heuristic, EvidenceStrength::Correlated] {
            let finding = Finding {
                finding_id: [0xf5; 16],
                reconciliation: record(result, strength),
                subject_agent: Some("aip1agent".into()),
            };
            let w = evaluate(&finding, &p, NOW).expect("well-formed");
            assert!(
                w.response <= ResponseClass::Alert,
                "{result:?} at {strength:?} → {:?}",
                w.response
            );
        }
    }
}
