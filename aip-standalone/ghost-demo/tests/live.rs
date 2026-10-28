//! Live end-to-end tests. NOT FIXTURES: each test spawns the real
//! `ghost-demo-agent` binary, makes (or does not make) a real TCP connection
//! to a real listener, reads the real kernel socket table under a real pidfd
//! anchor, attests it with a real collector, and reconciles with the real
//! engine. Linux only.

#![cfg(target_os = "linux")]

use aip_reconcile::{
    ActionComparison, EvidenceRef, EvidenceStrength, IdentityComparison, ReasonCode,
    ReconciliationResult,
};
use ghost_demo::{run, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

#[test]
fn positive_authorized_connection_is_verified_at_attested() {
    let d = run(Scenario::Positive, AGENT);
    let r = &d.reconciliation;
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(
        r.strength,
        EvidenceStrength::Attested,
        "never Proven: procfs content"
    );
    assert_eq!(r.reason, ReasonCode::ActionEvidenceMatches);
    assert!(matches!(r.identity, IdentityComparison::Match { .. }));
    match r.action {
        ActionComparison::Match(seal) => assert_eq!(
            seal.mechanism(),
            aip_observe::SourceMechanism::ProcNetTable,
            "the evidence is polled socket-table metadata, and the record says so"
        ),
        other => panic!("expected action Match, got {other:?}"),
    }
}

#[test]
fn a_expected_but_not_executed_is_cannot_prove_not_phantom() {
    let r = run(Scenario::ExpectedNotExecuted, AGENT).reconciliation;
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_ne!(r.result, ReconciliationResult::PhantomClaim);
    // The instance was seen (anchored presence observation), but no
    // connection of the authorized class was — and polled coverage can never
    // turn that silence into non-execution.
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnavailable);
    assert!(matches!(r.identity, IdentityComparison::Match { .. }));
    assert!(!r.action.is_observable());
}

#[test]
fn b_executed_but_not_expected_with_attested_absence_is_unattributed_effect() {
    // The defining ghost detection, live: a real process makes a real
    // connection under no decision, the observer attests it, and the
    // decision point signs — from its own ledger — that no decision exists
    // for that agent over the observed window.
    let r = run(Scenario::ExecutedNotExpected, AGENT).reconciliation;
    assert_eq!(r.result, ReconciliationResult::UnattributedEffect, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(r.reason, ReasonCode::NoExpectationAttested);
    assert!(matches!(r.identity, IdentityComparison::Match { .. }));
    assert!(
        r.evidence
            .iter()
            .any(|e| matches!(e, EvidenceRef::CoverageStatement { .. })),
        "the verdict must cite the decision point's statement: {r:?}"
    );
}

#[test]
fn b_u_executed_but_not_expected_without_a_statement_is_cannot_prove() {
    // Same observation, no coverage statement: absence is only absence.
    let r = run(Scenario::ExecutedNotExpectedUnattested, AGENT).reconciliation;
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_ne!(r.result, ReconciliationResult::UnattributedEffect);
    assert_eq!(r.reason, ReasonCode::ExpectedSideCompletenessUnknown);
}

#[test]
fn c_different_parameters_is_cannot_prove_with_action_mismatch() {
    let r = run(Scenario::DifferentParameters, AGENT).reconciliation;
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceDoesNotMatch);
    assert!(matches!(r.action, ActionComparison::Mismatch(_)));
    assert!(matches!(r.identity, IdentityComparison::Match { .. }));
}

#[test]
fn d_wrong_process_instance_is_identity_divergence_never_verified() {
    let r = run(Scenario::WrongInstance, AGENT).reconciliation;
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    // Same binary, different instance, claiming the bound instance's
    // decision: that is exactly divergence.
    assert_eq!(r.result, ReconciliationResult::IdentityDivergence);
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert!(matches!(r.identity, IdentityComparison::Divergent { .. }));
}

#[test]
fn e_lost_observation_is_cannot_prove() {
    let r = run(Scenario::LostObservation, AGENT).reconciliation;
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert_eq!(r.reason, ReasonCode::ObserverDegraded);
}

#[test]
fn f_replayed_evidence_does_not_verify_another_decision() {
    let r = run(Scenario::ReplayedEvidence, AGENT).reconciliation;
    assert_eq!(r.result, ReconciliationResult::CannotProve, "{r:?}");
    assert!(r.replay_detected, "the duplicated batch is flagged");
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnclaimed);
}

#[test]
fn g_tampered_evidence_is_sensor_integrity_failure_proven() {
    let r = run(Scenario::TamperedEvidence, AGENT).reconciliation;
    assert_eq!(
        r.result,
        ReconciliationResult::SensorIntegrityFailure,
        "{r:?}"
    );
    assert_eq!(r.strength, EvidenceStrength::Proven);
}

// This checks the startup boundary against independently measured procfs
// identity. A readiness string is never used as the measured executable hash.
#[test]
fn idle_readiness_precedes_binding_collection() {
    let image = ghost_demo::hash_binary(AGENT);
    for _ in 0..64 {
        let agent = ghost_demo::Agent::idle(AGENT);
        let binding =
            aip_core::execution_binding::collect_binding_for_pid("idle-test", agent.pid).unwrap();
        let observed = aip_observe::ProcfsProbe::new("idle-test")
            .measure(agent.pid)
            .unwrap();
        assert_eq!(binding.exe_content_sha256, image);
        assert!(
            observed.matches_process_of(&binding),
            "{binding:?} != {observed:?}"
        );
    }
}

/// Capture the old unsynchronized boundary as a diagnostic, then check the
/// post-handshake measurements. A zero count means the race did not reproduce
/// on this host; it is not a claim that spawn completion guarantees readiness.
#[test]
fn idle_startup_race_diagnostic() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let mut different = 0;
    let attempts = if cfg!(debug_assertions) { 16 } else { 4096 };
    for _ in 0..attempts {
        let mut child = Command::new(AGENT)
            .arg("--idle")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let before =
            aip_core::execution_binding::collect_binding_for_pid("idle-test", child.id()).unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ghost-demo-agent idle");
        let after =
            aip_core::execution_binding::collect_binding_for_pid("idle-test", child.id()).unwrap();
        if !before.same_execution(&after) {
            different += 1;
            if different == 1 {
                eprintln!("startup binding changed: before={before:?}; after={after:?}");
            }
        }
        let measured = aip_observe::ProcfsProbe::new("idle-test")
            .measure(child.id())
            .unwrap();
        let matches = measured.matches_process_of(&after);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(matches, "post-readiness binding differs from measurement");
    }
    eprintln!("pre-readiness identity changes: {different}/{attempts}");
}
