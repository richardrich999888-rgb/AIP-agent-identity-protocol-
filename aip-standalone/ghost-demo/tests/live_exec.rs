//! Process execution as action evidence — live, Linux only, real processes.
//!
//! Written **before** the implementation, against `5c4c2d0`. The positive
//! case fails there (`CANNOT_PROVE / ActionEvidenceUnavailable`): the agent
//! spawns a child executing the authorized image, the observer is live, and
//! nothing interprets a fork/exec pair as an action. The negatives pass there
//! only because nothing verifies; they are pinned so the new class cannot
//! over-reach.
//!
//! Hosts without tracefs/perf skip with a message; nothing is simulated.

#![cfg(target_os = "linux")]

use aip_reconcile::ReconciliationResult;
use ghost_demo::{run, tracer_available, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

fn tracer_or_skip(test: &str) -> bool {
    match tracer_available() {
        Ok(()) => true,
        Err(why) => {
            eprintln!("{test}: SKIPPED — kernel source unavailable: {why}");
            false
        }
    }
}

#[test]
fn x_p_authorized_image_executed_by_a_child_of_the_agent_verifies() {
    if !tracer_or_skip("x_p") {
        return;
    }
    let d = run(Scenario::ExecPositive, AGENT);
    let r = &d.reconciliation;
    assert_eq!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "{}\n{r:?}",
        d.note
    );
}

#[test]
fn x_a_child_executing_a_different_image_does_not_verify() {
    if !tracer_or_skip("x_a") {
        return;
    }
    let d = run(Scenario::ExecWrongBinary, AGENT);
    assert_ne!(
        d.reconciliation.result,
        ReconciliationResult::VerifiedExecution,
        "{}\n{:?}",
        d.note,
        d.reconciliation
    );
}

#[test]
fn x_b_spawn_by_another_instance_does_not_verify() {
    if !tracer_or_skip("x_b") {
        return;
    }
    let d = run(Scenario::ExecByOtherInstance, AGENT);
    assert_ne!(
        d.reconciliation.result,
        ReconciliationResult::VerifiedExecution,
        "{}\n{:?}",
        d.note,
        d.reconciliation
    );
}

#[test]
fn x_c_spawn_attested_before_the_decision_does_not_verify() {
    if !tracer_or_skip("x_c") {
        return;
    }
    let d = run(Scenario::ExecBeforeAuthorization, AGENT);
    assert_ne!(
        d.reconciliation.result,
        ReconciliationResult::VerifiedExecution,
        "{}\n{:?}",
        d.note,
        d.reconciliation
    );
    assert_eq!(d.reconciliation.result, ReconciliationResult::CannotProve);
}

// ─── GREEN-phase pins: exactly which facts carried each verdict ───

#[test]
fn x_p_verifies_on_the_kernel_fork_exec_pair_with_the_image_hash() {
    if !tracer_or_skip("x_p_kind") {
        return;
    }
    let d = run(Scenario::ExecPositive, AGENT);
    let r = &d.reconciliation;
    assert_eq!(
        r.reason,
        aip_reconcile::ReasonCode::ActionEvidenceMatches,
        "{}\n{r:?}",
        d.note
    );
    assert_eq!(r.strength, aip_reconcile::EvidenceStrength::Attested);
    match r.action {
        aip_reconcile::ActionComparison::Match(seal) => {
            assert_eq!(seal.kind(), aip_reconcile::ActionEvidenceKind::Transition);
            assert_eq!(
                seal.mechanism(),
                aip_observe::SourceMechanism::SchedTracepoint
            );
        }
        other => panic!("expected an exec transition match, got {other:?}"),
    }
}

#[test]
fn x_a_wrong_image_is_a_transition_mismatch_on_content() {
    if !tracer_or_skip("x_a_reason") {
        return;
    }
    let r = run(Scenario::ExecWrongBinary, AGENT).reconciliation;
    assert_eq!(
        r.reason,
        aip_reconcile::ReasonCode::ActionEvidenceDoesNotMatch,
        "{r:?}"
    );
    assert!(matches!(
        r.action,
        aip_reconcile::ActionComparison::Mismatch(_)
    ));
}

#[test]
fn x_b_other_instance_is_identity_divergence() {
    if !tracer_or_skip("x_b_reason") {
        return;
    }
    let r = run(Scenario::ExecByOtherInstance, AGENT).reconciliation;
    // The actor's spawn under the bound instance's claim is divergent. The
    // tracer also captured the bound (idle) agent's *own* exec event, which
    // genuinely matches the binding, so the identity picture is ambiguous —
    // and ambiguity is CANNOT_PROVE, never a verdict.
    assert_ne!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert!(
        matches!(
            r.identity,
            aip_reconcile::IdentityComparison::Divergent { .. }
                | aip_reconcile::IdentityComparison::Ambiguous { .. }
        ),
        "{r:?}"
    );
    assert!(
        r.result == ReconciliationResult::IdentityDivergence
            || r.reason == aip_reconcile::ReasonCode::AmbiguousObservations,
        "{r:?}"
    );
}

#[test]
fn x_c_is_placed_before_the_window() {
    if !tracer_or_skip("x_c_reason") {
        return;
    }
    let r = run(Scenario::ExecBeforeAuthorization, AGENT).reconciliation;
    assert_eq!(
        r.reason,
        aip_reconcile::ReasonCode::ActionPrecedesAuthorization,
        "{r:?}"
    );
    assert_eq!(r.temporal, aip_reconcile::TemporalComparison::BeforeWindow);
}
