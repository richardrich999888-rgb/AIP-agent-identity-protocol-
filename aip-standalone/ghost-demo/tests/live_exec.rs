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
