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
use ghost_demo::{run, tracer_available, Demo, Scenario};

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

/// How many times a run may be repeated while the observer fails to see the
/// execution at all. Three is enough that a loaded host recovers, and small
/// enough that a host which genuinely cannot observe still fails in seconds.
const COVERAGE_ATTEMPTS: usize = 3;

/// Did the observer see the execution at all?
///
/// `ActionComparison::Unobservable` is the engine saying the `fork`/`exec`
/// pair was not there to compare. It is a correct output and it is a
/// **precondition** of every assertion below that names a specific reason
/// code — not a property under test.
///
/// Deliberately **not** `availability.is_covered()`. In this demonstrator the
/// attested coverage window is a separate question from whether the action
/// was seen, and a run that reaches `VerifiedExecution` on a matched exec
/// transition still reports `WindowNotCovered`. Using coverage here would
/// reject runs that proved exactly what the test asks about.
fn observed(d: &Demo) -> bool {
    !matches!(
        d.reconciliation.action,
        aip_reconcile::ActionComparison::Unobservable
    )
}

/// Run `scenario` until the execution was observed as action evidence.
///
/// Only for the tests whose assertion is **about the action comparison**.
/// `x_b` and `x_c` deliberately do not use it: for
/// `Scenario::ExecBeforeAuthorization`, `Unobservable` is the correct action
/// outcome — the exec fell outside the window, so it is never compared as
/// action evidence, and the verdict rests on `temporal: BeforeWindow`.
/// Applying this precondition there would reject the very result the test
/// exists to pin.
///
/// # Why this retry is legitimate and a retry on the assertion would not be
///
/// These scenarios reconcile a real `fork`/`exec` pair delivered through perf
/// tracepoints. On a loaded host — several test binaries and a compiler on
/// four CPUs — the pair can be incomplete when the window closes, and the
/// engine then answers `ActionTransitionIncomplete` with the action
/// `Unobservable`. That is the architecture working: absence of evidence is not
/// converted into a finding. But a test that asks *"is a wrong image reported
/// as a content mismatch?"* is asking a question that only has an answer once
/// the image was seen, and asserting the mismatch reason against a run that
/// saw nothing conflates two different facts.
///
/// So the retry fires **only** when the run reports it could not see. It never
/// fires because the observer saw something and the verdict disagreed with the
/// test: a real regression still fails on the first attempt. If coverage is
/// never established the test fails and says so, rather than passing quietly
/// on a run that proved nothing.
fn run_observed(scenario: Scenario, test: &str) -> Demo {
    let mut d = run(scenario, AGENT);
    for attempt in 1..COVERAGE_ATTEMPTS {
        if observed(&d) {
            return d;
        }
        eprintln!(
            "{test}: attempt {attempt} did not observe the execution \
             (action {:?}, reason {:?}); retrying the run, not the assertion",
            d.reconciliation.action, d.reconciliation.reason
        );
        d = run(scenario, AGENT);
    }
    assert!(
        observed(&d),
        "{test}: the execution was never observed in {COVERAGE_ATTEMPTS} attempts, so there is \
         nothing to assert about the action. This is not a pass. Last result:\n{:?}",
        d.reconciliation
    );
    d
}

#[test]
fn x_p_authorized_image_executed_by_a_child_of_the_agent_verifies() {
    if !tracer_or_skip("x_p") {
        return;
    }
    let d = run_observed(Scenario::ExecPositive, "x_p");
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
    let d = run_observed(Scenario::ExecPositive, "x_p_kind");
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
    let r = run_observed(Scenario::ExecWrongBinary, "x_a_reason").reconciliation;
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
