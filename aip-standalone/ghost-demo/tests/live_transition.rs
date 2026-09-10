//! Stage 7b — the gap between "a connection existed" and "a connection was
//! created". Live, Linux only, real processes and real sockets, real
//! `perf_event_open` on `sock:inet_sock_set_state`.
//!
//! The first two tests were written **before** the kernel-pushed socket-state
//! source existed. Against the implementation at `ab05544` both failed, for
//! opposite reasons:
//!
//! * T-A: a connection established and attested *before* the decision was
//!   issued, still open inside the window, produced `VERIFIED_EXECUTION` —
//!   the polled socket table shows existence at the sample, not creation, so
//!   the engine could not tell a pre-existing connection from a new one.
//! * T-C: a connection made and closed inside the window before any poll
//!   produced `CANNOT_PROVE` — a genuine authorized action was unprovable,
//!   because polling only sees what is open at the sample.
//!
//! Hosts that do not permit the tracepoint (no tracefs, `perf_event_paranoid`
//! too strict, no `CAP_PERFMON`) skip these tests with a message: the
//! capability does not exist there and nothing is simulated.

#![cfg(target_os = "linux")]

use aip_reconcile::{
    ActionComparison, ActionEvidenceKind, EvidenceStrength, ReasonCode, ReconciliationResult,
    TemporalComparison,
};
use ghost_demo::{run, tracer_available, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

fn tracer_or_skip(test: &str) -> bool {
    match tracer_available() {
        Ok(()) => true,
        Err(why) => {
            eprintln!("{test}: SKIPPED — kernel socket-state source unavailable: {why}");
            false
        }
    }
}

#[test]
fn t_a_connection_established_before_authorization_must_not_verify() {
    if !tracer_or_skip("t_a") {
        return;
    }
    let d = run(Scenario::PreExistingConnection, AGENT);
    let r = &d.reconciliation;
    assert_ne!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "the connection predates the decision: {}\n{r:?}",
        d.note
    );
    assert_eq!(r.result, ReconciliationResult::CannotProve);
}

#[test]
fn t_c_connection_made_and_closed_before_any_poll_must_still_verify() {
    if !tracer_or_skip("t_c") {
        return;
    }
    let d = run(Scenario::ConnectThenClose, AGENT);
    let r = &d.reconciliation;
    assert_eq!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "the transition happened inside the window; polling missed it: {}\n{r:?}",
        d.note
    );
}

// ─── GREEN-phase pins: exactly which facts carried each verdict ───

#[test]
fn t_a_is_placed_before_the_window_by_the_collector_clock() {
    if !tracer_or_skip("t_a_reason") {
        return;
    }
    let r = run(Scenario::PreExistingConnection, AGENT).reconciliation;
    assert_eq!(r.reason, ReasonCode::ActionPrecedesAuthorization, "{r:?}");
    assert_eq!(r.temporal, TemporalComparison::BeforeWindow);
    assert!(!r.action.is_observable());
}

#[test]
fn t_c_verifies_on_transition_evidence_not_presence() {
    if !tracer_or_skip("t_c_kind") {
        return;
    }
    let d = run(Scenario::ConnectThenClose, AGENT);
    let r = &d.reconciliation;
    assert!(
        d.note.contains("0 established connection(s) in the poll"),
        "the table must have been empty: {}",
        d.note
    );
    match r.action {
        ActionComparison::Match(seal) => {
            assert_eq!(seal.kind(), ActionEvidenceKind::Transition);
            assert_eq!(
                seal.mechanism(),
                aip_observe::SourceMechanism::SockStateTracepoint
            );
        }
        other => panic!("expected a transition match, got {other:?}"),
    }
    assert_eq!(r.strength, EvidenceStrength::Attested, "never Proven");
    assert_eq!(r.temporal, TemporalComparison::WithinWindow);
}

#[test]
fn t_p_authorized_connection_verifies_on_the_kernel_transition() {
    if !tracer_or_skip("t_p") {
        return;
    }
    let d = run(Scenario::PositiveTransition, AGENT);
    let r = &d.reconciliation;
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.strength, EvidenceStrength::Attested);
    assert_eq!(
        r.action.evidence_kind(),
        Some(ActionEvidenceKind::Transition),
        "with the tracer live, the transition — not the table row — carries the verdict: {}",
        d.note
    );
}
