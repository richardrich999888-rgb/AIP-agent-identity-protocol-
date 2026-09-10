//! Gate 3 — `ghost.net.send.v1` on a live host. Linux only, real processes,
//! a real TCP connection over loopback, real `perf_event_open` on
//! `sock:sock_send_length` and `sock:inet_sock_set_state`.

#![cfg(target_os = "linux")]

use aip_reconcile::{
    ActionComparison, ActionEvidenceKind, EvidenceStrength, ReasonCode, ReconciliationResult,
};
use ghost_demo::{run, send_tracer_available, tracer_available, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

fn sources_or_skip(test: &str) -> bool {
    if let Err(why) = tracer_available() {
        eprintln!("{test}: SKIPPED — kernel socket-state source unavailable: {why}");
        return false;
    }
    if let Err(why) = send_tracer_available() {
        eprintln!("{test}: SKIPPED — send tracepoint unavailable: {why}");
        return false;
    }
    true
}

#[test]
fn s_p_the_agents_hello_verifies_as_a_send_to_the_authorized_endpoint() {
    if !sources_or_skip("s_p") {
        return;
    }
    let d = run(Scenario::SendPositive, AGENT);
    let r = &d.reconciliation;
    assert_eq!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "{}\n{r:?}",
        d.note
    );
    assert_eq!(r.strength, EvidenceStrength::Attested);
    match &r.action {
        ActionComparison::Match(seal) => {
            assert_eq!(seal.kind(), ActionEvidenceKind::Transition);
            assert_eq!(
                seal.mechanism(),
                aip_observe::SourceMechanism::SockSendTracepoint
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(d.note.contains("send event(s)"), "{}", d.note);
}

#[test]
fn s_a_a_send_authorized_to_another_endpoint_does_not_match() {
    if !sources_or_skip("s_a") {
        return;
    }
    let d = run(Scenario::SendWrongEndpoint, AGENT);
    let r = &d.reconciliation;
    assert_eq!(
        r.result,
        ReconciliationResult::CannotProve,
        "{}\n{r:?}",
        d.note
    );
    assert_eq!(r.reason, ReasonCode::ActionEvidenceDoesNotMatch);
}
