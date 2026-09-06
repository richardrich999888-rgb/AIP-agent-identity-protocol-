//! Gate 2 — the wire tap on a live host. Linux only, real processes, a real
//! TCP connection over loopback, real `AF_PACKET` capture on every device,
//! real `perf_event_open` on the socket-state tracepoint.
//!
//! Hosts without `CAP_NET_RAW` (or without the tracepoint) skip with a
//! message: the capability does not exist there and nothing is simulated.

#![cfg(target_os = "linux")]

use aip_reconcile::{EvidenceStrength, ReconciliationResult, WireCorroboration};
use ghost_demo::{run, tracer_available, wire_tap_available, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

fn sources_or_skip(test: &str) -> bool {
    if let Err(why) = tracer_available() {
        eprintln!("{test}: SKIPPED — kernel socket-state source unavailable: {why}");
        return false;
    }
    if let Err(why) = wire_tap_available() {
        eprintln!("{test}: SKIPPED — wire tap unavailable: {why}");
        return false;
    }
    true
}

#[test]
fn w_p_the_kernel_transition_is_corroborated_on_the_wire() {
    if !sources_or_skip("w_p") {
        return;
    }
    let d = run(Scenario::PositiveTransition, AGENT);
    let r = &d.reconciliation;
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.wire, WireCorroboration::Corroborated, "{}\n{r:?}", d.note);
    assert_eq!(r.strength, EvidenceStrength::Attested, "never Proven");
    assert!(
        d.note.contains("wire segment(s)"),
        "the note reports how many segments the tap captured: {}",
        d.note
    );
}

#[test]
fn w_n_without_a_tap_the_wire_question_is_unavailable_and_the_verdict_unchanged() {
    if let Err(why) = tracer_available() {
        eprintln!("w_n: SKIPPED — kernel socket-state source unavailable: {why}");
        return;
    }
    let d = ghost_demo::run_without_wire_tap(Scenario::PositiveTransition, AGENT);
    let r = &d.reconciliation;
    assert_eq!(r.result, ReconciliationResult::VerifiedExecution, "{r:?}");
    assert_eq!(r.wire, WireCorroboration::Unavailable, "{r:?}");
}
