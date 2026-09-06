//! Gate 4 — `ghost.fs.write.v1` on a live host. Linux only, a real child
//! process writing a real file, real `fanotify` with `FAN_REPORT_PIDFD` on
//! the mount that holds the temp directory.

#![cfg(target_os = "linux")]

use aip_reconcile::{
    ActionComparison, ActionEvidenceKind, EvidenceStrength, ReasonCode, ReconciliationResult,
};
use ghost_demo::{fanotify_available, run, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

fn source_or_skip(test: &str) -> bool {
    if let Err(why) = fanotify_available() {
        eprintln!("{test}: SKIPPED — fanotify unavailable: {why}");
        return false;
    }
    true
}

#[test]
fn f_p_the_agents_write_to_the_authorized_path_verifies() {
    if !source_or_skip("f_p") {
        return;
    }
    let d = run(Scenario::FileWritePositive, AGENT);
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
            assert_eq!(seal.mechanism(), aip_observe::SourceMechanism::Fanotify);
        }
        other => panic!("{other:?}"),
    }
    assert!(d.note.contains("file event(s)"), "{}", d.note);
}

#[test]
fn f_a_a_write_authorized_for_another_path_does_not_match() {
    if !source_or_skip("f_a") {
        return;
    }
    let d = run(Scenario::FileWriteWrongPath, AGENT);
    let r = &d.reconciliation;
    assert_eq!(
        r.result,
        ReconciliationResult::CannotProve,
        "{}\n{r:?}",
        d.note
    );
    assert_eq!(r.reason, ReasonCode::ActionEvidenceDoesNotMatch);
}

#[test]
fn f_n_no_write_by_the_agent_is_not_observed_and_never_a_phantom() {
    if !source_or_skip("f_n") {
        return;
    }
    let d = run(Scenario::FileWriteNotDone, AGENT);
    let r = &d.reconciliation;
    assert_eq!(
        r.result,
        ReconciliationResult::CannotProve,
        "{}\n{r:?}",
        d.note
    );
    assert_eq!(r.reason, ReasonCode::ActionEvidenceUnavailable);
}
