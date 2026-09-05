//! Stage 7b — the gap between "a connection existed" and "a connection was
//! created". Live, Linux only, real processes and real sockets.
//!
//! Written **before** the kernel-pushed socket-state source existed. Against
//! the implementation at `ab05544` both tests fail, for opposite reasons:
//!
//! * T-A: a connection established and attested *before* the decision was
//!   issued, still open inside the window, produced `VERIFIED_EXECUTION` —
//!   the polled socket table shows existence at the sample, not creation, so
//!   the engine could not tell a pre-existing connection from a new one.
//! * T-C: a connection made and closed inside the window before any poll
//!   produced `CANNOT_PROVE` — a genuine authorized action was unprovable,
//!   because polling only sees what is open at the sample.
//!
//! Both are what a kernel-pushed socket-state transition source is for.

#![cfg(target_os = "linux")]

use aip_reconcile::ReconciliationResult;
use ghost_demo::{run, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

#[test]
fn t_a_connection_established_before_authorization_must_not_verify() {
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
    let d = run(Scenario::ConnectThenClose, AGENT);
    let r = &d.reconciliation;
    assert_eq!(
        r.result,
        ReconciliationResult::VerifiedExecution,
        "the transition happened inside the window; polling missed it: {}\n{r:?}",
        d.note
    );
}
