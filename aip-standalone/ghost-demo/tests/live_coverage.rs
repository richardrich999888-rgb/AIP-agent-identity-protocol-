//! The coverage statement, live: the decision point's *own* ledger, a real
//! process, the real observer and the real reconciler. Each case is an
//! attack on the one object that licenses `UNATTRIBUTED_EFFECT`, and each
//! is refused by name.

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use aip_authorize::{DecisionPointTrustAnchors, DenialReason};
use aip_observe::AgentClaim;
use aip_reconcile::{
    reconcile_observation, ExpectedSideCoverage, ObservationTarget, ObserverEvidence,
    ObserverSequence, ReasonCode, ReconciliationContext, ReconciliationResult,
};
use aip_types::CoverageWindow;
use ghost_demo::{now_ms, Agent, Authority, Observer, HEALTH_MAX_AGE_MS};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

/// Everything one live run leaves behind: the observed window, the
/// evidence, the verification time and the target observation.
struct Run {
    a: Authority,
    o: Observer,
    ev: ObserverEvidence,
    window: CoverageWindow,
    seq: u64,
    at: u64,
    remote: SocketAddrV4,
    pid: u32,
    _agent: Agent,
}

fn v4(l: &TcpListener) -> SocketAddrV4 {
    match l.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => panic!("IPv4 listener"),
    }
}

/// A real agent connects; `decide` may issue a decision for its binding
/// first (and returns the id the agent's claim should carry).
fn observed(decide: impl FnOnce(&Authority, u32, SocketAddrV4, u64) -> Option<[u8; 16]>) -> Run {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let remote = v4(&listener);
    let a = Authority::new();
    let mut o = Observer::new();
    let agent = Agent::connect(AGENT, &listener);
    let now = now_ms();
    let decision_id = decide(&a, agent.pid, remote, now);
    let b1 = o.epoch_start(now);
    let c = AgentClaim {
        agent_id: a.agent_id.clone(),
        claim_source: "ghost-demo".into(),
        decision_id,
    };
    let (b2, n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
    assert!(n >= 1, "the agent's connection must be observed");
    let at = now_ms().max(b2.batch.claimed_to_ms);
    let window = CoverageWindow {
        from_ms: b2.batch.claimed_from_ms,
        to_ms: b2.batch.claimed_to_ms,
    };
    let seq = b2.sequence;
    let ev = ObserverEvidence {
        batches: vec![b1, b2],
        health: o.health(at),
    };
    Run {
        a,
        o,
        ev,
        window,
        seq,
        at,
        remote,
        pid: agent.pid,
        _agent: agent,
    }
}

fn ctx(r: &Run, expected_side: ExpectedSideCoverage) -> ReconciliationContext {
    ReconciliationContext {
        decision_point_anchors: r.a.anchors.clone(),
        observer_anchors: r.o.anchors.clone(),
        verification_time_ms: r.at,
        health_max_age_ms: HEALTH_MAX_AGE_MS,
        window_tolerance_ms: 0,
        expected_side,
        agent_public_key: Some(r.a.agent_kp.public_key.clone()),
    }
}

fn verdict(r: &Run, c: &ReconciliationContext) -> aip_reconcile::Reconciliation {
    reconcile_observation(
        &r.ev,
        ObservationTarget::Observation {
            batch_sequence: ObserverSequence(r.seq),
            index: 0,
        },
        c,
    )
}

#[test]
fn cs01_attested_absence_over_the_observed_window_is_unattributed_effect() {
    let r = observed(|_, _, _, _| None);
    let stmt = r.a.coverage_statement(r.window, r.at).unwrap();
    assert!(stmt.decision_ids.is_empty());
    let v = verdict(&r, &ctx(&r, ExpectedSideCoverage::Attested(Box::new(stmt))));
    assert_eq!(v.result, ReconciliationResult::UnattributedEffect, "{v:?}");
    assert_eq!(v.reason, ReasonCode::NoExpectationAttested);
}

#[test]
fn cs02_a_decision_the_ledger_holds_is_listed_and_the_effect_is_not_unattributed() {
    // The decision point did authorize this connection, and the agent
    // claims that decision. The ledger-derived statement lists it, so the
    // reconciler defers to the expected side instead of naming a ghost.
    let r = observed(|a, pid, remote, now| {
        let ee = a
            .authorize_connect(a.binding_for(pid), remote, now)
            .unwrap();
        Some(ee.decision_id)
    });
    let stmt = r.a.coverage_statement(r.window, r.at).unwrap();
    assert_eq!(stmt.decision_ids.len(), 1, "{stmt:?}");
    let v = verdict(&r, &ctx(&r, ExpectedSideCoverage::Attested(Box::new(stmt))));
    assert_eq!(v.result, ReconciliationResult::CannotProve, "{v:?}");
    assert_eq!(v.reason, ReasonCode::ExpectationExistsForObservation);
}

#[test]
fn cs03_a_statement_that_does_not_cover_the_observed_window_licenses_nothing() {
    let r = observed(|_, _, _, _| None);
    // One millisecond short of the observation's window end.
    let narrow = CoverageWindow {
        from_ms: r.window.from_ms,
        to_ms: r.window.to_ms.saturating_sub(1).max(r.window.from_ms),
    };
    if narrow == r.window {
        // Zero-length observation window; the narrower statement cannot
        // be formed. The property is pinned synthetically in
        // aip-reconcile/tests/adversarial.rs (t05).
        return;
    }
    let stmt = r.a.coverage_statement(narrow, r.at).unwrap();
    let v = verdict(&r, &ctx(&r, ExpectedSideCoverage::Attested(Box::new(stmt))));
    assert_eq!(v.result, ReconciliationResult::CannotProve, "{v:?}");
    assert_eq!(v.reason, ReasonCode::ExpectedSideStatementDoesNotCover);
}

#[test]
fn cs04_a_statement_from_a_decision_point_the_verifier_does_not_anchor_is_invalid() {
    let r = observed(|_, _, _, _| None);
    let stmt = r.a.coverage_statement(r.window, r.at).unwrap();
    let mut c = ctx(&r, ExpectedSideCoverage::Attested(Box::new(stmt)));
    c.decision_point_anchors = DecisionPointTrustAnchors::new();
    let v = verdict(&r, &c);
    assert_eq!(v.result, ReconciliationResult::CannotProve, "{v:?}");
    assert_eq!(v.reason, ReasonCode::ExpectedSideStatementInvalid);
}

#[test]
fn cs05_the_decision_point_will_not_falsify_a_statement_it_signed() {
    // After attesting "no decision over the window", a request to
    // authorize the same agent *inside* that window is denied: the ledger
    // closes what it has sworn to.
    let r = observed(|_, _, _, _| None);
    let _stmt = r.a.coverage_statement(r.window, r.at).unwrap();
    let d =
        r.a.authorize_connect(r.a.binding_for(r.pid), r.remote, r.window.to_ms)
            .unwrap_err();
    assert_eq!(d.reason, DenialReason::AttestedWindowClosed, "{d:?}");
    // Strictly after the attested window, the same request is authorized.
    assert!(r
        .a
        .authorize_connect(r.a.binding_for(r.pid), r.remote, r.window.to_ms + 1)
        .is_ok());
}

#[test]
fn cs06_a_window_before_the_ledger_epoch_is_refused_by_the_decision_point() {
    let r = observed(|_, _, _, _| None);
    let early = CoverageWindow {
        from_ms: r.window.from_ms.saturating_sub(3_600_000),
        to_ms: r.window.to_ms,
    };
    assert!(matches!(
        r.a.coverage_statement(early, r.at),
        Err(aip_authorize::CoverageIssueError::WindowPrecedesLedger { .. })
    ));
}
