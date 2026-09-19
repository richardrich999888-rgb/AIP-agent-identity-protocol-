//! The expected-side completeness producer, adversarially.
//!
//! A coverage statement is the one object that can turn "no expectation
//! found" into "no expectation exists". These tests pin that it is derived
//! from the decision point's own ledger, never from the caller; that it
//! refuses every window it cannot vouch for; and that, once issued, the
//! decision point will not falsify it by back-issuing a decision into the
//! attested window.

use aip_authorize::*;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_types::{
    Action, CoverageWindow, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple,
    ScopeAction, EXECUTION_BINDING_VERSION,
};

const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn binding_for(agent_id: &str, pid: u32) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 433_843,
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v1"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

/// One decision point, two agents under the same orchestrator, and a
/// request template for each. `now` is the earliest valid decision time.
struct Fx {
    dp: DecisionPoint,
    dp_id: String,
    dp_kp: KeyPair,
    anchors: DecisionPointTrustAnchors,
    req_a: AuthorizationRequest,
    req_b: AuthorizationRequest,
    now: u64,
}

/// `ledger` enables the coverage ledger with its epoch at the fixture's
/// own `now`, so every decision time the tests use is at or after it.
fn fixture(ledger: bool) -> Fx {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_a, _) = create_identity(provenance("agent-a"), None).unwrap();
    let (agent_b, _) = create_identity(provenance("agent-b"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop_a =
        create_delegation(&root, &orch_kp.private_key, &agent_a.id, scope_submitter()).unwrap();
    let hop_b =
        create_delegation(&root, &orch_kp.private_key, &agent_b.id, scope_submitter()).unwrap();
    let now = root.issued_at.max(hop_a.issued_at).max(hop_b.issued_at) + 1;

    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let mut dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch.id, &orch_kp.public_key);
    if ledger {
        dp = dp.with_coverage_ledger(now);
    }
    let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    let req = |agent_id: &str, hop, pid| AuthorizationRequest {
        agent_id: agent_id.to_string(),
        root_token: root.clone(),
        delegation_chain: vec![hop],
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: ActionParameters::from_pairs([("invoice", b"INV-1".to_vec())]).unwrap(),
        execution_binding: binding_for(agent_id, pid),
        requested_ttl_ms: TTL,
    };
    let req_a = req(&agent_a.id, hop_a, 4242);
    let req_b = req(&agent_b.id, hop_b, 4343);
    Fx {
        dp,
        dp_id,
        dp_kp,
        anchors,
        req_a,
        req_b,
        now,
    }
}

fn authorized(dp: &DecisionPoint, req: &AuthorizationRequest, at: u64) -> ExpectedExecution {
    match dp.authorize_at(req, at) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("expected authorization, got {d:?}"),
    }
}

type Mutation = Box<dyn Fn(&mut DecisionPointCoverageStatement)>;

fn window(from_ms: u64, to_ms: u64) -> CoverageWindow {
    CoverageWindow { from_ms, to_ms }
}

// ─── Producer refusals ───

#[test]
fn p01_no_ledger_epoch_no_statement() {
    let f = fixture(false);
    let _ = authorized(&f.dp, &f.req_a, f.now);
    assert_eq!(f.dp.coverage_ledger_since(), None);
    assert_eq!(
        f.dp.coverage_statement(&f.req_a.agent_id, window(f.now, f.now + 10), f.now + 10),
        Err(CoverageIssueError::LedgerNotEnabled)
    );
}

#[test]
fn p02_window_before_the_ledger_epoch_is_refused() {
    let f = fixture(true);
    let since = f.dp.coverage_ledger_since().unwrap();
    assert_eq!(
        f.dp.coverage_statement(&f.req_a.agent_id, window(since - 1, since + 10), since + 10),
        Err(CoverageIssueError::WindowPrecedesLedger { since_ms: since })
    );
    // Exactly at the epoch is fine.
    assert!(f
        .dp
        .coverage_statement(&f.req_a.agent_id, window(since, since + 10), since + 10)
        .is_ok());
}

#[test]
fn p03_window_not_yet_closed_at_issue_time_is_refused() {
    let f = fixture(true);
    let since = f.dp.coverage_ledger_since().unwrap();
    let issued_at = since + 100;
    assert_eq!(
        f.dp.coverage_statement(&f.req_a.agent_id, window(since, issued_at + 1), issued_at),
        Err(CoverageIssueError::WindowNotClosed {
            issued_at_ms: issued_at
        })
    );
    // Closing exactly at issue time is allowed: that instant has passed.
    assert!(f
        .dp
        .coverage_statement(&f.req_a.agent_id, window(since, issued_at), issued_at)
        .is_ok());
}

#[test]
fn p04_malformed_inputs_are_refused_before_the_ledger_is_consulted() {
    let f = fixture(true);
    let since = f.dp.coverage_ledger_since().unwrap();
    assert_eq!(
        f.dp.coverage_statement("", window(since, since + 1), since + 1),
        Err(CoverageIssueError::EmptyAgentId)
    );
    assert_eq!(
        f.dp.coverage_statement(&f.req_a.agent_id, window(since + 5, since + 4), since + 10),
        Err(CoverageIssueError::InvalidWindow)
    );
    // Neither refusal closed anything: a decision at `since` still issues.
    let _ = authorized(&f.dp, &f.req_a, since);
}

// ─── The list is derived, not supplied ───

#[test]
fn p05_statement_lists_exactly_the_intersecting_decisions_for_that_agent() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    // Agent A: one decision valid [t0, t0+TTL]; agent B: one at the same time.
    let ee_a = authorized(&f.dp, &f.req_a, t0);
    let ee_b = authorized(&f.dp, &f.req_b, t0);
    assert_eq!(f.dp.issued_count(), 2);

    // A window inside A's validity: exactly A's decision, not B's.
    let stmt =
        f.dp.coverage_statement(&f.req_a.agent_id, window(t0 + 10, t0 + 20), t0 + 20)
            .unwrap();
    assert_eq!(stmt.version, DECISION_POINT_COVERAGE_VERSION);
    assert_eq!(stmt.decision_point_id, f.dp_id);
    assert_eq!(stmt.agent_id, f.req_a.agent_id);
    assert_eq!(stmt.decision_ids, vec![ee_a.decision_id]);
    assert!(!stmt.decision_ids.contains(&ee_b.decision_id));
    assert_eq!(stmt.verify(&f.anchors), Ok(()));

    // The same window for B names only B's.
    let stmt_b =
        f.dp.coverage_statement(&f.req_b.agent_id, window(t0 + 10, t0 + 20), t0 + 20)
            .unwrap();
    assert_eq!(stmt_b.decision_ids, vec![ee_b.decision_id]);
}

#[test]
fn p06_a_decision_whose_validity_ends_before_the_window_is_not_listed() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    let ee = authorized(&f.dp, &f.req_a, t0);
    let end = ee.valid_until;
    // Touching at `valid_until` intersects (both ends inclusive)...
    let touching =
        f.dp.coverage_statement(&f.req_a.agent_id, window(end, end + 5), end + 5)
            .unwrap();
    assert_eq!(touching.decision_ids, vec![ee.decision_id]);
    // ...one millisecond later does not.
    let after =
        f.dp.coverage_statement(&f.req_a.agent_id, window(end + 1, end + 5), end + 5)
            .unwrap();
    assert!(after.decision_ids.is_empty());
    assert_eq!(after.verify(&f.anchors), Ok(()));
}

#[test]
fn p07_an_empty_window_is_an_honest_empty_statement() {
    // No decisions at all: the statement is empty and still signed. This is
    // the statement that licenses UNATTRIBUTED_EFFECT for anything observed
    // in the window.
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    let stmt =
        f.dp.coverage_statement(&f.req_a.agent_id, window(t0, t0 + 100), t0 + 100)
            .unwrap();
    assert!(stmt.decision_ids.is_empty());
    assert_eq!(stmt.verify(&f.anchors), Ok(()));
}

#[test]
fn p08_a_denied_request_is_not_in_the_ledger() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    let mut bad = f.req_a.clone();
    bad.requested_ttl_ms = 0;
    assert!(matches!(f.dp.authorize_at(&bad, t0), Decision::Denied(_)));
    assert_eq!(f.dp.issued_count(), 0);
    let stmt =
        f.dp.coverage_statement(&f.req_a.agent_id, window(t0, t0 + 1), t0 + 1)
            .unwrap();
    assert!(stmt.decision_ids.is_empty());
}

#[test]
fn p09_two_statements_over_the_same_ledger_state_have_identical_preimages() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    let _ = authorized(&f.dp, &f.req_a, t0);
    let _ = authorized(&f.dp, &f.req_a, t0 + 1);
    let w = window(t0, t0 + 50);
    let s1 =
        f.dp.coverage_statement(&f.req_a.agent_id, w, t0 + 50)
            .unwrap();
    let s2 =
        f.dp.coverage_statement(&f.req_a.agent_id, w, t0 + 50)
            .unwrap();
    assert_eq!(s1.decision_ids.len(), 2);
    assert_eq!(s1.signing_preimage(), s2.signing_preimage());
    let mut sorted = s1.decision_ids.clone();
    sorted.sort_unstable();
    assert_eq!(
        s1.decision_ids, sorted,
        "ids are emitted in canonical order"
    );
}

// ─── The statement stays true after it is issued ───

#[test]
fn p10_a_decision_back_issued_into_an_attested_window_is_denied() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    let stmt =
        f.dp.coverage_statement(&f.req_a.agent_id, window(t0, t0 + 100), t0 + 100)
            .unwrap();
    assert!(stmt.decision_ids.is_empty());

    // Inside and at the edge of the attested window: refused.
    for at in [t0, t0 + 50, t0 + 100] {
        match f.dp.authorize_at(&f.req_a, at) {
            Decision::Denied(d) => assert_eq!(d.reason, DenialReason::AttestedWindowClosed),
            Decision::Authorized(ee) => panic!("back-issued into attested window: {ee:?}"),
        }
    }
    assert_eq!(f.dp.issued_count(), 0);
    // One millisecond after the window: issues normally.
    let _ = authorized(&f.dp, &f.req_a, t0 + 101);
    // Another agent is not closed by A's statement.
    let _ = authorized(&f.dp, &f.req_b, t0 + 50);
}

#[test]
fn p11_closure_is_monotone_a_narrower_later_statement_does_not_reopen() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    let _ =
        f.dp.coverage_statement(&f.req_a.agent_id, window(t0, t0 + 100), t0 + 100)
            .unwrap();
    let _ =
        f.dp.coverage_statement(&f.req_a.agent_id, window(t0, t0 + 10), t0 + 100)
            .unwrap();
    assert!(matches!(
        f.dp.authorize_at(&f.req_a, t0 + 100),
        Decision::Denied(Denial {
            reason: DenialReason::AttestedWindowClosed,
            ..
        })
    ));
}

#[test]
fn p12_a_refused_statement_closes_nothing() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    // Not yet closed at issue time: refused, and the window stays open.
    assert!(f
        .dp
        .coverage_statement(&f.req_a.agent_id, window(t0, t0 + 100), t0 + 50)
        .is_err());
    let _ = authorized(&f.dp, &f.req_a, t0 + 10);
}

// ─── Verifier refusals against the producer's output ───

#[test]
fn p13_a_statement_forged_under_another_key_does_not_verify() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    let genuine =
        f.dp.coverage_statement(&f.req_a.agent_id, window(t0, t0 + 1), t0 + 1)
            .unwrap();
    let other = generate_ed25519_keypair();
    let mut forged = genuine.clone();
    forged.signature =
        sign_ed25519(&other.private_key, &f.dp_id, &forged.signing_preimage()).unwrap();
    assert_eq!(
        forged.verify(&f.anchors),
        Err(CoverageStatementError::SignatureInvalid)
    );
    // The verifier anchoring the forger's key under the decision point's id
    // is the verifier's own error; under the real anchor it fails.
    let wrong_anchor = DecisionPointTrustAnchors::new().trust(&f.dp_id, &other.public_key);
    assert_eq!(
        genuine.verify(&wrong_anchor),
        Err(CoverageStatementError::SignatureInvalid)
    );
}

#[test]
fn p14_every_signed_field_is_bound() {
    let f = fixture(true);
    let t0 = f.dp.coverage_ledger_since().unwrap();
    let _ = authorized(&f.dp, &f.req_a, t0);
    let stmt =
        f.dp.coverage_statement(&f.req_a.agent_id, window(t0, t0 + 1), t0 + 1)
            .unwrap();
    assert_eq!(stmt.verify(&f.anchors), Ok(()));
    let mutations: Vec<Mutation> = vec![
        Box::new(|s| s.decision_ids.clear()),
        Box::new(|s| s.decision_ids.push([0xee; 16])),
        Box::new(|s| s.window.to_ms += 1),
        Box::new(|s| s.window.from_ms -= 1),
        Box::new(|s| s.issued_at_ms += 1),
        Box::new(|s| s.agent_id.push('x')),
    ];
    for m in mutations {
        let mut t = stmt.clone();
        m(&mut t);
        assert_eq!(
            t.verify(&f.anchors),
            Err(CoverageStatementError::PayloadHashMismatch)
        );
    }
    let mut t = stmt.clone();
    t.version += 1;
    assert_eq!(
        t.verify(&f.anchors),
        Err(CoverageStatementError::UnsupportedVersion(t.version))
    );
    let mut t = stmt.clone();
    t.decision_point_id.push('x');
    assert!(matches!(
        t.verify(&f.anchors),
        Err(CoverageStatementError::UntrustedDecisionPoint(_))
    ));
    // Same key anchored under the tampered id: the signature names the
    // real id, so the signer check refuses.
    let anchors2 =
        DecisionPointTrustAnchors::new().trust(&t.decision_point_id, &f.dp_kp.public_key);
    assert_eq!(
        t.verify(&anchors2),
        Err(CoverageStatementError::SignerMismatch)
    );
}
