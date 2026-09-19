//! R4 — the tool boundary: authorized versus received versus claimed.
//!
//! The scenario is a payments transfer. The decision point authorizes
//! `mcp:payments:transfer` with a commitment to one argument set; the agent
//! claims it asked for that; the institution's payments gateway signs what it
//! actually received. Every test below is about which of those three
//! documents disagree, and about what the comparison refuses to say.

use aip_airi::*;
use aip_authorize::{
    tool_invoke_action, tool_invoke_parameters, AuthorityRef, DecisionPointTrustAnchors,
    ExpectedExecution, EXPECTED_EXECUTION_VERSION,
};
use aip_observe::{ObserverAttestor, ObserverTrustAnchors, SourceMechanism};
use aip_reconcile::{
    reconcile_expectation, ExpectedSideCoverage, ObserverEvidence, ReasonCode,
    ReconciliationContext, ReconciliationResult,
};

mod support;
use support::*;

const TOOL: &str = "mcp:payments:transfer";
const GW: &str = "gw-payments-1";
/// The canonical tool arguments as the SDK serialises them. They appear in
/// this test file and nowhere else: not in the mandate, not in the receipt,
/// not in the claim.
const AUTHORIZED_ARGS: &[u8] =
    br#"{"amount":"250000.00","beneficiary":"HDFC0001234:50100012345678","currency":"INR"}"#;
const OTHER_ARGS: &[u8] =
    br#"{"amount":"2500000.00","beneficiary":"HDFC0001234:50100012345678","currency":"INR"}"#;

struct DecisionPoint {
    anchors: DecisionPointTrustAnchors,
    private_key: Vec<u8>,
}

fn decision_point() -> DecisionPoint {
    let kp = aip_crypto::generate_ed25519_keypair();
    DecisionPoint {
        anchors: DecisionPointTrustAnchors::new().trust("dp-1", &kp.public_key),
        private_key: kp.private_key,
    }
}

/// A tool-invoke authorization for `agent`, sealed by the decision point.
fn authorize(dp: &DecisionPoint, a: &Agent, tool: &str, args: &[u8]) -> ExpectedExecution {
    let mut ee = ExpectedExecution {
        version: EXPECTED_EXECUTION_VERSION,
        decision_id: DECISION_A,
        decision_point_id: "dp-1".into(),
        agent_id: a.agent_id.clone(),
        authority: AuthorityRef {
            root_jti: [0x01; 16],
            chain_jtis: vec![],
        },
        action_kind: tool_invoke_action(),
        parameter_digest: tool_invoke_parameters(tool, commit(args)).unwrap().digest(),
        execution_binding: binding(&a.agent_id, 4321),
        issued_at: 0,
        valid_until: 10_000,
        decision_sig: empty_signature(),
    };
    let preimage = ee.signing_preimage();
    ee.decision_sig = aip_crypto::sign_ed25519(&dp.private_key, "dp-1", &preimage).unwrap();
    ee
}

struct Gateway {
    signer: GatewaySigner,
    anchors: GatewayTrustAnchors,
    public_key: Vec<u8>,
}

fn gateway() -> Gateway {
    let kp = aip_crypto::generate_ed25519_keypair();
    Gateway {
        signer: GatewaySigner::new(GW, 1, &kp.private_key).unwrap(),
        anchors: GatewayTrustAnchors::new().trust(GW, 1, &kp.public_key),
        public_key: kp.public_key,
    }
}

/// What the gateway received: it recomputes the commitment over the
/// request bytes it holds, exactly as the SDK would have.
fn receipt_for(a: &Agent, decision: [u8; 16], tool: &str, received_args: &[u8]) -> ToolReceipt {
    ToolReceipt {
        version: TOOL_RECEIPT_VERSION,
        gateway_id: GW.into(),
        key_version: 1,
        decision_id: decision,
        agent_id: a.agent_id.clone(),
        tool_id: tool.into(),
        parameter_commitment: parameter_commitment(received_args),
        tool_call_id: Some(ToolCallId("call_1".into())),
        disposition: GatewayDisposition::Forwarded,
        response_commitment: Some(parameter_commitment(b"{\"status\":\"ACCEPTED\"}")),
        received_at_ms: 5_000,
    }
}

fn verified(gw: &Gateway, a: &Agent, r: ToolReceipt) -> VerifiedToolReceipt {
    let signed = gw.signer.sign(r).unwrap();
    verify_tool_receipt(&signed, &gw.anchors, Some(&a.public_key)).unwrap()
}

// ─── Agreement ───

#[test]
fn a_receipt_matching_the_authorization_agrees_and_so_does_the_claim() {
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);
    let r = verified(&gw, &a, receipt_for(&a, DECISION_A, TOOL, AUTHORIZED_ARGS));
    let claim = signed_tool_request(&a, EXEC_A, Some(DECISION_A), TOOL, AUTHORIZED_ARGS);
    verify_airi_event(&claim, &a.public_key).unwrap();

    assert_eq!(
        compare_tool_boundary(&ee, &dp.anchors, Some(&r), Some(&claim)),
        ToolBoundary::Agrees {
            claim: ClaimStanding::Agrees
        }
    );
    assert_eq!(
        compare_tool_boundary(&ee, &dp.anchors, Some(&r), None),
        ToolBoundary::Agrees {
            claim: ClaimStanding::NotSupplied
        }
    );
}

// ─── The disputed-transaction class ───

#[test]
fn a_gateway_that_received_other_parameters_is_the_named_divergence() {
    // Authorized 2,50,000; the switch received 25,00,000. The agent's own
    // claim says the authorized amount — and that changes nothing.
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);
    let r = verified(&gw, &a, receipt_for(&a, DECISION_A, TOOL, OTHER_ARGS));
    let honest_claim = signed_tool_request(&a, EXEC_A, Some(DECISION_A), TOOL, AUTHORIZED_ARGS);

    let out = compare_tool_boundary(&ee, &dp.anchors, Some(&r), Some(&honest_claim));
    assert!(out.is_divergence());
    assert_eq!(
        out.divergence(),
        Some(&ToolBoundaryDivergence::ReceiptDoesNotMatchAuthorization {
            received: tool_invoke_parameters(TOOL, parameter_commitment(OTHER_ARGS))
                .unwrap()
                .digest(),
            authorized: ee.parameter_digest,
        })
    );
    // The same answer with no claim at all: the agent's account is not what
    // the finding rests on.
    assert_eq!(compare_tool_boundary(&ee, &dp.anchors, Some(&r), None), out);
}

#[test]
fn a_gateway_that_received_a_call_to_another_tool_is_a_divergence() {
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);
    let r = verified(
        &gw,
        &a,
        receipt_for(&a, DECISION_A, "mcp:payments:refund", AUTHORIZED_ARGS),
    );
    assert!(matches!(
        compare_tool_boundary(&ee, &dp.anchors, Some(&r), None),
        ToolBoundary::Diverges {
            divergence: ToolBoundaryDivergence::ReceiptDoesNotMatchAuthorization { .. }
        }
    ));
}

#[test]
fn an_agent_that_misreports_a_request_the_gateway_received_correctly_is_named_separately() {
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);
    let r = verified(&gw, &a, receipt_for(&a, DECISION_A, TOOL, AUTHORIZED_ARGS));
    let misreport = signed_tool_request(&a, EXEC_A, Some(DECISION_A), TOOL, OTHER_ARGS);

    assert_eq!(
        compare_tool_boundary(&ee, &dp.anchors, Some(&r), Some(&misreport)),
        ToolBoundary::Diverges {
            divergence: ToolBoundaryDivergence::ClaimDoesNotMatchAuthorization {
                claimed: tool_invoke_parameters(TOOL, parameter_commitment(OTHER_ARGS))
                    .unwrap()
                    .digest(),
                authorized: ee.parameter_digest,
            }
        }
    );
}

#[test]
fn a_claim_about_another_decision_or_another_kind_is_not_comparable_and_not_a_finding() {
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);
    let r = verified(&gw, &a, receipt_for(&a, DECISION_A, TOOL, AUTHORIZED_ARGS));

    let other_decision = signed_tool_request(&a, EXEC_A, Some(DECISION_B), TOOL, OTHER_ARGS);
    assert_eq!(
        compare_tool_boundary(&ee, &dp.anchors, Some(&r), Some(&other_decision)),
        ToolBoundary::Agrees {
            claim: ClaimStanding::NotComparable
        }
    );
    let model_claim = signed_model_request(&a, EXEC_A, Some(DECISION_A), "gpt-x", [0x9; 32]);
    assert_eq!(
        compare_tool_boundary(&ee, &dp.anchors, Some(&r), Some(&model_claim)),
        ToolBoundary::Agrees {
            claim: ClaimStanding::NotComparable
        }
    );
}

// ─── Absence is not an accusation ───

#[test]
fn no_receipt_is_not_evaluated_never_a_divergence() {
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);
    let misreport = signed_tool_request(&a, EXEC_A, Some(DECISION_A), TOOL, OTHER_ARGS);
    // Even a claim that disagrees with the authorization is not compared
    // without the independent side present.
    assert_eq!(
        compare_tool_boundary(&ee, &dp.anchors, None, Some(&misreport)),
        ToolBoundary::NotEvaluated {
            reason: ToolBoundaryNotEvaluated::NoReceipt
        }
    );
}

#[test]
fn a_receipt_for_another_decision_or_another_agent_is_not_comparable() {
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let other = agent("aip1Someone");
    let gw = gateway();
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);

    let r = verified(&gw, &a, receipt_for(&a, DECISION_B, TOOL, OTHER_ARGS));
    assert_eq!(
        compare_tool_boundary(&ee, &dp.anchors, Some(&r), None),
        ToolBoundary::NotEvaluated {
            reason: ToolBoundaryNotEvaluated::DifferentDecision {
                receipt_decision: DECISION_B,
                expectation_decision: DECISION_A,
            }
        }
    );
    let r = verified(
        &gw,
        &other,
        receipt_for(&other, DECISION_A, TOOL, OTHER_ARGS),
    );
    assert_eq!(
        compare_tool_boundary(&ee, &dp.anchors, Some(&r), None),
        ToolBoundary::NotEvaluated {
            reason: ToolBoundaryNotEvaluated::DifferentAgent {
                receipt_agent: other.agent_id.clone(),
                expectation_agent: a.agent_id.clone(),
            }
        }
    );
}

#[test]
fn an_expectation_that_is_not_a_tool_invocation_or_is_unanchored_is_not_compared() {
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let r = verified(&gw, &a, receipt_for(&a, DECISION_A, TOOL, AUTHORIZED_ARGS));

    // A socket authorization: the tool boundary has nothing to say.
    let socket_ee = sample_expectation(&a);
    assert!(matches!(
        compare_tool_boundary(&socket_ee, &dp.anchors, Some(&r), None),
        ToolBoundary::NotEvaluated {
            reason: ToolBoundaryNotEvaluated::NotAToolInvocation { .. }
        }
    ));

    // A tool authorization from a decision point the verifier does not
    // anchor: comparing against it would look like arithmetic and is not.
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);
    assert_eq!(
        compare_tool_boundary(&ee, &DecisionPointTrustAnchors::new(), Some(&r), None),
        ToolBoundary::NotEvaluated {
            reason: ToolBoundaryNotEvaluated::ExpectationNotVerified
        }
    );
}

// ─── The receipt under attack ───

#[test]
fn a_receipt_the_verifier_does_not_anchor_or_that_the_agent_could_have_signed_is_refused() {
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let signed = gw
        .signer
        .sign(receipt_for(&a, DECISION_A, TOOL, AUTHORIZED_ARGS))
        .unwrap();

    assert!(matches!(
        verify_tool_receipt(&signed, &GatewayTrustAnchors::new(), None),
        Err(ReceiptError::GatewayNotAnchored { .. })
    ));
    // A key version the verifier has not been provisioned with.
    let stale = GatewayTrustAnchors::new().trust(GW, 2, &gw.public_key);
    assert!(matches!(
        verify_tool_receipt(&signed, &stale, None),
        Err(ReceiptError::GatewayNotAnchored { key_version: 1, .. })
    ));

    // The "gateway" is the agent: anchored under the agent's own key.
    let agent_signer = GatewaySigner::new(GW, 1, &a.private_key).unwrap();
    let self_signed = agent_signer
        .sign(receipt_for(&a, DECISION_A, TOOL, AUTHORIZED_ARGS))
        .unwrap();
    let agent_as_gateway = GatewayTrustAnchors::new().trust(GW, 1, &a.public_key);
    assert_eq!(
        verify_tool_receipt(&self_signed, &agent_as_gateway, Some(&a.public_key)),
        Err(ReceiptError::GatewayKeyIsAgentKey)
    );
}

#[test]
fn a_receipt_altered_after_signing_or_signed_by_an_impostor_is_refused() {
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let signed = gw
        .signer
        .sign(receipt_for(&a, DECISION_A, TOOL, OTHER_ARGS))
        .unwrap();

    // "Correct" the commitment after the fact.
    let mut t = signed.clone();
    t.receipt.parameter_commitment = parameter_commitment(AUTHORIZED_ARGS);
    assert_eq!(
        verify_tool_receipt(&t, &gw.anchors, None),
        Err(ReceiptError::PayloadHashMismatch)
    );

    // Re-sign the corrected receipt with a key that is not the gateway's.
    let impostor = aip_crypto::generate_ed25519_keypair();
    let re = GatewaySigner::new(GW, 1, &impostor.private_key)
        .unwrap()
        .sign(t.receipt.clone())
        .unwrap();
    assert_eq!(
        verify_tool_receipt(&re, &gw.anchors, None),
        Err(ReceiptError::SignatureInvalid)
    );

    // Signature naming another signer than the receipt does.
    let mut s = signed.clone();
    s.attestation.signer_id = "gw-other".into();
    assert_eq!(
        verify_tool_receipt(&s, &gw.anchors, None),
        Err(ReceiptError::SignerIsNotGateway)
    );

    // A structure version this build does not implement.
    let mut v = signed.clone();
    v.receipt.version = TOOL_RECEIPT_VERSION + 1;
    assert_eq!(
        verify_tool_receipt(&v, &gw.anchors, None),
        Err(ReceiptError::UnsupportedVersion(TOOL_RECEIPT_VERSION + 1))
    );
}

// ─── Privacy: the arguments are in this file and nowhere else ───

#[test]
fn the_transaction_arguments_appear_in_no_signed_document() {
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let gw = gateway();
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);
    let signed = gw
        .signer
        .sign(receipt_for(&a, DECISION_A, TOOL, AUTHORIZED_ARGS))
        .unwrap();
    let claim = signed_tool_request(&a, EXEC_A, Some(DECISION_A), TOOL, AUTHORIZED_ARGS);

    let documents = [
        serde_json::to_string(&ee).unwrap(),
        serde_json::to_string(&signed).unwrap(),
        serde_json::to_string(&claim).unwrap(),
        hex::encode(ee.signing_preimage()),
        hex::encode(signed.receipt.canonical_bytes()),
        hex::encode(claim.signing_preimage()),
    ];
    let secrets = [
        "250000.00",
        "HDFC0001234",
        "50100012345678",
        "beneficiary",
        &hex::encode(AUTHORIZED_ARGS),
    ];
    for d in &documents {
        for s in &secrets {
            assert!(
                !d.contains(s),
                "plaintext `{s}` leaked into a signed document"
            );
        }
    }
}

// ─── The kernel side says nothing about this class ───

#[test]
fn the_reconciler_derives_no_action_evidence_for_a_tool_invocation() {
    // A trusted decision point, a trusted observer, and a kernel-pushed
    // socket transition on the authorized instance claimed under this very
    // decision. For a socket authorization that is the verified path. For a
    // tool authorization it is not evidence of the action at all, and the
    // engine must say so rather than match a socket to a tool call.
    let dp = decision_point();
    let a = agent("aip1LoanAgent");
    let ee = authorize(&dp, &a, TOOL, AUTHORIZED_ARGS);

    let mut o = Observer::new();
    o.signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let mut ev = socket_event(&ee.execution_binding);
    ev.attribution = aip_observe::AgentAttribution::Claimed {
        agent_id: a.agent_id.clone(),
        claim_source: "orchestrator".into(),
    };
    ev.claimed_decision_id = Some(DECISION_A);
    // Two chained batches, so the collector's continuity is verified and
    // the outcome below is about action evidence, not about the observer.
    let mut opening = raw_batch(1, 0, 5_000, vec![], vec![]);
    opening.probe_seq_first = 0;
    opening.probe_seq_last = 0;
    let first = attest(&mut o, opening, 5_000);
    let second = attest(
        &mut o,
        raw_batch(2, 5_000, 10_000, vec![], vec![ev]),
        10_000,
    );
    let health = o.signer.health(10_000).unwrap();
    let evidence = ObserverEvidence {
        batches: vec![first, second],
        health,
    };
    let ctx = ReconciliationContext {
        decision_point_anchors: dp.anchors.clone(),
        observer_anchors: ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, o.signer.public_key()),
        verification_time_ms: 10_000,
        health_max_age_ms: 60_000,
        window_tolerance_ms: 1_000,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: Some(a.public_key.clone()),
    };
    let rec = reconcile_expectation(&ee, Some(&evidence), &ctx);
    assert_ne!(rec.result, ReconciliationResult::VerifiedExecution);
    assert_eq!(rec.result, ReconciliationResult::CannotProve, "{rec:#?}");
    assert_eq!(
        rec.reason,
        ReasonCode::ActionEvidenceUnavailable,
        "{rec:#?}"
    );
    // And the mechanism list confirms the observer was watching sockets.
    assert!(evidence.batches[1]
        .batch
        .active_mechanisms
        .contains(&SourceMechanism::SockStateTracepoint));
}
