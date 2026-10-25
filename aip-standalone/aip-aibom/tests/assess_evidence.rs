//! C4 tools against gateway receipts, C5 approval gates against the approval
//! tier, C6 data access against the signed access ledger. Every artifact is
//! real, and every standing comes from the producing crate's own verifier.

mod common;

use aip_aibom::evidence::{AssessorContext, EvidenceBundle};
use aip_aibom::finding::FindingKind;
use aip_aibom::model::*;
use aip_aibom::standing::{NonEstablishment, Standing, Verifier};
use aip_airi::GatewayDisposition;
use aip_types::{Action, ScopeAction};
use common::evidence::*;
use common::staging::{at_of, authorised};
use common::*;

const AGENT: &str = "aip1TreasuryAgent";

fn ctx() -> AssessorContext {
    AssessorContext::trusting_nothing(T0 + 100_000)
}

fn tool(id: &str, kind: ToolKind) -> Tool {
    Tool {
        id: id.into(),
        kind,
        actions: vec![],
        endpoint: None,
    }
}

fn data(resource: &str) -> DataAccess {
    DataAccess {
        resource: resource.into(),
        kind: ResourceKind::Database,
        access: Access::ReadWrite,
    }
}

// ═══ C6 — data access against the access ledger ═══

#[test]
fn a_resource_the_ledger_shows_reached_is_verified_and_its_mode_is_not() {
    let l = ledger(AGENT, &[(CORE, CORE_PORT)]);
    let mut c = ctx();
    c.ledger_signers = l.anchors.clone();
    let mut m = manifest(AGENT);
    m.data_access = vec![data("core-banking-api")];
    let b = EvidenceBundle {
        access_ledgers: vec![l.ledger],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, "$.data_access[0]"),
        Standing::Verified {
            verifier: Verifier::AccessLedger
        }
    );
    assert_eq!(
        standing(&a, "$.data_access[0].access"),
        Standing::SelfReported
    );
}

/// Absence is never contradiction: the agent may not have reached the
/// resource inside the ledger's window.
#[test]
fn a_declared_resource_the_ledger_does_not_show_is_self_reported() {
    let l = ledger(AGENT, &[(CORE, CORE_PORT)]);
    let mut c = ctx();
    c.ledger_signers = l.anchors.clone();
    let mut m = manifest(AGENT);
    m.data_access = vec![data("ledger-db")];
    let b = EvidenceBundle {
        access_ledgers: vec![l.ledger],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert_eq!(standing(&a, "$.data_access[0]"), Standing::SelfReported);
    assert!(!a
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::Contradicted { .. })));
}

#[test]
fn an_undeclared_resource_and_an_unregistered_endpoint_are_findings() {
    let l = ledger(
        AGENT,
        &[
            (CORE, CORE_PORT),
            (LEDGER_DB, LEDGER_DB_PORT),
            (UNNAMED, 443),
        ],
    );
    let mut c = ctx();
    c.ledger_signers = l.anchors.clone();
    let mut m = manifest(AGENT);
    m.data_access = vec![data("core-banking-api")];
    let b = EvidenceBundle {
        access_ledgers: vec![l.ledger],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert!(has_finding(&a, |k| *k
        == FindingKind::UndeclaredResourceReached {
            resource: "ledger-db".into()
        }));
    assert!(has_finding(&a, |k| *k
        == FindingKind::UnregisteredEndpointReached { count: 1 }));
    assert!(!has_finding(&a, |k| *k
        == FindingKind::UndeclaredResourceReached {
            resource: "core-banking-api".into()
        }));
}

#[test]
fn an_adverse_row_is_critical_and_does_not_unverify_the_reach() {
    let l = ledger(AGENT, &[(CORE, CORE_PORT)]).with_adverse_row(CORE_PORT);
    let mut c = ctx();
    c.ledger_signers = l.anchors.clone();
    assert_eq!(
        l.ledger.verify(&l.anchors),
        Ok(()),
        "the re-signed ledger must itself verify"
    );
    let mut m = manifest(AGENT);
    m.data_access = vec![data("core-banking-api")];
    let b = EvidenceBundle {
        access_ledgers: vec![l.ledger],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, "$.data_access[0]"),
        Standing::Verified {
            verifier: Verifier::AccessLedger
        }
    );
    assert!(has_finding(&a, |k| *k
        == FindingKind::AdverseAccess {
            resource: "core-banking-api".into()
        }));
    assert!(a.has_critical());
}

#[test]
fn a_ledger_from_an_unanchored_signer_is_rejected_for_what_it_claimed() {
    let l = ledger(AGENT, &[(CORE, CORE_PORT)]);
    let mut m = manifest(AGENT);
    m.data_access = vec![data("core-banking-api")];
    let b = EvidenceBundle {
        access_ledgers: vec![l.ledger],
        ..Default::default()
    };
    let a = run(&m, &b, &ctx(), &[]);
    assert!(matches!(
        standing(&a, "$.data_access[0]"),
        Standing::EvidenceRejected { .. }
    ));
}

#[test]
fn another_agents_ledger_is_ignored() {
    let l = ledger("aip1SomeoneElse", &[(CORE, CORE_PORT)]);
    let mut c = ctx();
    c.ledger_signers = l.anchors.clone();
    let mut m = manifest(AGENT);
    m.data_access = vec![data("core-banking-api")];
    let b = EvidenceBundle {
        access_ledgers: vec![l.ledger],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert_eq!(standing(&a, "$.data_access[0]"), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::ForeignEvidence { count: 1 }));
}

// ═══ C4 — tools against gateway receipts ═══

fn with_receipts(
    g: &Gateway,
    receipts: Vec<aip_airi::SignedToolReceipt>,
) -> (EvidenceBundle, AssessorContext) {
    let mut c = ctx();
    c.gateways = g.anchors.clone();
    (
        EvidenceBundle {
            tool_receipts: receipts,
            ..Default::default()
        },
        c,
    )
}

#[test]
fn a_tool_the_gateway_forwarded_for_this_agent_is_verified_and_its_effect_is_not() {
    let g = gateway();
    let (b, c) = with_receipts(
        &g,
        vec![g.receipt(AGENT, "payments.create", GatewayDisposition::Forwarded)],
    );
    let mut m = manifest(AGENT);
    m.tools = vec![tool("payments.create", ToolKind::Api)];
    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, "$.tools[0]"),
        Standing::Verified {
            verifier: Verifier::ToolGateway
        }
    );
    assert_eq!(
        standing(&a, "$.tools[0].effects"),
        Standing::Unknowable {
            non_establishment: NonEstablishment::N2
        }
    );
}

/// A refused call shows the agent tried; it does not show the agent uses the
/// tool. Reported, and not credited.
#[test]
fn a_refused_call_is_reported_and_not_credited() {
    let g = gateway();
    let (b, c) = with_receipts(
        &g,
        vec![g.receipt(AGENT, "payments.create", GatewayDisposition::Refused)],
    );
    let mut m = manifest(AGENT);
    m.tools = vec![tool("payments.create", ToolKind::Api)];
    let a = run(&m, &b, &c, &[]);
    assert_eq!(standing(&a, "$.tools[0]"), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k
        == FindingKind::GatewayRefusals {
            tool_id: "payments.create".into(),
            count: 1
        }));
}

#[test]
fn a_tool_used_at_the_gateway_and_undeclared_is_a_finding() {
    let g = gateway();
    let (b, c) = with_receipts(
        &g,
        vec![g.receipt(AGENT, "crm.export", GatewayDisposition::Forwarded)],
    );
    let a = run(&manifest(AGENT), &b, &c, &[]);
    assert!(has_finding(&a, |k| *k
        == FindingKind::UndeclaredToolUsed {
            tool_id: "crm.export".into()
        }));
}

#[test]
fn a_receipt_from_an_unanchored_gateway_is_rejected() {
    let g = gateway();
    let b = EvidenceBundle {
        tool_receipts: vec![g.receipt(AGENT, "payments.create", GatewayDisposition::Forwarded)],
        ..Default::default()
    };
    let mut m = manifest(AGENT);
    m.tools = vec![tool("payments.create", ToolKind::Api)];
    let a = run(&m, &b, &ctx(), &[]);
    assert!(matches!(
        standing(&a, "$.tools[0]"),
        Standing::EvidenceRejected { .. }
    ));
}

/// A gateway anchored under the agent's own key is the agent's self-report
/// under another name, and the core refuses it.
#[test]
fn a_gateway_anchored_under_the_agents_own_key_is_refused() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let g = Gateway {
        signer: aip_airi::GatewaySigner::new(GATEWAY, 1, &kp.private_key).unwrap(),
        anchors: aip_airi::GatewayTrustAnchors::new().trust(GATEWAY, 1, &kp.public_key),
    };
    let (b, mut c) = with_receipts(
        &g,
        vec![g.receipt(AGENT, "payments.create", GatewayDisposition::Forwarded)],
    );
    c.agent_public_key = Some(kp.public_key.clone());
    let mut m = manifest(AGENT);
    m.tools = vec![tool("payments.create", ToolKind::Api)];
    let a = run(&m, &b, &c, &[]);
    assert!(matches!(
        standing(&a, "$.tools[0]"),
        Standing::EvidenceRejected { .. }
    ));
}

// ═══ C5 — approval gates against the approval tier ═══

fn gate() -> ApprovalGate {
    ApprovalGate {
        action: ScopeAction::Standard(Action::Write),
        above: usd(500),
        approver: "cfo".into(),
    }
}

#[test]
fn an_agreeing_approval_is_counted_and_the_gate_stays_the_authors_word() {
    let x = authorised();
    let s = surface();
    let mut c = AssessorContext::trusting_nothing(at_of(&x));
    c.decision_points = x.dp_anchors.clone();
    c.approval_surfaces = s.anchors.clone();
    let mut m = manifest(&x.agent_id);
    m.permissions.approval_gates = vec![gate()];
    let b = EvidenceBundle {
        expectations: vec![x.ee.clone()],
        approvals: vec![s.approval(&x.ee, x.ee.action_kind.clone(), x.ee.parameter_digest)],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, "$.permissions.approval_gates[0]"),
        Standing::SelfReported
    );
    assert!(has_finding(&a, |k| *k
        == FindingKind::ApprovalGateNotEnforceable { approvals: 1 }));
    assert!(!has_finding(&a, |k| *k == FindingKind::ApprovalGateNotEvidenced));
}

/// The class this tier exists for: a genuine approval of something other
/// than what was sealed.
#[test]
fn an_approval_of_different_parameters_is_critical() {
    let x = authorised();
    let s = surface();
    let mut c = AssessorContext::trusting_nothing(at_of(&x));
    c.decision_points = x.dp_anchors.clone();
    c.approval_surfaces = s.anchors.clone();
    let mut m = manifest(&x.agent_id);
    m.permissions.approval_gates = vec![gate()];
    let b = EvidenceBundle {
        expectations: vec![x.ee.clone()],
        approvals: vec![s.approval(
            &x.ee,
            x.ee.action_kind.clone(),
            sha256_of(b"amount_cents=5000000"),
        )],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert!(has_finding(&a, |k| matches!(
        k,
        FindingKind::ApprovalDiverged { .. }
    )));
    assert!(a.has_critical());
    assert!(
        has_finding(&a, |k| *k == FindingKind::ApprovalGateNotEvidenced),
        "a diverging approval is not an agreeing one"
    );
}

#[test]
fn an_approval_from_an_unanchored_surface_is_rejected() {
    let x = authorised();
    let s = surface();
    let mut c = AssessorContext::trusting_nothing(at_of(&x));
    c.decision_points = x.dp_anchors.clone();
    let b = EvidenceBundle {
        expectations: vec![x.ee.clone()],
        approvals: vec![s.approval(&x.ee, x.ee.action_kind.clone(), x.ee.parameter_digest)],
        ..Default::default()
    };
    let a = run(&manifest(&x.agent_id), &b, &c, &[]);
    assert!(a.findings.iter().any(|f| f.path == "bundle.approvals[0]"
        && matches!(f.kind, FindingKind::EvidenceRejected { .. })));
}

#[test]
fn an_approval_for_a_decision_nobody_offered_is_not_evaluated() {
    let x = authorised();
    let s = surface();
    let mut c = AssessorContext::trusting_nothing(at_of(&x));
    c.approval_surfaces = s.anchors.clone();
    let b = EvidenceBundle {
        approvals: vec![s.approval(&x.ee, x.ee.action_kind.clone(), x.ee.parameter_digest)],
        ..Default::default()
    };
    let a = run(&manifest(&x.agent_id), &b, &c, &[]);
    assert!(has_finding(&a, |k| matches!(
        k,
        FindingKind::ApprovalNotEvaluated { .. }
    )));
}

fn sha256_of(b: &[u8]) -> [u8; 32] {
    aip_crypto::sha256(b)
}

#[test]
fn another_agents_receipt_is_ignored() {
    let g = gateway();
    let (b, c) = with_receipts(
        &g,
        vec![g.receipt(
            "aip1SomeoneElse",
            "payments.create",
            GatewayDisposition::Forwarded,
        )],
    );
    let mut m = manifest(AGENT);
    m.tools = vec![tool("payments.create", ToolKind::Api)];
    let a = run(&m, &b, &c, &[]);
    assert_eq!(standing(&a, "$.tools[0]"), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::ForeignEvidence { count: 1 }));
}

/// Approvals count toward a gate only for this agent's decisions, and only
/// for the gate's own action.
#[test]
fn an_approval_counts_only_for_this_agents_gate_on_the_same_action() {
    let x = authorised();
    let s = surface();
    let mut c = AssessorContext::trusting_nothing(at_of(&x));
    c.decision_points = x.dp_anchors.clone();
    c.approval_surfaces = s.anchors.clone();
    let b = EvidenceBundle {
        expectations: vec![x.ee.clone()],
        approvals: vec![s.approval(&x.ee, x.ee.action_kind.clone(), x.ee.parameter_digest)],
        ..Default::default()
    };

    let mut other_action = manifest(&x.agent_id);
    other_action.permissions.approval_gates = vec![ApprovalGate {
        action: custom("refund_payment"),
        above: usd(500),
        approver: "cfo".into(),
    }];
    let a = run(&other_action, &b, &c, &[]);
    assert!(has_finding(&a, |k| *k == FindingKind::ApprovalGateNotEvidenced));

    let mut other_agent = manifest("aip1SomeoneElse");
    other_agent.permissions.approval_gates = vec![gate()];
    let a = run(&other_agent, &b, &c, &[]);
    assert!(has_finding(&a, |k| *k == FindingKind::ApprovalGateNotEvidenced));
}

#[test]
fn an_approval_surface_anchored_under_the_agents_own_key_is_refused() {
    let x = authorised();
    let s = Surface {
        key: x.agent_kp.clone(),
        anchors: aip_approval::ApprovalSurfaceAnchors::new().trust(SURFACE, &x.agent_kp.public_key),
    };
    let mut c = AssessorContext::trusting_nothing(at_of(&x));
    c.decision_points = x.dp_anchors.clone();
    c.approval_surfaces = s.anchors.clone();
    c.agent_public_key = Some(x.agent_kp.public_key.clone());
    let b = EvidenceBundle {
        expectations: vec![x.ee.clone()],
        approvals: vec![s.approval(&x.ee, x.ee.action_kind.clone(), x.ee.parameter_digest)],
        ..Default::default()
    };
    let mut m = manifest(&x.agent_id);
    m.permissions.approval_gates = vec![gate()];
    let a = run(&m, &b, &c, &[]);
    assert!(a.findings.iter().any(|f| f.path == "bundle.approvals[0]"
        && matches!(f.kind, FindingKind::EvidenceRejected { .. })));
    assert!(has_finding(&a, |k| *k == FindingKind::ApprovalGateNotEvidenced));
}
