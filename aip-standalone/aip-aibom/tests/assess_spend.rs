//! C5 limits and approval thresholds against signed spend authority
//! (ADR-018). Every policy is signed by a real issuer key; every attestation
//! and refusal comes from a real `DecisionPoint` enforcing it.

mod common;

use aip_aibom::evidence::EvidenceBundle;
use aip_aibom::finding::{FindingKind, Priority};
use aip_aibom::model::*;
use aip_aibom::standing::{Standing, Verifier};
use common::evidence::surface;
use common::spend::*;
use common::*;

const VERIFIED: Standing = Standing::Verified {
    verifier: Verifier::SpendPolicy,
};

fn limit(dollars: u64, per: LimitPeriod) -> Limit {
    Limit {
        action: pay(),
        per,
        max: usd(dollars),
    }
}

fn gate(dollars: u64) -> ApprovalGate {
    ApprovalGate {
        action: pay(),
        above: usd(dollars),
        approver: "cfo-delegate".into(),
    }
}

fn with_limit(t: &Treasury, l: Limit) -> Manifest {
    let mut m = manifest(&t.agent_id);
    m.permissions.limits = vec![l];
    m
}

const LIMIT: &str = "$.permissions.limits[0]";

// ═══ Limits ═══

/// The product's claim: a declared $1,000 limit is backed by the
/// institution's signature, and the decision point is shown enforcing it.
#[test]
fn a_declared_limit_matching_the_signed_policy_is_verified_and_enforced() {
    let t = treasury();
    let (ee, att) = t.paid("40000");
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        expectations: vec![ee],
        spend_attestations: vec![att],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    assert_eq!(standing(&a, LIMIT), VERIFIED);
    assert!(!has_finding(&a, |k| *k == FindingKind::LimitNotEnforceable));
    assert!(!has_finding(&a, |k| *k == FindingKind::SpendEnforcementNotEvidenced));
}

#[test]
fn a_signed_limit_with_no_decision_point_record_is_verified_but_not_shown_enforced() {
    let t = treasury();
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    assert_eq!(standing(&a, LIMIT), VERIFIED);
    assert!(has_finding(&a, |k| *k == FindingKind::SpendEnforcementNotEvidenced));
}

/// The manifest says $5,000; the institution signed $1,000. Signature
/// arithmetic against the declaration: critical.
#[test]
fn a_declared_limit_above_the_signed_one_is_contradicted() {
    let t = treasury();
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(5_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    assert!(matches!(standing(&a, LIMIT), Standing::Contradicted { .. }));
    assert!(a.has_critical());
}

#[test]
fn a_limit_in_another_currency_or_scale_is_contradicted_not_converted() {
    let t = treasury();
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        ..Default::default()
    };
    let mut eur = limit(1_000, LimitPeriod::PerAction);
    eur.max.currency = "EUR".into();
    let a = run(&with_limit(&t, eur), &b, &t.ctx(), &[]);
    assert!(matches!(standing(&a, LIMIT), Standing::Contradicted { .. }));

    let mut scaled = limit(1_000, LimitPeriod::PerAction);
    // The same number of minor units at another scale is $100, not $1,000.
    scaled.max = Amount {
        minor_units: LIMIT_CENTS,
        currency: "USD".into(),
        exponent: 3,
    };
    let a = run(&with_limit(&t, scaled), &b, &t.ctx(), &[]);
    assert!(matches!(standing(&a, LIMIT), Standing::Contradicted { .. }));
}

/// A policy carries per-action maxima only. A per-day limit is not
/// contradicted by one, and not verified by one either.
#[test]
fn a_per_day_limit_is_carried_by_nothing_and_stays_self_reported() {
    let t = treasury();
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerDay)),
        &b,
        &t.ctx(),
        &[],
    );
    assert_eq!(standing(&a, LIMIT), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::LimitNotEnforceable));
}

#[test]
fn without_a_policy_a_limit_is_the_authors_word() {
    let t = treasury();
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &EvidenceBundle::default(),
        &t.ctx(),
        &[],
    );
    assert_eq!(standing(&a, LIMIT), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::LimitNotEnforceable));
}

// ═══ The policy itself ═══

#[test]
fn a_policy_from_an_issuer_the_assessor_does_not_anchor_is_rejected() {
    let t = treasury();
    let mut c = t.ctx();
    c.spend_policy_anchors = aip_spend::SpendPolicyAnchors::new();
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &b,
        &c,
        &[],
    );
    assert_eq!(standing(&a, LIMIT), Standing::SelfReported);
    assert!(has_finding(&a, |k| matches!(
        k,
        FindingKind::EvidenceRejected { .. }
    )));
}

#[test]
fn a_raised_policy_is_rejected() {
    let t = treasury();
    let mut raised = t.current();
    raised.policy.rules[0].max_per_action = 500_000;
    let b = EvidenceBundle {
        spend_policies: vec![raised],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(5_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    assert_eq!(standing(&a, LIMIT), Standing::SelfReported);
    assert!(has_finding(&a, |k| matches!(
        k,
        FindingKind::EvidenceRejected { .. }
    )));
}

/// A policy the agent could sign is its self-report under another name.
#[test]
fn a_policy_issuer_anchored_under_the_agents_key_is_rejected() {
    let t = treasury();
    let mut c = t.ctx();
    c.spend_policy_anchors =
        aip_spend::SpendPolicyAnchors::new().trust(POLICY_ISSUER, &t.agent_kp.public_key);
    c.agent_public_key = Some(t.agent_kp.public_key.clone());
    let p = signed_by(&t, &t.agent_kp);
    let b = EvidenceBundle {
        spend_policies: vec![p],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &b,
        &c,
        &[],
    );
    assert_eq!(standing(&a, LIMIT), Standing::SelfReported);
    assert!(has_finding(
        &a,
        |k| matches!(k, FindingKind::EvidenceRejected { reason } if reason.contains("agent's own key"))
    ));
}

/// Two different policies signed at the same revision: the issuer
/// equivocated, and neither is relied on.
#[test]
fn two_different_policies_at_one_revision_are_not_relied_on() {
    let t = treasury();
    let other = t.signed(t.policy(REVISION, 500_000, None));
    let b = EvidenceBundle {
        spend_policies: vec![t.current(), other],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    assert_eq!(standing(&a, LIMIT), Standing::SelfReported);
    assert!(has_finding(
        &a,
        |k| matches!(k, FindingKind::EvidenceRejected { reason } if reason.contains("revision 3"))
    ));
}

/// The highest revision governs, and a decision point found enforcing an
/// older one is reported: it is applying terms the institution replaced.
#[test]
fn a_decision_point_enforcing_a_superseded_revision_is_reported() {
    let t = treasury();
    let (ee, att) = t.paid("40000");
    let newer = t.signed(t.policy(REVISION + 1, 200_000, Some(APPROVAL_ABOVE_CENTS)));
    let b = EvidenceBundle {
        spend_policies: vec![t.current(), newer],
        expectations: vec![ee],
        spend_attestations: vec![att],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(2_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    assert_eq!(standing(&a, LIMIT), VERIFIED);
    assert!(has_finding(&a, |k| *k
        == FindingKind::SpendPolicyMismatch {
            cited_revision: REVISION,
            current_revision: REVISION + 1
        }));
    assert!(has_finding(&a, |k| *k == FindingKind::SpendEnforcementNotEvidenced));
}

// ═══ Refusals ═══

/// The $5,000 attempt against the $1,000 limit, provable from signed bytes.
#[test]
fn the_five_thousand_dollar_attempt_is_reported_from_the_signed_refusal() {
    let t = treasury();
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        spend_refusals: vec![t.refused("500000")],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    let f = a
        .findings
        .iter()
        .find(|f| matches!(f.kind, FindingKind::SpendRefused { .. }))
        .expect("the refusal is reported");
    assert_eq!(f.priority, Priority::High);
    assert_eq!(f.path, "bundle.spend_refusals[0]");
    assert_eq!(
        f.kind,
        FindingKind::SpendRefused {
            action: "standard:Write".into(),
            reason: "LimitExceeded".into(),
            requested_minor_units: Some(500_000),
            limit_minor_units: LIMIT_CENTS,
            currency: "USD".into(),
            exponent: 2,
        }
    );
    assert!(f.message.contains("500000") && f.message.contains("100000"));
    // A refusal citing the current policy is itself evidence of enforcement.
    assert_eq!(standing(&a, LIMIT), VERIFIED);
    assert!(!has_finding(&a, |k| *k == FindingKind::SpendEnforcementNotEvidenced));
}

#[test]
fn a_refusal_whose_amount_was_rewritten_is_rejected() {
    let t = treasury();
    let mut r = t.refused("500000");
    r.refusal.requested_minor_units = Some(100_001);
    let b = EvidenceBundle {
        spend_refusals: vec![r],
        ..Default::default()
    };
    let a = run(&manifest(&t.agent_id), &b, &t.ctx(), &[]);
    assert!(!has_finding(&a, |k| matches!(
        k,
        FindingKind::SpendRefused { .. }
    )));
    assert!(has_finding(&a, |k| matches!(
        k,
        FindingKind::EvidenceRejected { .. }
    )));
}

#[test]
fn a_record_from_a_decision_point_anchored_under_the_agents_key_is_rejected() {
    let t = treasury();
    let mut c = t.ctx();
    c.agent_public_key = Some(t.agent_kp.public_key.clone());
    c.decision_points =
        aip_authorize::DecisionPointTrustAnchors::new().trust(&t.dp_id, &t.agent_kp.public_key);
    let b = EvidenceBundle {
        spend_refusals: vec![t.refused("500000")],
        ..Default::default()
    };
    let a = run(&manifest(&t.agent_id), &b, &c, &[]);
    assert!(has_finding(
        &a,
        |k| matches!(k, FindingKind::EvidenceRejected { reason } if reason.contains("agent's own key"))
    ));
}

#[test]
fn records_about_another_agent_are_ignored_and_counted() {
    let t = treasury();
    let (_, att) = t.paid("40000");
    let a = run(
        &manifest("aip1SomeoneElse"),
        &EvidenceBundle {
            spend_refusals: vec![t.refused("500000")],
            spend_attestations: vec![att],
            ..Default::default()
        },
        &t.ctx(),
        &[],
    );
    assert!(!has_finding(&a, |k| matches!(
        k,
        FindingKind::SpendRefused { .. }
    )));
    assert!(has_finding(&a, |k| *k == FindingKind::ForeignEvidence { count: 2 }));
}

/// Another agent's signed policy says nothing about this agent's limit.
#[test]
fn a_policy_for_another_agent_does_not_verify_this_agents_limit() {
    let t = treasury();
    let mut p = t.policy(REVISION, LIMIT_CENTS, Some(APPROVAL_ABOVE_CENTS));
    p.agent_id = "aip1SomeoneElse".into();
    let b = EvidenceBundle {
        spend_policies: vec![t.signed(p)],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    assert_eq!(standing(&a, LIMIT), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::ForeignEvidence { count: 1 }));
}

/// The CLI's context file is how an assessor anchors a policy issuer.
#[test]
fn a_context_file_anchors_spend_policy_issuers() {
    let t = treasury();
    let mut f = aip_aibom::evidence::ContextFile::default();
    f.spend_policy_issuers
        .insert(POLICY_ISSUER.into(), hex::encode(&t.issuer_kp.public_key));
    let c = f.into_context(t.now + 1).unwrap();
    assert_eq!(
        c.spend_policy_anchors.get(POLICY_ISSUER),
        Some(t.issuer_kp.public_key.as_slice())
    );
    let mut bad = aip_aibom::evidence::ContextFile::default();
    bad.spend_policy_issuers
        .insert(POLICY_ISSUER.into(), "not hex".into());
    assert!(bad.into_context(0).is_err());
}

/// The bundle is untrusted input; every spend collection is bounded.
#[test]
fn a_bundle_with_too_many_spend_records_is_refused() {
    let t = treasury();
    let one = serde_json::to_value(t.refused("500000")).unwrap();
    let many = serde_json::json!({ "spend_refusals": vec![one; 513] });
    let err = EvidenceBundle::from_json(&serde_json::to_vec(&many).unwrap()).unwrap_err();
    assert!(matches!(
        err,
        aip_aibom::evidence::InputError::TooMany {
            field: "spend_refusals",
            ..
        }
    ));
}

/// An attestation binds one expectation. Offered next to a different one
/// for its decision, it is rejected.
#[test]
fn an_attestation_offered_with_a_different_expectation_is_rejected() {
    let t = treasury();
    let (_, att) = t.paid("40000");
    let (mut other, _) = t.paid("30000");
    other.decision_id = att.attestation.decision_id;
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        expectations: vec![other],
        spend_attestations: vec![att],
        ..Default::default()
    };
    let a = run(
        &with_limit(&t, limit(1_000, LimitPeriod::PerAction)),
        &b,
        &t.ctx(),
        &[],
    );
    assert!(has_finding(
        &a,
        |k| matches!(k, FindingKind::EvidenceRejected { reason } if reason.contains("different expectation"))
    ));
    assert!(has_finding(&a, |k| *k == FindingKind::SpendEnforcementNotEvidenced));
}

// ═══ Approval thresholds ═══

fn with_gate(t: &Treasury, dollars: u64) -> Manifest {
    let mut m = manifest(&t.agent_id);
    m.permissions.approval_gates = vec![gate(dollars)];
    m
}

#[test]
fn a_gate_matching_the_signed_threshold_is_verified_and_its_approver_is_not() {
    let t = treasury();
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        ..Default::default()
    };
    let a = run(&with_gate(&t, 500), &b, &t.ctx(), &[]);
    assert_eq!(
        standing(&a, "$.permissions.approval_gates[0].above"),
        VERIFIED
    );
    assert_eq!(
        standing(&a, "$.permissions.approval_gates[0].approver"),
        Standing::SelfReported
    );
    assert!(a
        .findings
        .iter()
        .any(|f| f.path == "$.permissions.approval_gates[0]"
            && f.kind == FindingKind::SpendEnforcementNotEvidenced));
}

#[test]
fn a_gate_the_signed_policy_disagrees_with_is_contradicted() {
    let t = treasury();
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        ..Default::default()
    };
    let a = run(&with_gate(&t, 2_000), &b, &t.ctx(), &[]);
    assert!(matches!(
        standing(&a, "$.permissions.approval_gates[0].above"),
        Standing::Contradicted { .. }
    ));

    let none = EvidenceBundle {
        spend_policies: vec![t.signed(t.policy(REVISION, LIMIT_CENTS, None))],
        ..Default::default()
    };
    let a = run(&with_gate(&t, 500), &none, &t.ctx(), &[]);
    assert!(matches!(
        standing(&a, "$.permissions.approval_gates[0].above"),
        Standing::Contradicted { reason } if reason.contains("requires no approval")
    ));
}

/// The decision point authorised $750 on condition of approval. No
/// approval for that decision was offered: reported, by decision id.
#[test]
fn an_approval_required_decision_without_an_agreeing_approval_is_reported() {
    let t = treasury();
    let (ee, att) = t.paid("75000");
    let id = hex::encode(att.attestation.decision_id);
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        expectations: vec![ee],
        spend_attestations: vec![att],
        ..Default::default()
    };
    let a = run(&with_gate(&t, 500), &b, &t.ctx(), &[]);
    assert!(has_finding(&a, |k| *k
        == FindingKind::RequiredApprovalNotEvidenced {
            decision_id: id.clone()
        }));
}

#[test]
fn an_approval_required_decision_with_an_agreeing_approval_is_not_reported() {
    let t = treasury();
    let s = surface();
    let mut c = t.ctx();
    c.approval_surfaces = s.anchors.clone();
    let (ee, att) = t.paid("75000");
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        approvals: vec![s.approval(&ee, ee.action_kind.clone(), ee.parameter_digest)],
        expectations: vec![ee],
        spend_attestations: vec![att],
        ..Default::default()
    };
    let a = run(&with_gate(&t, 500), &b, &c, &[]);
    assert!(!has_finding(&a, |k| matches!(
        k,
        FindingKind::RequiredApprovalNotEvidenced { .. }
    )));
    assert!(!has_finding(&a, |k| matches!(
        k,
        FindingKind::ApprovalGateNotEnforceable { .. }
    )));
}

/// An approval for a different decision does not satisfy this one.
#[test]
fn an_approval_for_another_decision_does_not_count() {
    let t = treasury();
    let s = surface();
    let mut c = t.ctx();
    c.approval_surfaces = s.anchors.clone();
    let (ee, att) = t.paid("75000");
    let (other, _) = t.paid("75000");
    let b = EvidenceBundle {
        spend_policies: vec![t.current()],
        approvals: vec![s.approval(&other, other.action_kind.clone(), other.parameter_digest)],
        expectations: vec![ee, other],
        spend_attestations: vec![att],
        ..Default::default()
    };
    let a = run(&with_gate(&t, 500), &b, &c, &[]);
    assert!(has_finding(&a, |k| matches!(
        k,
        FindingKind::RequiredApprovalNotEvidenced { .. }
    )));
}

/// The standard policy signed with an arbitrary key, for independence tests.
fn signed_by(t: &Treasury, kp: &aip_types::KeyPair) -> aip_spend::SignedSpendPolicy {
    aip_spend::SignedSpendPolicy::sign(
        t.policy(REVISION, LIMIT_CENTS, Some(APPROVAL_ABOVE_CENTS)),
        &kp.private_key,
    )
    .unwrap()
}
