//! C5 permissions and C8 delegation — the treasury agent, honestly.
//!
//! Every standing above `SelfReported` here comes from
//! `verify_delegation_chain`. The tests attack the comparison the engine adds
//! on top of it — scope containment and the signed window — and the rule that
//! absence of evidence is never a contradiction.

mod common;

use aip_aibom::evidence::{AssessorContext, EvidenceBundle};
use aip_aibom::finding::FindingKind;
use aip_aibom::model::*;
use aip_aibom::standing::{Lapse, Standing, Verifier};
use common::*;

struct World {
    cfo: Principal,
    agent: String,
    token: aip_types::ScopedToken,
}

fn world() -> World {
    let cfo = principal("cfo");
    let (doc, _) = active_identity("treasury-agent");
    let token = grant(
        &cfo,
        &doc.id,
        scope(&["read_balance", "create_payment"], &["refund_payment"]),
        Some(HOUR_MS),
    );
    World {
        agent: doc.id,
        cfo,
        token,
    }
}

fn ctx(w: &World) -> AssessorContext {
    let mut c = AssessorContext::trusting_nothing(w.token.issued_at + 1);
    c.issuer_keys
        .insert(w.cfo.id.clone(), w.cfo.kp.public_key.clone());
    c
}

fn declaring(w: &World, actions: &[&str]) -> Manifest {
    let mut m = manifest(&w.agent);
    m.permissions.allowed = actions.iter().map(|a| custom(a)).collect();
    m
}

fn bundle(w: &World) -> EvidenceBundle {
    EvidenceBundle {
        authority: vec![chain(w.token.clone())],
        ..Default::default()
    }
}

const P0: &str = "$.permissions.allowed[0]";
const P1: &str = "$.permissions.allowed[1]";

#[test]
fn a_granted_action_is_verified_by_the_delegation_chain() {
    let w = world();
    let a = run(
        &declaring(&w, &["create_payment"]),
        &bundle(&w),
        &ctx(&w),
        &[],
    );
    assert_eq!(
        standing(&a, P0),
        Standing::Verified {
            verifier: Verifier::DelegationChain
        }
    );
}

/// The rule the whole product rests on: a permission no offered chain grants
/// is the author's word, not a contradiction. The bundle may simply not hold
/// the grant.
#[test]
fn an_ungranted_action_is_self_reported_not_contradicted() {
    let w = world();
    let a = run(
        &declaring(&w, &["create_payment", "wire_transfer"]),
        &bundle(&w),
        &ctx(&w),
        &[],
    );
    assert_eq!(standing(&a, P1), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::PermissionNotBacked));
    assert!(!a
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::Contradicted { .. })));
}

/// Contradiction requires positive disagreement: a verified scope that
/// explicitly denies the declared action.
#[test]
fn an_explicitly_denied_action_is_contradicted() {
    let w = world();
    let a = run(
        &declaring(&w, &["refund_payment"]),
        &bundle(&w),
        &ctx(&w),
        &[],
    );
    assert!(matches!(standing(&a, P0), Standing::Contradicted { .. }));
    assert!(a.has_critical());
}

/// Authority the agent holds and does not declare is the inventory
/// understating privilege — the thing a discovery exists to catch.
#[test]
fn undeclared_live_authority_is_a_finding() {
    let w = world();
    let a = run(
        &declaring(&w, &["read_balance"]),
        &bundle(&w),
        &ctx(&w),
        &[],
    );
    assert!(has_finding(&a, |k| *k
        == FindingKind::UndeclaredAuthority {
            action: "custom:create_payment".into()
        }));
    assert!(!has_finding(&a, |k| *k
        == FindingKind::UndeclaredAuthority {
            action: "custom:read_balance".into()
        }));
}

#[test]
fn expired_authority_is_lapsed_at_the_assessors_present() {
    let w = world();
    let mut c = ctx(&w);
    c.present_time_ms = w.token.expires_at.unwrap() + 1;
    let a = run(&declaring(&w, &["create_payment"]), &bundle(&w), &c, &[]);
    assert_eq!(
        standing(&a, P0),
        Standing::Lapsed {
            lapse: Lapse::Expired {
                valid_until_ms: w.token.expires_at.unwrap()
            }
        }
    );
    assert!(has_finding(&a, |k| *k == FindingKind::LapsedAuthority));
}

#[test]
fn authority_before_its_issuance_is_not_yet_valid() {
    let w = world();
    let mut c = ctx(&w);
    c.present_time_ms = w.token.issued_at - 1;
    let a = run(&declaring(&w, &["create_payment"]), &bundle(&w), &c, &[]);
    assert!(matches!(
        standing(&a, P0),
        Standing::Lapsed {
            lapse: Lapse::NotYetValid { .. }
        }
    ));
}

/// **A3.** Revocation comes from the assessor. A bundle cannot omit its way
/// out of one: it has no revocation field at all.
#[test]
fn revocation_is_the_assessors_and_cannot_be_omitted_by_the_bundle() {
    let w = world();
    let mut c = ctx(&w);
    c.revoked_jtis.insert(w.token.jti);
    let a = run(&declaring(&w, &["create_payment"]), &bundle(&w), &c, &[]);
    assert_eq!(
        standing(&a, P0),
        Standing::Lapsed {
            lapse: Lapse::Revoked
        }
    );
}

/// A revoked *link* revokes the chain, not only a revoked root.
#[test]
fn revoking_a_delegation_hop_revokes_the_chain() {
    let root = principal("cfo");
    let middle = principal("orchestrator");
    let (doc, _) = active_identity("treasury-agent");
    let ch = two_hop(&root, &middle, &doc.id, scope(&["create_payment"], &[]));
    let mut c = AssessorContext::trusting_nothing(ch.delegations[0].issued_at + 1);
    c.issuer_keys
        .insert(root.id.clone(), root.kp.public_key.clone());
    c.issuer_keys
        .insert(middle.id.clone(), middle.kp.public_key.clone());
    let mut m = manifest(&doc.id);
    m.permissions.allowed = vec![custom("create_payment")];
    m.relationships.delegated_from = vec![root.id.clone(), middle.id.clone()];
    let b = EvidenceBundle {
        authority: vec![ch.clone()],
        ..Default::default()
    };

    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, P0),
        Standing::Verified {
            verifier: Verifier::DelegationChain
        }
    );
    assert_eq!(
        standing(&a, "$.relationships.delegated_from[1]"),
        Standing::Verified {
            verifier: Verifier::DelegationChain
        }
    );

    c.revoked_jtis.insert(ch.delegations[0].jti);
    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, P0),
        Standing::Lapsed {
            lapse: Lapse::Revoked
        }
    );
}

/// **A5.** A forged chain offered for an action is never outvoted — not even
/// by a genuine chain granting the same action.
#[test]
fn a_forged_chain_is_rejected_and_never_outvoted() {
    let w = world();
    let mut forged = w.token.clone();
    forged.scope.allowed.push(custom("wire_transfer"));
    let b = EvidenceBundle {
        authority: vec![chain(w.token.clone()), chain(forged)],
        ..Default::default()
    };
    let a = run(
        &declaring(&w, &["create_payment", "wire_transfer"]),
        &b,
        &ctx(&w),
        &[],
    );
    assert!(matches!(
        standing(&a, P0),
        Standing::EvidenceRejected { .. }
    ));
    assert!(matches!(
        standing(&a, P1),
        Standing::EvidenceRejected { .. }
    ));
    assert!(a.findings.iter().any(|f| f.path == "bundle.authority[1]"
        && matches!(f.kind, FindingKind::EvidenceRejected { .. })));
}

/// An issuer the assessor does not anchor verifies nothing: the bundle cannot
/// supply the key it is judged by.
#[test]
fn an_unanchored_issuer_verifies_nothing() {
    let w = world();
    let c = AssessorContext::trusting_nothing(w.token.issued_at + 1);
    let a = run(&declaring(&w, &["create_payment"]), &bundle(&w), &c, &[]);
    assert!(matches!(
        standing(&a, P0),
        Standing::EvidenceRejected { .. }
    ));
}

/// An expired grant beside a live one is no evidence against the live one.
#[test]
fn one_live_grant_outranks_a_lapsed_one() {
    let w = world();
    let mut c = ctx(&w);
    let short = grant(&w.cfo, &w.agent, scope(&["create_payment"], &[]), Some(1));
    c.present_time_ms = short.expires_at.unwrap() + 10;
    let b = EvidenceBundle {
        authority: vec![chain(short), chain(w.token.clone())],
        ..Default::default()
    };
    let a = run(&declaring(&w, &["create_payment"]), &b, &c, &[]);
    assert_eq!(
        standing(&a, P0),
        Standing::Verified {
            verifier: Verifier::DelegationChain
        }
    );
}

/// Another agent's authority does not become this one's by being in the
/// bundle.
#[test]
fn another_agents_authority_is_ignored() {
    let w = world();
    let (other, _) = active_identity("someone-else");
    let theirs = grant(
        &w.cfo,
        &other.id,
        scope(&["create_payment"], &[]),
        Some(HOUR_MS),
    );
    let b = EvidenceBundle {
        authority: vec![chain(theirs)],
        ..Default::default()
    };
    let a = run(&declaring(&w, &["create_payment"]), &b, &ctx(&w), &[]);
    assert_eq!(standing(&a, P0), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::ForeignEvidence { count: 1 }));
}

#[test]
fn authority_that_never_expires_is_a_finding() {
    let w = world();
    let forever = grant(&w.cfo, &w.agent, scope(&["read_balance"], &[]), None);
    // Assessed just after *this* token's issuance. `issue_scoped_token`
    // stamps the wall clock, so `forever` is issued after `w.token`; using
    // `ctx(&w)`'s instant made the test race the clock — under load the
    // token was correctly not yet valid, and the assertion failed for a
    // mutation that touched nothing here.
    let mut c = ctx(&w);
    c.present_time_ms = forever.issued_at + 1;
    let b = EvidenceBundle {
        authority: vec![chain(forever)],
        ..Default::default()
    };
    let a = run(&declaring(&w, &["read_balance"]), &b, &c, &[]);
    assert_eq!(
        standing(&a, P0),
        Standing::Verified {
            verifier: Verifier::DelegationChain
        }
    );
    assert!(has_finding(&a, |k| *k == FindingKind::UnboundedAuthority));
}

/// The $1,000 / $5,000 story. No AIP artifact carries an amount, so the limit
/// and the approval gate rest on the author's word — and the report says so
/// instead of implying they are enforced.
#[test]
fn a_monetary_limit_and_an_approval_gate_are_never_verified() {
    let w = world();
    let mut m = declaring(&w, &["create_payment"]);
    m.permissions.limits = vec![Limit {
        action: custom("create_payment"),
        per: LimitPeriod::PerAction,
        max: usd(1000),
    }];
    m.permissions.approval_gates = vec![ApprovalGate {
        action: custom("create_payment"),
        above: usd(500),
        approver: "cfo".into(),
    }];
    let a = run(&m, &bundle(&w), &ctx(&w), &[]);
    assert_eq!(
        standing(&a, P0),
        Standing::Verified {
            verifier: Verifier::DelegationChain
        }
    );
    assert_eq!(
        standing(&a, "$.permissions.limits[0]"),
        Standing::SelfReported
    );
    assert_eq!(
        standing(&a, "$.permissions.approval_gates[0]"),
        Standing::SelfReported
    );
    assert!(has_finding(&a, |k| *k == FindingKind::LimitNotEnforceable));
    assert!(has_finding(&a, |k| *k == FindingKind::ApprovalGateNotEvidenced));
}

#[test]
fn an_undeclared_delegator_is_a_finding() {
    let w = world();
    let a = run(
        &declaring(&w, &["create_payment"]),
        &bundle(&w),
        &ctx(&w),
        &[],
    );
    assert!(has_finding(&a, |k| *k
        == FindingKind::UndeclaredDelegator {
            issuer: w.cfo.id.clone()
        }));
}

#[test]
fn onward_delegation_is_verified_from_the_hop_the_agent_issued() {
    let root = principal("cfo");
    let (agent_doc, agent_kp) = active_identity("treasury-agent");
    let agent = Principal {
        id: agent_doc.id.clone(),
        kp: agent_kp,
    };
    let (sub, _) = active_identity("sub-agent");
    let ch = two_hop(&root, &agent, &sub.id, scope(&["read_balance"], &[]));
    let mut c = AssessorContext::trusting_nothing(ch.delegations[0].issued_at + 1);
    c.issuer_keys
        .insert(root.id.clone(), root.kp.public_key.clone());
    c.issuer_keys
        .insert(agent.id.clone(), agent.kp.public_key.clone());
    let mut m = manifest(&agent.id);
    m.relationships.delegates_to = vec![sub.id.clone(), "never-delegated".into()];
    let b = EvidenceBundle {
        authority: vec![ch],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, "$.relationships.delegates_to[0]"),
        Standing::Verified {
            verifier: Verifier::DelegationChain
        }
    );
    assert_eq!(
        standing(&a, "$.relationships.delegates_to[1]"),
        Standing::SelfReported
    );
}

/// A chain is live only while **every** link is. `create_delegation` copies
/// the parent's expiry, so this hop is built and signed by hand with an
/// earlier one — which `verify_delegation_chain` accepts, because a child may
/// expire sooner than its parent and never later. Between the two expiries the
/// chain has lapsed even though its root has not.
///
/// Written for mutation AB-08, which survived the first matrix run: taking
/// the latest expiry instead of the earliest went unnoticed because no other
/// test had links that expire at different times.
#[test]
fn a_chain_lapses_at_its_earliest_link_expiry() {
    let root = principal("cfo");
    let middle = principal("orchestrator");
    let (doc, _) = active_identity("treasury-agent");
    let mut ch = two_hop(&root, &middle, &doc.id, scope(&["create_payment"], &[]));
    let root_expiry = ch.root.expires_at.unwrap();
    let hop_expiry = root_expiry - HOUR_MS / 2;
    let hop = &mut ch.delegations[0];
    hop.expires_at = Some(hop_expiry);
    hop.issuer_sig = aip_crypto::sign_ed25519(
        &middle.kp.private_key,
        &middle.id,
        &aip_core::delegation::delegation_signing_payload(hop),
    )
    .unwrap();

    let mut c = AssessorContext::trusting_nothing(hop_expiry + 1);
    c.issuer_keys
        .insert(root.id.clone(), root.kp.public_key.clone());
    c.issuer_keys
        .insert(middle.id.clone(), middle.kp.public_key.clone());
    assert!(
        c.present_time_ms < root_expiry,
        "the root must still be live for this to test anything"
    );
    let mut m = manifest(&doc.id);
    m.permissions.allowed = vec![custom("create_payment")];
    let b = EvidenceBundle {
        authority: vec![ch],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, P0),
        Standing::Lapsed {
            lapse: Lapse::Expired {
                valid_until_ms: hop_expiry
            }
        }
    );
}

/// `delegates_to` credits only a hop *this agent* issued. Here the agent
/// delegates to an intermediary, and the intermediary — not the agent —
/// delegates on to `y`. The agent never delegated to `y`, so the declaration
/// rests on the author's word.
///
/// Written for mutation AB-16, which survived the first matrix run: crediting
/// any hop whose grantee is `y`, whoever issued it, went unnoticed.
#[test]
fn onward_delegation_by_someone_else_is_not_the_agents() {
    let root = principal("cfo");
    let (agent_doc, agent_kp) = active_identity("treasury-agent");
    let agent = Principal {
        id: agent_doc.id.clone(),
        kp: agent_kp,
    };
    let middle = principal("intermediary");
    let (y, _) = active_identity("downstream");
    let mut ch = two_hop(&root, &agent, &middle.id, scope(&["read_balance"], &[]));
    let hop2 = aip_core::delegation::create_sub_delegation(
        &ch.delegations[0],
        &middle.kp.private_key,
        &y.id,
        scope(&["read_balance"], &[]),
    )
    .unwrap();
    ch.delegations.push(hop2);

    let mut c = AssessorContext::trusting_nothing(ch.delegations[1].issued_at + 1);
    for p in [&root, &agent, &middle] {
        c.issuer_keys.insert(p.id.clone(), p.kp.public_key.clone());
    }
    let mut m = manifest(&agent.id);
    m.relationships.delegates_to = vec![middle.id.clone(), y.id.clone()];
    let b = EvidenceBundle {
        authority: vec![ch],
        ..Default::default()
    };
    let a = run(&m, &b, &c, &[]);
    assert_eq!(
        standing(&a, "$.relationships.delegates_to[0]"),
        Standing::Verified {
            verifier: Verifier::DelegationChain
        }
    );
    assert_eq!(
        standing(&a, "$.relationships.delegates_to[1]"),
        Standing::SelfReported
    );
}
