//! C1 identity, C8 lineage and C10 identity-key algorithm.

mod common;

use aip_aibom::evidence::{AssessorContext, EvidenceBundle};
use aip_aibom::finding::FindingKind;
use aip_aibom::standing::{Lapse, Standing, Verifier};
use aip_types::AlgorithmId;
use common::*;

const ID: &str = "$.agent.id";

fn ctx() -> AssessorContext {
    AssessorContext::trusting_nothing(1_000)
}

fn with_identity(doc: aip_types::AgentIdentityDocument) -> EvidenceBundle {
    EvidenceBundle {
        identity: Some(doc),
        ..Default::default()
    }
}

#[test]
fn a_validated_active_identity_is_verified() {
    let (doc, _) = active_identity("treasury-agent");
    let a = run(&manifest(&doc.id), &with_identity(doc), &ctx(), &[]);
    assert_eq!(
        standing(&a, ID),
        Standing::Verified {
            verifier: Verifier::IdentityDocument
        }
    );
    assert!(!has_finding(&a, |k| *k == FindingKind::NoIdentityEvidence));
}

#[test]
fn an_aip_id_with_no_document_is_self_reported_and_flagged() {
    let (doc, _) = active_identity("treasury-agent");
    let a = run(&manifest(&doc.id), &EvidenceBundle::default(), &ctx(), &[]);
    assert_eq!(standing(&a, ID), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::NoIdentityEvidence));
}

/// The product assesses agents that have no AIP identity yet — and says so.
#[test]
fn a_non_cryptographic_identifier_is_named_as_such() {
    let a = run(
        &manifest("agent-payment-001"),
        &EvidenceBundle::default(),
        &ctx(),
        &[],
    );
    assert_eq!(standing(&a, ID), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::NotACryptographicIdentity));
}

#[test]
fn a_valid_document_for_a_different_agent_is_a_contradiction() {
    let (mine, _) = active_identity("treasury-agent");
    let (theirs, _) = active_identity("someone-else");
    let a = run(&manifest(&mine.id), &with_identity(theirs), &ctx(), &[]);
    assert!(matches!(standing(&a, ID), Standing::Contradicted { .. }));
}

#[test]
fn a_tampered_document_is_rejected() {
    let (mut doc, _) = active_identity("treasury-agent");
    doc.sequence += 1;
    let id = doc.id.clone();
    let a = run(&manifest(&id), &with_identity(doc), &ctx(), &[]);
    assert!(matches!(
        standing(&a, ID),
        Standing::EvidenceRejected { .. }
    ));
    assert!(a.has_critical());
}

/// An unsigned document is refused by the core itself
/// (`MissingRequiredField`), and the assessor reports the core's refusal
/// rather than adding a check of its own.
#[test]
fn an_unsigned_document_is_rejected_by_the_core() {
    let (mut doc, _) = active_identity("treasury-agent");
    doc.self_signature = None;
    assert!(aip_core::validate_aid(&doc).is_err());
    let id = doc.id.clone();
    let a = run(&manifest(&id), &with_identity(doc), &ctx(), &[]);
    assert!(matches!(
        standing(&a, ID),
        Standing::EvidenceRejected { .. }
    ));
}

#[test]
fn a_pending_identity_is_not_live() {
    let (doc, _) = aip_core::create_identity(provenance("treasury-agent"), None).unwrap();
    let id = doc.id.clone();
    let a = run(&manifest(&id), &with_identity(doc), &ctx(), &[]);
    assert_eq!(
        standing(&a, ID),
        Standing::Lapsed {
            lapse: Lapse::IdentityNotActive {
                status: "Pending".into()
            }
        }
    );
}

/// `expires_at` is outside the self-signed bytes. Setting it — to the past or
/// the future — changes nothing the assessor relies on, and is reported.
#[test]
fn an_unsigned_identity_expiry_is_reported_and_not_relied_on() {
    let (mut doc, kp) = active_identity("treasury-agent");
    doc.expires_at = Some(1);
    assert!(
        aip_core::validate_aid(&doc).is_ok(),
        "expiry is not covered by the self-signature"
    );
    let _ = kp;
    let id = doc.id.clone();
    let a = run(
        &manifest(&id),
        &with_identity(doc),
        &AssessorContext::trusting_nothing(10_000),
        &[],
    );
    assert_eq!(
        standing(&a, ID),
        Standing::Verified {
            verifier: Verifier::IdentityDocument
        }
    );
    assert!(has_finding(&a, |k| *k == FindingKind::UnsignedIdentityExpiry));
}

#[test]
fn the_identity_key_algorithm_is_checked_against_the_validated_document() {
    let (doc, _) = active_identity("treasury-agent");
    let mut m = manifest(&doc.id);
    m.crypto.identity_key_algorithm = Some(AlgorithmId::Ed25519);
    let a = run(&m, &with_identity(doc.clone()), &ctx(), &[]);
    assert_eq!(
        standing(&a, "$.crypto.identity_key_algorithm"),
        Standing::Verified {
            verifier: Verifier::IdentityDocument
        }
    );

    m.crypto.identity_key_algorithm = Some(AlgorithmId::MlDsa65);
    let a = run(&m, &with_identity(doc), &ctx(), &[]);
    assert!(matches!(
        standing(&a, "$.crypto.identity_key_algorithm"),
        Standing::Contradicted { .. }
    ));
}

#[test]
fn identity_lineage_is_verified_through_the_parents_key() {
    let (mut parent, parent_kp) = active_identity("orchestrator");
    let (mut child, child_kp) = aip_core::create_identity(
        provenance("treasury-agent"),
        Some((&parent.id, &parent_kp.private_key)),
    )
    .unwrap();
    aip_core::activate_identity(&mut child).unwrap();
    resign(&mut child, &child_kp);
    resign(&mut parent, &parent_kp);
    let mut m = manifest(&child.id);
    m.relationships.parent_agent = Some(parent.id.clone());
    let b = EvidenceBundle {
        identity: Some(child.clone()),
        parent_identity: Some(parent.clone()),
        ..Default::default()
    };
    let a = run(&m, &b, &ctx(), &[]);
    assert_eq!(
        standing(&a, "$.relationships.parent_agent"),
        Standing::Verified {
            verifier: Verifier::IdentityLineage
        }
    );

    let (impostor, _) = active_identity("impostor-parent");
    let mut forged_parent = impostor.clone();
    forged_parent.id = parent.id.clone();
    let b = EvidenceBundle {
        identity: Some(child),
        parent_identity: Some(forged_parent),
        ..Default::default()
    };
    let a = run(&m, &b, &ctx(), &[]);
    assert!(matches!(
        standing(&a, "$.relationships.parent_agent"),
        Standing::EvidenceRejected { .. }
    ));
}
