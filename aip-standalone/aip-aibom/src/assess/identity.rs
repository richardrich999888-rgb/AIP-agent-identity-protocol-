//! C1 — agent identity, and C8's identity lineage.

use super::{Inputs, Sheet};
use crate::finding::FindingKind;
use crate::model::Component;
use crate::standing::{combine, Lapse, Standing, Verifier};
use aip_types::{AgentIdentityDocument, IdentityStatus};

/// Assess the identity fields. Returns the identity document when it is
/// genuinely this agent's — validated by `aip_core::validate_aid` and naming
/// the declared id — for the components that read its key.
pub(super) fn run<'a>(i: &Inputs<'a>, sheet: &mut Sheet) -> Option<&'a AgentIdentityDocument> {
    let declared = &i.manifest.agent.id;
    let (standing, doc) = identity_standing(i, declared);
    if matches!(standing, Standing::SelfReported) {
        let kind = if aip_crypto::validate_aip_id(declared).is_ok() {
            FindingKind::NoIdentityEvidence
        } else {
            FindingKind::NotACryptographicIdentity
        };
        sheet.finding(Component::Identity, "$.agent.id", kind);
    }
    if doc.is_some_and(|d| d.expires_at.is_some()) {
        sheet.finding(
            Component::Identity,
            "bundle.identity",
            FindingKind::UnsignedIdentityExpiry,
        );
    }
    sheet.field(Component::Identity, "$.agent.id", standing);
    for field in ["name", "owner", "version", "deployment"] {
        sheet.field(
            Component::Identity,
            format!("$.agent.{field}"),
            Standing::SelfReported,
        );
    }
    lineage(i, doc, sheet);
    doc
}

fn identity_standing<'a>(
    i: &Inputs<'a>,
    declared: &str,
) -> (Standing, Option<&'a AgentIdentityDocument>) {
    let Some(doc) = i.bundle.identity.as_ref() else {
        return (Standing::SelfReported, None);
    };
    if let Err(e) = aip_core::validate_aid(doc) {
        return (
            Standing::EvidenceRejected {
                reason: format!("identity document refused by validate_aid: {e:?}"),
            },
            None,
        );
    }
    if doc.id != declared {
        return (
            Standing::Contradicted {
                reason:
                    "the identity document offered for this agent derives to a different AIP-ID"
                        .into(),
            },
            None,
        );
    }
    (lapse_of(doc), Some(doc))
}

/// A valid document is still not live if its signed lifecycle status says
/// otherwise.
///
/// `expires_at` is **not** read. It is outside the bytes the self-signature
/// covers (`aip_core::identity_signing_payload`), so anyone holding the
/// document can extend or delete it. Relying on it would let an unsigned
/// number decide liveness; its presence is reported as a finding instead.
fn lapse_of(doc: &AgentIdentityDocument) -> Standing {
    if doc.status != IdentityStatus::Active {
        return Standing::Lapsed {
            lapse: Lapse::IdentityNotActive {
                status: format!("{:?}", doc.status),
            },
        };
    }
    Standing::Verified {
        verifier: Verifier::IdentityDocument,
    }
}

/// C8 `parent_agent`: verified only through `validate_aid_with_parent`, with
/// the parent's key taken from a parent document that itself validates.
fn lineage(i: &Inputs<'_>, doc: Option<&AgentIdentityDocument>, sheet: &mut Sheet) {
    let Some(parent_id) = &i.manifest.relationships.parent_agent else {
        return;
    };
    let path = "$.relationships.parent_agent";
    let standing = match (doc, i.bundle.parent_identity.as_ref()) {
        (Some(child), Some(parent)) if &parent.id == parent_id => {
            let parent_ok = aip_core::validate_aid(parent);
            let link =
                aip_core::validate_aid_with_parent(child, parent_id, &parent.primary_key.key_bytes);
            combine([match (parent_ok, link) {
                (Ok(()), Ok(())) => Standing::Verified {
                    verifier: Verifier::IdentityLineage,
                },
                (Err(e), _) | (_, Err(e)) => Standing::EvidenceRejected {
                    reason: format!("identity lineage refused: {e:?}"),
                },
            }])
        }
        _ => Standing::SelfReported,
    };
    sheet.field(Component::Relationships, path, standing);
}
