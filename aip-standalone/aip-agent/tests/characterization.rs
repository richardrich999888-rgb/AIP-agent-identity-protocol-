//! Phase B characterization — what the existing identity primitives do
//! today. These tests compile against `aip-core` alone and **pin** the
//! weaknesses that Phase B must work around rather than trust. They are not
//! expected to change when Phase B goes green; if one of them flips, the
//! upstream primitive changed and the profile's labelling must be revisited.

use aip_core::{
    activate_identity, create_identity, suspend_identity, validate_aid, validate_aid_with_parent,
};
use aip_crypto::sha256;
use aip_types::{AipError, IdentityStatus, ProvenanceTriple};

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

/// c01 — the lifecycle state machine has no authority: anyone holding the
/// document can flip `status`, and because `status` and `sequence` are inside
/// the self-signed bytes the document then fails its own validation. There is
/// no signer for a lifecycle transition anywhere in the repository.
#[test]
fn c01_lifecycle_mutation_has_no_signer_and_breaks_the_self_signature() {
    let (mut aid, _kp) = create_identity(provenance("agent"), None).unwrap();
    assert_eq!(aid.status, IdentityStatus::Pending);
    assert!(validate_aid(&aid).is_ok(), "a fresh document validates");

    activate_identity(&mut aid).unwrap();
    assert_eq!(aid.status, IdentityStatus::Active);
    assert_eq!(
        validate_aid(&aid),
        Err(AipError::SignatureInvalid),
        "activation is an unsigned in-place mutation; the self-signature no longer covers the bytes"
    );

    // The same holds for every other transition.
    suspend_identity(&mut aid).unwrap();
    assert_eq!(validate_aid(&aid), Err(AipError::SignatureInvalid));
}

/// c02 — `lineage_depth` does not chain: a grandchild created from a child
/// carries the same depth as the child. Ancestry beyond one generation must
/// be rebuilt from lineage proofs, never read from the depth field.
#[test]
fn c02_lineage_depth_does_not_chain_past_one_generation() {
    let (root, root_kp) = create_identity(provenance("root"), None).unwrap();
    let (child, child_kp) =
        create_identity(provenance("child"), Some((&root.id, &root_kp.private_key))).unwrap();
    let (grandchild, _) =
        create_identity(provenance("grandchild"), Some((&child.id, &child_kp.private_key)))
            .unwrap();

    assert_eq!(root.lineage_depth, 0);
    assert_eq!(child.lineage_depth, 1);
    assert_eq!(
        grandchild.lineage_depth, 1,
        "depth is fixed at 1 for any parented identity; it is not parent.depth + 1"
    );

    // The proofs, by contrast, do chain: each one is verifiable against the
    // key of the identity that signed it and against nothing else.
    assert!(validate_aid_with_parent(&child, &root.id, &root_kp.public_key).is_ok());
    assert!(validate_aid_with_parent(&grandchild, &child.id, &child_kp.public_key).is_ok());
    assert_eq!(
        validate_aid_with_parent(&grandchild, &root.id, &root_kp.public_key),
        Err(AipError::LineageInvalid),
        "the grandparent did not sign the grandchild"
    );
}

/// c03 — a lineage proof names the parent *key holder* who endorsed the
/// child's key at creation. It says nothing about which process created
/// which, and it is the only identity-level endorsement by any party other
/// than the agent itself. The root document has no issuer at all.
#[test]
fn c03_the_only_external_identity_endorsement_is_the_parent_lineage_proof() {
    let (root, _) = create_identity(provenance("root"), None).unwrap();
    assert!(root.lineage_proof.is_none());
    assert_eq!(
        root.self_signature.as_ref().map(|s| s.signer_id.as_str()),
        Some(root.id.as_str()),
        "the only signature on a root document is the agent's own"
    );
}
