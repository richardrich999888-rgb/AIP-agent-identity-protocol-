#![cfg(feature = "p2p")]

use aip_core::{capability::issue_scoped_token, delegation::create_delegation};
use aip_crypto::{
    custody::{Custodian, InMemoryCustodian},
    generate_ed25519_keypair, sha256,
};
use aip_distribution::authorization::{
    authorize_package_operation, package_resource_action, AuthorizationError, PackageOperation,
    PackageResource,
};
use aip_distribution::revocation_snapshot::{
    verify_revocation_snapshot, RevocationAuthorityAnchor, RevocationSnapshot, RevokedCapability,
    VerifiedRevocationSnapshot,
};
use aip_types::{CapabilityScope, RevocationReason, ScopeAction};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn verified_revocations(entries: Vec<RevokedCapability>) -> VerifiedRevocationSnapshot {
    let now = now_ms();
    let issued_at = now.saturating_sub(10_000);
    let mut entries = entries;
    for entry in &mut entries {
        entry.revoked_at_ms = entry.revoked_at_ms.min(issued_at);
    }
    let signer = InMemoryCustodian::generate();
    let issuer = "aip:revocation-authority";
    let audience = "/aip/distribution/1.0.0";
    let snapshot = RevocationSnapshot::sign(
        issuer,
        1,
        issued_at,
        now + 5_000,
        audience,
        entries,
        &signer,
    )
    .unwrap();
    let anchor = RevocationAuthorityAnchor::new(
        issuer.into(),
        signer.public_key().to_vec(),
        1,
        audience.into(),
        60_000,
        60_000,
    )
    .unwrap();
    verify_revocation_snapshot(&snapshot, Some(&anchor), None, audience, now).unwrap()
}

fn resource() -> PackageResource {
    PackageResource {
        package_id: "com.example.model".into(),
        publisher_id: "aip:publisher".into(),
        release_digest: sha256(b"release-1"),
        recipient_id: "aip:receiver".into(),
    }
}

fn scope_for(operation: PackageOperation, resource: &PackageResource) -> CapabilityScope {
    CapabilityScope {
        allowed: vec![ScopeAction::Custom(package_resource_action(
            operation, resource,
        ))],
        denied: vec![],
    }
}

fn token_fixture(
    operation: PackageOperation,
    resource: &PackageResource,
) -> (aip_types::ScopedToken, HashMap<String, Vec<u8>>) {
    let issuer = generate_ed25519_keypair();
    let subject_key = generate_ed25519_keypair();
    let issuer_id = "aip:capability-issuer";
    let subject_id = "aip:receiver";
    let token = issue_scoped_token(
        issuer_id,
        &issuer.private_key,
        subject_id,
        scope_for(operation, resource),
        Some(60_000),
    )
    .unwrap();
    let mut keys = HashMap::new();
    keys.insert(issuer_id.into(), issuer.public_key);
    keys.insert(subject_id.into(), subject_key.public_key);
    (token, keys)
}

fn authorize(
    operation: PackageOperation,
    resource: &PackageResource,
    token: &aip_types::ScopedToken,
    keys: &HashMap<String, Vec<u8>>,
    revocations: &VerifiedRevocationSnapshot,
) -> Result<(), AuthorizationError> {
    authorize_package_operation(
        operation,
        resource,
        "aip:receiver",
        token,
        &[],
        keys,
        revocations,
        now_ms(),
    )
    .map(|_| ())
}

#[test]
fn exact_package_operation_resource_is_authorized() {
    let resource = resource();
    let operation = PackageOperation::Receive;
    let (token, keys) = token_fixture(operation, &resource);
    let revocations = verified_revocations(vec![]);
    assert!(authorize(operation, &resource, &token, &keys, &revocations).is_ok());
}

#[test]
fn serving_peer_resume_permission_is_separate_from_receiver_resume() {
    let resource = resource();
    let issuer = generate_ed25519_keypair();
    let issuer_id = "aip:capability-issuer";
    let server_id = "aip:server";
    let token = issue_scoped_token(
        issuer_id,
        &issuer.private_key,
        server_id,
        scope_for(PackageOperation::ServeResume, &resource),
        Some(60_000),
    )
    .unwrap();
    let keys = HashMap::from([(issuer_id.into(), issuer.public_key)]);
    let revocations = verified_revocations(vec![]);
    assert!(authorize_package_operation(
        PackageOperation::ServeResume,
        &resource,
        server_id,
        &token,
        &[],
        &keys,
        &revocations,
        now_ms(),
    )
    .is_ok());
    assert!(authorize_package_operation(
        PackageOperation::Resume,
        &resource,
        server_id,
        &token,
        &[],
        &keys,
        &revocations,
        now_ms(),
    )
    .is_err());
}

#[test]
fn broad_read_scope_does_not_grant_package_operation() {
    let resource = resource();
    let issuer = generate_ed25519_keypair();
    let token = issue_scoped_token(
        "aip:capability-issuer",
        &issuer.private_key,
        "aip:receiver",
        CapabilityScope {
            allowed: vec![ScopeAction::Standard(aip_types::Action::Read)],
            denied: vec![],
        },
        Some(60_000),
    )
    .unwrap();
    let keys = HashMap::from([("aip:capability-issuer".into(), issuer.public_key)]);
    assert!(authorize(
        PackageOperation::Receive,
        &resource,
        &token,
        &keys,
        &verified_revocations(vec![])
    )
    .is_err());
}

#[test]
fn changed_resource_or_operation_is_denied() {
    let resource = resource();
    let (token, keys) = token_fixture(PackageOperation::Receive, &resource);
    let revocations = verified_revocations(vec![]);
    let mut other = resource.clone();
    other.release_digest = sha256(b"release-2");
    assert!(authorize(
        PackageOperation::Receive,
        &other,
        &token,
        &keys,
        &revocations
    )
    .is_err());
    assert!(authorize(
        PackageOperation::Install,
        &resource,
        &token,
        &keys,
        &revocations
    )
    .is_err());
}

#[test]
fn recipient_must_match_authenticated_receiver() {
    let mut resource = resource();
    resource.recipient_id = "aip:someone-else".into();
    let (token, keys) = token_fixture(PackageOperation::Receive, &resource);
    assert!(authorize(
        PackageOperation::Receive,
        &resource,
        &token,
        &keys,
        &verified_revocations(vec![])
    )
    .is_err());
}

#[test]
fn expired_capability_is_denied_before_use() {
    let resource = resource();
    let (mut token, keys) = token_fixture(PackageOperation::Receive, &resource);
    token.expires_at = Some(1);
    assert!(authorize(
        PackageOperation::Receive,
        &resource,
        &token,
        &keys,
        &verified_revocations(vec![])
    )
    .is_err());
}

#[test]
fn verified_revocation_snapshot_is_required_and_stale_snapshot_is_rejected() {
    let resource = resource();
    let (token, keys) = token_fixture(PackageOperation::Receive, &resource);
    assert!(authorize(
        PackageOperation::Receive,
        &resource,
        &token,
        &keys,
        &verified_revocations(vec![])
    )
    .is_ok());
    let snapshot = verified_revocations(vec![]);
    assert!(snapshot.ensure_fresh("/wrong", now_ms()).is_err());
    assert!(snapshot
        .ensure_fresh("/aip/distribution/1.0.0", now_ms() + 60_001)
        .is_err());
}

#[test]
fn revoked_token_is_rejected() {
    let resource = resource();
    let (token, keys) = token_fixture(PackageOperation::Receive, &resource);
    let revocations = verified_revocations(vec![RevokedCapability {
        jti: token.jti,
        revoked_at_ms: now_ms(),
        reason: RevocationReason::AdminRevocation,
        revoked_by: "aip:admin".into(),
    }]);
    assert!(authorize(
        PackageOperation::Receive,
        &resource,
        &token,
        &keys,
        &revocations
    )
    .is_err());
}

#[test]
fn delegated_exact_resource_scope_is_enforced_for_final_holder() {
    let resource = resource();
    let root_issuer = generate_ed25519_keypair();
    let grantor = generate_ed25519_keypair();
    let root_issuer_id = "aip:root-issuer";
    let grantor_id = "aip:grantor";
    let receiver_id = "aip:receiver";
    let scope = scope_for(PackageOperation::Receive, &resource);
    let root = issue_scoped_token(
        root_issuer_id,
        &root_issuer.private_key,
        grantor_id,
        scope.clone(),
        Some(60_000),
    )
    .unwrap();
    let hop = create_delegation(&root, &grantor.private_key, receiver_id, scope).unwrap();
    let keys = HashMap::from([
        (root_issuer_id.into(), root_issuer.public_key),
        (grantor_id.into(), grantor.public_key),
    ]);
    let allowed = authorize_package_operation(
        PackageOperation::Receive,
        &resource,
        receiver_id,
        &root,
        &[hop.clone()],
        &keys,
        &verified_revocations(vec![]),
        now_ms(),
    );
    assert!(allowed.is_ok());
    let wrong_subject = authorize_package_operation(
        PackageOperation::Receive,
        &resource,
        grantor_id,
        &root,
        &[hop],
        &keys,
        &verified_revocations(vec![]),
        now_ms(),
    );
    assert!(wrong_subject.is_err());
}

#[test]
fn revoked_delegation_is_denied() {
    let resource = resource();
    let root_issuer = generate_ed25519_keypair();
    let grantor = generate_ed25519_keypair();
    let root_issuer_id = "aip:root-issuer";
    let grantor_id = "aip:grantor";
    let receiver_id = "aip:receiver";
    let root = issue_scoped_token(
        root_issuer_id,
        &root_issuer.private_key,
        grantor_id,
        scope_for(PackageOperation::Receive, &resource),
        Some(60_000),
    )
    .unwrap();
    let hop = create_delegation(
        &root,
        &grantor.private_key,
        receiver_id,
        scope_for(PackageOperation::Receive, &resource),
    )
    .unwrap();
    let keys = HashMap::from([
        (root_issuer_id.into(), root_issuer.public_key),
        (grantor_id.into(), grantor.public_key),
    ]);
    let revocations = verified_revocations(vec![RevokedCapability {
        jti: hop.jti,
        revoked_at_ms: now_ms(),
        reason: RevocationReason::AdminRevocation,
        revoked_by: "aip:admin".into(),
    }]);
    assert!(authorize_package_operation(
        PackageOperation::Receive,
        &resource,
        receiver_id,
        &root,
        &[hop],
        &keys,
        &revocations,
        now_ms(),
    )
    .is_err());
}

#[test]
fn package_action_encoding_is_bounded_and_deterministic() {
    let resource = resource();
    let a = package_resource_action(PackageOperation::Serve, &resource);
    assert_eq!(
        a,
        package_resource_action(PackageOperation::Serve, &resource)
    );
    assert!(a.len() <= 64);
    assert_ne!(
        a,
        package_resource_action(PackageOperation::Receive, &resource)
    );
}
