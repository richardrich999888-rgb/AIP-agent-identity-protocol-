// Composition tests live in `aip-package-cli`, which owns the AIBOM dependency.
// Retained here without compiling so this crate cannot reverse the AIBOM layering.
#![cfg(any())]

use aip_aibom::{
    canonical::manifest_digest_hex,
    model::{
        AgentIdentity, CryptoPosture, Environment, Governance, Manifest, NetworkPosture,
        Permissions, Relationships, RuntimeKind, Validity, AIBOM_SCHEMA_VERSION,
    },
    seal::Publisher as AibomPublisher,
};
use aip_core::{capability::issue_scoped_token, create_identity, identity_signing_payload};
use aip_crypto::{
    custody::{Custodian, InMemoryCustodian},
    generate_ed25519_keypair, sha256, sign_ed25519,
};
use aip_distribution::{
    authorization::{package_resource_action, PackageOperation, PackageResource},
    create_manifest,
    offline_verify::{
        verify_offline_package_evidence, OfflinePackageEvidence, OfflinePackageTrust,
        OfflineTransferEvidence,
    },
    peer_binding::{
        PeerBindingIssuerAnchor, PeerBindingStatement, PeerBindingTrustAnchors, PeerIdentityStatus,
        PeerStatusAuthorityAnchor, PeerStatusCheckpoint, PeerStatusSnapshot,
    },
    revocation_snapshot::{RevocationAuthorityAnchor, RevocationSnapshot, SnapshotCheckpoint},
};
use aip_package::{build_package, export_package, sign_package, PackageFile};
use aip_types::{CapabilityScope, IdentityStatus, ProvenanceTriple, ScopeAction};
use libp2p::identity;
use std::collections::{BTreeMap, BTreeSet, HashMap};

struct Fixture {
    export_bytes: Vec<u8>,
    aibom: Manifest,
    aibom_seal: aip_aibom::seal::Seal,
    aid: aip_types::AgentIdentityDocument,
    binding: PeerBindingStatement,
    status: PeerStatusSnapshot,
    capability: aip_types::ScopedToken,
    revocations: RevocationSnapshot,
    package_custodian: InMemoryCustodian,
    package_public_key: Vec<u8>,
    aibom_anchors: BTreeMap<String, Vec<u8>>,
    binding_anchors: PeerBindingTrustAnchors,
    capability_issuer_keys: HashMap<String, Vec<u8>>,
    revocation_anchor: RevocationAuthorityAnchor,
    revocation_checkpoint: SnapshotCheckpoint,
    revocation_signer: InMemoryCustodian,
    now: u64,
}

fn valid_aibom() -> Manifest {
    Manifest {
        schema_version: AIBOM_SCHEMA_VERSION,
        validity: Validity {
            issued_at_ms: 1,
            valid_until_ms: Some(u64::MAX - 1),
        },
        agent: AgentIdentity {
            id: "aip:offline-agent".into(),
            name: "Offline Agent".into(),
            owner: "security-team".into(),
            version: "1.0.0".into(),
            deployment: "test".into(),
        },
        models: vec![],
        frameworks: vec![],
        tools: vec![],
        permissions: Permissions::default(),
        data_access: vec![],
        environment: Environment {
            runtime: RuntimeKind::Container,
            network: NetworkPosture::Restricted,
            binary: None,
        },
        relationships: Relationships::default(),
        security_controls: vec![],
        crypto: CryptoPosture::default(),
        supply_chain: vec![],
        governance: Governance::default(),
    }
}

fn fixture() -> Fixture {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let aibom = valid_aibom();
    let aibom_key = generate_ed25519_keypair();
    let aibom_publisher = AibomPublisher::new(
        "aip:aibom-authority",
        &aibom_key.private_key,
        &aibom_key.public_key,
    )
    .unwrap();
    let aibom_seal = aibom_publisher.seal(&aibom, now).unwrap();
    let aibom_anchors = BTreeMap::from([("aip:aibom-authority".into(), aibom_key.public_key)]);
    let aibom_digest = manifest_digest_hex(&aibom);

    let package_key = generate_ed25519_keypair();
    let package_custodian =
        InMemoryCustodian::new(&package_key.private_key, &package_key.public_key).unwrap();
    let package = build_package(
        "offline-engine",
        "1.2.3",
        "aip:package-publisher",
        &aibom_digest,
        vec![PackageFile {
            path: "model.bin".into(),
            contents: b"signed model payload".to_vec(),
        }],
    )
    .unwrap();
    let package_signature = sign_package(&package, &package_custodian).unwrap();
    let portable = export_package(&package, &package_signature).unwrap();
    let export_bytes = serde_json::to_vec(&portable).unwrap();

    let provenance = ProvenanceTriple {
        model_commitment: sha256(b"model"),
        environment_commitment: sha256(b"environment"),
        toolchain_commitment: sha256(b"toolchain"),
    };
    let (mut aid, aid_key) = create_identity(provenance, None).unwrap();
    aid.status = IdentityStatus::Active;
    aid.sequence = 1;
    aid.self_signature = Some(
        sign_ed25519(
            &aid_key.private_key,
            &aid.id,
            &identity_signing_payload(&aid),
        )
        .unwrap(),
    );

    let binding_issuer = InMemoryCustodian::generate();
    let status_issuer = InMemoryCustodian::generate();
    let peer_key = identity::Keypair::generate_ed25519();
    let binding = PeerBindingStatement::sign(
        &aid,
        peer_key.public().encode_protobuf(),
        "aip:binding-issuer",
        now - 10,
        now + 20_000,
        1,
        5,
        "/aip/distribution/1.0.0",
        &binding_issuer,
    )
    .unwrap();
    let status = PeerStatusSnapshot::sign(
        "aip:status-issuer",
        5,
        now - 10,
        now + 10_000,
        "/aip/distribution/1.0.0",
        BTreeMap::from([(
            aid.id.clone(),
            PeerIdentityStatus {
                status: IdentityStatus::Active,
                aid_sequence: aid.sequence,
                binding_sequence: binding.sequence,
                binding_digest: binding.statement_digest().unwrap(),
            },
        )]),
        &status_issuer,
    )
    .unwrap();
    let binding_anchors = PeerBindingTrustAnchors::new(
        BTreeMap::from([(
            "aip:binding-issuer".into(),
            PeerBindingIssuerAnchor::new(
                binding_issuer.public_key().to_vec(),
                BTreeSet::from([aid.id.clone()]),
            )
            .unwrap(),
        )]),
        BTreeMap::from([(
            "aip:status-issuer".into(),
            PeerStatusAuthorityAnchor::with_checkpoint(
                status_issuer.public_key().to_vec(),
                PeerStatusCheckpoint {
                    epoch: status.epoch,
                    digest: status.digest().unwrap(),
                },
            )
            .unwrap(),
        )]),
        30_000,
        30_000,
    )
    .unwrap();

    let resource = PackageResource {
        package_id: "offline-engine".into(),
        publisher_id: "aip:package-publisher".into(),
        release_digest: package.archive_sha256,
        recipient_id: aid.id.clone(),
    };
    let capability_key = generate_ed25519_keypair();
    let capability = issue_scoped_token(
        "aip:capability-issuer",
        &capability_key.private_key,
        &aid.id,
        CapabilityScope {
            allowed: vec![ScopeAction::Custom(package_resource_action(
                PackageOperation::Receive,
                &resource,
            ))],
            denied: vec![],
        },
        Some(60_000),
    )
    .unwrap();
    let capability_issuer_keys =
        HashMap::from([("aip:capability-issuer".into(), capability_key.public_key)]);

    let revocation_issuer = InMemoryCustodian::generate();
    let revocations = RevocationSnapshot::sign(
        "aip:revocation-authority",
        7,
        now - 100,
        now + 10_000,
        "/aip/distribution/1.0.0",
        vec![],
        &revocation_issuer,
    )
    .unwrap();
    let revocation_checkpoint = SnapshotCheckpoint::new(7, revocations.digest().unwrap()).unwrap();
    let revocation_anchor = RevocationAuthorityAnchor::new(
        "aip:revocation-authority".into(),
        revocation_issuer.public_key().to_vec(),
        7,
        "/aip/distribution/1.0.0".into(),
        30_000,
        30_000,
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    Fixture {
        export_bytes,
        aibom,
        aibom_seal,
        aid,
        binding,
        status,
        capability,
        revocations,
        package_custodian,
        package_public_key: package_key.public_key,
        aibom_anchors,
        binding_anchors,
        capability_issuer_keys,
        revocation_anchor,
        revocation_checkpoint,
        revocation_signer: revocation_issuer,
        now,
    }
}

fn verify(
    f: &Fixture,
    transfer: Option<OfflineTransferEvidence<'_>>,
) -> Result<
    aip_distribution::offline_verify::OfflinePackageVerificationReport,
    aip_distribution::offline_verify::OfflineVerifyError,
> {
    verify_with_snapshot(f, &f.revocations, transfer)
}

fn verify_with_snapshot(
    f: &Fixture,
    snapshot: &RevocationSnapshot,
    transfer: Option<OfflineTransferEvidence<'_>>,
) -> Result<
    aip_distribution::offline_verify::OfflinePackageVerificationReport,
    aip_distribution::offline_verify::OfflineVerifyError,
> {
    verify_offline_package_evidence(
        &OfflinePackageEvidence {
            export_bytes: &f.export_bytes,
            aibom_manifest: &f.aibom,
            aibom_seal: &f.aibom_seal,
            aid: &f.aid,
            peer_binding: &f.binding,
            peer_status: &f.status,
            capability: &f.capability,
            delegation_chain: &[],
            revocation_snapshot: snapshot,
            transfer,
        },
        &OfflinePackageTrust {
            publisher_id: "aip:package-publisher",
            publisher_public_key: &f.package_public_key,
            aibom_publishers: &f.aibom_anchors,
            peer_binding_anchors: &f.binding_anchors,
            capability_issuer_keys: &f.capability_issuer_keys,
            revocation_authority: Some(&f.revocation_anchor),
            revocation_checkpoint: &f.revocation_checkpoint,
            expected_audience: "/aip/distribution/1.0.0",
            recipient_id: &f.aid.id,
            operation: PackageOperation::Receive,
            now_ms: f.now,
        },
    )
}

#[test]
fn offline_package_binding_authorization_and_revocation_verify_without_execution_claim() {
    let f = fixture();
    let report = verify(&f, None).unwrap();
    assert_eq!(report.status, "INPUTS_VERIFIED");
    assert_eq!(report.execution_status, "NOT_EVALUATED");
    assert!(report.publisher_signature_verified);
    assert!(report.aibom_seal_verified);
    assert!(report.peer_binding_verified);
    assert!(report.capability_authorized);
    assert!(!report.transfer_evidence_verified);
}

#[test]
fn optional_transfer_proofs_are_checked_against_exact_export_bytes() {
    let f = fixture();
    let (manifest, chunks) = create_manifest(&f.export_bytes, &f.package_custodian).unwrap();
    let report = verify(
        &f,
        Some(OfflineTransferEvidence {
            manifest: &manifest,
            chunks: &chunks,
        }),
    )
    .unwrap();
    assert!(report.transfer_evidence_verified);
    let mut tampered = chunks;
    tampered[0].bytes[0] ^= 1;
    assert!(verify(
        &f,
        Some(OfflineTransferEvidence {
            manifest: &manifest,
            chunks: &tampered
        })
    )
    .is_err());
}

#[test]
fn offline_verifier_fails_closed_on_missing_revocation_anchor_or_revoked_capability() {
    let f = fixture();
    let missing = OfflinePackageEvidence {
        export_bytes: &f.export_bytes,
        aibom_manifest: &f.aibom,
        aibom_seal: &f.aibom_seal,
        aid: &f.aid,
        peer_binding: &f.binding,
        peer_status: &f.status,
        capability: &f.capability,
        delegation_chain: &[],
        revocation_snapshot: &f.revocations,
        transfer: None,
    };
    let trust = OfflinePackageTrust {
        publisher_id: "aip:package-publisher",
        publisher_public_key: &f.package_public_key,
        aibom_publishers: &f.aibom_anchors,
        peer_binding_anchors: &f.binding_anchors,
        capability_issuer_keys: &f.capability_issuer_keys,
        revocation_authority: None,
        revocation_checkpoint: &f.revocation_checkpoint,
        expected_audience: "/aip/distribution/1.0.0",
        recipient_id: &f.aid.id,
        operation: PackageOperation::Receive,
        now_ms: f.now,
    };
    assert!(verify_offline_package_evidence(&missing, &trust).is_err());

    let checkpoint = SnapshotCheckpoint::new(8, [1; 32]).unwrap();
    let trust = OfflinePackageTrust {
        revocation_authority: Some(&f.revocation_anchor),
        revocation_checkpoint: &checkpoint,
        ..trust
    };
    assert!(verify_offline_package_evidence(&missing, &trust).is_err());
}

#[test]
fn offline_package_authorization_fails_if_capability_is_listed_as_revoked() {
    let f = fixture();
    let revoked = RevocationSnapshot::sign(
        "aip:revocation-authority",
        8,
        f.now - 100,
        f.now + 5_000,
        "/aip/distribution/1.0.0",
        vec![aip_distribution::revocation_snapshot::RevokedCapability {
            jti: f.capability.jti,
            revoked_at_ms: f.now - 200,
            reason: aip_types::RevocationReason::AdminRevocation,
            revoked_by: "aip:admin".into(),
        }],
        &f.revocation_signer,
    )
    .unwrap();
    assert!(verify_with_snapshot(&f, &revoked, None).is_err());
}
