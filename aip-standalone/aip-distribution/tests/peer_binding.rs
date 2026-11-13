#![cfg(feature = "p2p")]

use aip_core::{create_identity, identity_signing_payload};
use aip_crypto::{
    custody::{Custodian, InMemoryCustodian},
    sha256, sign_ed25519,
};
use aip_distribution::peer_binding::{
    aid_document_digest, parse_peer_binding, verify_authenticated_peer, verify_peer_binding,
    verify_peer_status_snapshot, PeerBindingError, PeerBindingIssuerAnchor, PeerBindingStatement,
    PeerBindingTrustAnchors, PeerIdentityStatus, PeerStatusAuthorityAnchor, PeerStatusSnapshot,
    PEER_BINDING_MAX_ENCODED_BYTES,
};
use aip_types::{AgentIdentityDocument, IdentityStatus, ProvenanceTriple};
use libp2p::{identity, PeerId};
use std::collections::{BTreeMap, BTreeSet};

struct Fixture {
    aid: AgentIdentityDocument,
    statement: PeerBindingStatement,
    status: PeerStatusSnapshot,
    anchors: PeerBindingTrustAnchors,
    now: u64,
    peer_id: PeerId,
    status_signer: std::sync::Arc<InMemoryCustodian>,
    issuer_public_key: Vec<u8>,
    issuer_id: String,
}

fn fixture() -> Fixture {
    let provenance = ProvenanceTriple {
        model_commitment: sha256(b"model"),
        environment_commitment: sha256(b"environment"),
        toolchain_commitment: sha256(b"toolchain"),
    };
    let (mut aid, keypair) = create_identity(provenance, None).expect("create AID");
    aid.status = IdentityStatus::Active;
    aid.sequence = 1;
    aid.self_signature = Some(
        sign_ed25519(
            &keypair.private_key,
            &aid.id,
            &identity_signing_payload(&aid),
        )
        .expect("sign active AID"),
    );

    let issuer = InMemoryCustodian::generate();
    let status_signer = std::sync::Arc::new(InMemoryCustodian::generate());
    let issuer_id = "aip:distribution-issuer";
    let status_signer_id = "aip:identity-status";
    let peer_key = identity::Keypair::generate_ed25519();
    let peer_public_key = peer_key.public().encode_protobuf();
    let peer_id = PeerId::from_public_key(&peer_key.public());
    let now = 1_800_000_000_000;
    let statement = PeerBindingStatement::sign(
        &aid,
        peer_public_key,
        issuer_id,
        now - 100,
        now + 5_000,
        7,
        12,
        "/aip/distribution/1.0.0",
        &issuer,
    )
    .expect("sign peer binding");
    let entry = PeerIdentityStatus {
        status: IdentityStatus::Active,
        aid_sequence: aid.sequence,
        binding_sequence: statement.sequence,
        binding_digest: statement.statement_digest().expect("statement digest"),
    };
    let status = PeerStatusSnapshot::sign(
        status_signer_id,
        12,
        now - 100,
        now + 4_000,
        "/aip/distribution/1.0.0",
        BTreeMap::from([(aid.id.clone(), entry)]),
        status_signer.as_ref(),
    )
    .expect("sign status snapshot");

    let binding_anchor = PeerBindingIssuerAnchor::new(
        issuer.public_key().to_vec(),
        BTreeSet::from([aid.id.clone()]),
    )
    .expect("issuer anchor");
    let anchors = PeerBindingTrustAnchors::new(
        BTreeMap::from([(issuer_id.to_string(), binding_anchor)]),
        BTreeMap::from([(
            status_signer_id.to_string(),
            PeerStatusAuthorityAnchor::new(status_signer.public_key().to_vec(), 12)
                .expect("status authority anchor"),
        )]),
        10_000,
        10_000,
    )
    .expect("trust anchors");
    Fixture {
        aid,
        statement,
        status,
        anchors,
        now,
        peer_id,
        status_signer,
        issuer_public_key: issuer.public_key().to_vec(),
        issuer_id: issuer_id.to_string(),
    }
}

fn verify(
    f: &Fixture,
    statement: &PeerBindingStatement,
    now: u64,
) -> Result<PeerId, PeerBindingError> {
    verify_peer_binding(
        statement,
        &f.aid,
        &f.status,
        &f.anchors,
        "/aip/distribution/1.0.0",
        now,
        None,
    )
}

#[test]
fn valid_binding_verifies_peer_key_aid_and_fresh_status() {
    let f = fixture();
    assert_eq!(verify(&f, &f.statement, f.now).unwrap(), f.peer_id);
}

#[test]
fn admission_requires_the_transport_authenticated_peer_to_match_binding() {
    let f = fixture();
    assert_eq!(
        verify_authenticated_peer(
            &f.peer_id,
            &f.statement,
            &f.aid,
            &f.status,
            &f.anchors,
            "/aip/distribution/1.0.0",
            f.now,
            None,
        )
        .unwrap(),
        f.aid.id
    );
    let wrong_peer = identity::Keypair::generate_ed25519().public().to_peer_id();
    assert!(verify_authenticated_peer(
        &wrong_peer,
        &f.statement,
        &f.aid,
        &f.status,
        &f.anchors,
        "/aip/distribution/1.0.0",
        f.now,
        None,
    )
    .is_err());
}

#[test]
fn complete_aid_digest_is_deterministic_and_covers_expiry() {
    let f = fixture();
    assert_eq!(aid_document_digest(&f.aid), aid_document_digest(&f.aid));
    let mut changed = f.aid.clone();
    changed.expires_at = Some(f.now + 1_000);
    assert_ne!(aid_document_digest(&f.aid), aid_document_digest(&changed));
}

#[test]
fn changed_peer_id_or_public_key_is_rejected() {
    let f = fixture();
    let mut altered = f.statement.clone();
    altered.peer_id = vec![1, 2, 3];
    assert!(verify(&f, &altered, f.now).is_err());

    let mut altered = f.statement.clone();
    altered.peer_public_key[0] ^= 1;
    assert!(verify(&f, &altered, f.now).is_err());
}

#[test]
fn wrong_aid_digest_and_wrong_audience_are_rejected() {
    let f = fixture();
    let mut aid = f.aid.clone();
    aid.expires_at = Some(f.now + 1_000);
    assert!(verify_peer_binding(
        &f.statement,
        &aid,
        &f.status,
        &f.anchors,
        "/aip/distribution/1.0.0",
        f.now,
        None,
    )
    .is_err());
    assert!(verify_peer_binding(
        &f.statement,
        &f.aid,
        &f.status,
        &f.anchors,
        "/other/protocol/1.0.0",
        f.now,
        None,
    )
    .is_err());
}

#[test]
fn changed_aid_identity_and_invalid_binding_signature_are_rejected() {
    let f = fixture();
    let mut changed_identity = f.aid.clone();
    changed_identity.id.push_str("-changed");
    assert!(verify_peer_binding(
        &f.statement,
        &changed_identity,
        &f.status,
        &f.anchors,
        "/aip/distribution/1.0.0",
        f.now,
        None,
    )
    .is_err());

    let mut bad_signature = f.statement.clone();
    bad_signature.signature.signature_bytes[0] ^= 1;
    assert!(verify(&f, &bad_signature, f.now).is_err());
}

#[test]
fn unknown_issuer_and_untrusted_status_authority_fail_closed() {
    let f = fixture();
    let empty = PeerBindingTrustAnchors::new(
        BTreeMap::from([(
            "other-issuer".into(),
            PeerBindingIssuerAnchor::new(vec![7; 32], BTreeSet::from([f.aid.id.clone()])).unwrap(),
        )]),
        BTreeMap::from([(
            "other-status".into(),
            PeerStatusAuthorityAnchor::new(vec![8; 32], 12).unwrap(),
        )]),
        10_000,
        10_000,
    )
    .unwrap();
    assert!(verify_peer_binding(
        &f.statement,
        &f.aid,
        &f.status,
        &empty,
        "/aip/distribution/1.0.0",
        f.now,
        None,
    )
    .is_err());
}

#[test]
fn expired_binding_stale_status_and_rollback_are_rejected() {
    let f = fixture();
    assert!(verify(&f, &f.statement, f.statement.not_after_ms + 1).is_err());
    assert!(verify(&f, &f.statement, f.status.valid_until_ms + 1).is_err());

    let mut stale_entries = f.status.identities.clone();
    stale_entries.get_mut(&f.aid.id).unwrap().binding_sequence -= 1;
    let stale_status = PeerStatusSnapshot::sign(
        &f.status.signer_id,
        f.status.epoch,
        f.status.issued_at_ms,
        f.status.valid_until_ms,
        &f.status.audience,
        stale_entries,
        f.status_signer.as_ref(),
    )
    .unwrap();
    assert!(verify_peer_binding(
        &f.statement,
        &f.aid,
        &stale_status,
        &f.anchors,
        "/aip/distribution/1.0.0",
        f.now,
        None,
    )
    .is_err());
}

#[test]
fn status_epoch_below_external_rollback_floor_is_rejected() {
    let f = fixture();
    // The trusted epoch floor is deliberately advanced beyond the signed
    // snapshot. Replaying that otherwise valid snapshot must fail closed.
    let anchors = PeerBindingTrustAnchors::new(
        BTreeMap::from([(
            f.issuer_id.clone(),
            PeerBindingIssuerAnchor::new(
                f.issuer_public_key.clone(),
                BTreeSet::from([f.aid.id.clone()]),
            )
            .unwrap(),
        )]),
        BTreeMap::from([(
            f.status.signer_id.clone(),
            PeerStatusAuthorityAnchor::new(f.status_signer.public_key().to_vec(), 13).unwrap(),
        )]),
        10_000,
        10_000,
    )
    .unwrap();
    assert!(verify_peer_binding(
        &f.statement,
        &f.aid,
        &f.status,
        &anchors,
        "/aip/distribution/1.0.0",
        f.now,
        None,
    )
    .is_err());
}

#[test]
fn pinned_status_checkpoint_rejects_same_epoch_equivocation() {
    let f = fixture();
    let status_key =
        PeerStatusAuthorityAnchor::new(f.status_signer.public_key().to_vec(), 12).unwrap();
    let checkpoint = verify_peer_status_snapshot(
        &f.status,
        &status_key,
        10_000,
        "/aip/distribution/1.0.0",
        f.now,
    )
    .unwrap();
    let pinned = PeerStatusAuthorityAnchor::with_checkpoint(
        f.status_signer.public_key().to_vec(),
        checkpoint,
    )
    .unwrap();
    let mut identities = f.status.identities.clone();
    identities.get_mut(&f.aid.id).unwrap().status = IdentityStatus::Suspended;
    let conflicting = PeerStatusSnapshot::sign(
        &f.status.signer_id,
        f.status.epoch,
        f.status.issued_at_ms,
        f.status.valid_until_ms,
        &f.status.audience,
        identities,
        f.status_signer.as_ref(),
    )
    .unwrap();
    assert!(verify_peer_status_snapshot(
        &conflicting,
        &pinned,
        10_000,
        "/aip/distribution/1.0.0",
        f.now,
    )
    .is_err());
}

#[test]
fn revoked_identity_in_signed_status_is_rejected() {
    let f = fixture();
    let mut entries = f.status.identities.clone();
    entries.get_mut(&f.aid.id).unwrap().status = IdentityStatus::Revoked;
    let revoked = PeerStatusSnapshot::sign(
        &f.status.signer_id,
        f.status.epoch,
        f.status.issued_at_ms,
        f.status.valid_until_ms,
        &f.status.audience,
        entries,
        f.status_signer.as_ref(),
    )
    .unwrap();
    assert!(verify_peer_binding(
        &f.statement,
        &f.aid,
        &revoked,
        &f.anchors,
        "/aip/distribution/1.0.0",
        f.now,
        None,
    )
    .is_err());
}

#[test]
fn malformed_unknown_and_oversized_binding_json_is_rejected() {
    assert!(parse_peer_binding(b"not-json").is_err());
    assert!(parse_peer_binding(&vec![b'a'; PEER_BINDING_MAX_ENCODED_BYTES + 1]).is_err());
    assert!(parse_peer_binding(br#"{"version":1,"unexpected":true}"#).is_err());
}

#[test]
fn deterministic_peer_binding_signature_vector() {
    let private = [0x37; 32];
    let public = aip_crypto::public_key_from_private(&private).unwrap();
    let peer_key = identity::PublicKey::try_decode_protobuf(
        &[vec![0x08, 0x01, 0x12, 0x20], vec![0x11; 32]].concat(),
    )
    .unwrap();
    let peer_id = PeerId::from_public_key(&peer_key).to_bytes();
    let mut statement = PeerBindingStatement {
        version: 1,
        identity_id: "aip:vector-identity".into(),
        aid_document_sha256: [0x22; 32],
        peer_public_key: peer_key.encode_protobuf(),
        peer_id,
        issuer_id: "aip:vector-issuer".into(),
        not_before_ms: 1_700,
        not_after_ms: 9_000,
        sequence: 5,
        status_epoch: 9,
        audience: "/aip/distribution/1.0.0".into(),
        signature: aip_types::Signature {
            algorithm: aip_types::AlgorithmId::Ed25519,
            signer_id: "aip:vector-issuer".into(),
            timestamp: 1_234,
            nonce: [0x55; 16],
            payload_hash: [0; 32],
            signature_bytes: vec![],
        },
    };
    let payload = statement.signing_bytes().unwrap();
    let payload_hash = sha256(&payload);
    let signed = aip_crypto::signature_signed_bytes(
        aip_types::AlgorithmId::Ed25519,
        "aip:vector-issuer",
        1_234,
        &[0x55; 16],
        &payload_hash,
    );
    statement.signature.payload_hash = payload_hash;
    statement.signature.signature_bytes = aip_crypto::sign_ed25519_raw(&private, &signed)
        .unwrap()
        .to_vec();
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/peer-binding-v1.json")).unwrap();
    assert_eq!(vector["issuer_public_key_hex"], hex::encode(public));
    assert_eq!(
        vector["peer_public_key_protobuf_hex"],
        hex::encode(&statement.peer_public_key)
    );
    assert_eq!(
        vector["peer_id_multihash_hex"],
        hex::encode(&statement.peer_id)
    );
    assert_eq!(vector["canonical_signing_bytes_hex"], hex::encode(payload));
    assert_eq!(vector["payload_hash_hex"], hex::encode(payload_hash));
    assert_eq!(
        vector["signature_hex"],
        hex::encode(&statement.signature.signature_bytes)
    );
    assert_eq!(
        vector["statement_digest_hex"],
        hex::encode(statement.statement_digest().unwrap())
    );
    assert!(aip_crypto::verify_ed25519(&public, &statement.signature).unwrap());
}
