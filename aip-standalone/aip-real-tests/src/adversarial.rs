//! Adversarial Attack Tests — Simulating real attack vectors against AIP.

use aip_core::*;
use aip_crypto::*;
use aip_types::*;
use std::collections::HashMap;

fn test_provenance() -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(b"adversarial-test-model"),
        environment_commitment: sha256(b"adversarial-test-env"),
        toolchain_commitment: sha256(b"adversarial-test-toolchain"),
    }
}

// ═══════════════════════════════════════════════════════════════
// SIGNATURE FORGERY ATTACKS
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_forged_signature_rejected() {
    let kp = generate_ed25519_keypair();
    let prov = test_provenance();
    let id = derive_aip_id(&kp.public_key, &prov);

    // Attacker creates a fake signature with random bytes
    let forged_sig = Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: id.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        nonce: [0xAA; 16],
        payload_hash: sha256(b"legitimate payload"),
        signature_bytes: vec![0xDE; 64], // Random 64 bytes
    };

    let valid = verify_ed25519(&kp.public_key, &forged_sig).unwrap();
    assert!(!valid, "Forged signature must NEVER verify");
}

#[test]
fn test_signature_from_different_payload() {
    let kp = generate_ed25519_keypair();
    let id = "aip1attacker";

    // Sign payload A
    let sig = sign_ed25519(&kp.private_key, id, b"payload A").unwrap();

    // Attacker claims this signature covers payload B
    // The payload_hash in the signature is for payload A, not B
    assert_ne!(sig.payload_hash, sha256(b"payload B"));

    // The signature itself verifies (it's cryptographically valid)
    // but the payload_hash mismatch proves the content is different
    let valid = verify_ed25519(&kp.public_key, &sig).unwrap();
    assert!(valid, "Sig is valid for original payload");

    // Attacker modifies payload_hash to match payload B → breaks sig
    let mut tampered = sig.clone();
    tampered.payload_hash = sha256(b"payload B");
    let tampered_valid = verify_ed25519(&kp.public_key, &tampered).unwrap();
    assert!(
        !tampered_valid,
        "Changing payload_hash must invalidate signature"
    );
}

// ═══════════════════════════════════════════════════════════════
// KEY SUBSTITUTION ATTACKS
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_key_substitution_attack() {
    // Victim creates identity
    let (victim_aid, _victim_kp) = create_identity(test_provenance(), None).unwrap();

    // Attacker generates their own key
    let attacker_kp = generate_ed25519_keypair();

    // Attacker tries to substitute their key into victim's AID
    let mut fake_aid = victim_aid.clone();
    fake_aid.primary_key.key_bytes = attacker_kp.public_key.clone();

    // AIP-ID is bound to (original key, provenance) → won't match attacker's key
    let result = validate_aid(&fake_aid);
    assert_eq!(
        result,
        Err(AipError::InvalidAipId),
        "Key substitution must fail: AIP-ID is provenance-bound"
    );
}

#[test]
fn test_self_signature_removal() {
    let (mut aid, _kp) = create_identity(test_provenance(), None).unwrap();
    aid.self_signature = None;

    assert_eq!(
        validate_aid(&aid),
        Err(AipError::MissingRequiredField),
        "AID without self-signature must be rejected"
    );
}

#[test]
fn test_self_signature_swap_between_aids() {
    let (aid_a, _kp_a) = create_identity(test_provenance(), None).unwrap();
    let (mut aid_b, _kp_b) = create_identity(test_provenance(), None).unwrap();

    // Swap A's self-signature onto B
    aid_b.self_signature = aid_a.self_signature.clone();

    let result = validate_aid(&aid_b);
    assert!(
        result.is_err(),
        "Using another AID's self-signature must fail: {:?}",
        result
    );
}

// ═══════════════════════════════════════════════════════════════
// PROVENANCE TAMPERING
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_tampered_provenance_detected() {
    let (mut aid, _kp) = create_identity(test_provenance(), None).unwrap();

    // Attacker changes the model commitment
    aid.provenance.model_commitment = sha256(b"attacker-model");

    let result = validate_aid(&aid);
    assert_eq!(
        result,
        Err(AipError::InvalidAipId),
        "Tampered provenance must invalidate AIP-ID binding"
    );
}

#[test]
fn test_tampered_magic_bytes() {
    let (mut aid, _kp) = create_identity(test_provenance(), None).unwrap();
    aid.magic = [0xFF, 0xFF, 0xFF, 0xFF];

    assert_eq!(validate_aid(&aid), Err(AipError::InvalidMagic));
}

#[test]
fn test_tampered_version() {
    let (mut aid, _kp) = create_identity(test_provenance(), None).unwrap();
    aid.version = 0x9999;

    assert_eq!(validate_aid(&aid), Err(AipError::UnsupportedVersion));
}

// ═══════════════════════════════════════════════════════════════
// LINEAGE FORGERY
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_lineage_forgery_wrong_parent_key() {
    let (parent_aid, parent_kp) = create_identity(test_provenance(), None).unwrap();
    let (child_aid, _child_kp) = create_identity(
        test_provenance(),
        Some((&parent_aid.id, &parent_kp.private_key)),
    )
    .unwrap();

    // Attacker tries to validate with a different "parent" key
    let attacker_kp = generate_ed25519_keypair();
    let result = validate_aid_with_parent(&child_aid, &parent_aid.id, &attacker_kp.public_key);
    assert_eq!(
        result,
        Err(AipError::LineageInvalid),
        "Lineage with wrong parent key must fail"
    );
}

#[test]
fn test_lineage_forgery_wrong_parent_id() {
    let (parent_aid, parent_kp) = create_identity(test_provenance(), None).unwrap();
    let (child_aid, _child_kp) = create_identity(
        test_provenance(),
        Some((&parent_aid.id, &parent_kp.private_key)),
    )
    .unwrap();

    // Attacker claims a different parent ID
    let result = validate_aid_with_parent(&child_aid, "aip1FakeParent", &parent_kp.public_key);
    assert_eq!(
        result,
        Err(AipError::LineageInvalid),
        "Lineage with wrong parent ID must fail"
    );
}

// ═══════════════════════════════════════════════════════════════
// CAPABILITY GRANT FORGERY
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_capability_grant_forgery() {
    let grantor_kp = generate_ed25519_keypair();
    let placeholder_sig = sign_ed25519(&grantor_kp.private_key, "grantor", b"x").unwrap();

    let mut grant = CapabilityGrant {
        id: [1u8; 16],
        grantor_id: "grantor".into(),
        grantee_id: "victim".into(),
        namespace: "com.secure".into(),
        actions: vec![Action::Admin],
        constraints: vec![],
        delegatable: true,
        issued_at: 1,
        expires_at: Some(999_999),
        grantor_sig: placeholder_sig,
    };

    // Properly sign the grant
    let canonical = {
        let mut buf = Vec::new();
        buf.extend_from_slice(&grant.id);
        buf.extend_from_slice(grant.grantor_id.as_bytes());
        buf.extend_from_slice(grant.grantee_id.as_bytes());
        buf.extend_from_slice(grant.namespace.as_bytes());
        for action in &grant.actions {
            buf.push(*action as u8);
        }
        buf.push(1); // delegatable
        buf.extend_from_slice(&grant.issued_at.to_le_bytes());
        buf.push(1);
        buf.extend_from_slice(&grant.expires_at.unwrap().to_le_bytes());
        buf
    };
    grant.grantor_sig = sign_ed25519(&grantor_kp.private_key, "grantor", &canonical).unwrap();

    // Attacker tampers with the namespace after signing
    grant.namespace = "com.evil.admin".into();

    let result = validate_capability_grant_with_key(&grant, &grantor_kp.public_key, 100);
    assert_eq!(
        result,
        Err(AipError::SignatureInvalid),
        "Tampered capability grant must fail signature check"
    );
}

// ═══════════════════════════════════════════════════════════════
// LIVENESS PROTOCOL ATTACKS
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_liveness_cross_agent_impersonation() {
    let kp_a = generate_ed25519_keypair();
    let kp_b = generate_ed25519_keypair();
    let id_a = derive_aip_id(&kp_a.public_key, &test_provenance());
    let id_b = derive_aip_id(&kp_b.public_key, &test_provenance());

    // Challenge targets agent A
    let challenge = issue_liveness_challenge("verifier", &id_a);

    // Agent B tries to respond instead of A
    let response = respond_to_challenge(&challenge, &kp_b.private_key, &id_b).unwrap();

    // Verify with A's key → must fail
    let valid = verify_liveness(&challenge, &response, &kp_a.public_key).unwrap();
    assert!(
        !valid,
        "Impersonation: B responding to A's challenge must fail"
    );
}

#[test]
fn test_liveness_replay_old_response() {
    let kp = generate_ed25519_keypair();
    let id = derive_aip_id(&kp.public_key, &test_provenance());

    // First challenge-response
    let challenge_1 = issue_liveness_challenge("verifier", &id);
    let response_1 = respond_to_challenge(&challenge_1, &kp.private_key, &id).unwrap();
    assert!(verify_liveness(&challenge_1, &response_1, &kp.public_key).unwrap());

    // New challenge
    let challenge_2 = issue_liveness_challenge("verifier", &id);

    // Attacker replays response_1 for challenge_2 → challenge_id mismatch
    let replay_valid = verify_liveness(&challenge_2, &response_1, &kp.public_key).unwrap();
    assert!(
        !replay_valid,
        "Replayed response for different challenge must fail"
    );
}

// ═══════════════════════════════════════════════════════════════
// REPUTATION ATTACKS
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_reputation_vote_forgery() {
    let kp = generate_ed25519_keypair();
    let mut vote = ReputationVote {
        voter_id: "voter1".into(),
        subject_id: "subject".into(),
        dimension: ReputationDimensionId::Reliability,
        score: 999_999,
        evidence_root: [0u8; 32],
        voted_at: 0,
        voter_sig: sign_ed25519(&kp.private_key, "voter1", b"placeholder").unwrap(),
    };

    // Tamper: change score after signing
    vote.score = 1;

    let mut keys = HashMap::new();
    keys.insert("voter1".to_string(), kp.public_key.clone());

    let result = aggregate_reputation_votes_verified("subject", &[vote], 1, &keys);
    // Tampered vote should be filtered out, so no quorum
    assert!(
        !result.consensus_reached || result.quorum_size == 0,
        "Tampered reputation vote must be filtered out"
    );
}

#[test]
fn test_sybil_multiple_ids_same_key_rejected() {
    let kp = generate_ed25519_keypair();

    // Create two votes with different voter IDs but same key
    let make_vote = |voter_id: &str| {
        let mut vote = ReputationVote {
            voter_id: voter_id.to_string(),
            subject_id: "target".to_string(),
            dimension: ReputationDimensionId::Honesty,
            score: 900_000,
            evidence_root: [0u8; 32],
            voted_at: 0,
            voter_sig: sign_ed25519(&kp.private_key, voter_id, b"placeholder").unwrap(),
        };
        // Properly sign with canonical encoding
        let mut canonical = Vec::new();
        canonical.extend_from_slice(vote.voter_id.as_bytes());
        canonical.extend_from_slice(vote.subject_id.as_bytes());
        canonical.push(vote.dimension as u8);
        canonical.extend_from_slice(&vote.score.to_le_bytes());
        canonical.extend_from_slice(&vote.evidence_root);
        canonical.extend_from_slice(&vote.voted_at.to_le_bytes());
        vote.voter_sig = sign_ed25519(&kp.private_key, voter_id, &canonical).unwrap();
        vote
    };

    let vote_a = make_vote("sybil_id_1");
    let vote_b = make_vote("sybil_id_2");

    let mut keys = HashMap::new();
    keys.insert("sybil_id_1".to_string(), kp.public_key.clone());
    keys.insert("sybil_id_2".to_string(), kp.public_key.clone());

    let result = aggregate_reputation_votes_verified("target", &[vote_a, vote_b], 2, &keys);
    assert!(
        !result.consensus_reached,
        "Sybil attack: same key with two IDs must not reach quorum of 2"
    );
    assert!(
        result.quorum_size <= 1,
        "Only one vote should survive anti-sybil: got {}",
        result.quorum_size
    );
}
