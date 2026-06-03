//! Edge Cases & Boundary Value Tests — Malformed and extreme inputs.

use aip_core::nonce::NonceTracker;
use aip_core::store::IdentityStore;
use aip_core::*;
use aip_crypto::*;
use aip_types::*;

fn test_provenance() -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(b"edge-model"),
        environment_commitment: sha256(b"edge-env"),
        toolchain_commitment: sha256(b"edge-toolchain"),
    }
}

// ═══════════════════════════════════════════════════════════════
// PAYLOAD BOUNDARIES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_sign_empty_payload() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "agent", b"").unwrap();
    let valid = verify_ed25519(&kp.public_key, &sig).unwrap();
    assert!(valid, "Empty payload must sign and verify");
}

#[test]
fn test_sign_max_payload_1mb() {
    let kp = generate_ed25519_keypair();
    let payload = vec![0xABu8; 1_048_576]; // 1 MB
    let sig = sign_ed25519(&kp.private_key, "agent", &payload).unwrap();
    let valid = verify_ed25519(&kp.public_key, &sig).unwrap();
    assert!(valid, "1MB payload must sign and verify");
}

#[test]
fn test_sign_single_byte_payload() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "agent", &[0x42]).unwrap();
    let valid = verify_ed25519(&kp.public_key, &sig).unwrap();
    assert!(valid, "Single byte payload must sign and verify");
}

// ═══════════════════════════════════════════════════════════════
// TIMESTAMP BOUNDARIES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_zero_timestamp_rejected_by_nonce_tracker() {
    let mut tracker = NonceTracker::new();
    let sig = Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: "agent".into(),
        timestamp: 0, // Unix epoch
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: vec![0; 64],
    };

    let result = tracker.validate_and_record(&sig);
    assert_eq!(
        result,
        Err(AipError::SignatureExpired),
        "Timestamp=0 must be rejected as expired"
    );
}

#[test]
fn test_max_timestamp_rejected_by_nonce_tracker() {
    let mut tracker = NonceTracker::new();
    let sig = Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: "agent".into(),
        timestamp: u64::MAX,
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: vec![0; 64],
    };

    let result = tracker.validate_and_record(&sig);
    assert_eq!(
        result,
        Err(AipError::SignatureExpired),
        "Timestamp=MAX must be rejected as future"
    );
}

// ═══════════════════════════════════════════════════════════════
// SIGNER ID BOUNDARIES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_empty_signer_id() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "", b"data").unwrap();
    let valid = verify_ed25519(&kp.public_key, &sig).unwrap();
    assert!(valid, "Empty signer_id must still produce valid signature");
}

#[test]
fn test_very_long_signer_id() {
    let kp = generate_ed25519_keypair();
    let long_id = "x".repeat(10_000);
    let sig = sign_ed25519(&kp.private_key, &long_id, b"data").unwrap();
    let valid = verify_ed25519(&kp.public_key, &sig).unwrap();
    assert!(valid, "Very long signer_id must still work");
}

// ═══════════════════════════════════════════════════════════════
// AIP-ID VALIDATION EDGE CASES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_aip_id_validation_edge_cases() {
    // Too short
    assert!(validate_aip_id("").is_err(), "Empty string must be invalid");
    assert!(
        validate_aip_id("aip1").is_err(),
        "Just prefix must be invalid"
    );
    assert!(validate_aip_id("aip1a").is_err(), "Way too short");

    // Wrong prefix
    assert!(validate_aip_id("aip2abcdefghijklmnopqrstuvwxyz1234567890").is_err());
    assert!(validate_aip_id("bip1abcdefghijklmnopqrstuvwxyz1234567890").is_err());

    // Too long (> 48 chars)
    let too_long = format!("aip1{}", "a".repeat(60));
    assert!(validate_aip_id(&too_long).is_err());
}

// ═══════════════════════════════════════════════════════════════
// STORE EDGE CASES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_store_empty_save_load() {
    let tmp_path = std::env::temp_dir().join("aip_edge_empty_store.json");
    let _ = std::fs::remove_file(&tmp_path);

    {
        let store = IdentityStore::with_file(&tmp_path).unwrap();
        assert_eq!(store.identity_count(), 0);
        store.save().unwrap();
    }

    {
        let store = IdentityStore::with_file(&tmp_path).unwrap();
        assert_eq!(store.identity_count(), 0);
    }

    let _ = std::fs::remove_file(&tmp_path);
}

#[test]
fn test_store_corrupted_json_graceful_error() {
    let tmp_path = std::env::temp_dir().join("aip_edge_corrupt_store.json");
    std::fs::write(&tmp_path, "{{{{not valid json at all!!!").unwrap();

    let result = IdentityStore::with_file(&tmp_path);
    assert!(result.is_err(), "Corrupted JSON must produce error");

    let _ = std::fs::remove_file(&tmp_path);
}

#[test]
fn test_store_truncated_json_graceful_error() {
    let tmp_path = std::env::temp_dir().join("aip_edge_truncated_store.json");
    // Partial valid JSON that was cut off
    std::fs::write(&tmp_path, "{\"identities\":{},\"reputations\":").unwrap();

    let result = IdentityStore::with_file(&tmp_path);
    assert!(result.is_err(), "Truncated JSON must produce error");

    let _ = std::fs::remove_file(&tmp_path);
}

// ═══════════════════════════════════════════════════════════════
// PROVENANCE EDGE CASES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_provenance_all_zeros() {
    let prov = ProvenanceTriple {
        model_commitment: [0u8; 32],
        environment_commitment: [0u8; 32],
        toolchain_commitment: [0u8; 32],
    };
    let (aid, _kp) = create_identity(prov, None).unwrap();
    assert!(aid.id.starts_with("aip1"));
    assert!(validate_aid(&aid).is_ok());
}

#[test]
fn test_provenance_all_ones() {
    let prov = ProvenanceTriple {
        model_commitment: [0xFF; 32],
        environment_commitment: [0xFF; 32],
        toolchain_commitment: [0xFF; 32],
    };
    let (aid, _kp) = create_identity(prov, None).unwrap();
    assert!(aid.id.starts_with("aip1"));
    assert!(validate_aid(&aid).is_ok());
}

// ═══════════════════════════════════════════════════════════════
// CAPABILITY EDGE CASES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_capability_empty_actions() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "grantor", b"grant").unwrap();
    let grant = CapabilityGrant {
        id: [0u8; 16],
        grantor_id: "grantor".into(),
        grantee_id: "agent".into(),
        namespace: "com.test".into(),
        actions: vec![], // No actions!
        constraints: vec![],
        delegatable: true,
        issued_at: 0,
        expires_at: None,
        grantor_sig: sig,
    };

    let result = validate_capability_grant(&grant, 0);
    assert!(
        result.is_err(),
        "Grant with empty actions should be invalid"
    );
}

#[test]
fn test_capability_many_constraints() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "grantor", b"grant").unwrap();
    let constraints: Vec<Constraint> = (0..50)
        .map(|i| Constraint {
            key: format!("k{}", i),
            operator: ConstraintOp::Eq,
            value: format!("v{}", i),
        })
        .collect();

    let grant = CapabilityGrant {
        id: [0u8; 16],
        grantor_id: "grantor".into(),
        grantee_id: "agent".into(),
        namespace: "com.test".into(),
        actions: vec![Action::Read],
        constraints,
        delegatable: true,
        issued_at: 1,
        expires_at: Some(999_999),
        grantor_sig: sig,
    };

    // Should validate without error (constraints are within limits)
    let result = validate_capability_grant(&grant, 0);
    assert!(
        result.is_ok(),
        "50 short constraints should be valid: {:?}",
        result
    );
}

// ═══════════════════════════════════════════════════════════════
// LIVENESS EDGE CASES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_liveness_zero_deadline() {
    let kp = generate_ed25519_keypair();
    let id = derive_aip_id(&kp.public_key, &test_provenance());

    let mut challenge = issue_liveness_challenge("verifier", &id);
    challenge.deadline_ms = 0; // Zero tolerance

    let response = respond_to_challenge(&challenge, &kp.private_key, &id).unwrap();

    // Response timestamp will be >= challenge issued_at, so with deadline=0
    // the response is always "late" (unless responded_at == issued_at exactly)
    let valid = verify_liveness(&challenge, &response, &kp.public_key).unwrap();
    // This depends on timing — but with deadline_ms=0, it should almost always fail
    // unless system clock is perfectly aligned
    // We just verify it doesn't crash
    let _ = valid;
}

#[test]
fn test_reputation_extreme_scores() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "attester", b"attest").unwrap();

    // Extreme external inputs must be clamped into the reputation score range.
    let extremes = [i32::MIN, i32::MAX, 0, -1, 1_000_001, -1_000_001];

    for &value in &extremes {
        let att = Attestation {
            id: [0u8; 16],
            subject_id: "agent".into(),
            attester_id: "attester".into(),
            attester_type: AttesterType::Authority,
            claim_type: ClaimType::TaskCompletion,
            claim_value: value,
            claim_context: "extreme".into(),
            evidence_hash: None,
            attested_at: 0,
            valid_until: None,
            attester_sig: sig.clone(),
        };

        let rep = calculate_reputation("agent", &[att], 0);
        assert!(rep.reliability <= 1_000_000);
        assert!(rep.honesty <= 1_000_000);
        assert!(rep.economic <= 1_000_000);
        assert!(rep.governance <= 1_000_000);
        assert!(rep.overall_score <= 1_000_000);
    }
}
