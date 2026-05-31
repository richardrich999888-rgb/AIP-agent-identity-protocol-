//! Security & Crypto-Specific Tests — Verifying cryptographic correctness.

use aip_crypto::*;
use aip_types::*;

// ═══════════════════════════════════════════════════════════════
// KEY VALIDATION
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_malformed_public_key_31_bytes() {
    let short_key = vec![0xAA; 31]; // 1 byte too short
    let sig = Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: "test".into(),
        timestamp: 0,
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: vec![0; 64],
    };

    let result = verify_ed25519(&short_key, &sig);
    assert_eq!(
        result,
        Err(AipError::InvalidPublicKey),
        "31-byte key must be rejected"
    );
}

#[test]
fn test_malformed_public_key_33_bytes() {
    let long_key = vec![0xBB; 33]; // 1 byte too long
    let sig = Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: "test".into(),
        timestamp: 0,
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: vec![0; 64],
    };

    let result = verify_ed25519(&long_key, &sig);
    assert_eq!(
        result,
        Err(AipError::InvalidPublicKey),
        "33-byte key must be rejected"
    );
}

#[test]
fn test_malformed_private_key_rejected() {
    let short_key = vec![0xCC; 16]; // Way too short
    let result = sign_ed25519(&short_key, "test", b"payload");
    assert!(result.is_err(), "16-byte private key must be rejected");
}

#[test]
fn test_all_zero_public_key_fails_verification() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "test", b"data").unwrap();

    // All-zero key is a low-order point → verification should fail
    let zero_key = vec![0u8; 32];
    let result = verify_ed25519(&zero_key, &sig);
    // Either returns Err or Ok(false) — both are acceptable
    match result {
        Ok(false) => {} // Expected
        Err(_) => {}    // Also acceptable (InvalidPublicKey)
        Ok(true) => panic!("All-zero public key must NEVER verify a real signature"),
    }
}

#[test]
fn test_all_zero_private_key_can_sign() {
    // Ed25519 hashes the private key internally, so all-zeros is valid
    let zero_key = [0u8; 32];
    let result = sign_ed25519(&zero_key, "zero-agent", b"test");
    assert!(
        result.is_ok(),
        "All-zero private key should still produce a valid signature"
    );

    // The resulting signature should verify with the corresponding public key
    let sig = result.unwrap();
    // Derive the public key from the zero private key
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&zero_key);
    let verifying_key = signing_key.verifying_key();
    let valid = verify_ed25519(verifying_key.as_bytes(), &sig).unwrap();
    assert!(
        valid,
        "Signature from zero key should verify with its derived public key"
    );
}

// ═══════════════════════════════════════════════════════════════
// SIGNATURE INTEGRITY
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_private_key_not_in_signature_bytes() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "agent", b"sensitive data").unwrap();

    // Signature bytes must not contain the private key
    let sig_hex: Vec<u8> = sig.signature_bytes.clone();
    let contains_private = sig_hex
        .windows(kp.private_key.len())
        .any(|window| window == kp.private_key.as_slice());
    assert!(
        !contains_private,
        "Private key material must NEVER appear in signature bytes"
    );
}

#[test]
fn test_signature_malleability_rejected() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "agent", b"data").unwrap();
    assert!(verify_ed25519(&kp.public_key, &sig).unwrap());

    // Attempt to create a malleable signature by flipping bits
    let mut malleable = sig.clone();
    if !malleable.signature_bytes.is_empty() {
        malleable.signature_bytes[63] ^= 0x80; // Flip high bit of s-value
    }

    let malleable_valid = verify_ed25519(&kp.public_key, &malleable).unwrap();
    assert!(
        !malleable_valid,
        "Malleable (bit-flipped) signature must not verify"
    );
}

#[test]
fn test_truncated_signature_rejected() {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "agent", b"data").unwrap();

    // Truncate to 32 bytes (should be 64)
    let mut truncated = sig.clone();
    truncated.signature_bytes.truncate(32);

    let result = verify_ed25519(&kp.public_key, &truncated);
    assert!(
        result.is_err() || result == Ok(false),
        "Truncated signature must not verify"
    );
}

// ═══════════════════════════════════════════════════════════════
// HASH COLLISION RESISTANCE
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_sha256_uniqueness_10k_inputs() {
    use std::collections::HashSet;
    let mut hashes = HashSet::new();

    for i in 0u64..10_000 {
        let hash = sha256(&i.to_le_bytes());
        assert!(
            hashes.insert(hash),
            "SHA-256 collision detected at input {}!",
            i
        );
    }
    assert_eq!(hashes.len(), 10_000);
}

#[test]
fn test_merkle_domain_separation() {
    // Leaf and internal node must use different domain separators
    // so that a leaf hash can't be confused with an internal node
    let data = b"test data";
    let leaf = merkle_leaf(data);

    // If someone tries to pass leaf hash as an internal node directly
    let fake_internal_from_raw = sha256(data); // No domain separator
    assert_ne!(
        leaf, fake_internal_from_raw,
        "Leaf hash must differ from raw SHA-256 (domain separation)"
    );

    // Internal node uses 0x01 prefix, leaf uses 0x00 prefix
    let left = merkle_leaf(b"left");
    let right = merkle_leaf(b"right");
    let internal = merkle_internal(&left, &right);

    // Constructing the same bytes without the internal-node prefix must differ
    let mut raw_concat = Vec::new();
    raw_concat.extend_from_slice(&left);
    raw_concat.extend_from_slice(&right);
    let fake_internal = sha256(&raw_concat);
    assert_ne!(
        internal, fake_internal,
        "Internal node hash must differ from raw concatenation (domain separation)"
    );
}
