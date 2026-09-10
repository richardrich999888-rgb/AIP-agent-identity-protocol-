//! AIP Crypto — Ed25519 signing, SHA-256 hashing, Base58, AIP-ID derivation.

pub mod custody;

use aip_types::{AlgorithmId, KeyPair, ProvenanceTriple, Signature};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Generate an Ed25519 key pair.
pub fn generate_ed25519_keypair() -> KeyPair {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    KeyPair {
        algorithm: AlgorithmId::Ed25519,
        public_key: verifying_key.to_bytes().to_vec(),
        private_key: signing_key.to_bytes().to_vec(),
    }
}

/// Compute SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute fingerprint from public key bytes (§3.4).
pub fn fingerprint(key_bytes: &[u8]) -> [u8; 32] {
    sha256(key_bytes)
}

/// Compute provenance-bound fingerprint (NM-10, v0.3.0).
/// fingerprint = SHA-256(public_key.key_bytes || provenance_bytes)[0:26]
pub fn provenance_bound_fingerprint(key_bytes: &[u8], provenance: &ProvenanceTriple) -> [u8; 26] {
    let mut input = Vec::with_capacity(key_bytes.len() + 96);
    input.extend_from_slice(key_bytes);
    input.extend_from_slice(&provenance.to_bytes());
    let hash = sha256(&input);
    let mut out = [0u8; 26];
    out.copy_from_slice(&hash[..26]);
    out
}

/// Derive AIP-ID from public key and provenance triple (§4.1, NM-10).
/// Format: aip1<fingerprint_b58><checksum_b58>
pub fn derive_aip_id(key_bytes: &[u8], provenance: &ProvenanceTriple) -> String {
    let fp_bytes = provenance_bound_fingerprint(key_bytes, provenance);
    let fingerprint_b58 = bs58::encode(&fp_bytes).into_string();

    // Checksum: SHA-256(SHA-256("aip1" || fingerprint_b58))[0:4]
    let prefix = "aip1";
    let inner = format!("{}{}", prefix, fingerprint_b58);
    let first_hash = sha256(inner.as_bytes());
    let second_hash = sha256(&first_hash);
    let checksum_bytes = &second_hash[..4];
    let checksum_b58 = bs58::encode(checksum_bytes).into_string();

    format!("{}{}{}", prefix, fingerprint_b58, checksum_b58)
}

/// Validate an AIP-ID string (§4.1).
pub fn validate_aip_id(id: &str) -> Result<(), aip_types::AipError> {
    if !id.starts_with("aip1") {
        return Err(aip_types::AipError::InvalidAipId);
    }

    let without_prefix = &id[4..];
    // Base58 is a strict ASCII alphabet. Rejecting non-ASCII here also
    // guarantees every byte index below is a char boundary, so the slicing
    // can never panic on externally supplied input.
    if !without_prefix.is_ascii() {
        return Err(aip_types::AipError::InvalidAipId);
    }
    if without_prefix.len() < 5 {
        return Err(aip_types::AipError::InvalidAipId);
    }

    // Try checksum split from the right (last 1-6 chars)
    for checksum_len in (1..=6).rev() {
        if checksum_len > without_prefix.len() {
            continue;
        }
        let split_point = without_prefix.len() - checksum_len;
        let fingerprint_b58 = &without_prefix[..split_point];
        let checksum_b58 = &without_prefix[split_point..];

        if let Ok(checksum_bytes) = bs58::decode(checksum_b58).into_vec() {
            if checksum_bytes.len() == 4 {
                let inner = format!("aip1{}", fingerprint_b58);
                let first_hash = sha256(inner.as_bytes());
                let second_hash = sha256(&first_hash);
                if &second_hash[..4] == checksum_bytes.as_slice() {
                    return Ok(());
                }
            }
        }
    }

    Err(aip_types::AipError::InvalidChecksum)
}

/// Sign a message with raw Ed25519 (no AIP envelope) — the detached 64-byte
/// signature over `msg` exactly. Used for signing audit-export manifests so
/// the signature can be verified offline with only the public key + bytes.
pub fn sign_ed25519_raw(private_key: &[u8], msg: &[u8]) -> Result<[u8; 64], aip_types::AipError> {
    if private_key.len() != 32 {
        return Err(aip_types::AipError::InvalidPublicKey);
    }
    let signing_key = SigningKey::from_bytes(
        private_key
            .try_into()
            .map_err(|_| aip_types::AipError::InvalidPublicKey)?,
    );
    Ok(signing_key.sign(msg).to_bytes())
}

/// Verify a raw Ed25519 detached signature over `msg`.
pub fn verify_ed25519_raw(public_key: &[u8], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(key_arr): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_arr) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    verifying_key.verify(msg, &signature).is_ok()
}

/// The 32 bytes an AIP signature envelope actually covers.
///
/// `signed_bytes = SHA-256(algorithm || signer_id || timestamp_le || nonce ||
/// payload_hash)`.
///
/// Extracted so the signer and the verifier cannot drift: this construction
/// previously existed twice, written out by hand in [`sign_ed25519`] and again
/// in [`verify_ed25519`], and a custodian-backed signer would have made it
/// three copies. Two hand-built encodings that must agree byte for byte are a
/// latent divergence; one function is the fix.
///
/// The encoding is unchanged from the original pair, so every signature
/// produced or accepted before this extraction remains valid.
///
/// Note the encoding is not prefix-free: `signer_id` is embedded without a
/// length. That is pre-existing wire format and is not altered here; the
/// prefix-free canonical encodings elsewhere in the workspace (`put_domain`
/// and friends) are the pattern new formats follow.
pub fn signature_signed_bytes(
    algorithm: AlgorithmId,
    signer_id: &str,
    timestamp: u64,
    nonce: &[u8; 16],
    payload_hash: &[u8; 32],
) -> [u8; 32] {
    let mut signed_input = Vec::new();
    signed_input.push(algorithm as u8);
    signed_input.extend_from_slice(signer_id.as_bytes());
    signed_input.extend_from_slice(&timestamp.to_le_bytes());
    signed_input.extend_from_slice(nonce);
    signed_input.extend_from_slice(payload_hash);
    sha256(&signed_input)
}

/// Sign a payload with Ed25519.
pub fn sign_ed25519(
    private_key: &[u8],
    signer_id: &str,
    payload: &[u8],
) -> Result<Signature, aip_types::AipError> {
    if private_key.len() != 32 {
        return Err(aip_types::AipError::InvalidPublicKey);
    }

    let signing_key = SigningKey::from_bytes(
        private_key
            .try_into()
            .map_err(|_| aip_types::AipError::InvalidPublicKey)?,
    );

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let mut nonce = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let payload_hash = sha256(payload);

    let signed_bytes = signature_signed_bytes(
        AlgorithmId::Ed25519,
        signer_id,
        timestamp,
        &nonce,
        &payload_hash,
    );

    let sig = signing_key.sign(&signed_bytes);

    Ok(Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: signer_id.to_string(),
        timestamp,
        nonce,
        payload_hash,
        signature_bytes: sig.to_bytes().to_vec(),
    })
}

/// Verify an Ed25519 signature.
pub fn verify_ed25519(
    public_key: &[u8],
    signature: &Signature,
) -> Result<bool, aip_types::AipError> {
    if public_key.len() != 32 {
        return Err(aip_types::AipError::InvalidPublicKey);
    }
    // This verifier implements exactly one algorithm. A signature labelled
    // anything else is not "verified" here even if its envelope happens to
    // check out under Ed25519 — the label would otherwise become a lie the
    // evidence chain carries as fact.
    if signature.algorithm != AlgorithmId::Ed25519 {
        return Err(aip_types::AipError::EvolutionRequired);
    }

    let verifying_key = VerifyingKey::from_bytes(
        public_key
            .try_into()
            .map_err(|_| aip_types::AipError::InvalidPublicKey)?,
    )
    .map_err(|_| aip_types::AipError::InvalidPublicKey)?;

    let signed_bytes = signature_signed_bytes(
        signature.algorithm,
        &signature.signer_id,
        signature.timestamp,
        &signature.nonce,
        &signature.payload_hash,
    );

    let sig = ed25519_dalek::Signature::from_bytes(
        signature
            .signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| aip_types::AipError::SignatureInvalid)?,
    );

    Ok(verifying_key.verify(&signed_bytes, &sig).is_ok())
}

/// Merkle tree helpers (§3.4).
pub fn merkle_leaf(data: &[u8]) -> [u8; 32] {
    let mut input = vec![0x00u8];
    input.extend_from_slice(data);
    sha256(&input)
}

pub fn merkle_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = vec![0x01u8];
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    sha256(&input)
}

pub fn merkle_empty() -> [u8; 32] {
    sha256(b"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = generate_ed25519_keypair();
        assert_eq!(kp.algorithm, AlgorithmId::Ed25519);
        assert_eq!(kp.public_key.len(), 32);
        assert_eq!(kp.private_key.len(), 32);
    }

    #[test]
    fn test_aip_id_derivation_and_validation() {
        let kp = generate_ed25519_keypair();
        let prov = ProvenanceTriple {
            model_commitment: sha256(b"gpt-4o"),
            environment_commitment: sha256(b"linux-x86_64"),
            toolchain_commitment: sha256(b"rustc-1.77"),
        };
        let id = derive_aip_id(&kp.public_key, &prov);
        assert!(id.starts_with("aip1"));
        assert!(validate_aip_id(&id).is_ok());
    }

    #[test]
    fn test_aip_id_invalid() {
        assert!(validate_aip_id("xxx_invalid").is_err());
        assert!(validate_aip_id("aip1AAAA").is_err());
    }

    /// Malformed externally supplied IDs must produce an error, never a panic.
    /// Multi-byte UTF-8 placed where the checksum split lands used to hit a
    /// non-char-boundary slice.
    #[test]
    fn test_aip_id_malformed_never_panics() {
        let cases: [&str; 12] = [
            "",
            "aip",
            "aip1",
            "aip1é",
            "aip1ééééé",
            "aip1abcdé",
            "aip1abcdéfgh",
            "aip1\u{1F600}\u{1F600}\u{1F600}",
            "aip1abc\u{0}def",
            "aip1\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}",
            "AIP1abcdefghijk",
            "aip1 abcdefghijk",
        ];
        for c in cases {
            let r = std::panic::catch_unwind(|| validate_aip_id(c));
            assert!(r.is_ok(), "validate_aip_id panicked on {c:?}");
            assert!(r.unwrap().is_err(), "malformed id {c:?} was accepted");
        }
        // Boundary sweep: a 2-byte char at every position around the split.
        for n in 0..12 {
            let s = format!("aip1{}é{}", "a".repeat(n), "b".repeat(11 - n));
            let r = std::panic::catch_unwind(|| validate_aip_id(&s));
            assert!(r.is_ok(), "validate_aip_id panicked on {s:?}");
            assert!(r.unwrap().is_err());
        }
    }

    /// PR3 A-2. An Ed25519 signature whose `algorithm` label claims a
    /// post-quantum suite must not verify as Ed25519: the label would then be
    /// a lie the whole evidence chain carries as fact (I7).
    #[test]
    fn test_algorithm_label_cannot_lie() {
        let kp = generate_ed25519_keypair();
        let signer_id = "aip1labeller";
        let payload_hash = sha256(b"payload");
        let timestamp = 1_700_000_000_000u64;
        let nonce = [7u8; 16];
        // Reproduce the envelope exactly, but stamp a PQC algorithm byte.
        let mut signed_input = Vec::new();
        signed_input.push(AlgorithmId::MlDsa65 as u8);
        signed_input.extend_from_slice(signer_id.as_bytes());
        signed_input.extend_from_slice(&timestamp.to_le_bytes());
        signed_input.extend_from_slice(&nonce);
        signed_input.extend_from_slice(&payload_hash);
        let signed_bytes = sha256(&signed_input);
        let signing_key = SigningKey::from_bytes(kp.private_key.as_slice().try_into().unwrap());
        let sig_bytes = signing_key.sign(&signed_bytes).to_bytes().to_vec();
        let lying = Signature {
            algorithm: AlgorithmId::MlDsa65,
            signer_id: signer_id.to_string(),
            timestamp,
            nonce,
            payload_hash,
            signature_bytes: sig_bytes,
        };
        let result = verify_ed25519(&kp.public_key, &lying);
        assert!(
            !matches!(result, Ok(true)),
            "SECURITY: an Ed25519 signature labelled MlDsa65 verified as valid: {result:?}"
        );
        // And a Hybrid label likewise.
        let mut hybrid = lying.clone();
        hybrid.algorithm = AlgorithmId::Hybrid;
        assert!(!matches!(verify_ed25519(&kp.public_key, &hybrid), Ok(true)));
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = generate_ed25519_keypair();
        let prov = ProvenanceTriple {
            model_commitment: [0u8; 32],
            environment_commitment: [0u8; 32],
            toolchain_commitment: [0u8; 32],
        };
        let id = derive_aip_id(&kp.public_key, &prov);
        let payload = b"Hello, AIP!";

        let sig = sign_ed25519(&kp.private_key, &id, payload).unwrap();
        let valid = verify_ed25519(&kp.public_key, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_verify_tampered() {
        let kp = generate_ed25519_keypair();
        let id = "aip1test";
        let sig = sign_ed25519(&kp.private_key, id, b"original").unwrap();

        // Tamper with payload hash
        let mut tampered = sig.clone();
        tampered.payload_hash[0] ^= 0xFF;
        let valid = verify_ed25519(&kp.public_key, &tampered).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_merkle_helpers() {
        let leaf = merkle_leaf(b"test data");
        let empty = merkle_empty();
        let internal = merkle_internal(&leaf, &empty);
        assert_ne!(leaf, empty);
        assert_ne!(internal, leaf);
    }

    #[test]
    fn test_raw_sign_verify_roundtrip() {
        let kp = generate_ed25519_keypair();
        let msg = b"audit-export manifest bytes";
        let sig = sign_ed25519_raw(&kp.private_key, msg).unwrap();
        assert!(verify_ed25519_raw(&kp.public_key, msg, &sig));
        // Wrong message fails.
        assert!(!verify_ed25519_raw(&kp.public_key, b"different", &sig));
        // Wrong key fails.
        let other = generate_ed25519_keypair();
        assert!(!verify_ed25519_raw(&other.public_key, msg, &sig));
    }
}
