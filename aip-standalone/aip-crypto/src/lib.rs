//! AIP Crypto — Ed25519 signing, SHA-256 hashing, Base58, AIP-ID derivation.

use aip_types::{AlgorithmId, KeyPair, ProvenanceTriple, Signature};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

const VERIFY_CACHE_LIMIT: usize = 4096;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct VerifyCacheKey {
    public_key: [u8; 32],
    algorithm: u8,
    signer_id: String,
    timestamp: u64,
    nonce: [u8; 16],
    payload_hash: [u8; 32],
    signature_bytes: Vec<u8>,
}

#[derive(Default)]
struct VerifyCache {
    results: HashMap<VerifyCacheKey, bool>,
    order: VecDeque<VerifyCacheKey>,
}

static VERIFY_CACHE: OnceLock<Mutex<VerifyCache>> = OnceLock::new();

fn verify_cache() -> &'static Mutex<VerifyCache> {
    VERIFY_CACHE.get_or_init(|| Mutex::new(VerifyCache::default()))
}

fn get_cached_verification(key: &VerifyCacheKey) -> Option<bool> {
    verify_cache()
        .lock()
        .ok()
        .and_then(|cache| cache.results.get(key).copied())
}

fn cache_verification(key: VerifyCacheKey, result: bool) {
    let Ok(mut cache) = verify_cache().lock() else {
        return;
    };

    if cache.results.contains_key(&key) {
        return;
    }

    cache.order.push_back(key.clone());
    cache.results.insert(key, result);

    while cache.order.len() > VERIFY_CACHE_LIMIT {
        if let Some(oldest) = cache.order.pop_front() {
            cache.results.remove(&oldest);
        }
    }
}

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

    // signed_bytes = SHA-256(algorithm || signer_id || timestamp || nonce || payload_hash)
    let mut signed_input = Vec::new();
    signed_input.push(AlgorithmId::Ed25519 as u8);
    signed_input.extend_from_slice(signer_id.as_bytes());
    signed_input.extend_from_slice(&timestamp.to_le_bytes());
    signed_input.extend_from_slice(&nonce);
    signed_input.extend_from_slice(&payload_hash);
    let signed_bytes = sha256(&signed_input);

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

    if signature.signature_bytes.len() != 64 {
        return Err(aip_types::AipError::SignatureInvalid);
    }

    let public_key_array: [u8; 32] = public_key
        .try_into()
        .map_err(|_| aip_types::AipError::InvalidPublicKey)?;

    let cache_key = VerifyCacheKey {
        public_key: public_key_array,
        algorithm: signature.algorithm as u8,
        signer_id: signature.signer_id.clone(),
        timestamp: signature.timestamp,
        nonce: signature.nonce,
        payload_hash: signature.payload_hash,
        signature_bytes: signature.signature_bytes.clone(),
    };

    if let Some(valid) = get_cached_verification(&cache_key) {
        return Ok(valid);
    }

    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| aip_types::AipError::InvalidPublicKey)?;

    // Reconstruct signed_bytes
    let mut signed_input = Vec::new();
    signed_input.push(signature.algorithm as u8);
    signed_input.extend_from_slice(signature.signer_id.as_bytes());
    signed_input.extend_from_slice(&signature.timestamp.to_le_bytes());
    signed_input.extend_from_slice(&signature.nonce);
    signed_input.extend_from_slice(&signature.payload_hash);
    let signed_bytes = sha256(&signed_input);

    let sig = ed25519_dalek::Signature::from_bytes(
        signature
            .signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| aip_types::AipError::SignatureInvalid)?,
    );

    let valid = verifying_key.verify(&signed_bytes, &sig).is_ok();
    cache_verification(cache_key, valid);
    Ok(valid)
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
}
