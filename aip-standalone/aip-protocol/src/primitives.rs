//! Cryptographic primitives used by AIP v4.

use crate::errors::{AipError, AipResult};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub use aip_types::{AlgorithmId, PublicKey, Signature};

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub algorithm: AlgorithmId,
    pub public_key: PublicKey,
    pub private_key: Vec<u8>,
}

impl KeyPair {
    pub fn generate_ed25519() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            algorithm: AlgorithmId::Ed25519,
            public_key: PublicKey {
                algorithm: AlgorithmId::Ed25519,
                key_bytes: verifying_key.to_bytes().to_vec(),
            },
            private_key: signing_key.to_bytes().to_vec(),
        }
    }

    pub fn generate_mldsa65() -> Self {
        let (public_key, private_key) = dilithium3::keypair();
        Self {
            algorithm: AlgorithmId::MlDsa65,
            public_key: PublicKey {
                algorithm: AlgorithmId::MlDsa65,
                key_bytes: public_key.as_bytes().to_vec(),
            },
            private_key: private_key.as_bytes().to_vec(),
        }
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

pub(crate) fn signed_metadata_hash(signature: &Signature) -> [u8; 32] {
    let mut input = Vec::new();
    input.push(signature.algorithm as u8);
    input.extend_from_slice(signature.signer_id.as_bytes());
    input.extend_from_slice(&signature.timestamp.to_le_bytes());
    input.extend_from_slice(&signature.nonce);
    input.extend_from_slice(&signature.payload_hash);
    sha256(&input)
}

pub fn sign_ed25519_payload(
    private_key: &[u8],
    signer_id: &str,
    payload: &[u8],
    timestamp: u64,
) -> AipResult<Signature> {
    let private_key: [u8; 32] = private_key
        .try_into()
        .map_err(|_| AipError::InvalidPrivateKey)?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let payload_hash = sha256(payload);
    let mut signature = Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: signer_id.to_string(),
        timestamp,
        nonce: generate_nonce(),
        payload_hash,
        signature_bytes: Vec::new(),
    };
    let signed_bytes = signed_metadata_hash(&signature);
    signature.signature_bytes = signing_key.sign(&signed_bytes).to_bytes().to_vec();
    Ok(signature)
}

pub fn sign_mldsa65_payload(
    private_key: &[u8],
    signer_id: &str,
    payload: &[u8],
    timestamp: u64,
) -> AipResult<Signature> {
    let signing_key =
        dilithium3::SecretKey::from_bytes(private_key).map_err(|_| AipError::InvalidPrivateKey)?;
    let payload_hash = sha256(payload);
    let mut signature = Signature {
        algorithm: AlgorithmId::MlDsa65,
        signer_id: signer_id.to_string(),
        timestamp,
        nonce: generate_nonce(),
        payload_hash,
        signature_bytes: Vec::new(),
    };
    let signed_bytes = signed_metadata_hash(&signature);
    signature.signature_bytes = dilithium3::detached_sign(&signed_bytes, &signing_key)
        .as_bytes()
        .to_vec();
    Ok(signature)
}

pub fn verify_payload_signature(
    public_key: &PublicKey,
    payload: &[u8],
    signature: &Signature,
) -> AipResult<()> {
    if public_key.algorithm != signature.algorithm {
        return Err(AipError::SignatureInvalid);
    }
    if signature.payload_hash != sha256(payload) {
        return Err(AipError::SignatureInvalid);
    }

    let signed_bytes = signed_metadata_hash(signature);
    match public_key.algorithm {
        AlgorithmId::Ed25519 => verify_ed25519_signature(public_key, signature, &signed_bytes),
        AlgorithmId::MlDsa65 => verify_mldsa65_signature(public_key, signature, &signed_bytes),
        AlgorithmId::Hybrid => Err(AipError::SignatureInvalid),
    }
}

fn verify_ed25519_signature(
    public_key: &PublicKey,
    signature: &Signature,
    signed_bytes: &[u8; 32],
) -> AipResult<()> {
    if public_key.key_bytes.len() != 32 {
        return Err(AipError::InvalidPublicKey);
    }
    if signature.signature_bytes.len() != 64 {
        return Err(AipError::SignatureInvalid);
    }
    let key_bytes: [u8; 32] = public_key
        .key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AipError::InvalidPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| AipError::InvalidPublicKey)?;
    let sig_bytes: [u8; 64] = signature
        .signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AipError::SignatureInvalid)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(signed_bytes, &sig)
        .map_err(|_| AipError::SignatureInvalid)
}

fn verify_mldsa65_signature(
    public_key: &PublicKey,
    signature: &Signature,
    signed_bytes: &[u8; 32],
) -> AipResult<()> {
    let verifying_key = dilithium3::PublicKey::from_bytes(&public_key.key_bytes)
        .map_err(|_| AipError::InvalidPublicKey)?;
    let detached_signature = dilithium3::DetachedSignature::from_bytes(&signature.signature_bytes)
        .map_err(|_| AipError::SignatureInvalid)?;
    dilithium3::verify_detached_signature(&detached_signature, signed_bytes, &verifying_key)
        .map_err(|_| AipError::SignatureInvalid)
}
