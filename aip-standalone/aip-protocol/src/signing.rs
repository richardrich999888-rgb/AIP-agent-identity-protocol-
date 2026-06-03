//! Signing helpers for AIP v4 records.

use crate::errors::AipResult;
use crate::primitives::{
    sign_ed25519_payload, sign_mldsa65_payload, AlgorithmId, KeyPair, Signature,
};

pub fn sign_payload(
    key_pair: &KeyPair,
    signer_id: &str,
    payload: &[u8],
    timestamp: u64,
) -> AipResult<Signature> {
    match key_pair.algorithm {
        AlgorithmId::Ed25519 => {
            sign_ed25519_payload(&key_pair.private_key, signer_id, payload, timestamp)
        }
        AlgorithmId::MlDsa65 => {
            sign_mldsa65_payload(&key_pair.private_key, signer_id, payload, timestamp)
        }
        AlgorithmId::Hybrid => Err(crate::errors::AipError::SignatureInvalid),
    }
}
