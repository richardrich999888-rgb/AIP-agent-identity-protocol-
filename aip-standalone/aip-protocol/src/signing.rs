//! Signing helpers for AIP v4 records.

use crate::errors::AipResult;
use crate::primitives::{sign_ed25519_payload, KeyPair, Signature};

pub fn sign_payload(
    key_pair: &KeyPair,
    signer_id: &str,
    payload: &[u8],
    timestamp: u64,
) -> AipResult<Signature> {
    sign_ed25519_payload(&key_pair.private_key, signer_id, payload, timestamp)
}
