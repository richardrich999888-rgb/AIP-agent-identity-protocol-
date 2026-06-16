//! Deterministic, unambiguous byte encoding for EvidencePacket hashing and
//! signing.
//!
//! Every variable-length field is length-prefixed (u32 LE), so no two
//! distinct packets can produce the same canonical byte stream. This is the
//! load-bearing property for tamper detection: `packet_hash` and the agent
//! signature both cover these bytes.

use aip_types::{CapabilityScope, ScopeAction, Signature};

pub(crate) fn put_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

pub(crate) fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn put_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

pub(crate) fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

pub(crate) fn put_opt_str(buf: &mut Vec<u8>, s: &Option<String>) {
    match s {
        Some(v) => {
            put_u8(buf, 1);
            put_str(buf, v);
        }
        None => put_u8(buf, 0),
    }
}

pub(crate) fn put_opt_u64(buf: &mut Vec<u8>, v: &Option<u64>) {
    match v {
        Some(x) => {
            put_u8(buf, 1);
            put_u64(buf, *x);
        }
        None => put_u8(buf, 0),
    }
}

pub(crate) fn encode_scope_action(buf: &mut Vec<u8>, action: &ScopeAction) {
    match action {
        ScopeAction::Standard(a) => {
            put_u8(buf, 0x00);
            put_u8(buf, *a as u8);
        }
        ScopeAction::Custom(s) => {
            put_u8(buf, 0x01);
            put_str(buf, s);
        }
    }
}

pub(crate) fn encode_scope(buf: &mut Vec<u8>, scope: &CapabilityScope) {
    buf.extend_from_slice(&(scope.allowed.len() as u32).to_le_bytes());
    for a in &scope.allowed {
        encode_scope_action(buf, a);
    }
    buf.extend_from_slice(&(scope.denied.len() as u32).to_le_bytes());
    for d in &scope.denied {
        encode_scope_action(buf, d);
    }
}

/// Encode a full signature (used when a signature is *content* of the packet
/// — e.g. delegation issuer signatures and the counterparty receipt
/// signature — so that tampering with embedded signatures is detectable).
pub(crate) fn encode_signature(buf: &mut Vec<u8>, sig: &Signature) {
    put_u8(buf, sig.algorithm as u8);
    put_str(buf, &sig.signer_id);
    put_u64(buf, sig.timestamp);
    buf.extend_from_slice(&sig.nonce);
    buf.extend_from_slice(&sig.payload_hash);
    put_bytes(buf, &sig.signature_bytes);
}

pub(crate) fn put_opt_signature(buf: &mut Vec<u8>, sig: &Option<Signature>) {
    match sig {
        Some(s) => {
            put_u8(buf, 1);
            encode_signature(buf, s);
        }
        None => put_u8(buf, 0),
    }
}
