//! Deterministic, unambiguous byte encoding for every signed or hashed AIP
//! structure (authority tokens, delegation hops, capability grants, AID
//! self-signatures, EvidencePacket canonical bytes).
//!
//! Every variable-length field is length-prefixed (u32 LE), every `Option`
//! carries an explicit presence byte, and every signed payload begins with a
//! domain tag, so no two distinct values — and no two distinct *kinds* of
//! value — can produce the same byte stream. This is the load-bearing
//! property for signature soundness: a signature over these bytes commits to
//! exactly one interpretation.
//!
//! This module lives in `aip-types` (the dependency root) so that `aip-core`
//! authority code and `aip-protocol` packet code share one encoder rather
//! than each carrying its own.

use crate::{CapabilityScope, ScopeAction, Signature};

/// Write a domain-separation tag as the first element of a signed payload.
///
/// The tag enters the signed bytes, so a signature produced over one object
/// type can never verify as a signature over another type whose remaining
/// fields happen to serialize identically.
pub fn put_domain(buf: &mut Vec<u8>, domain: &str) {
    put_str(buf, domain);
}

pub fn put_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

pub fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Length-prefixed (u32 LE) byte string. Use for every variable-length
/// field. Fixed-width fields (e.g. a `[u8; 16]` JTI) may be appended raw.
pub fn put_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    put_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

pub fn put_opt_str(buf: &mut Vec<u8>, s: &Option<String>) {
    match s {
        Some(v) => {
            put_u8(buf, 1);
            put_str(buf, v);
        }
        None => put_u8(buf, 0),
    }
}

pub fn put_opt_u64(buf: &mut Vec<u8>, v: &Option<u64>) {
    match v {
        Some(x) => {
            put_u8(buf, 1);
            put_u64(buf, *x);
        }
        None => put_u8(buf, 0),
    }
}

pub fn encode_scope_action(buf: &mut Vec<u8>, action: &ScopeAction) {
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

pub fn encode_scope(buf: &mut Vec<u8>, scope: &CapabilityScope) {
    put_u32(buf, scope.allowed.len() as u32);
    for a in &scope.allowed {
        encode_scope_action(buf, a);
    }
    put_u32(buf, scope.denied.len() as u32);
    for d in &scope.denied {
        encode_scope_action(buf, d);
    }
}

/// Encode a full signature (used when a signature is *content* of the packet
/// — e.g. delegation issuer signatures and the counterparty receipt
/// signature — so that tampering with embedded signatures is detectable).
pub fn encode_signature(buf: &mut Vec<u8>, sig: &Signature) {
    put_u8(buf, sig.algorithm as u8);
    put_str(buf, &sig.signer_id);
    put_u64(buf, sig.timestamp);
    buf.extend_from_slice(&sig.nonce);
    buf.extend_from_slice(&sig.payload_hash);
    put_bytes(buf, &sig.signature_bytes);
}

pub fn put_opt_signature(buf: &mut Vec<u8>, sig: &Option<Signature>) {
    match sig {
        Some(s) => {
            put_u8(buf, 1);
            encode_signature(buf, s);
        }
        None => put_u8(buf, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Action;

    fn pair(a: &str, b: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        put_str(&mut buf, a);
        put_str(&mut buf, b);
        buf
    }

    #[test]
    fn adjacent_strings_are_injective() {
        // The classic raw-concatenation collision: "ab"+"c" == "a"+"bc".
        assert_ne!(pair("ab", "c"), pair("a", "bc"));
        assert_ne!(pair("", "abc"), pair("abc", ""));
        assert_ne!(pair("abc", ""), pair("ab", "c"));
    }

    #[test]
    fn interior_nul_is_unambiguous() {
        // A NUL inside a string must not be confusable with a terminator.
        assert_ne!(pair("a\0", "b"), pair("a", "\0b"));
        assert_ne!(pair("a\0b", ""), pair("a", "b"));
        let mut with_nul = Vec::new();
        encode_scope_action(&mut with_nul, &ScopeAction::Custom("x\0y".into()));
        let mut without = Vec::new();
        encode_scope_action(&mut without, &ScopeAction::Custom("x".into()));
        assert_ne!(with_nul, without);
        assert!(with_nul.len() > without.len());
    }

    #[test]
    fn option_presence_is_explicit() {
        let mut none = Vec::new();
        put_opt_u64(&mut none, &None);
        let mut some_zero = Vec::new();
        put_opt_u64(&mut some_zero, &Some(0));
        assert_ne!(none, some_zero);
        assert_eq!(none, vec![0u8]);
        assert_eq!(some_zero[0], 1u8);
    }

    #[test]
    fn scope_counts_prevent_allowed_denied_migration() {
        // Moving an action from `denied` into `allowed` must change the bytes
        // even though the multiset of actions is identical.
        let a = CapabilityScope {
            allowed: vec![ScopeAction::Standard(Action::Read)],
            denied: vec![ScopeAction::Standard(Action::Write)],
        };
        let b = CapabilityScope {
            allowed: vec![
                ScopeAction::Standard(Action::Read),
                ScopeAction::Standard(Action::Write),
            ],
            denied: vec![],
        };
        let mut ea = Vec::new();
        encode_scope(&mut ea, &a);
        let mut eb = Vec::new();
        encode_scope(&mut eb, &b);
        assert_ne!(ea, eb);
    }

    #[test]
    fn domain_tag_leads_payload() {
        let mut buf = Vec::new();
        put_domain(&mut buf, "AIP/Test/v1");
        put_u64(&mut buf, 7);
        let tag = b"AIP/Test/v1";
        assert_eq!(&buf[..4], &(tag.len() as u32).to_le_bytes());
        assert_eq!(&buf[4..4 + tag.len()], tag);
    }
}
