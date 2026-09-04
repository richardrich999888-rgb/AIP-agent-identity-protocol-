//! The deterministic accountability core: one implementation of the
//! canonical bytes, hash chains, Merkle roots, and lifecycle law that every
//! consumer — the native `ot-verifier` CLI, the browser (compiled to
//! `wasm32-unknown-unknown` behind the `wasm` feature), and any future
//! service — shares. Writer and verifier drift is impossible when there is
//! only one definition of the bytes.
//!
//! # Byte compatibility with the TypeScript writer
//!
//! Every chain uses `SHA-256(previousHash + canonicalJson(record minus its
//! two chain fields))`, where canonical JSON is compact serialization with
//! recursively sorted object keys. `serde_json`'s default `Map` is
//! BTree-backed, so ordinary compact serialization of a parsed `Value` *is*
//! the canonical form — one representation, produced by the parser itself,
//! not a re-implementation that could drift. The `float_roundtrip` feature
//! keeps parsed doubles bit-faithful so re-serialized numbers reproduce the
//! JavaScript writer's shortest-round-trip formatting. The same code path
//! runs natively and under WASM, which is what makes the encoding
//! byte-deterministic across targets.
//!
//! Known representational limits (documented, not silent): JavaScript key
//! sorting is UTF-16 code-unit order while this crate sorts UTF-8 bytes —
//! identical for the ASCII keys these schemas use; and JSON text containing
//! lone surrogates or negative zero would not round-trip identically. None
//! occur in records the console writes.

pub mod aip;
pub mod authority;
pub mod authority_journal;
pub mod chain;
pub mod identity;
pub mod lifecycle;
pub mod merkle;
pub mod stream;
#[cfg(feature = "wasm")]
pub mod wasm;

use sha2::{Digest, Sha256};

/// The published genesis constant every chain starts from.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Canonical JSON bytes of a value: compact, keys recursively sorted.
/// `serde_json`'s default map is a `BTreeMap`, so plain compact
/// serialization of a parsed `Value` is already canonical.
pub fn canonical_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).expect("a parsed Value always serializes")
}

/// Lowercase hex SHA-256 of a string, matching the console's `sha256Hex`.
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// True for a well-formed lowercase 64-hex digest.
pub fn is_hex_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// True for the all-zero placeholder digest — structurally valid, but it
/// attests nothing, which strict consumers treat as a failure.
pub fn is_placeholder_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b == b'0')
}

/// Canonical bytes of a chained record: the record minus its chain fields —
/// the exact payload the TypeScript writers hash.
pub fn chain_payload_bytes(record: &serde_json::Value, chain_fields: &[&str]) -> String {
    let mut copy = record.clone();
    if let Some(obj) = copy.as_object_mut() {
        for field in chain_fields {
            obj.remove(*field);
        }
    }
    canonical_json(&copy)
}

/// Seals the next link: `SHA-256(previous_hash + payload_bytes)`.
pub fn seal_hash(previous_hash: &str, payload_bytes: &str) -> String {
    sha256_hex(&format!("{previous_hash}{payload_bytes}"))
}
