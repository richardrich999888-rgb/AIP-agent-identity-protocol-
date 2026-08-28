//! Browser bindings: the same deterministic core, compiled to
//! `wasm32-unknown-unknown` and exposed through `wasm-bindgen`.
//!
//! Inputs and outputs are JSON strings rather than structured `JsValue`s —
//! one serialization boundary, owned by the same canonical serializer the
//! hashes use, with no `serde-wasm-bindgen` dependency to drift. Verdicts
//! come back as the camelCase `ChainVerdict` JSON the TypeScript layer
//! already speaks; malformed input raises a `JsError` so the TS wrapper's
//! try/catch (and its Web Crypto fallback) engages naturally.

use wasm_bindgen::prelude::*;

use crate::chain::{verify_anchor_chain, verify_packet_chain};
use crate::merkle::merkle_root;
use crate::{canonical_json, chain_payload_bytes, sha256_hex};

fn parse_array(json: &str, what: &str) -> Result<Vec<serde_json::Value>, JsError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| JsError::new(&format!("{what}: {e}")))?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| JsError::new(&format!("{what}: expected a JSON array")))
}

/// Verifies a NEXORA lifecycle anchor chain. Takes the anchors as a JSON
/// array string; returns the `ChainVerdict` as JSON
/// (`{valid, total, brokenSequence?, reason?}`).
#[wasm_bindgen]
pub fn verify_anchor_chain_wasm(chain_json: &str) -> Result<String, JsError> {
    let anchors = parse_array(chain_json, "anchor chain")?;
    Ok(serde_json::to_string(&verify_anchor_chain(&anchors)).expect("verdict serializes"))
}

/// Verifies an AIP evidence packet chain. Same contract as
/// [`verify_anchor_chain_wasm`].
#[wasm_bindgen]
pub fn verify_evidence_packets_wasm(packets_json: &str) -> Result<String, JsError> {
    let packets = parse_array(packets_json, "evidence packets")?;
    Ok(serde_json::to_string(&verify_packet_chain(&packets)).expect("verdict serializes"))
}

/// Canonical evidence hash of one record: SHA-256 over the canonical bytes
/// of the record minus its own chain-link fields — the exact payload digest
/// the sealers commit to. The tier is detected from the fields present;
/// packets are checked first because a packet also carries an `anchorHash`,
/// which is its lifecycle *binding* (payload), not a chain link.
#[wasm_bindgen]
pub fn compute_canonical_evidence_hash_wasm(packet_json: &str) -> Result<String, JsError> {
    let value: serde_json::Value =
        serde_json::from_str(packet_json).map_err(|e| JsError::new(&format!("packet: {e}")))?;
    let chain_fields: [&str; 2] = if value.get("packetHash").is_some() {
        ["previousPacketHash", "packetHash"]
    } else if value.get("anchorHash").is_some() {
        ["previousAnchorHash", "anchorHash"]
    } else {
        ["previousHash", "chainHash"]
    };
    Ok(sha256_hex(&chain_payload_bytes(&value, &chain_fields)))
}

/// SHA-256 over the canonical bytes of an arbitrary JSON value — the
/// primitive behind root digests and state-snapshot hashes.
#[wasm_bindgen]
pub fn canonical_sha256_wasm(value_json: &str) -> Result<String, JsError> {
    let value: serde_json::Value =
        serde_json::from_str(value_json).map_err(|e| JsError::new(&format!("value: {e}")))?;
    Ok(sha256_hex(&canonical_json(&value)))
}

/// SHA-256 of a raw UTF-8 string, as lowercase hex — the digest primitive
/// the TypeScript telemetry stack installs as its hash provider, so every
/// browser-side seal is computed by the same core the offline verifier
/// recomputes it with.
#[wasm_bindgen]
pub fn sha256_hex_wasm(text: &str) -> String {
    sha256_hex(text)
}

/// Merkle root over an execution evidence set: takes a JSON array of hex
/// leaf hashes, returns the root hex digest.
#[wasm_bindgen]
pub fn merkle_root_wasm(leaf_hashes_json: &str) -> Result<String, JsError> {
    let leaves = parse_array(leaf_hashes_json, "leaf hashes")?;
    let hex: Vec<String> = leaves
        .iter()
        .map(|v| v.as_str().map(String::from))
        .collect::<Option<_>>()
        .ok_or_else(|| JsError::new("leaf hashes: expected an array of strings"))?;
    Ok(merkle_root(&hex))
}
