//! Hash-chain verification: monotonic sequences from 1, previous-hash
//! linkage from the genesis constant, and per-record digest recomputation.
//! The verdict shape serializes camelCase so the WASM consumer's
//! `VerificationResult` and the TypeScript `ChainVerdict` read identically.

use serde::Serialize;
use serde_json::Value;

use crate::stream::StreamingChainVerifier;

/// Outcome of verifying one hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainVerdict {
    /// True when every link recomputes.
    pub valid: bool,
    /// Number of records examined.
    pub total: usize,
    /// Sequence number of the first record that fails, when invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_sequence: Option<u64>,
    /// Human-readable reason for the first failure, when invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ChainVerdict {
    fn valid(total: usize) -> Self {
        Self {
            valid: true,
            total,
            broken_sequence: None,
            reason: None,
        }
    }

    fn broken(total: usize, sequence: u64, reason: String) -> Self {
        Self {
            valid: false,
            total,
            broken_sequence: Some(sequence),
            reason: Some(reason),
        }
    }
}

/// Verifies a generic hash chain: `records[i].sequenceNumber == i+1`,
/// `records[i].<prev_field>` equals the preceding record's `<hash_field>`
/// (the genesis constant for the first), and every `<hash_field>` recomputes
/// as `SHA-256(previous + canonical(record minus the two chain fields))`.
///
/// A fold over [`StreamingChainVerifier`], so batch and streaming
/// verification cannot disagree about a rule or a message.
pub fn verify_hash_chain(
    records: &[Value],
    prev_field: &'static str,
    hash_field: &'static str,
) -> ChainVerdict {
    let mut verifier = StreamingChainVerifier::new(prev_field, hash_field);
    for record in records {
        if let Err(broken) = verifier.push(record) {
            return ChainVerdict::broken(records.len(), broken.sequence, broken.reason);
        }
    }
    ChainVerdict::valid(records.len())
}

/// NEXORA anchor chain: `previousAnchorHash` / `anchorHash`.
pub fn verify_anchor_chain(anchors: &[Value]) -> ChainVerdict {
    verify_hash_chain(anchors, "previousAnchorHash", "anchorHash")
}

/// AIP evidence packet chain: `previousPacketHash` / `packetHash`.
pub fn verify_packet_chain(packets: &[Value]) -> ChainVerdict {
    verify_hash_chain(packets, "previousPacketHash", "packetHash")
}

/// Agent action ledger chain: `previousHash` / `chainHash`.
pub fn verify_ledger_chain(entries: &[Value]) -> ChainVerdict {
    verify_hash_chain(entries, "previousHash", "chainHash")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chain_payload_bytes, seal_hash, GENESIS_HASH};
    use serde_json::json;

    fn sealed_chain(n: usize) -> Vec<Value> {
        let mut records = Vec::new();
        let mut previous = GENESIS_HASH.to_string();
        for i in 0..n {
            let mut record = json!({
                "sequenceNumber": i + 1,
                "payload": { "index": i },
            });
            let hash = seal_hash(
                &previous,
                &chain_payload_bytes(&record, &["previousPacketHash", "packetHash"]),
            );
            record["previousPacketHash"] = json!(previous);
            record["packetHash"] = json!(hash);
            previous = hash;
            records.push(record);
        }
        records
    }

    #[test]
    fn a_sealed_chain_verifies() {
        let verdict = verify_packet_chain(&sealed_chain(4));
        assert!(verdict.valid);
        assert_eq!(verdict.total, 4);
    }

    #[test]
    fn an_edited_record_breaks_at_its_sequence_and_camel_cases_the_verdict() {
        let mut records = sealed_chain(4);
        records[1]["payload"]["index"] = json!(99);
        let verdict = verify_packet_chain(&records);
        assert!(!verdict.valid);
        assert_eq!(verdict.broken_sequence, Some(2));
        let json = serde_json::to_string(&verdict).unwrap();
        assert!(json.contains("\"brokenSequence\":2"), "{json}");
    }

    #[test]
    fn the_empty_chain_is_vacuously_valid() {
        assert!(verify_anchor_chain(&[]).valid);
    }
}
