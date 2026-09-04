//! Streaming, checkpoint-resumable chain verification — the scale layer.
//!
//! Batch verification loads a whole chain and walks it; at fleet scale
//! (millions of agents, each with an unbounded history) neither "load the
//! whole chain" nor "re-verify from genesis on every append" survives. This
//! module gives both consumers what they need from one implementation:
//!
//! - [`StreamingChainVerifier`] consumes records one at a time in **O(1)
//!   memory** — its entire state is the expected previous hash and the next
//!   sequence number. An ingestion hub keeps one per live chain (~200 bytes
//!   per agent: two tails and counters, so ten million agents fit in a few
//!   gigabytes on one node, sharded horizontally by DID beyond that);
//! - [`Checkpoint`] captures a verified chain position, and
//!   [`StreamingChainVerifier::resume`] restarts from it — verifying a
//!   long-lived agent becomes O(records since the last trusted checkpoint)
//!   instead of O(lifetime);
//! - the batch [`crate::chain::verify_hash_chain`] is a fold over this
//!   verifier, so streaming and batch cannot disagree about a single rule
//!   or message.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{chain_payload_bytes, seal_hash, GENESIS_HASH};

/// A verified chain position: everything needed to continue verification
/// without the records before it. Trust in a checkpoint is trust in
/// whoever sealed it — pair it with a signature or a prior verification
/// run; the math here only guarantees continuation is consistent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    /// Sequence number of the last verified record.
    pub sequence_number: u64,
    /// That record's chain hash — the tail the next record must link to.
    pub tail_hash: String,
}

/// A chain break: the first offending sequence and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    pub sequence: u64,
    pub reason: String,
}

/// Incremental hash-chain verifier. Push records in order; the first
/// failure is returned and latched (later pushes keep failing with it).
#[derive(Debug, Clone)]
pub struct StreamingChainVerifier {
    prev_field: &'static str,
    hash_field: &'static str,
    expected_previous: String,
    next_sequence: u64,
    verified: u64,
    broken: Option<ChainBreak>,
}

impl StreamingChainVerifier {
    /// A verifier starting at genesis.
    pub fn new(prev_field: &'static str, hash_field: &'static str) -> Self {
        Self::resume(
            prev_field,
            hash_field,
            &Checkpoint {
                sequence_number: 0,
                tail_hash: GENESIS_HASH.to_string(),
            },
        )
    }

    /// A verifier continuing from a previously verified position.
    pub fn resume(
        prev_field: &'static str,
        hash_field: &'static str,
        checkpoint: &Checkpoint,
    ) -> Self {
        Self {
            prev_field,
            hash_field,
            expected_previous: checkpoint.tail_hash.clone(),
            next_sequence: checkpoint.sequence_number + 1,
            verified: checkpoint.sequence_number,
            broken: None,
        }
    }

    /// Checks the record against the current position without mutating
    /// anything. Returns the sealed hash to commit on success.
    fn validate(&self, record: &Value) -> Result<String, ChainBreak> {
        let sequence = record
            .get("sequenceNumber")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if sequence != self.next_sequence {
            return Err(ChainBreak {
                sequence,
                reason: format!(
                    "sequence gap at index {}: expected {}, found {sequence}",
                    self.next_sequence - 1,
                    self.next_sequence,
                ),
            });
        }
        let previous = record
            .get(self.prev_field)
            .and_then(Value::as_str)
            .unwrap_or("");
        if previous != self.expected_previous {
            return Err(ChainBreak {
                sequence,
                reason: format!(
                    "{} of sequence {sequence} does not match the preceding record's hash",
                    self.prev_field,
                ),
            });
        }
        let recorded = record
            .get(self.hash_field)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let recomputed = seal_hash(
            &self.expected_previous,
            &chain_payload_bytes(record, &[self.prev_field, self.hash_field]),
        );
        if recomputed != recorded {
            return Err(ChainBreak {
                sequence,
                reason: format!(
                    "{} mismatch at sequence {sequence}: record modified after sealing \
                     (recomputed {}…, recorded {}…)",
                    self.hash_field,
                    &recomputed[..12],
                    recorded.get(..12).unwrap_or(&recorded),
                ),
            });
        }
        Ok(recorded)
    }

    fn commit(&mut self, recorded: String) {
        self.next_sequence += 1;
        self.verified = self.next_sequence - 1;
        self.expected_previous = recorded;
    }

    /// Verifies the next record of a **fixed stream**. O(record size); no
    /// history retained. The first failure latches: everything after a
    /// breach in a recorded stream is untrusted, so later pushes keep
    /// returning it.
    pub fn push(&mut self, record: &Value) -> Result<(), ChainBreak> {
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        match self.validate(record) {
            Ok(recorded) => {
                self.commit(recorded);
                Ok(())
            }
            Err(broken) => {
                self.broken = Some(broken.clone());
                Err(broken)
            }
        }
    }

    /// Verifies the next record of a **live ingestion feed**. A failure
    /// rejects the submission and leaves the verified tail untouched — the
    /// submitter retries with a correct record; the chain does not poison.
    pub fn try_push(&mut self, record: &Value) -> Result<(), ChainBreak> {
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        let recorded = self.validate(record)?;
        self.commit(recorded);
        Ok(())
    }

    /// Records verified so far (checkpoint sequence included when resumed).
    pub fn verified(&self) -> u64 {
        self.verified
    }

    /// The first break, if any.
    pub fn broken(&self) -> Option<&ChainBreak> {
        self.broken.as_ref()
    }

    /// The current verified position, for persistence and later
    /// [`resume`](Self::resume). None while broken — a breach has no
    /// trustworthy tail.
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        if self.broken.is_some() {
            return None;
        }
        Some(Checkpoint {
            sequence_number: self.verified,
            tail_hash: self.expected_previous.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::verify_hash_chain;
    use serde_json::json;

    fn sealed_chain(n: usize) -> Vec<Value> {
        let mut records = Vec::new();
        let mut previous = GENESIS_HASH.to_string();
        for i in 0..n {
            let mut record = json!({ "sequenceNumber": i + 1, "payload": { "i": i } });
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
    fn streaming_agrees_with_batch_on_valid_and_tampered_chains() {
        let valid = sealed_chain(6);
        let mut v = StreamingChainVerifier::new("previousPacketHash", "packetHash");
        for r in &valid {
            v.push(r).unwrap();
        }
        assert_eq!(v.verified(), 6);
        assert!(verify_hash_chain(&valid, "previousPacketHash", "packetHash").valid);

        let mut tampered = sealed_chain(6);
        tampered[2]["payload"]["i"] = json!(99);
        let mut v = StreamingChainVerifier::new("previousPacketHash", "packetHash");
        let mut first_break = None;
        for r in &tampered {
            if let Err(b) = v.push(r) {
                first_break = Some(b);
                break;
            }
        }
        let batch = verify_hash_chain(&tampered, "previousPacketHash", "packetHash");
        let stream_break = first_break.unwrap();
        assert_eq!(Some(stream_break.sequence), batch.broken_sequence);
        assert_eq!(Some(stream_break.reason), batch.reason);
    }

    #[test]
    fn a_break_latches_and_yields_no_checkpoint() {
        let mut records = sealed_chain(3);
        records[1]["payload"]["i"] = json!(7);
        let mut v = StreamingChainVerifier::new("previousPacketHash", "packetHash");
        v.push(&records[0]).unwrap();
        assert!(v.push(&records[1]).is_err());
        // The valid third record is still refused: a broken chain stays
        // broken, it does not resynchronize past the breach.
        assert!(v.push(&records[2]).is_err());
        assert!(v.checkpoint().is_none());
    }

    #[test]
    fn resuming_from_a_checkpoint_verifies_only_the_delta() {
        let records = sealed_chain(8);
        let mut first = StreamingChainVerifier::new("previousPacketHash", "packetHash");
        for r in &records[..4] {
            first.push(r).unwrap();
        }
        let checkpoint = first.checkpoint().unwrap();
        assert_eq!(checkpoint.sequence_number, 4);

        let mut resumed =
            StreamingChainVerifier::resume("previousPacketHash", "packetHash", &checkpoint);
        for r in &records[4..] {
            resumed.push(r).unwrap();
        }
        assert_eq!(resumed.verified(), 8);
        // And a delta that does not link to the checkpoint is refused.
        let mut wrong =
            StreamingChainVerifier::resume("previousPacketHash", "packetHash", &checkpoint);
        assert!(wrong.push(&records[5]).is_err());
    }
}
