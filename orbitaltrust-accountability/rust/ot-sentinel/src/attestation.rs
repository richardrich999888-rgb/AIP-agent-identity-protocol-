//! Attesting the sensor's own stream, the same way the ledger attests an
//! agent's.
//!
//! Every other stream this crate holds an opinion about — the lifecycle
//! anchor chain, the evidence packet chain — is hash-chained and checked for
//! breaks by [`crate::detector::ChainIntegrityDetector`]. The sensor's raw
//! input never was: [`crate::sensors::JsonlAccessLog`] read whatever bytes
//! were on disk and trusted them, with [`crate::observation::Sensor::trusted`]
//! standing in for a proof that never existed. An operator vouching for a
//! sensor is a policy decision worth recording; it is not a substitute for
//! knowing the bytes the sensor read are the bytes the tool server actually
//! wrote, or for knowing the sensor was watching at all during a given
//! window.
//!
//! A [`SensorCheckpoint`] closes both gaps the same way the rest of this
//! crate closes gaps: with arithmetic instead of a trust flag. Each patrol,
//! the tailer's running hash over every line it has consumed so far is
//! sealed onto the sentinel's own chain as a `SENSOR_STREAM_ATTESTATION`
//! anchor — the exact same construction
//! ([`SHA-256(previous ‖ payload)`](ot_accountability_core::seal_hash)) the
//! evidence chain uses, applied to the sensor's raw input instead of a
//! sealed packet. Two things become checkable that were previously assumed:
//!
//! - **Forgery.** [`crate::sensors::JsonlAccessLog::deep_verify`] re-reads
//!   the file from the tailer's own starting point and recomputes the same
//!   chain; any earlier checkpoint whose live recomputation no longer
//!   matches its sealed hash proves the file changed after being attested —
//!   arithmetic, not inference, so
//!   [`crate::detector::SensorIntegrityDetector`] reaches
//!   [`crate::finding::Strength::Proof`] the same way a broken evidence
//!   chain does.
//! - **Silence.** A sensor that stops checkpointing is a sensor whose
//!   declared coverage nobody can back up for however long it stayed quiet.
//!   Coverage was previously a static, all-or-nothing declaration;
//!   [`crate::detector::SensorLivenessDetector`] makes an unattested gap in
//!   that declaration a first-class, sealed finding instead of a silence
//!   that reads identically to a clean patrol.

use ot_accountability_core::{seal_hash, GENESIS_HASH};
use serde_json::{json, Value};

/// The anchor type a sealed checkpoint is written under.
pub const SENSOR_STREAM_ATTESTATION: &str = "SENSOR_STREAM_ATTESTATION";

/// Extends a running stream hash by one more line's raw bytes.
///
/// The same construction as [`ot_accountability_core::seal_hash`], applied
/// to a log line instead of a chained record's canonical payload. Exposed
/// so [`crate::sensors::JsonlAccessLog`]'s incremental poll and its full-file
/// `deep_verify` compute the identical chain — the property this whole
/// mechanism depends on, since a tamper detector that hashes its two sides
/// differently would never agree even on an untampered file.
pub fn extend_stream_hash(previous: &str, line: &str) -> String {
    seal_hash(previous, line)
}

/// One sealed position in a sensor's stream: "as of this many bytes
/// consumed from where this tailer started, the running hash over every
/// line was this."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorCheckpoint {
    /// Which sensor this checkpoint belongs to.
    pub sensor: String,
    /// Bytes consumed from the stream as of this checkpoint, measured from
    /// the tailer's own starting offset (0 for a tailer reading from the
    /// beginning; the file length at attach time for one started with
    /// [`crate::sensors::JsonlAccessLog::from_end`]) — never from absolute
    /// byte zero of a file the sensor was never asked to vouch for before
    /// that point.
    pub offset: u64,
    /// `SHA-256` chain over every line consumed so far:
    /// `H(H(...H(GENESIS, line_1)...), line_n)`.
    pub stream_tail_hash: String,
    /// When this checkpoint was taken. Liveness is read from this field: a
    /// sensor is "covering" only up to its most recent checkpoint, and a gap
    /// past the deadline is exactly what
    /// [`crate::detector::SensorLivenessDetector`] flags.
    pub checkpointed_at_utc: String,
}

impl SensorCheckpoint {
    /// The canonical payload sealed into the `SENSOR_STREAM_ATTESTATION`
    /// anchor.
    pub fn to_payload(&self) -> Value {
        json!({
            "sensor": self.sensor,
            "offset": self.offset,
            "streamTailHash": self.stream_tail_hash,
            "checkpointedAtUtc": self.checkpointed_at_utc,
        })
    }

    /// Reads back what [`SensorCheckpoint::to_payload`] sealed.
    ///
    /// The inverse exists so a checkpoint history can survive a restart via
    /// [`crate::state::PatrolState`]. Strict about every field: a checkpoint
    /// missing its hash or its offset cannot be verified against anything,
    /// and a silently-defaulted one would be worse than absent — it would
    /// recompute against the wrong position and read as a tamper.
    pub fn from_payload(value: &Value) -> Result<Self, String> {
        let field = |name: &str| -> Result<&str, String> {
            value
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("checkpoint is missing a string \"{name}\""))
        };
        Ok(Self {
            sensor: field("sensor")?.to_string(),
            offset: value
                .get("offset")
                .and_then(Value::as_u64)
                .ok_or("checkpoint is missing an unsigned \"offset\"")?,
            stream_tail_hash: field("streamTailHash")?.to_string(),
            checkpointed_at_utc: field("checkpointedAtUtc")?.to_string(),
        })
    }
}

/// A previously sealed checkpoint whose live recomputation disagrees with
/// what was sealed — proof the stream changed after attestation, or that it
/// no longer reaches the attested offset at all (truncation is tampering
/// too: something that was there was removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TamperedCheckpoint {
    /// The sensor whose stream no longer recomputes.
    pub sensor: String,
    /// The offset the mismatch was found at.
    pub offset: u64,
    /// What was sealed.
    pub sealed_hash: String,
    /// What the current file content recomputes to at that offset, or a
    /// stated reason it could not be reached (e.g. the file is now shorter
    /// than the checkpoint's offset).
    pub recomputed_hash: String,
}

/// The identity element a stream's running hash starts from — the same
/// [`GENESIS_HASH`] every other chain in this workspace starts from, so a
/// sensor stream with nothing consumed yet and a lifecycle chain with no
/// anchors yet are, deliberately, indistinguishable: neither has attested
/// anything.
pub fn stream_genesis() -> String {
    GENESIS_HASH.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extending_the_same_genesis_with_the_same_lines_agrees() {
        let a = extend_stream_hash(&extend_stream_hash(&stream_genesis(), "l1"), "l2");
        let b = extend_stream_hash(&extend_stream_hash(&stream_genesis(), "l1"), "l2");
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_line_produces_a_different_tail() {
        let a = extend_stream_hash(&stream_genesis(), "line-a");
        let b = extend_stream_hash(&stream_genesis(), "line-b");
        assert_ne!(a, b);
    }

    #[test]
    fn checkpoint_payload_carries_every_field_a_verifier_needs() {
        let checkpoint = SensorCheckpoint {
            sensor: "tool-server-log".into(),
            offset: 128,
            stream_tail_hash: "a".repeat(64),
            checkpointed_at_utc: "2026-08-28T00:00:00.000Z".into(),
        };
        let payload = checkpoint.to_payload();
        assert_eq!(payload["sensor"], "tool-server-log");
        assert_eq!(payload["offset"], 128);
        assert_eq!(payload["streamTailHash"], "a".repeat(64));
        assert_eq!(payload["checkpointedAtUtc"], "2026-08-28T00:00:00.000Z");
    }
}
