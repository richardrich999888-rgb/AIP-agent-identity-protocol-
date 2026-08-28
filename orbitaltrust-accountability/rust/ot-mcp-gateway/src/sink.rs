//! Where sealed evidence goes.
//!
//! The funnel keeps only chain heads, so something has to persist the records
//! themselves. A trait, because the right destination differs: a JSONL file
//! on an air-gapped host, the governance hub over the network, an in-memory
//! buffer in a test.
//!
//! # Durability is part of the guarantee
//!
//! A sink that loses a record silently turns "every call is evidenced" into
//! "every call the disk happened to keep is evidenced". [`EvidenceSink::record`]
//! therefore returns a `Result`, and the gateway surfaces a sink failure to
//! the caller as an error rather than swallowing it: a governed call whose
//! evidence could not be written did not happen, as far as the operator is
//! concerned, and the client needs to know that.

use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

/// A destination for sealed packets and lifecycle anchors.
pub trait EvidenceSink {
    /// Persists one sealed packet and, when the lifecycle chain was writable,
    /// its `ACTION_EXECUTION_SEAL` anchor.
    fn record(&mut self, packet: &Value, seal_anchor: Option<&Value>) -> Result<(), String>;

    /// Persists a lifecycle anchor written outside an execution — genesis, a
    /// model migration, a revocation.
    fn record_anchor(&mut self, anchor: &Value) -> Result<(), String>;
}

/// A boxed sink is a sink, so a caller who needs to choose a destination at
/// runtime can use `Box<dyn EvidenceSink + Send + Sync>` wherever a concrete
/// sink is expected, without the gateway giving up its static type.
impl<T: EvidenceSink + ?Sized> EvidenceSink for Box<T> {
    fn record(&mut self, packet: &Value, seal_anchor: Option<&Value>) -> Result<(), String> {
        (**self).record(packet, seal_anchor)
    }

    fn record_anchor(&mut self, anchor: &Value) -> Result<(), String> {
        (**self).record_anchor(anchor)
    }
}

/// Buffers everything in memory. For tests and for callers that drain it
/// themselves; it retains records without bound, so it is not a deployment
/// sink.
#[derive(Debug, Default)]
pub struct MemoryEvidenceSink {
    /// Sealed packets, in the order they were written.
    pub packets: Vec<Value>,
    /// Lifecycle anchors, in the order they were written.
    pub anchors: Vec<Value>,
}

impl MemoryEvidenceSink {
    /// An empty sink.
    pub fn new() -> Self {
        Self::default()
    }
}

impl EvidenceSink for MemoryEvidenceSink {
    fn record(&mut self, packet: &Value, seal_anchor: Option<&Value>) -> Result<(), String> {
        self.packets.push(packet.clone());
        if let Some(anchor) = seal_anchor {
            self.anchors.push(anchor.clone());
        }
        Ok(())
    }

    fn record_anchor(&mut self, anchor: &Value) -> Result<(), String> {
        self.anchors.push(anchor.clone());
        Ok(())
    }
}

/// Append-only JSONL on disk: one record per line, `{"kind":…,"record":…}`.
///
/// # One writer per file
///
/// Each gateway process keeps its own chain heads, so two processes appending
/// to one file interleave two independent chains and the result does not
/// verify when read linearly. Nothing here can detect that — the writes are
/// individually well-formed — so it is an operational constraint: one
/// evidence file belongs to one process. A fleet wants a sink per gateway, or
/// a hub sink that keeps chains apart by agent.
///
/// Flushed and `fsync`ed on every write. That costs a syscall per governed
/// call and is the right trade here — the file is the evidence, and evidence
/// buffered in a page cache when the host loses power is evidence that never
/// existed. Throughput belongs to a hub sink, not to the local audit trail.
pub struct JsonlEvidenceSink {
    writer: BufWriter<File>,
}

impl JsonlEvidenceSink {
    /// Opens (creating if needed) the JSONL ledger at `path` for appending.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|e| {
                format!(
                    "cannot open evidence ledger {}: {e}",
                    path.as_ref().display()
                )
            })?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    fn write_line(&mut self, kind: &str, record: &Value) -> Result<(), String> {
        let line = serde_json::json!({ "kind": kind, "record": record });
        serde_json::to_writer(&mut self.writer, &line)
            .map_err(|e| format!("cannot serialize evidence: {e}"))?;
        self.writer
            .write_all(b"\n")
            .map_err(|e| format!("cannot write evidence: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("cannot flush evidence: {e}"))?;
        self.writer
            .get_ref()
            .sync_data()
            .map_err(|e| format!("cannot sync evidence to disk: {e}"))
    }
}

impl EvidenceSink for JsonlEvidenceSink {
    fn record(&mut self, packet: &Value, seal_anchor: Option<&Value>) -> Result<(), String> {
        self.write_line("packet", packet)?;
        match seal_anchor {
            Some(anchor) => self.write_line("anchor", anchor),
            None => Ok(()),
        }
    }

    fn record_anchor(&mut self, anchor: &Value) -> Result<(), String> {
        self.write_line("anchor", anchor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_jsonl_sink_appends_a_readable_line_per_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        {
            let mut sink = JsonlEvidenceSink::open(&path).unwrap();
            sink.record(&json!({ "id": "p1" }), Some(&json!({ "id": "a1" })))
                .unwrap();
            sink.record(&json!({ "id": "p2" }), None).unwrap();
            sink.record_anchor(&json!({ "id": "a2" })).unwrap();
        }
        // Reopening appends rather than truncating: a restarted gateway must
        // never erase the trail it is meant to be keeping.
        {
            let mut sink = JsonlEvidenceSink::open(&path).unwrap();
            sink.record(&json!({ "id": "p3" }), None).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0]["kind"], json!("packet"));
        assert_eq!(lines[1]["kind"], json!("anchor"));
        assert_eq!(lines[1]["record"]["id"], json!("a1"));
        assert_eq!(lines[4]["record"]["id"], json!("p3"));
    }

    #[test]
    fn the_memory_sink_keeps_packets_and_anchors_in_write_order() {
        let mut sink = MemoryEvidenceSink::new();
        sink.record(&json!({ "n": 1 }), Some(&json!({ "n": "a" })))
            .unwrap();
        sink.record(&json!({ "n": 2 }), None).unwrap();
        assert_eq!(sink.packets.len(), 2);
        assert_eq!(sink.anchors.len(), 1);
    }
}
