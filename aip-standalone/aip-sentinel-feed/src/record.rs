//! The effect-log record: one line of what a kernel observer saw leave or run.
//!
//! # The schema is somebody else's
//!
//! These field names (`id`, `timestampUtc`, `kind`, `command`, `destination`,
//! `bytes`, `agentDid`) are the out-of-band reconciler's effect-log schema,
//! not a shape chosen here. This module exists so that fact is in one place:
//! if the consumer's schema moves, one file moves with it, and a conformance
//! test on the far side of the boundary fails loudly rather than the feed
//! quietly producing lines nothing parses.
//!
//! # Extra fields are deliberate, and safe
//!
//! `exeSha256` and `observer` are not in the consumer's schema. Its parser
//! reads the fields it knows and ignores the rest, so additive fields cost
//! nothing and give a human reading a finding the two things the schema
//! cannot carry: **what the executable actually was** (a path is context;
//! the content digest is identity), and **which observer said so**. Neither
//! is ever read back as part of a comparison.
//!
//! # Why `agentDid` is optional and never guessed
//!
//! The consumer reads a missing `agentDid` as an anonymous subject — "something
//! acted and nothing on the wire says who" — which is its strongest ghost
//! signal. AIP's own attribution is a *claim* recorded by the observer, never
//! a proof, and the consumer's `Claimed` subject carries exactly that meaning.
//! The two line up, so the mapping is direct: a claim is passed through as a
//! claim, and its absence is passed through as absence. Nothing is inferred
//! from a process tree, a path or a uid to fill the gap.

use aip_reconcile::EventPosition;
use serde_json::{Map, Value};

/// Which effect a record reports. The wire values are the consumer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectKind {
    /// A process was launched.
    Spawn,
    /// A connection to a remote endpoint was established.
    Egress,
}

impl EffectKind {
    /// The `kind` discriminator as the consumer's parser matches it.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Egress => "egress",
        }
    }

    /// The two-letter tag used in a record id.
    fn tag(self) -> &'static str {
        match self {
            Self::Spawn => "sp",
            Self::Egress => "eg",
        }
    }
}

/// The payload that distinguishes one kind from the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectDetail {
    /// What ran.
    Spawn {
        /// The kernel-resolved path of the executed image.
        ///
        /// This is **not** a command line: AIP observes `execve` through the
        /// scheduler tracepoint and does not capture `argv`. Rendering a bare
        /// path into a field the schema calls `command` is a scope difference
        /// that is stated here and in the feed's report, never padded out
        /// with invented arguments.
        path: String,
        /// SHA-256 of the executed file's contents, as the probe measured it.
        exe_sha256: String,
    },
    /// Where bytes went.
    Egress {
        /// Canonical `host:port`.
        destination: String,
        /// Bytes the kernel accepted on this socket, when a send was observed.
        ///
        /// `None` means *not measured*, which is not the same as zero. The
        /// connection was established — that is what the record asserts — and
        /// the volume is unknown. The field is omitted rather than written as
        /// `0`, because a zero a reader cannot distinguish from a measurement
        /// is worse than a silence they can.
        bytes: Option<u64>,
    },
}

/// One line of the effect log, with the provenance that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectRecord {
    /// Deterministic, sortable identifier, cited in any finding drawn from
    /// this line. See [`EffectRecord::new`] for its construction.
    pub id: String,
    /// RFC 3339 UTC with millisecond precision.
    pub timestamp_utc: String,
    /// Which effect.
    pub kind: EffectKind,
    /// The AIP identity *claimed* for the acting instance, if any was.
    pub agent_did: Option<String>,
    /// Kind-specific payload.
    pub detail: EffectDetail,
    /// Where in the attested evidence this line came from. Not serialised:
    /// the id already encodes it, and the consumer has no use for it. Kept so
    /// ordering is a property of the evidence rather than of the timestamps,
    /// which two events can share.
    pub position: EventPosition,
}

impl EffectRecord {
    /// Build a record, deriving its id from its position in the evidence.
    ///
    /// The id is `aip-<tag>-<batch sequence>-<event index>`, zero-padded so
    /// lexical order matches evidence order, and unique because no two events
    /// share a `(batch, index)` pair. An operator reading a finding can go
    /// from the id straight to the event in the signed archive — which is the
    /// whole purpose the consumer states for the field.
    pub fn new(
        kind: EffectKind,
        position: EventPosition,
        timestamp_utc: String,
        agent_did: Option<String>,
        detail: EffectDetail,
    ) -> Self {
        let id = format!(
            "aip-{}-{:012}-{:06}",
            kind.tag(),
            position.batch_sequence,
            position.index
        );
        Self {
            id,
            timestamp_utc,
            kind,
            agent_did,
            detail,
            position,
        }
    }

    /// Total order over records: evidence order, then kind.
    ///
    /// `(batch_sequence, index)` is unique per event, but one event can yield
    /// records of two kinds, so the kind breaks the tie. Deliberately not
    /// ordered by timestamp: two events in the same millisecond would then
    /// have no defined order and the output would not be reproducible.
    pub fn sort_key(&self) -> (u64, u32, EffectKind) {
        (self.position.batch_sequence, self.position.index, self.kind)
    }

    /// The JSON object for this record.
    ///
    /// `serde_json`'s map is B-tree backed by default, so keys serialise in
    /// sorted order and one record has exactly one byte representation. That
    /// is what makes a feed diffable and a re-run comparable to the last one.
    pub fn to_json(&self, observer_id: &str) -> Value {
        let mut map = Map::new();
        map.insert("id".into(), Value::String(self.id.clone()));
        map.insert(
            "timestampUtc".into(),
            Value::String(self.timestamp_utc.clone()),
        );
        map.insert("kind".into(), Value::String(self.kind.wire().into()));
        map.insert("observer".into(), Value::String(observer_id.to_string()));
        if let Some(did) = &self.agent_did {
            map.insert("agentDid".into(), Value::String(did.clone()));
        }
        match &self.detail {
            EffectDetail::Spawn { path, exe_sha256 } => {
                map.insert("command".into(), Value::String(path.clone()));
                map.insert("exeSha256".into(), Value::String(exe_sha256.clone()));
            }
            EffectDetail::Egress { destination, bytes } => {
                map.insert("destination".into(), Value::String(destination.clone()));
                if let Some(b) = bytes {
                    map.insert("bytes".into(), Value::Number((*b).into()));
                }
            }
        }
        Value::Object(map)
    }

    /// The record as one line of JSONL, without its newline.
    pub fn to_line(&self, observer_id: &str) -> String {
        self.to_json(observer_id).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(batch_sequence: u64, index: u32) -> EventPosition {
        EventPosition {
            batch_sequence,
            index,
            kernel_timestamp_ns: 0,
        }
    }

    fn spawn(batch: u64, index: u32, did: Option<&str>) -> EffectRecord {
        EffectRecord::new(
            EffectKind::Spawn,
            at(batch, index),
            "2026-09-20T10:00:00.000Z".into(),
            did.map(str::to_string),
            EffectDetail::Spawn {
                path: "/usr/bin/curl".into(),
                exe_sha256: "ab".repeat(32),
            },
        )
    }

    #[test]
    fn r01_the_id_encodes_the_evidence_position_and_sorts_lexically() {
        assert_eq!(spawn(7, 3, None).id, "aip-sp-000000000007-000003");
        let mut ids = [spawn(10, 0, None).id, spawn(2, 0, None).id];
        ids.sort();
        assert_eq!(
            ids,
            ["aip-sp-000000000002-000000", "aip-sp-000000000010-000000"],
            "zero padding must make lexical order agree with evidence order"
        );
    }

    #[test]
    fn r02_a_claimed_identity_is_passed_through_as_a_claim() {
        let line = spawn(1, 0, Some("did:aip:agent:A1")).to_line("collector.x");
        assert!(line.contains(r#""agentDid":"did:aip:agent:A1""#), "{line}");
    }

    #[test]
    fn r03_no_claim_means_the_field_is_absent_not_empty() {
        // The consumer reads absence as an anonymous subject. An empty string
        // would be a claim of "", which is a different and false statement.
        let line = spawn(1, 0, None).to_line("collector.x");
        assert!(!line.contains("agentDid"), "{line}");
    }

    #[test]
    fn r04_a_spawn_line_carries_the_path_and_the_content_digest() {
        let line = spawn(1, 0, None).to_line("collector.x");
        assert!(line.contains(r#""kind":"spawn""#), "{line}");
        assert!(line.contains(r#""command":"/usr/bin/curl""#), "{line}");
        assert!(
            line.contains(&format!(r#""exeSha256":"{}""#, "ab".repeat(32))),
            "{line}"
        );
    }

    #[test]
    fn r05_an_unmeasured_byte_count_is_omitted_not_written_as_zero() {
        let none = EffectRecord::new(
            EffectKind::Egress,
            at(1, 0),
            "2026-09-20T10:00:00.000Z".into(),
            None,
            EffectDetail::Egress {
                destination: "10.0.0.7:443".into(),
                bytes: None,
            },
        );
        assert!(
            !none.to_line("o").contains("bytes"),
            "{}",
            none.to_line("o")
        );

        let some = EffectRecord::new(
            EffectKind::Egress,
            at(1, 0),
            "2026-09-20T10:00:00.000Z".into(),
            None,
            EffectDetail::Egress {
                destination: "10.0.0.7:443".into(),
                bytes: Some(81_920),
            },
        );
        assert!(some.to_line("o").contains(r#""bytes":81920"#));
    }

    #[test]
    fn r06_serialisation_is_byte_stable() {
        let a = spawn(4, 1, Some("did:aip:agent:A1")).to_line("collector.x");
        let b = spawn(4, 1, Some("did:aip:agent:A1")).to_line("collector.x");
        assert_eq!(a, b);
        // Keys sorted, so the representation is one string, not one of many.
        assert!(a.starts_with(r#"{"agentDid":"#), "{a}");
    }

    #[test]
    fn r07_a_path_with_json_metacharacters_is_escaped_not_concatenated() {
        // Paths are attacker-influenced: a quote or a newline in one must not
        // be able to end the string or forge a second record.
        let rec = EffectRecord::new(
            EffectKind::Spawn,
            at(1, 0),
            "2026-09-20T10:00:00.000Z".into(),
            None,
            EffectDetail::Spawn {
                path: "/tmp/\"a\nb\\c".into(),
                exe_sha256: "00".repeat(32),
            },
        );
        let line = rec.to_line("o");
        assert_eq!(line.lines().count(), 1, "one record is one line: {line}");
        let parsed: Value = serde_json::from_str(&line).expect("still valid JSON");
        assert_eq!(parsed["command"], Value::String("/tmp/\"a\nb\\c".into()));
    }

    #[test]
    fn r08_records_of_two_kinds_from_one_event_have_distinct_ids_and_a_defined_order() {
        let sp = spawn(1, 5, None);
        let eg = EffectRecord::new(
            EffectKind::Egress,
            at(1, 5),
            "2026-09-20T10:00:00.000Z".into(),
            None,
            EffectDetail::Egress {
                destination: "10.0.0.7:443".into(),
                bytes: None,
            },
        );
        assert_ne!(sp.id, eg.id);
        assert!(sp.sort_key() < eg.sort_key(), "Spawn orders before Egress");
    }
}
