//! The governance hub: fleet-scale ingestion and continuity verification
//! of agent accountability chains.
//!
//! # The scale contract
//!
//! Ten million agents cannot mean ten million chains held in memory. The
//! hub therefore keeps **O(1) state per agent** — two streaming-verifier
//! tails (hash + sequence), a closed flag, and a timestamp: roughly 300
//! bytes per agent including map overhead, so ten million agents fit in a
//! few gigabytes on a single node. Beyond one node, the keyspace shards by
//! agent DID with no coordination needed, because every agent's chains are
//! independent by construction — the same property that lets this hub run
//! all agents concurrently across 256 lock shards with no global lock.
//!
//! Records themselves are validated, counted, and released; durable storage
//! is the deployment's archival concern (object store, WORM log), and the
//! hub's checkpoint tails are exactly what lets an auditor later verify any
//! archived segment in O(delta) with `ot-verifier` / the shared core.
//!
//! # The law the hub enforces per submission
//!
//! - a chain must open with `AGENT_GENESIS`; anchors and packets must
//!   extend their chain's verified tail (hash, sequence) exactly;
//! - a terminal `AUTHORITY_REVOCATION` closes the lifecycle: later anchors
//!   are refused, and later `SUCCESS`/`FAILED` packets are refused as
//!   `UNAUTHORIZED_POST_REVOCATION_EXECUTION` (a `BLOCKED_BY_POLICY`
//!   refusal of a closed lifecycle is still legitimate evidence);
//! - a rejected submission never advances the tail: the chain does not
//!   poison, the submitter corrects and retries.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ot_accountability_core::stream::StreamingChainVerifier;
use serde::Serialize;
use serde_json::Value;

/// Lock shards. Contention is per-shard, so with uniformly hashed DIDs the
/// hub scales with cores until the shard count binds — 256 is far past any
/// realistic core count.
const SHARDS: usize = 256;

/// Per-agent state: the whole memory cost of tracking one agent.
struct AgentChains {
    anchors: StreamingChainVerifier,
    packets: StreamingChainVerifier,
    closed: bool,
    last_seen_utc: String,
}

/// Why a submission was refused.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestRejection {
    /// Stable machine-readable rejection code.
    pub code: &'static str,
    /// Human-readable reason.
    pub detail: String,
}

impl IngestRejection {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Acknowledgement of an accepted record.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestReceipt {
    /// The chain's agent.
    pub agent_did: String,
    /// Sequence number the record sealed at.
    pub sequence_number: u64,
    /// The chain's new verified tail hash.
    pub tail_hash: String,
}

/// Point-in-time view of one agent's chains.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSnapshot {
    /// The agent's DID.
    pub agent_did: String,
    /// Lifecycle anchors sealed.
    pub anchors: u64,
    /// Evidence packets sealed.
    pub packets: u64,
    /// Verified tail of the anchor chain.
    pub anchor_tail: String,
    /// Verified tail of the packet chain.
    pub packet_tail: String,
    /// True once a terminal revocation closed the lifecycle.
    pub closed: bool,
    /// Timestamp of the last accepted record.
    pub last_seen_utc: String,
}

/// Fleet counters.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HubStats {
    /// Distinct agents with a born lifecycle.
    pub agents: u64,
    /// Lifecycle anchors accepted.
    pub anchors_sealed: u64,
    /// Evidence packets accepted.
    pub packets_sealed: u64,
    /// Submissions refused (chain breaks, lifecycle-law violations).
    pub rejected: u64,
    /// Accepted records the durability journal failed to append — zero on a
    /// healthy hub; any other value means the archive is behind the tails.
    pub journal_errors: u64,
}

/// The append-only durability journal: every accepted record, one JSON line
/// (`{"kind": "anchor"|"packet", "record": {…}}`), in per-agent order.
/// Replaying it through the ordinary ingest path rebuilds every verified
/// tail — the journal is simultaneously the write-ahead log, the archive,
/// and the recovery procedure, and `ot-verifier` can audit any per-agent
/// slice of it offline.
struct Journal {
    writer: Mutex<std::io::BufWriter<std::fs::File>>,
    path: PathBuf,
}

/// The sharded, multi-tenant accountability ingestion hub.
pub struct GovernanceHub {
    shards: Vec<Mutex<HashMap<String, AgentChains>>>,
    agents: AtomicU64,
    anchors_sealed: AtomicU64,
    packets_sealed: AtomicU64,
    rejected: AtomicU64,
    journal: Option<Journal>,
    journal_errors: AtomicU64,
}

impl Default for GovernanceHub {
    fn default() -> Self {
        Self::new()
    }
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn is_terminal_revocation(anchor: &Value) -> bool {
    str_field(anchor, "anchorType") == "AUTHORITY_REVOCATION"
        && anchor
            .get("payload")
            .and_then(|p| p.get("terminal"))
            .and_then(Value::as_bool)
            == Some(true)
}

impl GovernanceHub {
    /// An empty, memory-only hub (state dies with the process).
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            agents: AtomicU64::new(0),
            anchors_sealed: AtomicU64::new(0),
            packets_sealed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            journal: None,
            journal_errors: AtomicU64::new(0),
        }
    }

    /// A durable hub: replays the journal at `path` (if it exists) through
    /// the ordinary ingest path — rebuilding every agent's verified tail in
    /// O(1) memory per agent — then appends every subsequently accepted
    /// record to it.
    ///
    /// The journal contains only records the hub already accepted, so a
    /// replay rejection means the file was edited after the fact; the hub
    /// refuses to start on a tampered journal rather than serving from a
    /// history it cannot vouch for.
    pub fn with_journal(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut hub = Self::new();
        if path.exists() {
            let file = std::fs::File::open(&path)?;
            for (n, line) in std::io::BufReader::new(file).lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let entry: Value = serde_json::from_str(&line).map_err(|err| {
                    std::io::Error::other(format!("journal line {}: not JSON: {err}", n + 1))
                })?;
                let kind = entry.get("kind").and_then(Value::as_str).unwrap_or("");
                let record = entry.get("record").unwrap_or(&Value::Null);
                let replayed = match kind {
                    "anchor" => hub.ingest_anchor(record),
                    "packet" => hub.ingest_packet(record),
                    other => {
                        return Err(std::io::Error::other(format!(
                            "journal line {}: unknown kind {other:?}",
                            n + 1,
                        )))
                    }
                };
                if let Err(rejection) = replayed {
                    return Err(std::io::Error::other(format!(
                        "journal line {}: tampered journal — a previously accepted record no \
                         longer verifies ({}: {})",
                        n + 1,
                        rejection.code,
                        rejection.detail,
                    )));
                }
            }
        }
        // Replay legitimately re-ran the acceptance counters; rejections
        // during replay abort above, so only the accept counters moved.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        hub.journal = Some(Journal {
            writer: Mutex::new(std::io::BufWriter::new(file)),
            path,
        });
        Ok(hub)
    }

    /// The journal path, when this hub is durable.
    pub fn journal_path(&self) -> Option<&Path> {
        self.journal.as_ref().map(|j| j.path.as_path())
    }

    /// Appends one accepted record to the journal. Called while the record's
    /// shard lock is held, so per-agent order in the file matches per-agent
    /// commit order — which is what makes replay deterministic. A write
    /// failure is counted and reported in stats rather than un-accepting a
    /// record whose tail has already advanced.
    fn journal_append(&self, kind: &str, record: &Value) {
        let Some(journal) = &self.journal else { return };
        let line = serde_json::json!({ "kind": kind, "record": record });
        let mut writer = journal.writer.lock().expect("journal lock never poisons");
        let outcome = serde_json::to_writer(&mut *writer, &line)
            .map_err(std::io::Error::other)
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush());
        if let Err(err) = outcome {
            self.journal_errors.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "governance journal append failed ({}): {err}",
                journal.path.display(),
            );
        }
    }

    fn shard(&self, did: &str) -> &Mutex<HashMap<String, AgentChains>> {
        let mut hasher = DefaultHasher::new();
        did.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % SHARDS]
    }

    fn reject(&self, code: &'static str, detail: impl Into<String>) -> IngestRejection {
        self.rejected.fetch_add(1, Ordering::Relaxed);
        IngestRejection::new(code, detail)
    }

    fn agent_did_of(&self, record: &Value) -> Result<String, IngestRejection> {
        let did = str_field(record, "agentDid");
        if !did.starts_with("did:syntriass:agent:") || did.len() <= "did:syntriass:agent:".len() {
            return Err(self.reject(
                "INVALID_AGENT_DID",
                format!("{did:?} is not a did:syntriass:agent identifier"),
            ));
        }
        Ok(did.to_string())
    }

    /// Ingests one lifecycle anchor.
    pub fn ingest_anchor(&self, anchor: &Value) -> Result<IngestReceipt, IngestRejection> {
        let did = self.agent_did_of(anchor)?;
        let mut shard = self.shard(&did).lock().expect("shard lock never poisons");
        let chains = match shard.get_mut(&did) {
            Some(chains) => chains,
            None => {
                if str_field(anchor, "anchorType") != "AGENT_GENESIS" {
                    return Err(self.reject(
                        "NO_GENESIS",
                        format!(
                            "first anchor for {did} must be AGENT_GENESIS, found {:?}",
                            str_field(anchor, "anchorType"),
                        ),
                    ));
                }
                self.agents.fetch_add(1, Ordering::Relaxed);
                shard.entry(did.clone()).or_insert_with(|| AgentChains {
                    anchors: StreamingChainVerifier::new("previousAnchorHash", "anchorHash"),
                    packets: StreamingChainVerifier::new("previousPacketHash", "packetHash"),
                    closed: false,
                    last_seen_utc: String::new(),
                })
            }
        };
        if chains.closed {
            return Err(self.reject(
                "LIFECYCLE_CLOSED",
                format!("{did} is terminally revoked; its lifecycle chain is closed"),
            ));
        }
        if let Err(broken) = chains.anchors.try_push(anchor) {
            return Err(self.reject("CHAIN_BREAK", broken.reason));
        }
        if is_terminal_revocation(anchor) {
            chains.closed = true;
        }
        chains.last_seen_utc = str_field(anchor, "timestampUtc").to_string();
        self.anchors_sealed.fetch_add(1, Ordering::Relaxed);
        self.journal_append("anchor", anchor);
        let checkpoint = chains.anchors.checkpoint().expect("just verified");
        Ok(IngestReceipt {
            agent_did: did,
            sequence_number: checkpoint.sequence_number,
            tail_hash: checkpoint.tail_hash,
        })
    }

    /// Ingests one evidence packet.
    pub fn ingest_packet(&self, packet: &Value) -> Result<IngestReceipt, IngestRejection> {
        let did = self.agent_did_of(packet)?;
        let mut shard = self.shard(&did).lock().expect("shard lock never poisons");
        let Some(chains) = shard.get_mut(&did) else {
            return Err(self.reject(
                "NO_GENESIS",
                format!("{did} has no AGENT_GENESIS anchor; evidence needs a born lifecycle"),
            ));
        };
        let status = packet
            .pointer("/toolExecuted/status")
            .and_then(Value::as_str)
            .unwrap_or("");
        if chains.closed && status != "BLOCKED_BY_POLICY" {
            return Err(self.reject(
                "UNAUTHORIZED_POST_REVOCATION_EXECUTION",
                format!("{did} is terminally revoked; a {status} packet cannot execute after it"),
            ));
        }
        if let Err(broken) = chains.packets.try_push(packet) {
            return Err(self.reject("CHAIN_BREAK", broken.reason));
        }
        chains.last_seen_utc = str_field(packet, "timestampUtc").to_string();
        self.packets_sealed.fetch_add(1, Ordering::Relaxed);
        self.journal_append("packet", packet);
        let checkpoint = chains.packets.checkpoint().expect("just verified");
        Ok(IngestReceipt {
            agent_did: did,
            sequence_number: checkpoint.sequence_number,
            tail_hash: checkpoint.tail_hash,
        })
    }

    /// Point-in-time snapshot of one agent, or None when unknown.
    pub fn agent_snapshot(&self, did: &str) -> Option<AgentSnapshot> {
        let shard = self.shard(did).lock().expect("shard lock never poisons");
        let chains = shard.get(did)?;
        let anchor_cp = chains.anchors.checkpoint()?;
        let packet_cp = chains.packets.checkpoint()?;
        Some(AgentSnapshot {
            agent_did: did.to_string(),
            anchors: anchor_cp.sequence_number,
            packets: packet_cp.sequence_number,
            anchor_tail: anchor_cp.tail_hash,
            packet_tail: packet_cp.tail_hash,
            closed: chains.closed,
            last_seen_utc: chains.last_seen_utc.clone(),
        })
    }

    /// Fleet counters.
    pub fn stats(&self) -> HubStats {
        HubStats {
            agents: self.agents.load(Ordering::Relaxed),
            anchors_sealed: self.anchors_sealed.load(Ordering::Relaxed),
            packets_sealed: self.packets_sealed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            journal_errors: self.journal_errors.load(Ordering::Relaxed),
        }
    }
}
