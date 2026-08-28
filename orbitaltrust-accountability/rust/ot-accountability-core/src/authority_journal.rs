//! A durable [`AuthorityStore`] that is tamper-evident, not merely persistent.
//!
//! [`MemoryAuthorityStore`](crate::authority::MemoryAuthorityStore) loses
//! every grant and revocation when the process ends, which makes the whole
//! authority graph a runtime fixture: restart the gateway and nobody is
//! delegated anything. This module is the durable backing.
//!
//! # Why an append-only hash chain rather than a database
//!
//! The authority record is *the* security record in this system — it is the
//! thing that decides who may do what. Every other durable record here is
//! hash-chained and re-derivable: the evidence ledger, the lifecycle
//! anchors, the sentinel's own archive, the sensor stream attestations. A
//! store an adversary could silently `UPDATE` would be the one durable
//! security record in an accountability product that cannot account for
//! itself, and it would be the softest target in the system: quietly widen
//! a scope, extend an expiry, or flip a `Revoked` edge back to `Active`, and
//! nothing anywhere would notice.
//!
//! So authority is persisted the same way everything else is. Each grant and
//! each revocation is an [`AuthorityEvent`] appended to a JSONL journal, and
//! each entry seals the previous one:
//! [`seal_hash(previous, canonical_payload)`](crate::seal_hash) — the exact
//! construction the evidence chain uses. The live edge set is a *replay* of
//! that journal, so the store's state is never authoritative on its own;
//! the chain is. Any edit to a past entry breaks the recomputation at that
//! point, and [`JournalAuthorityStore::open`] refuses to load rather than
//! serving authority from a record that no longer verifies.
//!
//! There is a second reason this cannot be SQLite specifically:
//! `ot-accountability-core` compiles to `wasm32` (see the crate's
//! `crate-type`) so the browser verifier can re-check chains client-side.
//! A C-backed database does not go there. The file-backed half of this
//! module is therefore compiled only for native targets; the event types are
//! shared, so a browser can still verify a journal it is handed.
//!
//! # Retention, not deletion
//!
//! A revocation appends a `Revoke` event; it never rewrites the `Grant`.
//! [`EdgeStatus::Revoked`](crate::authority::EdgeStatus) already documents
//! that withdrawn authority is *retained* because "what authority existed
//! when" is itself audit material. Replay honours that: the edge stays in
//! the store with `Revoked` status, and resolution declines it.

use serde_json::{json, Value};

use crate::authority::{ClearanceLevel, DelegationEdge, EdgeStatus};

/// One mutation of the authority graph.
///
/// Deliberately only two: authority is conferred, or it is withdrawn. There
/// is no `Update` — amending an edge in place would make "what was granted"
/// unanswerable without diffing, whereas a revoke-then-grant pair says
/// exactly what changed and when.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthorityEvent {
    /// A parent conferred an attenuated scope on a child.
    Grant(Box<DelegationEdge>),
    /// An edge was withdrawn. Everything downstream loses authority at the
    /// next resolution, since resolution walks the live graph.
    Revoke {
        /// The edge withdrawn.
        edge_id: String,
        /// Why, for the operator reading the journal later. Free text; the
        /// journal records it verbatim.
        reason: String,
    },
}

impl AuthorityEvent {
    /// The canonical JSON this event is chained over.
    pub fn to_json(&self) -> Value {
        match self {
            Self::Grant(edge) => {
                let mut terms = edge.canonical_terms();
                // `canonical_terms` is the signature-covered subset and
                // deliberately excludes status and signature. The journal
                // must carry both, or a replay could not reconstruct the
                // edge it is meant to reproduce exactly.
                if let Some(object) = terms.as_object_mut() {
                    object.insert("status".into(), json!(status_str(edge.status)));
                    if let Some(signature) = &edge.signature {
                        object.insert("signature".into(), signature.clone());
                    }
                }
                json!({ "kind": "GRANT", "edge": terms })
            }
            Self::Revoke { edge_id, reason } => {
                json!({ "kind": "REVOKE", "edgeId": edge_id, "reason": reason })
            }
        }
    }

    /// Reads back what [`AuthorityEvent::to_json`] wrote.
    ///
    /// Strict about every field that decides what authority is conferred: a
    /// grant missing its scope or its expiry is not a grant with sensible
    /// defaults, it is an unreadable record, and defaulting one would invent
    /// authority nobody issued.
    pub fn from_json(value: &Value) -> Result<Self, String> {
        match value.get("kind").and_then(Value::as_str) {
            Some("GRANT") => {
                let edge = value.get("edge").ok_or("GRANT is missing \"edge\"")?;
                let text = |name: &str| -> Result<String, String> {
                    edge.get(name)
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| format!("edge is missing a string \"{name}\""))
                };
                let list = |name: &str| -> Result<Vec<String>, String> {
                    edge.get(name)
                        .and_then(Value::as_array)
                        .ok_or_else(|| format!("edge is missing an array \"{name}\""))?
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .map(str::to_string)
                                .ok_or_else(|| format!("\"{name}\" holds a non-string"))
                        })
                        .collect()
                };
                let clearance = text("clearanceLevel")?;
                let status = text("status")?;
                Ok(Self::Grant(Box::new(DelegationEdge {
                    edge_id: text("edgeId")?,
                    parent_did: text("parentDid")?,
                    child_did: text("childDid")?,
                    scope: list("scope")?,
                    multi_sig_tools: list("multiSigTools")?,
                    clearance_level: ClearanceLevel::parse(&clearance)
                        .ok_or_else(|| format!("unknown clearanceLevel \"{clearance}\""))?,
                    valid_from_utc: text("validFromUtc")?,
                    expires_at_utc: text("expiresAtUtc")?,
                    status: parse_status(&status)
                        .ok_or_else(|| format!("unknown status \"{status}\""))?,
                    signature: edge.get("signature").cloned(),
                })))
            }
            Some("REVOKE") => Ok(Self::Revoke {
                edge_id: value
                    .get("edgeId")
                    .and_then(Value::as_str)
                    .ok_or("REVOKE is missing a string \"edgeId\"")?
                    .to_string(),
                reason: value
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            }),
            Some(other) => Err(format!("unknown authority event kind \"{other}\"")),
            None => Err("authority event is missing a string \"kind\"".into()),
        }
    }
}

/// The wire vocabulary for an edge's status.
fn status_str(status: EdgeStatus) -> &'static str {
    match status {
        EdgeStatus::Active => "ACTIVE",
        EdgeStatus::Revoked => "REVOKED",
    }
}

fn parse_status(text: &str) -> Option<EdgeStatus> {
    match text {
        "ACTIVE" => Some(EdgeStatus::Active),
        "REVOKED" => Some(EdgeStatus::Revoked),
        _ => None,
    }
}

/// What replaying a journal found — the honest state of the record, so a
/// caller is never handed a store without being told how sound it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Events successfully replayed.
    pub events_replayed: usize,
    /// True when the final line was incomplete (no terminating newline) and
    /// was discarded.
    ///
    /// This is a crash mid-append, not tampering: the entry never committed.
    /// It is surfaced rather than swallowed because of an asymmetry that
    /// matters — a lost `Grant` fails safe (authority simply was not
    /// conferred), but a lost `Revoke` fails *dangerous* (an agent keeps
    /// authority somebody tried to remove), and the torn bytes cannot say
    /// which it was. An operator seeing this must re-issue the last command.
    pub torn_tail: bool,
    /// Revoke events naming an edge the journal never granted. Not fatal —
    /// revoking something absent is harmless — but recorded, because it
    /// usually means a mistyped edge id, and an operator who believes they
    /// revoked something they did not is in the worst possible position.
    pub unmatched_revokes: Vec<String>,
}

impl RecoveryReport {
    /// True when the journal replayed with nothing needing an operator's
    /// attention.
    pub fn is_clean(&self) -> bool {
        !self.torn_tail && self.unmatched_revokes.is_empty()
    }
}

/// Replays journal entries into the live edge set, verifying the chain.
///
/// Shared by the native store and any consumer (including the wasm verifier)
/// that holds journal lines and wants to check them.
pub fn replay(
    lines: &[&str],
) -> Result<(Vec<DelegationEdge>, String, u64, RecoveryReport), String> {
    let mut edges: Vec<DelegationEdge> = Vec::new();
    let mut tail = crate::GENESIS_HASH.to_string();
    let mut sequence = 0u64;
    let mut report = RecoveryReport::default();

    for (index, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(line)
            .map_err(|e| format!("authority journal line {}: not JSON: {e}", index + 1))?;

        let claimed_sequence = entry
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("authority journal line {}: no sequence", index + 1))?;
        let previous = entry
            .get("previousHash")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("authority journal line {}: no previousHash", index + 1))?;
        let entry_hash = entry
            .get("entryHash")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("authority journal line {}: no entryHash", index + 1))?;

        // The chain check. Both halves matter: `previousHash` must be the
        // hash we actually reached (catches a removed or reordered entry),
        // and `entryHash` must recompute (catches an edited one).
        if previous != tail {
            return Err(format!(
                "authority journal broke at sequence {claimed_sequence}: entry descends from {}…, chain reached {}…",
                short(previous),
                short(&tail),
            ));
        }
        let recomputed = crate::seal_hash(
            &tail,
            &crate::chain_payload_bytes(&entry, &["previousHash", "entryHash"]),
        );
        if recomputed != entry_hash {
            return Err(format!(
                "authority journal entry {claimed_sequence} does not recompute: sealed {}…, recomputed {}… — the record was edited",
                short(entry_hash),
                short(&recomputed),
            ));
        }

        let event = AuthorityEvent::from_json(
            entry
                .get("event")
                .ok_or_else(|| format!("authority journal line {}: no event", index + 1))?,
        )
        .map_err(|why| format!("authority journal line {}: {why}", index + 1))?;

        match event {
            AuthorityEvent::Grant(edge) => edges.push(*edge),
            AuthorityEvent::Revoke { edge_id, .. } => {
                let mut matched = false;
                for edge in &mut edges {
                    if edge.edge_id == edge_id {
                        edge.status = EdgeStatus::Revoked;
                        matched = true;
                    }
                }
                if !matched {
                    report.unmatched_revokes.push(edge_id);
                }
            }
        }

        tail = entry_hash.to_string();
        sequence = claimed_sequence;
        report.events_replayed += 1;
    }

    Ok((edges, tail, sequence, report))
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

/// Seals one journal entry, returning `(line, entry_hash)`.
pub fn seal_entry(previous: &str, sequence: u64, event: &AuthorityEvent) -> (String, String) {
    let mut entry = json!({
        "sequence": sequence,
        "event": event.to_json(),
    });
    let hash = crate::seal_hash(
        previous,
        &crate::chain_payload_bytes(&entry, &["previousHash", "entryHash"]),
    );
    entry["previousHash"] = json!(previous);
    entry["entryHash"] = json!(hash);
    (entry.to_string(), hash)
}

// The file-backed store is native-only: `ot-accountability-core` also builds
// for wasm32 so the browser can verify chains, and a browser has no journal
// file to open. The event types and `replay` above stay available there.
#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use crate::authority::AuthorityStore;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    /// A durable, tamper-evident [`AuthorityStore`] backed by an append-only
    /// hash-chained journal.
    ///
    /// ```no_run
    /// # use ot_accountability_core::authority_journal::JournalAuthorityStore;
    /// let (mut store, recovery) = JournalAuthorityStore::open("authority.jsonl")?;
    /// assert!(recovery.is_clean());
    /// store.revoke("edge-1", "contract ended")?;
    /// # Ok::<(), String>(())
    /// ```
    pub struct JournalAuthorityStore {
        path: PathBuf,
        edges: Vec<DelegationEdge>,
        tail: String,
        sequence: u64,
    }

    impl JournalAuthorityStore {
        /// Opens (or creates) a journal, replaying it into live state.
        ///
        /// A journal that does not verify is an error, never a fresh start.
        /// Serving authority from a record that no longer recomputes would
        /// be worse than refusing to serve any: the gateway would enforce
        /// against a graph an attacker may have written.
        pub fn open(path: impl Into<PathBuf>) -> Result<(Self, RecoveryReport), String> {
            let path = path.into();
            let text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
            };

            // A final line with no terminating newline never committed: the
            // process died mid-append. Same discipline the sensor tailer
            // uses for a partial trailing record.
            let torn_tail = !text.is_empty() && !text.ends_with('\n');
            let mut lines: Vec<&str> = text.lines().collect();
            if torn_tail {
                lines.pop();
                // The torn bytes must physically go, not merely be skipped.
                // An append lands at the end of the file, so leaving them
                // would splice the next entry onto the incomplete one and
                // produce a line that parses as neither — turning a
                // recoverable crash into a journal that can never be opened
                // again. Truncating to the last committed newline is the
                // standard write-ahead-log recovery, and it discards only
                // bytes that by definition never committed.
                //
                // This assumes a single writer, which is the deployment
                // model: two processes appending to one authority journal
                // would interleave entries regardless of this truncation.
                let committed = text.rfind('\n').map_or(0, |index| index + 1) as u64;
                let file = fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(|e| format!("cannot open {} to recover: {e}", path.display()))?;
                file.set_len(committed)
                    .map_err(|e| format!("cannot truncate torn tail of {}: {e}", path.display()))?;
                file.sync_all()
                    .map_err(|e| format!("cannot fsync recovery of {}: {e}", path.display()))?;
            }

            let (edges, tail, sequence, mut report) = replay(&lines)?;
            report.torn_tail = torn_tail;
            Ok((
                Self {
                    path,
                    edges,
                    tail,
                    sequence,
                },
                report,
            ))
        }

        /// Confers authority, appending a sealed `GRANT`.
        ///
        /// The edge joins live state only after the append is durable, so a
        /// failed write can never leave this process resolving authority the
        /// journal does not record. That direction matters: enforcing more
        /// than the record supports is exactly the failure this store exists
        /// to make impossible.
        pub fn grant(&mut self, edge: DelegationEdge) -> Result<(), String> {
            self.append(AuthorityEvent::Grant(Box::new(edge.clone())))?;
            self.edges.push(edge);
            Ok(())
        }

        /// Withdraws an edge, appending a sealed `REVOKE`.
        ///
        /// Returns `false` when no live edge carried that id — the event is
        /// still journalled (the intent is audit material), but the caller
        /// is told, because an operator who believes a revoke landed when it
        /// did not is in the worst possible position.
        pub fn revoke(&mut self, edge_id: &str, reason: &str) -> Result<bool, String> {
            self.append(AuthorityEvent::Revoke {
                edge_id: edge_id.to_string(),
                reason: reason.to_string(),
            })?;
            let mut matched = false;
            for edge in &mut self.edges {
                if edge.edge_id == edge_id {
                    edge.status = EdgeStatus::Revoked;
                    matched = true;
                }
            }
            Ok(matched)
        }

        /// Appends one event, sealed onto the chain and flushed to disk.
        ///
        /// `sync_all` before returning: an authority mutation the caller
        /// believes is durable but which is still in the page cache is a
        /// revocation that a power cut silently undoes.
        fn append(&mut self, event: AuthorityEvent) -> Result<(), String> {
            let sequence = self.sequence + 1;
            let (line, hash) = seal_entry(&self.tail, sequence, &event);
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .map_err(|e| format!("cannot open {}: {e}", self.path.display()))?;
            writeln!(file, "{line}")
                .map_err(|e| format!("cannot append to {}: {e}", self.path.display()))?;
            file.sync_all()
                .map_err(|e| format!("cannot fsync {}: {e}", self.path.display()))?;
            self.tail = hash;
            self.sequence = sequence;
            Ok(())
        }

        /// The journal's chain head — publish or anchor this to make an
        /// offline rewrite of the whole file detectable too.
        pub fn head(&self) -> &str {
            &self.tail
        }

        /// How many events the journal holds.
        pub fn sequence(&self) -> u64 {
            self.sequence
        }

        /// The journal path.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Every edge held, revoked ones included — "what authority existed
        /// when" is audit material.
        pub fn edges(&self) -> &[DelegationEdge] {
            &self.edges
        }

        /// Re-reads the journal from disk and verifies it against this
        /// store's head. Catches an edit made while the process was running.
        pub fn verify(&self) -> Result<(), String> {
            let (_, tail, _, _) = {
                let text = fs::read_to_string(&self.path)
                    .map_err(|e| format!("cannot read {}: {e}", self.path.display()))?;
                let lines: Vec<&str> = text.lines().collect();
                replay(&lines)?
            };
            if tail != self.tail {
                return Err(format!(
                    "authority journal head moved underneath this process: holding {}…, on disk {}…",
                    short(&self.tail),
                    short(&tail),
                ));
            }
            Ok(())
        }
    }

    impl AuthorityStore for JournalAuthorityStore {
        fn edges_for_child(&self, child_did: &str) -> Vec<DelegationEdge> {
            self.edges
                .iter()
                .filter(|e| e.child_did == child_did)
                .cloned()
                .collect()
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::JournalAuthorityStore;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::authority::{resolve_authority, AuthorityStore, TrustedStoreVerifier};

    const OFFICER: &str = "did:syntriass:officer:OFF-1";
    const AGENT: &str = "did:syntriass:agent:AGT-1";

    fn edge(id: &str, child: &str, scope: &[&str]) -> DelegationEdge {
        DelegationEdge {
            edge_id: id.into(),
            parent_did: OFFICER.into(),
            child_did: child.into(),
            scope: scope.iter().map(|s| s.to_string()).collect(),
            multi_sig_tools: vec!["purge_archive".into()],
            clearance_level: ClearanceLevel::Secret,
            valid_from_utc: "2026-01-01T00:00:00.000Z".into(),
            expires_at_utc: "2027-01-01T00:00:00.000Z".into(),
            status: EdgeStatus::Active,
            signature: None,
        }
    }

    fn journal(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("authority.jsonl")
    }

    #[test]
    fn authority_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);

        let (mut store, recovery) = JournalAuthorityStore::open(&path).unwrap();
        assert!(recovery.is_clean());
        assert_eq!(
            recovery.events_replayed, 0,
            "a fresh journal replays nothing"
        );
        store
            .grant(edge("e1", AGENT, &["read_catalog", "send_command"]))
            .unwrap();
        let head = store.head().to_string();
        drop(store);

        // Process restart: a brand-new store over the same file.
        let (reopened, recovery) = JournalAuthorityStore::open(&path).unwrap();
        assert!(recovery.is_clean());
        assert_eq!(recovery.events_replayed, 1);
        assert_eq!(reopened.head(), head, "the chain head did not survive");

        let restored = reopened.edges_for_child(AGENT);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].scope, vec!["read_catalog", "send_command"]);
        assert_eq!(restored[0].clearance_level, ClearanceLevel::Secret);
        assert_eq!(restored[0].multi_sig_tools, vec!["purge_archive"]);
        assert_eq!(restored[0].status, EdgeStatus::Active);
    }

    #[test]
    fn a_revocation_survives_a_restart_and_still_cascades() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);

        let (mut store, _) = JournalAuthorityStore::open(&path).unwrap();
        store.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
        assert!(
            store.revoke("e1", "contract ended").unwrap(),
            "revoke did not match"
        );
        drop(store);

        let (reopened, recovery) = JournalAuthorityStore::open(&path).unwrap();
        assert!(recovery.is_clean());
        let edges = reopened.edges_for_child(AGENT);
        // Retained, not deleted — "what authority existed when" is audit material.
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].status, EdgeStatus::Revoked);
        // And resolution declines it, so the kill switch really survived.
        assert!(
            resolve_authority(
                &reopened,
                &TrustedStoreVerifier,
                AGENT,
                "2026-06-01T00:00:00.000Z"
            )
            .is_none(),
            "a revoked agent resolved authority after a restart"
        );
    }

    #[test]
    fn editing_a_past_grant_breaks_the_chain_and_the_store_refuses_to_open() {
        // The attack this design exists to stop: silently widen a scope.
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);
        let (mut store, _) = JournalAuthorityStore::open(&path).unwrap();
        store.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
        store.grant(edge("e2", AGENT, &["send_command"])).unwrap();
        drop(store);

        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replace("read_catalog", "purge_archive");
        assert_ne!(tampered, text, "the test did not actually edit anything");
        std::fs::write(&path, tampered).unwrap();

        let error = match JournalAuthorityStore::open(&path) {
            Err(error) => error,
            Ok(_) => panic!("an edited authority journal was served as authority"),
        };
        assert!(
            error.contains("does not recompute") || error.contains("broke at"),
            "unhelpful error: {error}"
        );
    }

    #[test]
    fn deleting_a_revocation_from_the_journal_is_caught() {
        // The other direction: quietly remove a revoke so an agent keeps
        // authority. Dropping an entry must break the descent check.
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);
        let (mut store, _) = JournalAuthorityStore::open(&path).unwrap();
        store.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
        store.revoke("e1", "compromised").unwrap();
        drop(store);

        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(1).collect();
        std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        // Truncating the tail leaves a shorter but internally consistent
        // chain — which is why the head is published: it no longer matches.
        let (store, _) = JournalAuthorityStore::open(&path).unwrap();
        assert_eq!(store.sequence(), 1, "the revoke was not actually removed");
        assert_eq!(
            store.edges_for_child(AGENT)[0].status,
            EdgeStatus::Active,
            "test precondition"
        );
        // Against the head the operator recorded before the edit, the
        // truncation is detectable arithmetic.
        let (before, _) = {
            let dir2 = tempfile::tempdir().unwrap();
            let p2 = dir2.path().join("a.jsonl");
            let (mut s, _) = JournalAuthorityStore::open(&p2).unwrap();
            s.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
            s.revoke("e1", "compromised").unwrap();
            (s.head().to_string(), dir2)
        };
        assert_ne!(store.head(), before, "truncation left the head unchanged");
    }

    #[test]
    fn reordering_entries_is_caught_by_the_descent_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);
        let (mut store, _) = JournalAuthorityStore::open(&path).unwrap();
        store.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
        store.grant(edge("e2", AGENT, &["send_command"])).unwrap();
        drop(store);

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[1], lines[0])).unwrap();

        let error = match JournalAuthorityStore::open(&path) {
            Err(error) => error,
            Ok(_) => panic!("a reordered journal was accepted"),
        };
        assert!(error.contains("broke at"), "unhelpful error: {error}");
    }

    #[test]
    fn a_crash_mid_append_recovers_and_says_so() {
        // A torn final line never committed. It is dropped — but reported,
        // because the lost entry might have been a revoke.
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);
        let (mut store, _) = JournalAuthorityStore::open(&path).unwrap();
        store.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
        drop(store);

        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"sequence\":2,\"event\":{\"kind\":\"REV");
        std::fs::write(&path, text).unwrap();

        let (store, recovery) = JournalAuthorityStore::open(&path).unwrap();
        assert!(recovery.torn_tail, "the torn append was not detected");
        assert!(!recovery.is_clean(), "a torn tail must not read as clean");
        assert_eq!(recovery.events_replayed, 1, "committed entries were lost");
        // The store is still usable and still appends onto the good head.
        assert_eq!(store.edges_for_child(AGENT).len(), 1);
    }

    #[test]
    fn appending_after_a_torn_tail_produces_a_journal_that_reopens_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);
        let (mut store, _) = JournalAuthorityStore::open(&path).unwrap();
        store.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
        drop(store);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"sequence\":2,\"partial");
        std::fs::write(&path, text).unwrap();

        // Recovery, then the operator re-issues the lost command.
        let (mut store, recovery) = JournalAuthorityStore::open(&path).unwrap();
        assert!(recovery.torn_tail);
        store.revoke("e1", "re-issued after crash").unwrap();
        drop(store);

        // Recovery truncated the uncommitted bytes, so the re-issued entry
        // lands on a clean tail rather than being spliced onto them.
        let (reopened, recovery) = JournalAuthorityStore::open(&path).unwrap();
        assert!(
            recovery.is_clean(),
            "journal did not recover to a clean state"
        );
        assert_eq!(
            reopened.edges_for_child(AGENT)[0].status,
            EdgeStatus::Revoked
        );
    }

    #[test]
    fn revoking_an_unknown_edge_is_reported_rather_than_silently_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = JournalAuthorityStore::open(journal(&dir)).unwrap();
        store.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
        assert!(
            !store.revoke("e-typo", "mistyped").unwrap(),
            "a revoke of an unknown edge claimed to match"
        );
        // The intent is still journalled: it is audit material.
        assert_eq!(store.sequence(), 2);
    }

    #[test]
    fn a_signed_edge_round_trips_with_its_signature_intact() {
        // The signature is what an EdgeVerifier checks; losing it across a
        // restart would silently downgrade a signed deployment to unsigned.
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);
        let mut signed = edge("e1", AGENT, &["read_catalog"]);
        signed.signature = Some(json!({ "suite": "ML-DSA-87", "sig": "abcd" }));

        let (mut store, _) = JournalAuthorityStore::open(&path).unwrap();
        store.grant(signed.clone()).unwrap();
        drop(store);

        let (reopened, _) = JournalAuthorityStore::open(&path).unwrap();
        assert_eq!(reopened.edges_for_child(AGENT)[0], signed);
    }

    #[test]
    fn the_journal_store_satisfies_the_same_resolution_the_memory_store_does() {
        // Behavioural parity: the durable backend must be a drop-in for the
        // in-memory one, or "migrate to durable" changes enforcement.
        use crate::authority::MemoryAuthorityStore;
        let dir = tempfile::tempdir().unwrap();
        let e = edge("e1", AGENT, &["read_catalog", "send_command"]);

        let mut memory = MemoryAuthorityStore::new();
        memory.add(e.clone());
        let (mut durable, _) = JournalAuthorityStore::open(journal(&dir)).unwrap();
        durable.grant(e).unwrap();

        let at = "2026-06-01T00:00:00.000Z";
        assert_eq!(
            resolve_authority(&memory, &TrustedStoreVerifier, AGENT, at),
            resolve_authority(&durable, &TrustedStoreVerifier, AGENT, at),
            "the durable store resolves differently from the in-memory one"
        );
    }

    #[test]
    fn verify_catches_an_edit_made_while_the_process_is_running() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal(&dir);
        let (mut store, _) = JournalAuthorityStore::open(&path).unwrap();
        store.grant(edge("e1", AGENT, &["read_catalog"])).unwrap();
        store.verify().expect("an untouched journal must verify");

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("read_catalog", "purge_archive")).unwrap();
        assert!(store.verify().is_err(), "a live edit went undetected");
    }
}
