//! Surviving a restart without forgetting — and proving the memory is real.
//!
//! # The restart-to-forget attack
//!
//! Everything this crate seals is chained: an enforcement action and a
//! sensor attestation both extend [`Patrol`](crate::patrol::Patrol)'s own
//! `anchor_tail`, so the sentinel's conduct is tamper-evident *within one
//! process*. Across a restart it was not. [`Patrol::new`](crate::patrol::Patrol::new)
//! begins at [`GENESIS_HASH`] with sequence zero, unconditionally, which
//! makes a process restart indistinguishable from a first deployment and
//! hands an adversary a clean way to erase the record:
//!
//! - Every prior enforcement anchor is orphaned — the new chain descends
//!   from genesis, not from the last thing the sentinel actually sealed, so
//!   nothing links the two halves of its history.
//! - The sensor checkpoint history goes with it. That is the worse half:
//!   [`crate::sensors::JsonlAccessLog::deep_verify`] can only catch a
//!   retroactive edit by recomputing against a checkpoint sealed *before*
//!   the edit, so a sentinel that restarts holds no baseline and silently
//!   loses the ability to detect tampering that predates the restart.
//! - [`SensorLivenessDetector`](crate::detector::SensorLivenessDetector) is
//!   gated on having ever seen a checkpoint, so it goes quiet too, and the
//!   coverage gap that gating was built to surface stops being reported.
//!
//! The net effect is a watchdog that can be reset into amnesia by anything
//! that can cause a restart — a crash, an OOM kill, or simply waiting for
//! the next deploy — and which then reports a clean patrol because it has
//! nothing left to compare against. Silence reads identically to safety,
//! which is the failure this whole crate exists to remove.
//!
//! # Why persistence alone is not the fix
//!
//! Writing [`PatrolState`] to disk and reading it back closes the amnesia
//! but not the attack: an adversary who can restart the process can usually
//! also edit the file it resumes from, and a state file is self-consistent
//! by construction — whatever head it names is the head the sentinel adopts.
//! A digest over the file's own contents proves nothing either, since
//! whoever edits the contents recomputes the digest.
//!
//! What *is* checkable is an invariant across two independently held
//! records. The sentinel emits its anchors into an external archive; the
//! resumed head must equal the `anchorHash` of the highest-`sequenceNumber`
//! anchor that archive holds under the sentinel's DID. Neither copy is
//! trusted on its own, and disagreement is arithmetic rather than
//! judgement — which is why [`ContinuityDetector`](crate::detector::ContinuityDetector)
//! reports at [`Strength::Proof`](crate::finding::Strength::Proof), the same
//! standard [`ChainIntegrityDetector`](crate::detector::ChainIntegrityDetector)
//! reaches for a broken evidence chain.
//!
//! [`ContinuityBreak`] enumerates the four ways the two records can
//! disagree; [`verify_continuity`] is the arithmetic that distinguishes
//! them.

use ot_accountability_core::GENESIS_HASH;
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::attestation::SensorCheckpoint;

/// Everything the sentinel must carry across a restart to stay the same
/// sentinel: where its own chain had reached, and the sensor attestation
/// history that later deep verifications are checked against.
///
/// Deliberately not `Serialize`/`Deserialize` derived — the JSON shape is
/// written out by hand in [`PatrolState::to_json`] so it stays the same
/// camel-cased wire vocabulary the anchors use, rather than tracking Rust
/// field names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatrolState {
    /// Whose chain this is. Resuming one sentinel's state into a differently
    /// named sentinel would silently splice two chains together, so this
    /// travels with the state and is checked on resume.
    pub sentinel_did: String,
    /// Head of the sentinel's own anchor chain.
    pub anchor_tail: String,
    /// Sequence number of the last anchor sealed.
    pub anchor_sequence: u64,
    /// Sealed checkpoint history per sensor, oldest first.
    pub sensor_checkpoints: BTreeMap<String, Vec<SensorCheckpoint>>,
}

impl PatrolState {
    /// The state of a sentinel that has never sealed anything.
    pub fn genesis(sentinel_did: impl Into<String>) -> Self {
        Self {
            sentinel_did: sentinel_did.into(),
            anchor_tail: GENESIS_HASH.to_string(),
            anchor_sequence: 0,
            sensor_checkpoints: BTreeMap::new(),
        }
    }

    /// True when nothing has ever been sealed under this state.
    pub fn is_genesis(&self) -> bool {
        self.anchor_sequence == 0 && self.anchor_tail == GENESIS_HASH
    }

    /// The durable JSON form.
    pub fn to_json(&self) -> Value {
        let checkpoints: Vec<Value> = self
            .sensor_checkpoints
            .values()
            .flatten()
            .map(SensorCheckpoint::to_payload)
            .collect();
        json!({
            "sentinelDid": self.sentinel_did,
            "anchorTail": self.anchor_tail,
            "anchorSequence": self.anchor_sequence,
            "sensorCheckpoints": checkpoints,
        })
    }

    /// Reads back what [`PatrolState::to_json`] wrote.
    ///
    /// Strict: a state file that cannot be read completely is not silently
    /// downgraded to a partial resume, because a partial resume is exactly
    /// the amnesia this type exists to prevent — and it would present as a
    /// clean patrol.
    pub fn from_json(value: &Value) -> Result<Self, String> {
        let sentinel_did = value
            .get("sentinelDid")
            .and_then(Value::as_str)
            .ok_or("patrol state is missing a string \"sentinelDid\"")?
            .to_string();
        let anchor_tail = value
            .get("anchorTail")
            .and_then(Value::as_str)
            .ok_or("patrol state is missing a string \"anchorTail\"")?
            .to_string();
        let anchor_sequence = value
            .get("anchorSequence")
            .and_then(Value::as_u64)
            .ok_or("patrol state is missing an unsigned \"anchorSequence\"")?;

        let mut sensor_checkpoints: BTreeMap<String, Vec<SensorCheckpoint>> = BTreeMap::new();
        let raw = value
            .get("sensorCheckpoints")
            .and_then(Value::as_array)
            .ok_or("patrol state is missing an array \"sensorCheckpoints\"")?;
        for (index, entry) in raw.iter().enumerate() {
            let checkpoint = SensorCheckpoint::from_payload(entry)
                .map_err(|why| format!("sensorCheckpoints[{index}]: {why}"))?;
            sensor_checkpoints
                .entry(checkpoint.sensor.clone())
                .or_default()
                .push(checkpoint);
        }

        Ok(Self {
            sentinel_did,
            anchor_tail,
            anchor_sequence,
            sensor_checkpoints,
        })
    }
}

/// The ways a resumed chain head can disagree with the archive of anchors
/// the sentinel actually emitted.
///
/// Every variant is decided by comparing two numbers and two hashes, so a
/// break is never a heuristic. What a break does *not* say is which copy is
/// the honest one: an operator reading `RolledBack` knows the sentinel
/// resumed behind its own archive, not whether the state file was reverted
/// or the archive was replayed forward. Naming the tamper is the
/// investigation; detecting the disagreement is the sentinel's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuityBreak {
    /// The sentinel resumed at genesis while the archive holds anchors under
    /// its DID — the restart-to-forget signature. Either the state was lost
    /// (a crash before the first durable write) or it was deleted.
    Amnesia {
        /// Highest sequence the archive holds for this sentinel.
        archived_sequence: u64,
        /// The head the sentinel should have resumed from.
        archived_tail: String,
    },
    /// The sentinel resumed behind its own archive: an older state was
    /// restored over a newer one, which drops every enforcement action and
    /// attestation sealed in between.
    RolledBack {
        /// Where the state file said the chain had reached.
        resumed_sequence: u64,
        /// Where the archive says it had actually reached.
        archived_sequence: u64,
    },
    /// Same sequence number, different hash: the state file names a head the
    /// sentinel never sealed. One identity, two chains.
    Forked {
        /// The disputed sequence number.
        sequence: u64,
        /// The head the state file claims.
        resumed_tail: String,
        /// The head the archive recorded.
        archived_tail: String,
    },
    /// The sentinel is ahead of its own archive — it holds a record of
    /// sealing anchors the archive does not have. Anchors were removed from
    /// the archive, or never durably landed there.
    ///
    /// This is the one variant with a benign explanation: an archive still
    /// flushing the most recent patrol will read as truncated. Audit against
    /// a settled archive at resume time, not mid-write. See
    /// [`verify_continuity`].
    ArchiveTruncated {
        /// Where the sentinel's own state says the chain reached.
        resumed_sequence: u64,
        /// The highest sequence the archive holds, or zero when it holds
        /// nothing for this sentinel at all.
        archived_sequence: u64,
    },
}

impl ContinuityBreak {
    /// The wire vocabulary for which kind of disagreement this is.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Amnesia { .. } => "AMNESIA",
            Self::RolledBack { .. } => "ROLLED_BACK",
            Self::Forked { .. } => "FORKED",
            Self::ArchiveTruncated { .. } => "ARCHIVE_TRUNCATED",
        }
    }

    /// One line an operator can act on.
    pub fn summary(&self) -> String {
        match self {
            Self::Amnesia {
                archived_sequence,
                archived_tail,
            } => format!(
                "sentinel resumed at genesis but its archive holds {archived_sequence} sealed anchor(s) ending {}… — prior enforcement history and every sensor tamper baseline are orphaned",
                short(archived_tail),
            ),
            Self::RolledBack {
                resumed_sequence,
                archived_sequence,
            } => format!(
                "sentinel resumed at sequence {resumed_sequence} but its archive reached {archived_sequence} — an older state was restored, dropping {} sealed record(s)",
                archived_sequence.saturating_sub(*resumed_sequence),
            ),
            Self::Forked {
                sequence,
                resumed_tail,
                archived_tail,
            } => format!(
                "sentinel chain forked at sequence {sequence}: resumed {}…, archive recorded {}…",
                short(resumed_tail),
                short(archived_tail),
            ),
            Self::ArchiveTruncated {
                resumed_sequence,
                archived_sequence,
            } => format!(
                "sentinel holds sequence {resumed_sequence} but its archive holds only {archived_sequence} — {} sealed anchor(s) are missing from the archive",
                resumed_sequence.saturating_sub(*archived_sequence),
            ),
        }
    }

    /// Citations a reviewer can re-derive the break from.
    pub fn evidence(&self) -> Vec<String> {
        match self {
            Self::Amnesia {
                archived_sequence, ..
            } => vec![
                "sentinel-state:genesis".to_string(),
                format!("sentinel-archive:sequence:{archived_sequence}"),
            ],
            Self::RolledBack {
                resumed_sequence,
                archived_sequence,
            } => vec![
                format!("sentinel-state:sequence:{resumed_sequence}"),
                format!("sentinel-archive:sequence:{archived_sequence}"),
            ],
            Self::Forked {
                sequence,
                resumed_tail,
                archived_tail,
            } => vec![
                format!("sentinel-state:sequence:{sequence}:{resumed_tail}"),
                format!("sentinel-archive:sequence:{sequence}:{archived_tail}"),
            ],
            Self::ArchiveTruncated {
                resumed_sequence,
                archived_sequence,
            } => vec![
                format!("sentinel-state:sequence:{resumed_sequence}"),
                format!("sentinel-archive:sequence:{archived_sequence}"),
            ],
        }
    }
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

/// The highest-sequence anchor the archive holds under `sentinel_did`, as
/// `(sequence, anchorHash)`.
///
/// Anchors are matched on `agentDid` — the field
/// [`Patrol`](crate::patrol::Patrol) seals its own anchors under — so a
/// fleet-wide archive can be passed in whole without the caller having to
/// pre-filter it, and an anchor some other agent wrote can never be mistaken
/// for one of the sentinel's own.
fn archive_head(sentinel_did: &str, archived_anchors: &[Value]) -> Option<(u64, String)> {
    archived_anchors
        .iter()
        .filter(|a| a.get("agentDid").and_then(Value::as_str) == Some(sentinel_did))
        .filter_map(|a| {
            let sequence = a.get("sequenceNumber").and_then(Value::as_u64)?;
            let hash = a.get("anchorHash").and_then(Value::as_str)?;
            Some((sequence, hash.to_string()))
        })
        .max_by_key(|(sequence, _)| *sequence)
}

/// Checks a resumed chain head against the archive of anchors the sentinel
/// emitted, returning the disagreement if there is one.
///
/// `archived_anchors` may be the whole fleet's archive; only anchors sealed
/// under `sentinel_did` are considered. A sentinel resuming at genesis
/// against an archive that holds nothing for it is a first deployment, not a
/// break — the two cases are indistinguishable by construction, and treating
/// a fresh install as a tamper would make "not configured yet" the loudest
/// finding in the report.
///
/// # Ordering
///
/// Call this at resume, against an archive that has settled. Auditing while
/// the most recent patrol's anchors are still in flight will report
/// [`ContinuityBreak::ArchiveTruncated`] for records that are merely late,
/// which is the one false positive this arithmetic cannot rule out on its
/// own: from the sentinel's side, "not yet written" and "removed" look the
/// same.
pub fn verify_continuity(
    sentinel_did: &str,
    resumed_sequence: u64,
    resumed_tail: &str,
    archived_anchors: &[Value],
) -> Option<ContinuityBreak> {
    let Some((archived_sequence, archived_tail)) = archive_head(sentinel_did, archived_anchors)
    else {
        // Nothing archived under this DID.
        return if resumed_sequence == 0 {
            None
        } else {
            Some(ContinuityBreak::ArchiveTruncated {
                resumed_sequence,
                archived_sequence: 0,
            })
        };
    };

    match resumed_sequence.cmp(&archived_sequence) {
        std::cmp::Ordering::Less if resumed_sequence == 0 => Some(ContinuityBreak::Amnesia {
            archived_sequence,
            archived_tail,
        }),
        std::cmp::Ordering::Less => Some(ContinuityBreak::RolledBack {
            resumed_sequence,
            archived_sequence,
        }),
        std::cmp::Ordering::Greater => Some(ContinuityBreak::ArchiveTruncated {
            resumed_sequence,
            archived_sequence,
        }),
        std::cmp::Ordering::Equal if resumed_tail != archived_tail => {
            Some(ContinuityBreak::Forked {
                sequence: resumed_sequence,
                resumed_tail: resumed_tail.to_string(),
                archived_tail,
            })
        }
        std::cmp::Ordering::Equal => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(did: &str, sequence: u64, hash: &str) -> Value {
        json!({
            "agentDid": did,
            "sequenceNumber": sequence,
            "anchorHash": hash,
        })
    }

    const SENTINEL: &str = "did:ot:sentinel";

    #[test]
    fn a_fresh_deployment_against_an_empty_archive_is_not_a_break() {
        assert_eq!(verify_continuity(SENTINEL, 0, GENESIS_HASH, &[]), None);
    }

    #[test]
    fn resuming_exactly_where_the_archive_ended_is_continuous() {
        let archive = [anchor(SENTINEL, 7, "hash-7")];
        assert_eq!(verify_continuity(SENTINEL, 7, "hash-7", &archive), None);
    }

    #[test]
    fn restarting_at_genesis_with_history_in_the_archive_is_amnesia() {
        let archive = [anchor(SENTINEL, 4, "hash-4")];
        assert_eq!(
            verify_continuity(SENTINEL, 0, GENESIS_HASH, &archive),
            Some(ContinuityBreak::Amnesia {
                archived_sequence: 4,
                archived_tail: "hash-4".into(),
            })
        );
    }

    #[test]
    fn resuming_behind_the_archive_is_a_rollback() {
        let archive = [anchor(SENTINEL, 9, "hash-9")];
        assert_eq!(
            verify_continuity(SENTINEL, 3, "hash-3", &archive),
            Some(ContinuityBreak::RolledBack {
                resumed_sequence: 3,
                archived_sequence: 9,
            })
        );
    }

    #[test]
    fn the_same_sequence_with_a_different_hash_is_a_fork() {
        let archive = [anchor(SENTINEL, 5, "archived")];
        assert_eq!(
            verify_continuity(SENTINEL, 5, "forged", &archive),
            Some(ContinuityBreak::Forked {
                sequence: 5,
                resumed_tail: "forged".into(),
                archived_tail: "archived".into(),
            })
        );
    }

    #[test]
    fn being_ahead_of_the_archive_reports_the_missing_records() {
        let archive = [anchor(SENTINEL, 2, "hash-2")];
        assert_eq!(
            verify_continuity(SENTINEL, 6, "hash-6", &archive),
            Some(ContinuityBreak::ArchiveTruncated {
                resumed_sequence: 6,
                archived_sequence: 2,
            })
        );
    }

    #[test]
    fn a_wiped_archive_is_reported_even_with_nothing_to_compare_against() {
        assert_eq!(
            verify_continuity(SENTINEL, 3, "hash-3", &[]),
            Some(ContinuityBreak::ArchiveTruncated {
                resumed_sequence: 3,
                archived_sequence: 0,
            })
        );
    }

    #[test]
    fn another_agents_anchors_are_never_mistaken_for_the_sentinels_own() {
        // A busy fleet archive: only the sentinel's own anchors may set its
        // head, or any agent could push the sentinel's expected sequence up
        // and manufacture a rollback finding against it.
        let archive = [
            anchor("did:ot:agent-a", 99, "not-ours"),
            anchor(SENTINEL, 2, "hash-2"),
        ];
        assert_eq!(verify_continuity(SENTINEL, 2, "hash-2", &archive), None);
    }

    #[test]
    fn the_head_is_the_highest_sequence_not_the_last_listed() {
        // Archives are not guaranteed to arrive in order.
        let archive = [anchor(SENTINEL, 8, "hash-8"), anchor(SENTINEL, 3, "hash-3")];
        assert_eq!(verify_continuity(SENTINEL, 8, "hash-8", &archive), None);
        assert!(matches!(
            verify_continuity(SENTINEL, 3, "hash-3", &archive),
            Some(ContinuityBreak::RolledBack { .. })
        ));
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut state = PatrolState::genesis(SENTINEL);
        state.anchor_tail = "tail".into();
        state.anchor_sequence = 3;
        state.sensor_checkpoints.insert(
            "tool-log".into(),
            vec![SensorCheckpoint {
                sensor: "tool-log".into(),
                offset: 42,
                stream_tail_hash: "b".repeat(64),
                checkpointed_at_utc: "2026-08-28T00:00:00.000Z".into(),
            }],
        );

        let restored = PatrolState::from_json(&state.to_json()).expect("round trip");
        assert_eq!(restored, state);
    }

    #[test]
    fn a_truncated_state_file_is_an_error_not_a_silent_partial_resume() {
        let missing_tail = json!({
            "sentinelDid": SENTINEL,
            "anchorSequence": 2,
            "sensorCheckpoints": [],
        });
        let error = PatrolState::from_json(&missing_tail).expect_err("must not parse");
        assert!(error.contains("anchorTail"), "unhelpful error: {error}");
    }

    #[test]
    fn a_malformed_checkpoint_names_which_one_failed() {
        let bad = json!({
            "sentinelDid": SENTINEL,
            "anchorTail": GENESIS_HASH,
            "anchorSequence": 0,
            "sensorCheckpoints": [
                { "sensor": "a", "offset": 1, "streamTailHash": "h", "checkpointedAtUtc": "t" },
                { "sensor": "b", "offset": 2 },
            ],
        });
        let error = PatrolState::from_json(&bad).expect_err("must not parse");
        assert!(
            error.contains("sensorCheckpoints[1]"),
            "error should name the failing entry: {error}"
        );
    }
}
