//! Per-execution event chains: drop, duplicate, reorder and splice detection.
//!
//! # Why a chain and not just sequence numbers
//!
//! A sequence number alone catches a gap but not a *substitution*: an
//! attacker who removes event 4 and renumbers 5→4 leaves a contiguous run.
//! Each event therefore carries `prev_event_hash`, the SHA-256 of the
//! previous event's signed preimage, so the chain is only intact if every
//! link is the event that was actually there.
//!
//! # What this establishes, and what it does not
//!
//! An intact chain shows that the events *presented* form an unbroken,
//! agent-signed run. It does not show that the agent emitted everything it
//! should have: an agent that never emits an event for a tool call it made
//! produces a perfectly intact chain with the incriminating link missing.
//! Only independent observation can speak to that, which is
//! [`crate::corroborate`]'s job. A chain is an integrity check on a
//! narrative, not a guarantee that the narrative is complete.

use crate::error::AiriError;
use crate::event::{verify_airi_event, AiriEvent};

/// A way a presented run of events fails to be one intact chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainDefect {
    /// No events were supplied.
    Empty,
    /// The run does not start at sequence 0.
    DoesNotStartAtZero { first: u64 },
    /// The first event's `prev_event_hash` is not the zero genesis value.
    GenesisNotZero,
    /// Sequence numbers skip — at least one event is missing.
    SequenceGap { after: u64, found: u64 },
    /// The same sequence number appears twice. A replayed or duplicated event.
    SequenceDuplicate { sequence: u64 },
    /// Sequence numbers move backwards.
    SequenceOutOfOrder { previous: u64, found: u64 },
    /// An event's `prev_event_hash` is not the hash of the event before it.
    /// Something was substituted, removed, or altered.
    PrevHashMismatch { sequence: u64 },
    /// An event belongs to a different execution.
    ExecutionMismatch { sequence: u64 },
    /// An event was authored by a different agent.
    AgentMismatch { sequence: u64, agent_id: String },
    /// An event's own signature did not verify.
    EventUnverified { sequence: u64 },
}

/// A chain that passed every check in [`verify_event_chain`].
///
/// `#[non_exhaustive]` forbids struct-literal construction outside this
/// crate, so a caller cannot assert a chain it did not prove — the same
/// guarantee as `aip_reconcile`'s action-evidence seal, and for the same
/// reason: a value that means "verified" must be unforgeable by whoever
/// benefits from it. [`verify_event_chain`] is the only way to obtain one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedChain {
    /// The execution every event in the chain belongs to.
    pub execution_id: [u8; 16],
    /// The agent that authored every event.
    pub agent_id: String,
    /// Number of events, which is also `last_sequence + 1`.
    pub len: usize,
    /// Hash of the final event — what a continuation must carry.
    pub head: [u8; 32],
}

/// Outcome of checking a presented run of events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainReport {
    Intact(VerifiedChain),
    Defective(ChainDefect),
}

/// Verify that `events` form one intact, agent-signed chain.
///
/// Events must be supplied in the order the caller received them; this
/// function does **not** sort them, because reordering is one of the defects
/// it exists to detect. Sorting first would hide the attack.
///
/// Checks, in order, per event:
/// 1. the signature verifies under `agent_public_key`;
/// 2. the agent is the same throughout;
/// 3. the execution is the same throughout;
/// 4. the sequence is exactly one more than the previous;
/// 5. `prev_event_hash` is the previous event's hash.
///
/// A failed check short-circuits: later events are not examined, because
/// their relationship to a broken chain is not meaningful.
pub fn verify_event_chain(events: &[AiriEvent], agent_public_key: &[u8]) -> ChainReport {
    use ChainDefect as D;

    let Some(first) = events.first() else {
        return ChainReport::Defective(D::Empty);
    };

    if first.sequence != 0 {
        return ChainReport::Defective(D::DoesNotStartAtZero {
            first: first.sequence,
        });
    }
    if first.prev_event_hash != [0u8; 32] {
        return ChainReport::Defective(D::GenesisNotZero);
    }

    let execution_id = first.execution_id;
    let agent_id = first.agent_id.clone();
    let mut prev: Option<&AiriEvent> = None;

    for ev in events {
        if verify_airi_event(ev, agent_public_key).is_err() {
            return ChainReport::Defective(D::EventUnverified {
                sequence: ev.sequence,
            });
        }
        if ev.agent_id != agent_id {
            return ChainReport::Defective(D::AgentMismatch {
                sequence: ev.sequence,
                agent_id: ev.agent_id.clone(),
            });
        }
        if ev.execution_id != execution_id {
            return ChainReport::Defective(D::ExecutionMismatch {
                sequence: ev.sequence,
            });
        }

        if let Some(p) = prev {
            match ev.sequence.cmp(&p.sequence) {
                std::cmp::Ordering::Less => {
                    return ChainReport::Defective(D::SequenceOutOfOrder {
                        previous: p.sequence,
                        found: ev.sequence,
                    })
                }
                std::cmp::Ordering::Equal => {
                    return ChainReport::Defective(D::SequenceDuplicate {
                        sequence: ev.sequence,
                    })
                }
                std::cmp::Ordering::Greater => {
                    if ev.sequence != p.sequence + 1 {
                        return ChainReport::Defective(D::SequenceGap {
                            after: p.sequence,
                            found: ev.sequence,
                        });
                    }
                }
            }
            if ev.prev_event_hash != p.event_hash() {
                return ChainReport::Defective(D::PrevHashMismatch {
                    sequence: ev.sequence,
                });
            }
        }
        prev = Some(ev);
    }

    // `prev` is Some: `events.first()` succeeded above.
    let head = prev.expect("non-empty").event_hash();
    ChainReport::Intact(VerifiedChain {
        execution_id,
        agent_id,
        len: events.len(),
        head,
    })
}

impl ChainReport {
    /// The verified chain, or the defect as an error.
    pub fn into_result(self) -> Result<VerifiedChain, AiriError> {
        match self {
            Self::Intact(c) => Ok(c),
            Self::Defective(d) => Err(AiriError::Chain(d)),
        }
    }
}
