//! Continuity: the collector-side ledger that decides whether the observer
//! may claim it was watching.
//!
//! The ledger lives **at the collector**, off the observed host. That is the
//! whole point: a state file on a host the attacker controls proves nothing
//! about itself, because it can be erased, rolled back, or replayed. Here the
//! previous sequence and previous head are held by the party that signs, so a
//! host that is wiped cannot re-assert a position in attested history — it can
//! only produce a visible discontinuity.

use serde::{Deserialize, Serialize};

use crate::health::ContinuityStatus;

/// Why a submitted batch could not be admitted as a continuous successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContinuityFault {
    /// A batch at an already-consumed sequence, byte-identical to the one on
    /// record. A replayed signature is not a new observation (§17).
    Replay { sequence: u64 },
    /// A batch at an already-consumed sequence with a *different* head.
    /// Two distinct attested batches at one sequence under one key is an
    /// arithmetic proof of observer integrity failure.
    Fork {
        sequence: u64,
        recorded_head: [u8; 32],
        offered_head: [u8; 32],
    },
    /// Sequence moved backwards.
    Rollback { last: u64, offered: u64 },
    /// Sequence skipped forward; the skipped interval is not covered.
    Gap { expected: u64, offered: u64 },
    /// The batch's `prev_head` does not match the recorded head.
    HeadMismatch {
        expected: [u8; 32],
        offered: [u8; 32],
    },
    /// The first batch of a run did not declare the epoch start it claimed.
    UnverifiableEpoch,
}

/// How a collector's resumed state disagrees with the archive of its own
/// signed health records. Arithmetic on two independently held records;
/// about the observer's record only, never about any workload. Harvested
/// design: PR #3 `ot-sentinel/src/state.rs` (`6cc439f`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContinuityBreak {
    /// No state at all, but the archive holds sealed history: the collector
    /// forgot. Resuming from genesis would start a second chain under the
    /// same key, so the archive head is adopted instead.
    Amnesia {
        archived_sequence: u64,
        archived_head: [u8; 32],
    },
    /// The state is older than the archive: an older state was restored.
    /// The archive head is adopted.
    RolledBack {
        resumed_sequence: u64,
        archived_sequence: u64,
    },
    /// Same sequence, different head: two heads under one key at one
    /// position. An integrity failure of the observer's own record; the
    /// collector is quarantined.
    Forked {
        sequence: u64,
        resumed_head: [u8; 32],
        archived_head: [u8; 32],
    },
    /// The state is ahead of the archive: records the collector sealed are
    /// missing from the archive (a crash between state write and archive
    /// append, or a shortened archive). The state is kept and the gap is
    /// reported.
    ArchiveTruncated {
        resumed_sequence: u64,
        archived_sequence: u64,
    },
}

/// What the ledger did with a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Contiguous successor; continuity holds.
    Continuous,
    /// Admitted, but a gap preceded it. The skipped interval is not covered.
    AdmittedWithGap { missing: u64 },
    /// Admitted as the first batch of a new epoch with no verifiable link to
    /// prior attested state (fresh observer, or amnesia after state loss).
    NewEpochUnverified,
}

/// Per-observer continuity state, held by the collector.
#[derive(Debug, Clone, Default)]
pub struct ObserverLedger {
    last_sequence: Option<u64>,
    last_head: Option<[u8; 32]>,
    status: Option<ContinuityStatus>,
    quarantined: bool,
}

impl ObserverLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    pub fn last_head(&self) -> Option<[u8; 32]> {
        self.last_head
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantined
    }

    /// Continuity status implied by everything admitted so far.
    pub fn status(&self) -> ContinuityStatus {
        if self.quarantined {
            return ContinuityStatus::Broken;
        }
        self.status.unwrap_or(ContinuityStatus::Unverified)
    }

    /// The next sequence a well-behaved observer should present.
    pub fn next_sequence(&self) -> u64 {
        self.last_sequence.map(|s| s + 1).unwrap_or(1)
    }

    /// The `prev_head` a well-behaved observer should declare.
    pub fn expected_prev_head(&self) -> [u8; 32] {
        self.last_head.unwrap_or([0u8; 32])
    }

    /// Offer a (sequence, prev_head, head) triple for admission.
    ///
    /// Faults are returned, never repaired. Once a fork is proven the ledger
    /// stays quarantined: an integrity failure cannot be un-proven by later
    /// well-formed traffic.
    pub fn admit(
        &mut self,
        sequence: u64,
        prev_head: [u8; 32],
        head: [u8; 32],
    ) -> Result<Admission, ContinuityFault> {
        if self.quarantined {
            return Err(ContinuityFault::Fork {
                sequence,
                recorded_head: self.last_head.unwrap_or([0u8; 32]),
                offered_head: head,
            });
        }

        match (self.last_sequence, self.last_head) {
            // First batch this collector has seen for the observer.
            (None, _) => {
                if sequence == 0 {
                    return Err(ContinuityFault::UnverifiableEpoch);
                }
                self.last_sequence = Some(sequence);
                self.last_head = Some(head);
                // A first batch links to nothing this collector witnessed.
                // Even a well-formed zero prev_head is only an assertion that
                // an epoch started; it is not verified continuity.
                self.status = Some(ContinuityStatus::Unverified);
                Ok(Admission::NewEpochUnverified)
            }
            (Some(last_seq), Some(last_head)) => {
                if sequence == last_seq {
                    return if head == last_head {
                        Err(ContinuityFault::Replay { sequence })
                    } else {
                        self.quarantined = true;
                        self.status = Some(ContinuityStatus::Broken);
                        Err(ContinuityFault::Fork {
                            sequence,
                            recorded_head: last_head,
                            offered_head: head,
                        })
                    };
                }
                if sequence < last_seq {
                    return Err(ContinuityFault::Rollback {
                        last: last_seq,
                        offered: sequence,
                    });
                }
                if prev_head != last_head {
                    return Err(ContinuityFault::HeadMismatch {
                        expected: last_head,
                        offered: prev_head,
                    });
                }
                let expected = last_seq + 1;
                self.last_sequence = Some(sequence);
                self.last_head = Some(head);
                if sequence == expected {
                    if self.status != Some(ContinuityStatus::GapObserved) {
                        self.status = Some(ContinuityStatus::Verified);
                    }
                    Ok(Admission::Continuous)
                } else {
                    self.status = Some(ContinuityStatus::GapObserved);
                    Ok(Admission::AdmittedWithGap {
                        missing: sequence - expected,
                    })
                }
            }
            (Some(_), None) => Err(ContinuityFault::UnverifiableEpoch),
        }
    }

    /// Adopt a chain position carried across a collector restart. Continuity
    /// is **not** re-established by resuming: the status is `Unverified`
    /// until the next contiguous batch is admitted. With no position the
    /// ledger stays fresh.
    pub fn resume_at(&mut self, sequence: Option<u64>, head: Option<[u8; 32]>) {
        if let (Some(s), Some(h)) = (sequence, head) {
            self.last_sequence = Some(s);
            self.last_head = Some(h);
            if !self.quarantined {
                self.status = Some(ContinuityStatus::Unverified);
            }
        }
    }

    /// Latch an integrity failure of the observer's own record. Never
    /// un-latched by later traffic.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.status = Some(ContinuityStatus::Broken);
    }

    /// Record that the observer restarted. Continuity is not re-established
    /// by a restart, and the ledger never invents a link across one.
    pub fn note_restart(&mut self) {
        if !self.quarantined {
            self.status = Some(ContinuityStatus::Unverified);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn first_batch_is_never_verified_continuity() {
        let mut l = ObserverLedger::new();
        assert_eq!(
            l.admit(1, [0u8; 32], h(1)),
            Ok(Admission::NewEpochUnverified)
        );
        assert_eq!(l.status(), ContinuityStatus::Unverified);
    }

    #[test]
    fn contiguous_chain_verifies() {
        let mut l = ObserverLedger::new();
        l.admit(1, [0u8; 32], h(1)).unwrap();
        assert_eq!(l.admit(2, h(1), h(2)), Ok(Admission::Continuous));
        assert_eq!(l.status(), ContinuityStatus::Verified);
        assert_eq!(l.next_sequence(), 3);
        assert_eq!(l.expected_prev_head(), h(2));
    }

    #[test]
    fn exact_replay_is_refused() {
        let mut l = ObserverLedger::new();
        l.admit(1, [0u8; 32], h(1)).unwrap();
        l.admit(2, h(1), h(2)).unwrap();
        assert_eq!(
            l.admit(2, h(1), h(2)),
            Err(ContinuityFault::Replay { sequence: 2 })
        );
        assert!(!l.is_quarantined());
    }

    #[test]
    fn fork_at_one_sequence_quarantines_permanently() {
        let mut l = ObserverLedger::new();
        l.admit(1, [0u8; 32], h(1)).unwrap();
        let fault = l.admit(1, [0u8; 32], h(9)).unwrap_err();
        assert!(matches!(fault, ContinuityFault::Fork { sequence: 1, .. }));
        assert!(l.is_quarantined());
        assert_eq!(l.status(), ContinuityStatus::Broken);
        // Later well-formed traffic cannot clear it.
        assert!(l.admit(2, h(1), h(2)).is_err());
        assert_eq!(l.status(), ContinuityStatus::Broken);
    }

    #[test]
    fn rollback_and_gap_and_head_mismatch_are_distinct() {
        let mut l = ObserverLedger::new();
        l.admit(5, [0u8; 32], h(5)).unwrap();
        l.admit(6, h(5), h(6)).unwrap();
        assert_eq!(
            l.admit(4, h(3), h(4)),
            Err(ContinuityFault::Rollback {
                last: 6,
                offered: 4
            })
        );
        assert_eq!(
            l.admit(7, h(99), h(7)),
            Err(ContinuityFault::HeadMismatch {
                expected: h(6),
                offered: h(99)
            })
        );
        assert_eq!(
            l.admit(9, h(6), h(9)),
            Ok(Admission::AdmittedWithGap { missing: 2 })
        );
        assert_eq!(l.status(), ContinuityStatus::GapObserved);
    }

    #[test]
    fn gap_status_is_not_silently_upgraded_by_later_contiguity() {
        let mut l = ObserverLedger::new();
        l.admit(1, [0u8; 32], h(1)).unwrap();
        l.admit(2, h(1), h(2)).unwrap();
        l.admit(5, h(2), h(5)).unwrap(); // gap
        assert_eq!(l.status(), ContinuityStatus::GapObserved);
        l.admit(6, h(5), h(6)).unwrap(); // contiguous again
        assert_eq!(
            l.status(),
            ContinuityStatus::GapObserved,
            "a later good batch must not erase a recorded gap"
        );
    }

    #[test]
    fn restart_does_not_imply_continuity() {
        let mut l = ObserverLedger::new();
        l.admit(1, [0u8; 32], h(1)).unwrap();
        l.admit(2, h(1), h(2)).unwrap();
        assert_eq!(l.status(), ContinuityStatus::Verified);
        l.note_restart();
        assert_eq!(l.status(), ContinuityStatus::Unverified);
    }
}
