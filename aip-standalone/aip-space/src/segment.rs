//! Reassembly across contacts, over the continuity ledger that already exists.
//!
//! # This is not a second ledger
//!
//! `aip-observe::ObserverLedger` is the continuity authority. It decides
//! whether a segment is a contiguous successor, a replay, a fork, a rollback or
//! a gap, and once it proves a fork it stays quarantined. Nothing here
//! overrules it, repairs a fault it returns, or reimplements its arithmetic.
//!
//! What this module adds is the layer a disconnected mission needs and a live
//! link does not: **bundles arrive out of order**, and the ledger is strictly
//! ordered. Offering segment 12 and then segment 7 to the ledger produces a
//! `Rollback`, which is correct and unhelpful — the sender did nothing wrong,
//! the contacts simply happened in that order.
//!
//! So arriving bundles are *staged* first and offered *in sequence order*. Only
//! a bundle that arrives after the ledger has genuinely moved past its range is
//! a true late arrival, and that case is recorded rather than forced.
//!
//! # Gaps are recorded, and closing one requires the evidence
//!
//! A gap is a set of sequence numbers nobody has supplied. It is closed when
//! those exact sequences arrive and the ledger admits them, and by nothing
//! else. Not by reconnection, not by a later segment, not by an operator.
//! [`SegmentLedger::unfilled_gaps`] is the honest state of the mission, and
//! [`SegmentLedger::non_occurrence_admissible`] is `false` regardless of it.

use std::collections::{BTreeMap, BTreeSet};

use aip_observe::{Admission, ContinuityFault, ContinuityStatus, ObserverLedger};

use crate::bundle::{BundleLedger, StoreAndForwardBundle};
use crate::error::SpaceError;

/// What happened to one staged bundle when it was drained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentOutcome {
    /// Every segment was a contiguous successor.
    Continuous { first: u64, last: u64 },
    /// Admitted, and a gap preceded it. The skipped sequences are recorded.
    AdmittedWithGap {
        first: u64,
        last: u64,
        missing: Vec<u64>,
    },
    /// The first segments this ledger has seen for the observer. Continuity is
    /// asserted by the sender and verified by nobody.
    NewEpochUnverified { first: u64, last: u64 },
    /// The bundle covers sequences the ledger has already moved past. The
    /// evidence is retained and the chain is **not** rewound: a gap this
    /// bundle would have filled stays open, because admitting it would mean
    /// reordering attested history after the fact.
    LateArrival {
        first: u64,
        last: u64,
        ledger_at: u64,
    },
}

impl SegmentOutcome {
    /// Whether the outcome advanced the continuity chain.
    pub fn advanced_chain(&self) -> bool {
        !matches!(self, Self::LateArrival { .. })
    }
}

/// Reassembly and gap accounting for one observer's chain.
#[derive(Debug, Default)]
pub struct SegmentLedger {
    /// The continuity authority for the **current contiguous run**. Delegated
    /// to, never replaced.
    ///
    /// A fresh one is started after a gap, and that is not a second ledger: it
    /// is the same authority applied to a second run, because a chain cannot
    /// link across evidence nobody supplied. `prev_head` after a gap refers to
    /// a head this ground station never received, so offering it would produce
    /// a `HeadMismatch` — which is true, and less useful than recording the gap
    /// and saying the two runs are unlinked.
    ledger: ObserverLedger,
    /// Duplicate detection across contacts.
    bundles: BundleLedger,
    /// Bundles received and not yet drained, keyed by first sequence.
    staged: BTreeMap<u64, StoreAndForwardBundle>,
    /// Sequences nobody has supplied. Only shrinks when the exact sequence is
    /// admitted; never cleared wholesale.
    gaps: BTreeSet<u64>,
    /// Sequences admitted into the chain.
    admitted: BTreeSet<u64>,
    /// Bundles that arrived after the chain had passed them.
    late: Vec<[u8; 32]>,
    /// Highest sequence admitted across every run. Not the current run's.
    position: Option<u64>,
    /// Latched: once a gap is observed it is never cleared. This is the sticky
    /// property `ContinuityStatus::GapObserved` already has inside a single
    /// ledger, carried across the run boundary a gap creates.
    gap_observed: bool,
    /// Latched: a proven fork stays proven.
    quarantined: bool,
}

impl SegmentLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage an arriving bundle.
    ///
    /// Checks the bundle's self-description and rejects a duplicate. Staging is
    /// not admission: nothing reaches the continuity ledger until [`Self::drain`].
    pub fn stage(&mut self, bundle: StoreAndForwardBundle) -> Result<(), SpaceError> {
        self.bundles.admit(&bundle)?;
        // Two distinct bundles claiming the same starting sequence is a fork at
        // the container level. Refused here rather than silently overwriting,
        // because a map insert would drop one of them without a word.
        if let Some(existing) = self.staged.get(&bundle.first_sequence) {
            if existing.digest() != bundle.digest() {
                return Err(SpaceError::ContinuityRefused {
                    fault: ContinuityFault::Fork {
                        sequence: bundle.first_sequence,
                        recorded_head: existing.digest(),
                        offered_head: bundle.digest(),
                    },
                });
            }
        }
        self.staged.insert(bundle.first_sequence, bundle);
        Ok(())
    }

    /// Offer every staged bundle to the continuity ledger, in sequence order.
    ///
    /// Ordering before offering is the whole point: it is what lets bundles
    /// arrive across contacts in any order without manufacturing a rollback.
    /// A fault the ledger returns is propagated, never repaired.
    pub fn drain(&mut self) -> Result<Vec<SegmentOutcome>, SpaceError> {
        let staged = std::mem::take(&mut self.staged);
        let mut outcomes = Vec::new();
        for (_, bundle) in staged {
            outcomes.push(self.offer(&bundle)?);
        }
        Ok(outcomes)
    }

    fn offer(&mut self, bundle: &StoreAndForwardBundle) -> Result<SegmentOutcome, SpaceError> {
        let first = bundle.first_sequence;
        let last = bundle.last_sequence;

        // Already past this range: a genuine late arrival.
        if let Some(at) = self.position {
            if last <= at {
                self.late.push(bundle.digest());
                return Ok(SegmentOutcome::LateArrival {
                    first,
                    last,
                    ledger_at: at,
                });
            }
        }

        // A gap is detected here, before the ledger sees anything, and the
        // exact sequences are recorded — not a count. "Three segments missing"
        // cannot be checked off later; "segments 7, 8 and 9 missing" can.
        let mut missing: Vec<u64> = Vec::new();
        if let Some(at) = self.position {
            if first > at + 1 {
                for m in (at + 1)..first {
                    self.gaps.insert(m);
                    missing.push(m);
                }
                self.gap_observed = true;
                // The new run cannot link to the old one. Starting a fresh
                // ledger records that honestly; carrying the old one would
                // produce a HeadMismatch that says less.
                self.ledger = ObserverLedger::new();
            }
        }

        let mut new_epoch = false;
        for s in bundle.segments() {
            match self.ledger.admit(s.sequence, s.prev_head, s.head) {
                Ok(Admission::Continuous) => {}
                Ok(Admission::NewEpochUnverified) => new_epoch = true,
                Ok(Admission::AdmittedWithGap { .. }) => {
                    // A gap the collector itself declared, inside one run.
                    let from = self.position.map(|p| p + 1).unwrap_or(0);
                    for m in from..s.sequence {
                        if !self.admitted.contains(&m) {
                            self.gaps.insert(m);
                            missing.push(m);
                        }
                    }
                    self.gap_observed = true;
                }
                Err(fault) => {
                    if matches!(fault, ContinuityFault::Fork { .. }) {
                        self.quarantined = true;
                    }
                    return Err(SpaceError::ContinuityRefused { fault });
                }
            }
            self.admitted.insert(s.sequence);
            // Deliberately no `self.gaps.remove(...)` here. A gap is never
            // filled: a bundle covering one arrives below the chain position
            // and is a `LateArrival`, which does not admit. A line that removed
            // a gap would be unreachable and would read as though gaps close.
            self.position = Some(match self.position {
                Some(p) if p > s.sequence => p,
                _ => s.sequence,
            });
        }

        Ok(if !missing.is_empty() {
            SegmentOutcome::AdmittedWithGap {
                first,
                last,
                missing,
            }
        } else if new_epoch {
            SegmentOutcome::NewEpochUnverified { first, last }
        } else {
            SegmentOutcome::Continuous { first, last }
        })
    }

    /// The sequences nobody has supplied.
    pub fn unfilled_gaps(&self) -> Vec<u64> {
        self.gaps.iter().copied().collect()
    }

    /// Whether the mission's evidence is continuous.
    ///
    /// Delegates to the ledger's own status, and latches a gap across the run
    /// boundary a gap creates: once a gap is observed, no later evidence
    /// restores `Verified`. That stickiness is `ContinuityStatus`'s own
    /// property inside one ledger; here it survives the new run too.
    pub fn continuity_status(&self) -> ContinuityStatus {
        if self.quarantined || self.ledger.is_quarantined() {
            return ContinuityStatus::Broken;
        }
        if self.gap_observed {
            return ContinuityStatus::GapObserved;
        }
        self.ledger.status()
    }

    /// Whether a fork has been proven for this observer. Latched.
    pub fn is_quarantined(&self) -> bool {
        self.quarantined || self.ledger.is_quarantined()
    }

    /// Bundles that arrived after the chain had passed them.
    pub fn late_arrivals(&self) -> &[[u8; 32]] {
        &self.late
    }

    /// Whether the absence of a segment may be read as the absence of an event.
    ///
    /// **`false`, always.** A gap means nobody looked, or nobody could send
    /// what they saw. Neither is a statement about the vehicle. The method
    /// takes no arguments deliberately: there is no state in which the answer
    /// differs, and a parameterised version would be one somebody could
    /// parameterise into optimism.
    pub fn non_occurrence_admissible(&self) -> bool {
        false
    }

    /// Whether a claim that the mission's evidence is complete may be made.
    ///
    /// Two conditions, and each covers something the other does not.
    ///
    /// `continuity_status()` already folds in the gap latch and the quarantine
    /// latch, so restating either here would be a branch no mutation could
    /// kill — and a predicate with unkillable branches is a predicate nobody
    /// can check. `late` is genuinely separate: a bundle can arrive below the
    /// chain position on a run with no gap at all, and a mission holding
    /// evidence it could not admit is not complete.
    pub fn completeness_claimable(&self) -> bool {
        self.late.is_empty() && self.continuity_status() == ContinuityStatus::Verified
    }

    /// Attempt to record a gap as closed.
    ///
    /// Succeeds only when every named sequence has actually been admitted.
    /// There is deliberately no way to close a gap by assertion.
    pub fn require_filled(&self, sequences: &[u64]) -> Result<(), SpaceError> {
        let missing: Vec<u64> = sequences
            .iter()
            .copied()
            .filter(|s| !self.admitted.contains(s))
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(SpaceError::GapNotFilled { missing })
        }
    }

    pub fn admitted_count(&self) -> usize {
        self.admitted.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BundleSegment;
    use crate::link::LinkState;

    /// A chain whose heads link: head(n) == prev_head(n+1).
    fn seg(sequence: u64) -> BundleSegment {
        BundleSegment {
            sequence,
            prev_head: head_for(sequence - 1),
            head: head_for(sequence),
            attested_at_ms: 1_000 + sequence,
            payload_digest: [0xAB; 32],
        }
    }

    fn head_for(n: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_le_bytes());
        h
    }

    fn bundle(range: std::ops::RangeInclusive<u64>) -> StoreAndForwardBundle {
        StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "onboard-collector",
            range.map(seg).collect(),
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap()
    }

    #[test]
    fn a_complete_mission_drains_continuously_and_claims_completeness() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.stage(bundle(4..=6)).unwrap();
        let outcomes = l.drain().unwrap();
        assert!(matches!(
            outcomes[0],
            SegmentOutcome::NewEpochUnverified { .. }
        ));
        assert!(matches!(outcomes[1], SegmentOutcome::Continuous { .. }));
        assert!(l.unfilled_gaps().is_empty());
        assert_eq!(l.admitted_count(), 6);
        // The first bundle is a new epoch, so the status is not Verified until
        // a contiguous successor lands — which the second bundle is.
        assert_eq!(l.continuity_status(), ContinuityStatus::Verified);
        assert!(l.completeness_claimable());
    }

    #[test]
    fn out_of_order_bundles_are_reassembled_rather_than_rejected() {
        // The contacts happened in the wrong order. Nothing is wrong with the
        // evidence, and staging before offering is what makes that true.
        let mut l = SegmentLedger::new();
        l.stage(bundle(4..=6)).unwrap();
        l.stage(bundle(1..=3)).unwrap();
        let outcomes = l.drain().unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(l.unfilled_gaps().is_empty());
        assert!(l.completeness_claimable());
    }

    #[test]
    fn a_missing_middle_segment_records_the_exact_sequences_and_never_closes() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.stage(bundle(7..=9)).unwrap();
        let outcomes = l.drain().unwrap();
        match &outcomes[1] {
            SegmentOutcome::AdmittedWithGap { missing, .. } => {
                assert_eq!(missing, &vec![4, 5, 6]);
            }
            other => panic!("expected a gap, got {other:?}"),
        }
        assert_eq!(l.unfilled_gaps(), vec![4, 5, 6]);
        assert_eq!(l.continuity_status(), ContinuityStatus::GapObserved);
        assert!(!l.completeness_claimable());
        assert!(l.require_filled(&[4, 5, 6]).is_err());
        // And no amount of further well-formed evidence closes it.
        l.stage(bundle(10..=12)).unwrap();
        l.drain().unwrap();
        assert_eq!(l.unfilled_gaps(), vec![4, 5, 6]);
        assert_eq!(l.continuity_status(), ContinuityStatus::GapObserved);
        assert!(!l.completeness_claimable());
    }

    #[test]
    fn a_gap_never_becomes_evidence_of_non_occurrence() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.stage(bundle(7..=9)).unwrap();
        l.drain().unwrap();
        assert!(!l.non_occurrence_admissible());
    }

    #[test]
    fn a_delayed_middle_segment_arriving_later_does_not_rewind_the_chain() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.stage(bundle(7..=9)).unwrap();
        l.drain().unwrap();
        assert_eq!(l.unfilled_gaps(), vec![4, 5, 6]);

        // The missing bundle finally arrives, two contacts late.
        l.stage(bundle(4..=6)).unwrap();
        let outcomes = l.drain().unwrap();
        match &outcomes[0] {
            SegmentOutcome::LateArrival {
                first,
                last,
                ledger_at,
            } => {
                assert_eq!((*first, *last, *ledger_at), (4, 6, 9));
            }
            other => panic!("expected a late arrival, got {other:?}"),
        }
        assert!(!outcomes[0].advanced_chain());
        // The evidence is retained and the gap stays open: admitting it would
        // mean reordering attested history after the fact.
        assert_eq!(l.unfilled_gaps(), vec![4, 5, 6]);
        assert_eq!(l.late_arrivals().len(), 1);
        assert!(!l.completeness_claimable());
    }

    #[test]
    fn a_duplicate_bundle_is_refused_before_it_reaches_the_ledger() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        assert!(matches!(
            l.stage(bundle(1..=3)),
            Err(SpaceError::BundleAlreadySeen { .. })
        ));
    }

    #[test]
    fn two_different_bundles_at_one_start_sequence_are_a_fork() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        // Same start, different content: a fork at the container level.
        let forked = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "onboard-collector",
            (1..=4).map(seg).collect(),
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap();
        assert!(matches!(
            l.stage(forked),
            Err(SpaceError::ContinuityRefused {
                fault: ContinuityFault::Fork { .. }
            })
        ));
    }

    #[test]
    fn a_replayed_segment_inside_a_new_bundle_is_refused_by_the_ledger() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.drain().unwrap();
        // A different bundle re-offering sequence 3 with the same head.
        let replay = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-115").unwrap(),
            "onboard-collector",
            (3..=5).map(seg).collect(),
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap();
        l.stage(replay).unwrap();
        // Sequence 3 is the ledger's current position with the same head, so
        // the ledger names it a replay. The profile carries the fault through
        // and does not repair it.
        assert!(matches!(
            l.drain(),
            Err(SpaceError::ContinuityRefused {
                fault: ContinuityFault::Replay { sequence: 3 }
            })
        ));
    }

    #[test]
    fn a_late_arrival_on_an_otherwise_complete_run_blocks_completeness() {
        // No gap anywhere: three segments admitted in order. Then a different
        // bundle re-covering ground the chain has passed. Continuity is still
        // `Verified`, and the mission is still not complete, because evidence
        // arrived that could not be admitted.
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.drain().unwrap();
        assert!(l.completeness_claimable());
        assert_eq!(l.continuity_status(), ContinuityStatus::Verified);

        let overlapping = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-115").unwrap(),
            "onboard-collector",
            (2..=3).map(seg).collect(),
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap();
        l.stage(overlapping).unwrap();
        let outcomes = l.drain().unwrap();
        assert!(matches!(outcomes[0], SegmentOutcome::LateArrival { .. }));
        assert!(l.unfilled_gaps().is_empty(), "no gap was ever observed");
        assert_eq!(l.continuity_status(), ContinuityStatus::Verified);
        assert!(
            !l.completeness_claimable(),
            "a mission holding evidence it could not admit is not complete"
        );
    }

    #[test]
    fn require_filled_cannot_be_satisfied_by_assertion() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.drain().unwrap();
        assert!(l.require_filled(&[1, 2, 3]).is_ok());
        match l.require_filled(&[1, 2, 3, 4]) {
            Err(SpaceError::GapNotFilled { missing }) => assert_eq!(missing, vec![4]),
            other => panic!("{other:?}"),
        }
    }
}
