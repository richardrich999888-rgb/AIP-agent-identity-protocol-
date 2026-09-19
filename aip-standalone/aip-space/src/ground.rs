//! The ground station's side: what may be concluded, and when.
//!
//! # Verification is offline by construction
//!
//! Nothing about checking a bundle needs a network. Signatures verify against
//! anchors the station provisioned itself, hashes recompute from bytes it
//! holds, and the continuity arithmetic is arithmetic. That is the property the
//! Skill 26 acceptance gate asks for — *verified later without cloud
//! dependence* — and it is inherited rather than built: `aip-nexora`'s verifier
//! is already a pure function of a package and a set of anchors.
//!
//! # Authority staleness is the verifier's question, not this profile's
//!
//! A command authorized three days before a spacecraft executed it, verified a
//! week after that, raises the question of whether the authority was still live
//! — and `aip-nexora::AuthorityStanding` already answers it, against a present
//! time the verifier supplies. This module does not reimplement that
//! arithmetic. It carries the station's present time so the verifier can be
//! asked, and says so.
//!
//! # What a station may conclude
//!
//! [`GroundConclusion`] has four variants and none of them is *"nothing
//! happened"*. That absence is deliberate: a station that cannot see a segment
//! has learned something about its own coverage, and nothing about the vehicle.

use serde::{Deserialize, Serialize};

use crate::error::SpaceError;
use crate::segment::SegmentLedger;

/// What a ground station concluded about a mission's evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroundConclusion {
    /// Every segment arrived, in order, with continuity verified.
    EvidenceComplete { segments: usize },
    /// Evidence arrived and named sequences are missing. **Not** a statement
    /// that anything did or did not happen during them.
    EvidenceIncomplete { missing: Vec<u64> },
    /// A fork was proven. The observer's chain is quarantined and stays so.
    ContinuityBroken,
    /// Nothing sufficient arrived to conclude anything.
    CannotProve { reason: &'static str },
}

impl GroundConclusion {
    /// Whether this conclusion asserts that the mission's evidence is whole.
    pub fn asserts_completeness(&self) -> bool {
        matches!(self, Self::EvidenceComplete { .. })
    }

    /// Whether this conclusion asserts that something did **not** happen.
    ///
    /// **`false` for every variant.** No conclusion this profile can reach is
    /// a non-occurrence claim, and the method exists so that is testable rather
    /// than merely absent.
    pub fn asserts_non_occurrence(&self) -> bool {
        false
    }

    pub fn code(&self) -> u8 {
        match self {
            Self::EvidenceComplete { .. } => 0x01,
            Self::EvidenceIncomplete { .. } => 0x02,
            Self::ContinuityBroken => 0x03,
            Self::CannotProve { .. } => 0x04,
        }
    }
}

/// The ground station's context at the moment of verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundVerificationContext {
    station_id: String,
    /// The station's own clock. Supplied by the caller; this crate reads no
    /// clock, so every branch is reachable from a test.
    pub present_time_ms: u64,
    /// Whether the station has provisioned its own trust anchors out of band.
    ///
    /// A station that imported anchors from beside the evidence has verified
    /// nothing, which is why `aip-nexora`'s export moves them separately and
    /// why this is recorded rather than assumed.
    pub anchors_provisioned: bool,
}

impl GroundVerificationContext {
    pub fn new(
        station_id: &str,
        present_time_ms: u64,
        anchors_provisioned: bool,
    ) -> Result<Self, SpaceError> {
        if station_id.is_empty() || station_id.len() > 128 {
            return Err(SpaceError::Malformed {
                reason: "station id must be 1-128 bytes",
            });
        }
        Ok(Self {
            station_id: station_id.to_owned(),
            present_time_ms,
            anchors_provisioned,
        })
    }

    pub fn station_id(&self) -> &str {
        &self.station_id
    }

    /// Whether verification here requires reaching any network.
    ///
    /// **`false`.** Signatures verify against anchors the station holds and
    /// hashes recompute from bytes it holds. This is the acceptance gate's
    /// "without cloud dependence", stated as a property rather than a promise.
    pub fn requires_network(&self) -> bool {
        false
    }

    /// Whether the station is in a position to verify at all.
    ///
    /// Anchors must have been provisioned out of band. Without them a station
    /// can parse evidence and can conclude nothing from it.
    pub fn may_verify(&self) -> bool {
        self.anchors_provisioned
    }

    /// Whether authority staleness is decided here.
    ///
    /// **`false`.** It is `aip-nexora::AuthorityStanding`'s question, answered
    /// by the existing verifier against the present time this context carries.
    /// A second implementation would be a second answer.
    pub fn decides_authority_standing(&self) -> bool {
        false
    }

    /// What this station may conclude about a mission's evidence.
    ///
    /// Reads the segment ledger and reports. It computes no verdict about the
    /// vehicle: `Reconciliation` is the core's, and nothing here produces one.
    pub fn conclude(&self, ledger: &SegmentLedger) -> GroundConclusion {
        if !self.may_verify() {
            return GroundConclusion::CannotProve {
                reason: "the station has no anchors provisioned; it can parse evidence and \
                         conclude nothing from it",
            };
        }
        if ledger.is_quarantined() {
            return GroundConclusion::ContinuityBroken;
        }
        if ledger.admitted_count() == 0 {
            return GroundConclusion::CannotProve {
                reason: "no segment was admitted; nothing arrived, which is a fact about the \
                         link and not about the vehicle",
            };
        }
        let missing = ledger.unfilled_gaps();
        if !missing.is_empty() {
            return GroundConclusion::EvidenceIncomplete { missing };
        }
        if !ledger.completeness_claimable() {
            return GroundConclusion::CannotProve {
                reason: "no gap is recorded and continuity is not verified; a late arrival or an \
                         unverified epoch is outstanding",
            };
        }
        GroundConclusion::EvidenceComplete {
            segments: ledger.admitted_count(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleSegment, StoreAndForwardBundle};
    use crate::link::LinkState;

    fn head_for(n: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_le_bytes());
        h
    }

    fn seg(sequence: u64) -> BundleSegment {
        BundleSegment {
            sequence,
            prev_head: head_for(sequence - 1),
            head: head_for(sequence),
            attested_at_ms: 1_000 + sequence,
            payload_digest: [0xAB; 32],
        }
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

    fn station() -> GroundVerificationContext {
        GroundVerificationContext::new("gs-svalbard", 1_000_000, true).unwrap()
    }

    #[test]
    fn verification_needs_no_network_and_does_not_decide_authority() {
        let s = station();
        assert!(!s.requires_network());
        assert!(!s.decides_authority_standing());
        assert!(s.may_verify());
    }

    #[test]
    fn a_station_with_no_anchors_concludes_nothing() {
        let s = GroundVerificationContext::new("gs", 1, false).unwrap();
        assert!(!s.may_verify());
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.drain().unwrap();
        assert!(matches!(
            s.conclude(&l),
            GroundConclusion::CannotProve { .. }
        ));
    }

    #[test]
    fn a_complete_mission_concludes_complete() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.stage(bundle(4..=6)).unwrap();
        l.drain().unwrap();
        assert_eq!(
            station().conclude(&l),
            GroundConclusion::EvidenceComplete { segments: 6 }
        );
    }

    #[test]
    fn a_gapped_mission_concludes_incomplete_and_never_non_occurrence() {
        let mut l = SegmentLedger::new();
        l.stage(bundle(1..=3)).unwrap();
        l.stage(bundle(7..=9)).unwrap();
        l.drain().unwrap();
        let c = station().conclude(&l);
        assert_eq!(
            c,
            GroundConclusion::EvidenceIncomplete {
                missing: vec![4, 5, 6]
            }
        );
        assert!(!c.asserts_completeness());
        assert!(!c.asserts_non_occurrence());
    }

    #[test]
    fn nothing_arriving_concludes_cannot_prove_rather_than_nothing_happened() {
        let l = SegmentLedger::new();
        let c = station().conclude(&l);
        match &c {
            GroundConclusion::CannotProve { reason } => {
                assert!(reason.contains("not about the vehicle"));
            }
            other => panic!("{other:?}"),
        }
        assert!(!c.asserts_non_occurrence());
    }

    #[test]
    fn no_conclusion_asserts_non_occurrence() {
        for c in [
            GroundConclusion::EvidenceComplete { segments: 9 },
            GroundConclusion::EvidenceIncomplete { missing: vec![4] },
            GroundConclusion::ContinuityBroken,
            GroundConclusion::CannotProve { reason: "x" },
        ] {
            assert!(!c.asserts_non_occurrence(), "{c:?}");
        }
        let mut codes: Vec<u8> = [
            GroundConclusion::EvidenceComplete { segments: 1 },
            GroundConclusion::EvidenceIncomplete { missing: vec![] },
            GroundConclusion::ContinuityBroken,
            GroundConclusion::CannotProve { reason: "x" },
        ]
        .iter()
        .map(|c| c.code())
        .collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 4);
    }

    #[test]
    fn a_station_id_is_bounded() {
        assert!(GroundVerificationContext::new("", 1, true).is_err());
        assert!(GroundVerificationContext::new(&"x".repeat(129), 1, true).is_err());
    }
}
