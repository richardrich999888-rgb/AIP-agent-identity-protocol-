//! Mission state, and what evidence each claim needs.
//!
//! The tiers are the ones every other vertical uses — `Declared`,
//! `DecisionSigned`, `ExecutionObserved`, `PhysicallyObserved`, in that order,
//! with the top one unreachable. Four verticals answering the same question
//! differently would be four accountability models.
//!
//! # The state this profile adds
//!
//! `EvidenceOutstanding`. A disconnected mission has a state the connected
//! verticals do not: the vehicle has done something, the evidence exists
//! aboard, and none of it has arrived. That is neither `Executing` (which would
//! claim observation the ground does not have) nor `Unknown` (which would
//! discard the fact that a bundle is expected). It sits at `DecisionSigned`,
//! because what is established is that the work was authorized.

use serde::{Deserialize, Serialize};

/// What evidence a state claim would need before a verifier may assert it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SpaceEvidence {
    Declared,
    DecisionSigned,
    ExecutionObserved,
    /// An independent mechanism measured the vehicle's physical state.
    /// **Unreachable in this build**, computed from the class table.
    PhysicallyObserved,
}

impl SpaceEvidence {
    pub fn code(self) -> u8 {
        match self {
            Self::Declared => 0x01,
            Self::DecisionSigned => 0x02,
            Self::ExecutionObserved => 0x03,
            Self::PhysicallyObserved => 0x04,
        }
    }

    pub fn is_reachable(self) -> bool {
        match self {
            Self::PhysicallyObserved => {
                aip_observation::ObservationClass::PhysicalEffect.is_implemented()
            }
            _ => true,
        }
    }
}

/// The state of a mission activity, as claimed or as evidence supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MissionState {
    Planned,
    Authorized,
    Uplinked,
    Executing,
    /// Work was authorized, the vehicle is out of contact, and its evidence has
    /// not arrived. A real state, not a gap in the model.
    EvidenceOutstanding,
    Degraded,
    Suspended,
    AbortRequested,
    Aborted,
    Completed,
    Unknown,
}

impl MissionState {
    pub const ALL: [MissionState; 11] = [
        Self::Planned,
        Self::Authorized,
        Self::Uplinked,
        Self::Executing,
        Self::EvidenceOutstanding,
        Self::Degraded,
        Self::Suspended,
        Self::AbortRequested,
        Self::Aborted,
        Self::Completed,
        Self::Unknown,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Planned => 0x01,
            Self::Authorized => 0x02,
            Self::Uplinked => 0x03,
            Self::Executing => 0x04,
            Self::EvidenceOutstanding => 0x05,
            Self::Degraded => 0x06,
            Self::Suspended => 0x07,
            Self::AbortRequested => 0x08,
            Self::Aborted => 0x09,
            Self::Completed => 0x0A,
            Self::Unknown => 0xFF,
        }
    }

    /// The weakest evidence that would justify asserting this state.
    ///
    /// `Uplinked` sits at `DecisionSigned` and not higher: that a command was
    /// radiated is a fact about the ground station, and that the vehicle
    /// received it is the vehicle's account. `Aborted` and `Completed` are
    /// statements about the vehicle's body and need a physical observation.
    pub fn evidence_required(self) -> SpaceEvidence {
        match self {
            Self::Planned | Self::Unknown => SpaceEvidence::Declared,
            Self::Authorized
            | Self::Uplinked
            | Self::EvidenceOutstanding
            | Self::AbortRequested => SpaceEvidence::DecisionSigned,
            Self::Executing | Self::Degraded | Self::Suspended => SpaceEvidence::ExecutionObserved,
            Self::Aborted | Self::Completed => SpaceEvidence::PhysicallyObserved,
        }
    }

    pub fn is_physical_claim(self) -> bool {
        matches!(self.evidence_required(), SpaceEvidence::PhysicallyObserved)
    }

    /// What may be asserted, given a claim and the available evidence.
    ///
    /// Returns `Unknown` whenever the claim outruns the evidence. Echo or
    /// weaken; never strengthen, never substitute.
    pub fn assertable(claimed: MissionState, available: SpaceEvidence) -> MissionState {
        if available >= claimed.evidence_required() && claimed.evidence_required().is_reachable() {
            claimed
        } else {
            MissionState::Unknown
        }
    }

    pub fn reachable_in_this_build(self) -> bool {
        self.evidence_required().is_reachable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_self_reported_completion_is_never_asserted() {
        for tier in [
            SpaceEvidence::Declared,
            SpaceEvidence::DecisionSigned,
            SpaceEvidence::ExecutionObserved,
            SpaceEvidence::PhysicallyObserved,
        ] {
            assert_eq!(
                MissionState::assertable(MissionState::Completed, tier),
                MissionState::Unknown,
                "{tier:?}"
            );
        }
    }

    #[test]
    fn evidence_outstanding_is_assertable_from_a_signature_alone() {
        // The point of the state: the ground knows the work was authorized and
        // has no observation. That is a real, assertable position.
        assert_eq!(
            MissionState::assertable(
                MissionState::EvidenceOutstanding,
                SpaceEvidence::DecisionSigned
            ),
            MissionState::EvidenceOutstanding
        );
        // And it is not Executing, which would claim an observation.
        assert_eq!(
            MissionState::assertable(MissionState::Executing, SpaceEvidence::DecisionSigned),
            MissionState::Unknown
        );
    }

    #[test]
    fn assertable_never_strengthens_or_substitutes() {
        for claimed in MissionState::ALL {
            for tier in [
                SpaceEvidence::Declared,
                SpaceEvidence::DecisionSigned,
                SpaceEvidence::ExecutionObserved,
                SpaceEvidence::PhysicallyObserved,
            ] {
                let out = MissionState::assertable(claimed, tier);
                assert!(
                    out == claimed || out == MissionState::Unknown,
                    "{claimed:?}/{tier:?}"
                );
            }
        }
    }

    #[test]
    fn the_physical_tier_is_unreachable_and_the_others_are_not() {
        assert!(!SpaceEvidence::PhysicallyObserved.is_reachable());
        for t in [
            SpaceEvidence::Declared,
            SpaceEvidence::DecisionSigned,
            SpaceEvidence::ExecutionObserved,
        ] {
            assert!(t.is_reachable(), "{t:?}");
        }
        for s in [MissionState::Aborted, MissionState::Completed] {
            assert!(s.is_physical_claim(), "{s:?}");
            assert!(!s.reachable_in_this_build(), "{s:?}");
        }
    }

    #[test]
    fn state_codes_are_unique() {
        let mut codes: Vec<u8> = MissionState::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), MissionState::ALL.len());
    }
}
