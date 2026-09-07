//! Mission state, and the rule that a claim never outruns its evidence.
//!
//! # The failure this module prevents
//!
//! A UAS that reports `COMPLETED` has reported `COMPLETED`. That is the whole
//! content of the message. Every operational system that treats it as the
//! mission's state has quietly promoted a self-report to a fact, and will do
//! so identically for an aircraft that landed successfully and for one whose
//! autonomy stack was replaced in flight.
//!
//! So states here carry the evidence they *require*, and
//! [`MissionState::assertable`] returns what may be said, which is often less
//! than what was claimed and is never more.
//!
//! # Why not a lattice with a `min`
//!
//! Because the states are not ordered. `Aborted` and `Completed` are not
//! comparable, and a `min` over them would silently pick one. Instead each
//! state names the evidence tier that would justify it, and a claim that
//! outruns the available evidence degrades to [`MissionState::Unknown`] —
//! which is a statement a verifier can act on, and more honest than a
//! neighbouring state chosen for looking close.

use serde::{Deserialize, Serialize};

/// What kind of evidence a mission state needs before a verifier may assert
/// it.
///
/// Ordered, and the ordering is the only operation that makes sense: each tier
/// subsumes the ones before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StateEvidence {
    /// Nothing beyond someone's declaration. Enough for a plan.
    Declared,
    /// A decision point's signature. Recomputable by a third party.
    DecisionSigned,
    /// An anchored observer measured the autonomy execution.
    ///
    /// Reachable in this build: the companion computer's process and socket
    /// observation.
    ExecutionObserved,
    /// An independent mechanism measured the aircraft's physical state.
    ///
    /// **Unreachable in this build.** `ObservationClass::PhysicalEffect` has
    /// no mechanism (ADR-003 decision 2), so every state requiring this tier
    /// resolves to `Unknown` for every real aircraft.
    PhysicallyObserved,
}

impl StateEvidence {
    pub fn code(self) -> u8 {
        match self {
            Self::Declared => 0x01,
            Self::DecisionSigned => 0x02,
            Self::ExecutionObserved => 0x03,
            Self::PhysicallyObserved => 0x04,
        }
    }

    /// Whether this tier is reachable at all in this build.
    ///
    /// Computed from the class table rather than written as a literal, so
    /// implementing a physical mechanism has to change the table — and fail
    /// this crate's tests — rather than leave a stale `false` behind.
    pub fn is_reachable(self) -> bool {
        match self {
            Self::PhysicallyObserved => {
                aip_observation::ObservationClass::PhysicalEffect.is_implemented()
            }
            _ => true,
        }
    }
}

/// The state of a mission, as someone claims it or as evidence supports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MissionState {
    /// A plan exists.
    Planned,
    /// A decision point authorized it.
    Authorized,
    /// The autonomy execution began.
    Started,
    /// The autonomy execution is running.
    InProgress,
    /// The autonomy execution is running with reduced observation or a
    /// reported fault.
    ///
    /// Note what this is *about*: the degradation a verifier can establish is
    /// degradation of its own visibility, not of the aircraft.
    Degraded,
    /// An abort was requested.
    AbortRequested,
    /// The mission was aborted, and the aircraft's behaviour reflects it.
    Aborted,
    /// The aircraft is returning to its launch point.
    Returning,
    /// The aircraft is on the ground.
    Landed,
    /// The mission's objectives were met.
    Completed,
    /// Nothing may be said. The default and the honest fallback.
    Unknown,
}

impl MissionState {
    pub const ALL: [MissionState; 11] = [
        Self::Planned,
        Self::Authorized,
        Self::Started,
        Self::InProgress,
        Self::Degraded,
        Self::AbortRequested,
        Self::Aborted,
        Self::Returning,
        Self::Landed,
        Self::Completed,
        Self::Unknown,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Planned => 0x01,
            Self::Authorized => 0x02,
            Self::Started => 0x03,
            Self::InProgress => 0x04,
            Self::Degraded => 0x05,
            Self::AbortRequested => 0x06,
            Self::Aborted => 0x07,
            Self::Returning => 0x08,
            Self::Landed => 0x09,
            Self::Completed => 0x0A,
            Self::Unknown => 0xFF,
        }
    }

    /// The weakest evidence that would justify asserting this state.
    ///
    /// The four at the bottom are the interesting ones. `Aborted`,
    /// `Returning`, `Landed` and `Completed` are all claims about **where the
    /// aircraft is and what it did**, not about software: an aborted mission
    /// whose aircraft kept flying is exactly the case that matters, and no
    /// amount of autonomy-execution observation distinguishes it from one that
    /// stopped. They require a physical observation, which does not exist.
    ///
    /// `AbortRequested` is deliberately weaker than `Aborted`: a request is a
    /// message, and a signed one is recomputable.
    pub fn evidence_required(self) -> StateEvidence {
        match self {
            Self::Planned => StateEvidence::Declared,
            Self::Authorized | Self::AbortRequested => StateEvidence::DecisionSigned,
            Self::Started | Self::InProgress | Self::Degraded => StateEvidence::ExecutionObserved,
            Self::Aborted | Self::Returning | Self::Landed | Self::Completed => {
                StateEvidence::PhysicallyObserved
            }
            // `Unknown` asserts nothing, so it needs nothing.
            Self::Unknown => StateEvidence::Declared,
        }
    }

    /// Whether this state is about the aircraft rather than about the
    /// software.
    pub fn is_physical_claim(self) -> bool {
        matches!(self.evidence_required(), StateEvidence::PhysicallyObserved)
    }

    /// What may be asserted, given what a party claimed and what evidence is
    /// available.
    ///
    /// Returns `Unknown` whenever the claim outruns the evidence. It never
    /// returns a state the claimant did not claim: this function weakens, and
    /// has no power to strengthen or to substitute.
    pub fn assertable(claimed: MissionState, available: StateEvidence) -> MissionState {
        if available >= claimed.evidence_required() && claimed.evidence_required().is_reachable() {
            claimed
        } else {
            MissionState::Unknown
        }
    }

    /// Whether a self-reporting aircraft could ever get this state asserted in
    /// this build.
    pub fn reachable_in_this_build(self) -> bool {
        self.evidence_required().is_reachable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_reported_completion_is_not_proven_completion() {
        // The headline case. An aircraft claims COMPLETED with the strongest
        // evidence this build can produce behind it.
        assert_eq!(
            MissionState::assertable(MissionState::Completed, StateEvidence::ExecutionObserved),
            MissionState::Unknown
        );
        // And with nothing behind it.
        assert_eq!(
            MissionState::assertable(MissionState::Completed, StateEvidence::Declared),
            MissionState::Unknown
        );
    }

    #[test]
    fn every_physical_state_is_unreachable_in_this_build() {
        for s in [
            MissionState::Aborted,
            MissionState::Returning,
            MissionState::Landed,
            MissionState::Completed,
        ] {
            assert!(s.is_physical_claim(), "{s:?}");
            assert!(
                !s.reachable_in_this_build(),
                "{s:?} became assertable; no mechanism implements a physical observation"
            );
            // Even handed the top tier, it stays Unknown, because the tier
            // itself is unreachable.
            assert_eq!(
                MissionState::assertable(s, StateEvidence::PhysicallyObserved),
                MissionState::Unknown,
                "{s:?}"
            );
        }
    }

    #[test]
    fn execution_states_are_assertable_from_observed_execution() {
        for s in [
            MissionState::Started,
            MissionState::InProgress,
            MissionState::Degraded,
        ] {
            assert_eq!(
                MissionState::assertable(s, StateEvidence::ExecutionObserved),
                s,
                "{s:?} is a statement about software and is reachable"
            );
            assert_eq!(
                MissionState::assertable(s, StateEvidence::DecisionSigned),
                MissionState::Unknown,
                "{s:?} must not be assertable from a signature alone"
            );
        }
    }

    #[test]
    fn authorization_states_need_a_decision_signature() {
        assert_eq!(
            MissionState::assertable(MissionState::Authorized, StateEvidence::DecisionSigned),
            MissionState::Authorized
        );
        assert_eq!(
            MissionState::assertable(MissionState::Authorized, StateEvidence::Declared),
            MissionState::Unknown
        );
    }

    #[test]
    fn an_abort_request_is_weaker_than_an_abort() {
        assert!(
            MissionState::AbortRequested.evidence_required()
                < MissionState::Aborted.evidence_required(),
            "a request is a message; an abort is a change in what the aircraft is doing"
        );
        assert_eq!(
            MissionState::assertable(MissionState::AbortRequested, StateEvidence::DecisionSigned),
            MissionState::AbortRequested
        );
        assert_eq!(
            MissionState::assertable(MissionState::Aborted, StateEvidence::DecisionSigned),
            MissionState::Unknown
        );
    }

    #[test]
    fn assertable_never_strengthens_or_substitutes() {
        for claimed in MissionState::ALL {
            for tier in [
                StateEvidence::Declared,
                StateEvidence::DecisionSigned,
                StateEvidence::ExecutionObserved,
                StateEvidence::PhysicallyObserved,
            ] {
                let out = MissionState::assertable(claimed, tier);
                assert!(
                    out == claimed || out == MissionState::Unknown,
                    "assertable({claimed:?}, {tier:?}) = {out:?}: it may only echo or weaken"
                );
            }
        }
    }

    #[test]
    fn unknown_is_always_assertable_and_asserts_nothing() {
        assert_eq!(
            MissionState::assertable(MissionState::Unknown, StateEvidence::Declared),
            MissionState::Unknown
        );
    }

    #[test]
    fn state_codes_are_unique() {
        let mut codes: Vec<u8> = MissionState::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), MissionState::ALL.len());
    }
}
