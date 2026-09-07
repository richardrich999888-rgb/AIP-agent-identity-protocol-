//! The state of a control-loop execution, as claimed and as evidence supports.
//!
//! # Why `PROCESS_CHANGED` is unreachable
//!
//! Each state names the evidence tier that would justify asserting it. The
//! states about the *plant* — an energised output, a moved actuator, a changed
//! process, a completed shutdown — need a physical observation, which no
//! mechanism provides, so they resolve to `Unknown` for every real deployment.
//! A control system that emits a "shutdown complete" event has emitted an event.
//!
//! # The tiers are the ones the other two verticals use
//!
//! `Declared`, `DecisionSigned`, `ExecutionObserved`, `PhysicallyObserved` —
//! the same four names, in the same order, with the same top tier unreachable,
//! as `aip-uas::StateEvidence` and `aip-robotics::TaskEvidence`. That is not
//! coincidence and it is not copy-paste convenience: three verticals answering
//! the same question differently would be three accountability models, and
//! `tests/cross_vertical.rs` compares all three name for name.

use serde::{Deserialize, Serialize};

/// What evidence a state would need before a verifier may assert it.
///
/// Ordered; each tier subsumes the ones before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProcessEvidence {
    /// Someone's declaration. Enough for a plan.
    Declared,
    /// A decision point's signature. Recomputable by a third party.
    DecisionSigned,
    /// An anchored observer measured the edge node's execution.
    ExecutionObserved,
    /// An independent mechanism measured the plant.
    ///
    /// **Unreachable in this build**, computed from the class table.
    PhysicallyObserved,
}

impl ProcessEvidence {
    pub fn code(self) -> u8 {
        match self {
            Self::Declared => 0x01,
            Self::DecisionSigned => 0x02,
            Self::ExecutionObserved => 0x03,
            Self::PhysicallyObserved => 0x04,
        }
    }

    /// Whether this tier is reachable at all in this build.
    pub fn is_reachable(self) -> bool {
        match self {
            Self::PhysicallyObserved => {
                aip_observation::ObservationClass::PhysicalEffect.is_implemented()
            }
            _ => true,
        }
    }
}

/// The state of a control-loop execution, as claimed or as evidence supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LoopState {
    Planned,
    Authorized,
    CommandIssued,
    Executing,
    Degraded,
    Suspended,
    AbortRequested,
    OutputEnergised,
    ActuatorMoved,
    ProcessChanged,
    ShutdownComplete,
    Unknown,
}

impl LoopState {
    pub const ALL: [LoopState; 12] = [
        Self::Planned,
        Self::Authorized,
        Self::CommandIssued,
        Self::Executing,
        Self::Degraded,
        Self::Suspended,
        Self::AbortRequested,
        Self::OutputEnergised,
        Self::ActuatorMoved,
        Self::ProcessChanged,
        Self::ShutdownComplete,
        Self::Unknown,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Planned => 0x01,
            Self::Authorized => 0x02,
            Self::CommandIssued => 0x03,
            Self::Executing => 0x04,
            Self::Degraded => 0x05,
            Self::Suspended => 0x06,
            Self::AbortRequested => 0x07,
            Self::OutputEnergised => 0x08,
            Self::ActuatorMoved => 0x09,
            Self::ProcessChanged => 0x0A,
            Self::ShutdownComplete => 0x0B,
            Self::Unknown => 0xFF,
        }
    }

    /// The weakest evidence that would justify asserting this state.
    ///
    /// `Suspended` and `Degraded` sit at `ExecutionObserved` because both are
    /// statements about the edge node — what it stopped doing, and what coverage
    /// the verifier lost. `OutputEnergised`, `ActuatorMoved`, `ProcessChanged`
    /// and `ShutdownComplete` are statements about the plant, and no amount of
    /// software observation distinguishes a shutdown that completed from one
    /// whose final element did not move.
    pub fn evidence_required(self) -> ProcessEvidence {
        match self {
            Self::Planned | Self::Unknown => ProcessEvidence::Declared,
            Self::Authorized | Self::AbortRequested => ProcessEvidence::DecisionSigned,
            Self::CommandIssued | Self::Executing | Self::Degraded | Self::Suspended => {
                ProcessEvidence::ExecutionObserved
            }
            Self::OutputEnergised
            | Self::ActuatorMoved
            | Self::ProcessChanged
            | Self::ShutdownComplete => ProcessEvidence::PhysicallyObserved,
        }
    }

    /// Whether this state is about the plant rather than the edge node.
    pub fn is_physical_claim(self) -> bool {
        matches!(
            self.evidence_required(),
            ProcessEvidence::PhysicallyObserved
        )
    }

    /// What may be asserted, given a claim and the available evidence.
    ///
    /// Returns `Unknown` whenever the claim outruns the evidence. It may only
    /// echo or weaken — never strengthen, never substitute a neighbouring state
    /// for looking close.
    pub fn assertable(claimed: LoopState, available: ProcessEvidence) -> LoopState {
        if available >= claimed.evidence_required() && claimed.evidence_required().is_reachable() {
            claimed
        } else {
            LoopState::Unknown
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
    fn a_self_reported_shutdown_is_never_asserted() {
        for tier in [
            ProcessEvidence::Declared,
            ProcessEvidence::DecisionSigned,
            ProcessEvidence::ExecutionObserved,
            ProcessEvidence::PhysicallyObserved,
        ] {
            assert_eq!(
                LoopState::assertable(LoopState::ShutdownComplete, tier),
                LoopState::Unknown,
                "SHUTDOWN_COMPLETE became assertable at {tier:?}"
            );
        }
    }

    #[test]
    fn every_plant_state_is_unreachable() {
        for s in [
            LoopState::OutputEnergised,
            LoopState::ActuatorMoved,
            LoopState::ProcessChanged,
            LoopState::ShutdownComplete,
        ] {
            assert!(s.is_physical_claim(), "{s:?}");
            assert!(!s.reachable_in_this_build(), "{s:?}");
        }
    }

    #[test]
    fn edge_node_states_are_assertable_from_observed_execution() {
        for s in [
            LoopState::CommandIssued,
            LoopState::Executing,
            LoopState::Degraded,
            LoopState::Suspended,
        ] {
            assert_eq!(
                LoopState::assertable(s, ProcessEvidence::ExecutionObserved),
                s,
                "{s:?}"
            );
            assert_eq!(
                LoopState::assertable(s, ProcessEvidence::DecisionSigned),
                LoopState::Unknown,
                "{s:?}"
            );
        }
    }

    #[test]
    fn an_abort_request_is_weaker_than_a_shutdown() {
        assert!(
            LoopState::AbortRequested.evidence_required()
                < LoopState::ShutdownComplete.evidence_required()
        );
        assert_eq!(
            LoopState::assertable(LoopState::AbortRequested, ProcessEvidence::DecisionSigned),
            LoopState::AbortRequested
        );
        assert_eq!(
            LoopState::assertable(LoopState::ShutdownComplete, ProcessEvidence::DecisionSigned),
            LoopState::Unknown
        );
    }

    #[test]
    fn assertable_never_strengthens_or_substitutes() {
        for claimed in LoopState::ALL {
            for tier in [
                ProcessEvidence::Declared,
                ProcessEvidence::DecisionSigned,
                ProcessEvidence::ExecutionObserved,
                ProcessEvidence::PhysicallyObserved,
            ] {
                let out = LoopState::assertable(claimed, tier);
                assert!(
                    out == claimed || out == LoopState::Unknown,
                    "{claimed:?}/{tier:?}"
                );
            }
        }
    }

    #[test]
    fn the_physical_tier_is_unreachable_and_the_others_are_not() {
        assert!(!ProcessEvidence::PhysicallyObserved.is_reachable());
        for t in [
            ProcessEvidence::Declared,
            ProcessEvidence::DecisionSigned,
            ProcessEvidence::ExecutionObserved,
        ] {
            assert!(t.is_reachable(), "{t:?}");
        }
    }

    #[test]
    fn state_codes_are_unique() {
        let mut codes: Vec<u8> = LoopState::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), LoopState::ALL.len());
    }
}
