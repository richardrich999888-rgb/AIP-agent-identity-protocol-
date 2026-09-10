//! The eight boundaries between deciding something and having done it.
//!
//! # Why this module is the centre of Skill 24
//!
//! A UAS profile has to keep telemetry apart from truth. A robot adds a harder
//! problem: it makes contact. Between "close the gripper" and "the object is
//! held" there are five separate physical events, each of which can occur
//! without the next, and every one of them produces the same signal on the
//! wire — a controller acknowledgement and an aperture that stopped changing.
//!
//! ```text
//!   autonomous decision       the autonomy stack chose an action
//!   task command              the command left the autonomy stack
//!   controller command        a controller says it received it
//!   actuator execution        a controller says it drove an actuator
//!   observed actuator state   a sensor on the robot reports a state
//!   contact interaction       something in the world was touched
//!   physical outcome          the world is different
//!   task success              a judgement that the difference was the goal
//! ```
//!
//! Two are observable in this build. Six are not, and the six are the ones
//! anybody cares about.
//!
//! # The specific failures each boundary hides
//!
//! - **command → controller command.** The controller is a device on a bus the
//!   subject owns. Its acknowledgement is a message from inside the system
//!   under scrutiny.
//! - **controller command → actuator execution.** A commanded current is not a
//!   produced torque. A disabled drive, a tripped brake and a blown fuse all
//!   accept commands.
//! - **actuator execution → observed actuator state.** A shaft turns with a
//!   slipped belt, a stripped gear, or a wheel off the ground. The encoder is
//!   downstream of the motor and upstream of the load.
//! - **observed actuator state → contact.** A gripper that stopped closing has
//!   stopped closing. It may hold an object, hold nothing at its mechanical
//!   limit, or have jammed.
//! - **contact → physical outcome.** Contact is not grasp; grasp is not lift;
//!   lift is not transport; transport is not placement.
//! - **physical outcome → task success.** The object moved. Whether it moved
//!   *where it was supposed to*, undamaged, and without moving anything else,
//!   is a judgement nothing here makes.
//!
//! # Nothing in this module resolves any of it
//!
//! Each rung reports who authored it, whether that party is inside the subject,
//! what could observe it, and — the useful column — what it is *not*.

use aip_execution::{EvidenceOrigin, ExecutionStage};
use serde::{Deserialize, Serialize};

use crate::sensing::SensingSource;

/// One boundary on the path from a decision to a physical outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EmbodiedRung {
    /// The autonomy stack chose an action.
    AutonomousDecision,
    /// The command left the autonomy stack.
    TaskCommand,
    /// A controller says it received the command.
    ControllerCommand,
    /// A controller says it drove an actuator.
    ActuatorExecution,
    /// A sensor on the robot reports an actuator state.
    ObservedActuatorState,
    /// Something in the world was touched.
    ContactInteraction,
    /// The world is different.
    PhysicalOutcome,
    /// The difference was the one the task wanted.
    TaskSuccess,
}

impl EmbodiedRung {
    /// Every rung, in order. The `Ord` derive follows declaration order, which
    /// is the causal order, deliberately.
    pub const ALL: [EmbodiedRung; 8] = [
        Self::AutonomousDecision,
        Self::TaskCommand,
        Self::ControllerCommand,
        Self::ActuatorExecution,
        Self::ObservedActuatorState,
        Self::ContactInteraction,
        Self::PhysicalOutcome,
        Self::TaskSuccess,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::AutonomousDecision => 0x01,
            Self::TaskCommand => 0x02,
            Self::ControllerCommand => 0x03,
            Self::ActuatorExecution => 0x04,
            Self::ObservedActuatorState => 0x05,
            Self::ContactInteraction => 0x06,
            Self::PhysicalOutcome => 0x07,
            Self::TaskSuccess => 0x08,
        }
    }

    /// The stage on Skill 18's twelve-rung ladder this corresponds to.
    ///
    /// `None` for the last three. The twelve stages stop at what happened
    /// outside the host; none of them is a measurement of contact, of the
    /// world, or of whether a goal was met. Inventing stages for them would be
    /// three claims in the type system.
    pub fn stage(self) -> Option<ExecutionStage> {
        match self {
            Self::AutonomousDecision => Some(ExecutionStage::ToolInvocation),
            Self::TaskCommand => Some(ExecutionStage::RuntimeExecution),
            Self::ControllerCommand | Self::ActuatorExecution | Self::ObservedActuatorState => {
                Some(ExecutionStage::PlatformInteraction)
            }
            Self::ContactInteraction | Self::PhysicalOutcome | Self::TaskSuccess => None,
        }
    }

    /// Where a statement at this rung comes from.
    ///
    /// Rungs three to five are `SelfReported` **even though a different device
    /// authors them**. A motion controller sits on a bus the subject owns; a
    /// compromise that reaches the autonomy stack usually reaches that bus, and
    /// a compromise of the controller needs no help from anyone. Treating a
    /// controller acknowledgement as independent evidence is the same mistake
    /// the UAS profile refuses for an autopilot, and it is worse here, because
    /// a robot's controller is what moves a mass through a space people stand
    /// in.
    pub fn origin(self) -> EvidenceOrigin {
        match self {
            Self::AutonomousDecision
            | Self::TaskCommand
            | Self::ControllerCommand
            | Self::ActuatorExecution
            | Self::ObservedActuatorState => EvidenceOrigin::SelfReported,
            // Not self-reported, and not observed either: nothing in this build
            // authors them. The world does, and nothing here reads the world.
            Self::ContactInteraction | Self::PhysicalOutcome | Self::TaskSuccess => {
                EvidenceOrigin::IndependentlyObserved
            }
        }
    }

    /// What could observe this rung in this build.
    pub fn observable_by(self) -> &'static [SensingSource] {
        match self {
            Self::AutonomousDecision => &[SensingSource::CompanionProcessObservation],
            Self::TaskCommand => &[SensingSource::CompanionNetworkObservation],
            _ => &[],
        }
    }

    /// Whether an anchored observer can establish this rung today.
    pub fn independently_observable(self) -> bool {
        self.observable_by()
            .iter()
            .any(|s| s.can_produce_observation_record() && s.is_independent())
    }

    /// What this rung is **not**. The column an incident review needs.
    pub fn is_not(self) -> &'static str {
        match self {
            Self::AutonomousDecision => "a command having been sent",
            Self::TaskCommand => "a controller having received or accepted it",
            Self::ControllerCommand => "an actuator having been driven",
            Self::ActuatorExecution => {
                "a load having moved: a commanded current is not a produced torque"
            }
            Self::ObservedActuatorState => {
                "the load having moved with it: a shaft turns with a slipped belt or a wheel \
                 off the ground"
            }
            Self::ContactInteraction => "a grasp, a hold, or an object having been identified",
            Self::PhysicalOutcome => "the outcome the task wanted",
            Self::TaskSuccess => "a fact this build can establish",
        }
    }

    /// The failure this boundary exists to keep visible.
    pub fn hidden_failure(self) -> &'static str {
        match self {
            Self::AutonomousDecision => "a decision recorded that no command followed",
            Self::TaskCommand => "a command sent into a link nothing was listening on",
            Self::ControllerCommand => "a controller that acknowledges and is in a fault state",
            Self::ActuatorExecution => "a disabled drive, a tripped brake, a blown fuse",
            Self::ObservedActuatorState => "a stripped gear, a slipped belt, a wheel in the air",
            Self::ContactInteraction => {
                "a gripper closed on nothing at its mechanical limit, or on the wrong object"
            }
            Self::PhysicalOutcome => "the object moved, and something else moved with it",
            Self::TaskSuccess => "everything measured went right and the goal was not met",
        }
    }
}

/// The chain, computed for this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbodiedChain {
    pub rungs: Vec<(EmbodiedRung, bool)>,
}

impl EmbodiedChain {
    /// Compute which rungs this build can establish.
    ///
    /// Takes no arguments and reads no configuration: the answer is a property
    /// of the mechanisms that exist, and a parameterised version would be a
    /// version someone could parameterise into optimism.
    pub fn current() -> Self {
        Self {
            rungs: EmbodiedRung::ALL
                .iter()
                .map(|r| (*r, r.independently_observable()))
                .collect(),
        }
    }

    /// The highest rung this build can independently establish.
    pub fn highest_observable(&self) -> Option<EmbodiedRung> {
        self.rungs
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(r, _)| *r)
            .next_back()
    }

    /// How many boundaries lie between the highest observable rung and a
    /// physical outcome.
    ///
    /// Reported because "we verified the robot" and "we verified two of eight
    /// rungs and there are five boundaries before anything moved" are the same
    /// run described honestly and dishonestly.
    pub fn unobserved_boundaries_to_outcome(&self) -> usize {
        let highest = self.highest_observable().map(|r| r.code()).unwrap_or(0);
        EmbodiedRung::ALL
            .iter()
            .filter(|r| r.code() > highest && r.code() <= EmbodiedRung::PhysicalOutcome.code())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chain_stops_at_the_task_command() {
        let c = EmbodiedChain::current();
        assert_eq!(c.highest_observable(), Some(EmbodiedRung::TaskCommand));
        assert_eq!(
            c.unobserved_boundaries_to_outcome(),
            5,
            "five boundaries lie between a sent command and a changed world"
        );
    }

    #[test]
    fn a_controller_acknowledgement_is_a_self_report() {
        for r in [
            EmbodiedRung::ControllerCommand,
            EmbodiedRung::ActuatorExecution,
            EmbodiedRung::ObservedActuatorState,
        ] {
            assert_eq!(r.origin(), EvidenceOrigin::SelfReported, "{r:?}");
            assert!(!r.origin().can_establish_occurrence(), "{r:?}");
            assert!(!r.independently_observable(), "{r:?}");
        }
    }

    #[test]
    fn nothing_beyond_the_task_command_is_observable() {
        for r in EmbodiedRung::ALL
            .iter()
            .filter(|r| **r > EmbodiedRung::TaskCommand)
        {
            assert!(!r.independently_observable(), "{r:?}");
            assert!(r.observable_by().is_empty(), "{r:?}");
        }
    }

    #[test]
    fn the_last_three_rungs_have_no_stage() {
        for r in [
            EmbodiedRung::ContactInteraction,
            EmbodiedRung::PhysicalOutcome,
            EmbodiedRung::TaskSuccess,
        ] {
            assert!(
                r.stage().is_none(),
                "{r:?}: no stage on the twelve-rung ladder measures the world"
            );
        }
        for r in EmbodiedRung::ALL.iter().take(5) {
            assert!(r.stage().is_some(), "{r:?}");
        }
    }

    #[test]
    fn the_stages_are_non_decreasing_along_the_chain() {
        let stages: Vec<ExecutionStage> =
            EmbodiedRung::ALL.iter().filter_map(|r| r.stage()).collect();
        for w in stages.windows(2) {
            assert!(w[0] <= w[1], "the chain must not run backwards: {w:?}");
        }
    }

    #[test]
    fn a_software_rung_may_not_establish_a_platform_rung() {
        let from = EmbodiedRung::AutonomousDecision.stage().unwrap();
        let to = EmbodiedRung::ActuatorExecution.stage().unwrap();
        assert!(
            !from.may_establish(to),
            "a decision must not establish that an actuator was driven"
        );
    }

    #[test]
    fn the_chain_is_strictly_ordered_and_every_rung_states_its_gaps() {
        let mut codes: Vec<u8> = EmbodiedRung::ALL.iter().map(|r| r.code()).collect();
        let sorted = {
            let mut c = codes.clone();
            c.sort_unstable();
            c
        };
        assert_eq!(codes, sorted, "declaration order must be causal order");
        codes.dedup();
        assert_eq!(codes.len(), 8);
        for r in EmbodiedRung::ALL {
            assert!(!r.is_not().is_empty(), "{r:?}");
            assert!(!r.hidden_failure().is_empty(), "{r:?}");
        }
    }

    #[test]
    fn observing_the_two_software_rungs_does_not_shorten_the_gap() {
        // The point of `unobserved_boundaries_to_outcome`: verifying the
        // software half honestly leaves five physical boundaries untouched.
        let c = EmbodiedChain::current();
        let observed = c.rungs.iter().filter(|(_, ok)| *ok).count();
        assert_eq!(observed, 2);
        assert_eq!(c.unobserved_boundaries_to_outcome(), 5);
    }
}
