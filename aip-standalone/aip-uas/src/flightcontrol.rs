//! The autonomy-to-airframe boundary, rung by rung.
//!
//! # Four transitions, three of which are invisible here
//!
//! ```text
//!   autonomy computer  ── flight-control command ──▶  flight controller
//!          │                                                 │
//!          │                                          actuator command
//!          │                                                 ▼
//!          └──────────────── the boundary ──────────▶  vehicle state
//! ```
//!
//! "set heading 090" is a message. "the flight controller accepted heading
//! 090" is a different message, from a different device, about the first. "the
//! aircraft rotated to 090" is a fact about the world that neither message
//! establishes, and no mechanism in this build observes.
//!
//! Every rung below therefore names the party that authors it, whether that
//! party is inside the subject, and what would be needed to observe it. Three
//! of the four are authored inside the subject; the fourth is authored by
//! physics and read by nothing.

use aip_execution::{EvidenceOrigin, ExecutionStage};
use serde::{Deserialize, Serialize};

use crate::telemetry::TelemetrySource;

/// One rung of the command path from autonomy to airframe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CommandRung {
    /// The autonomy stack decided to issue a command.
    AutonomyDecision,
    /// The command left the companion computer on a link.
    CommandTransmitted,
    /// The flight controller says it accepted the command.
    FlightControllerAccepted,
    /// The flight controller says it drove an actuator.
    ActuatorCommanded,
    /// The aircraft's state changed.
    VehicleStateChanged,
}

impl CommandRung {
    /// Every rung, in order.
    pub const ALL: [CommandRung; 5] = [
        Self::AutonomyDecision,
        Self::CommandTransmitted,
        Self::FlightControllerAccepted,
        Self::ActuatorCommanded,
        Self::VehicleStateChanged,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::AutonomyDecision => 0x01,
            Self::CommandTransmitted => 0x02,
            Self::FlightControllerAccepted => 0x03,
            Self::ActuatorCommanded => 0x04,
            Self::VehicleStateChanged => 0x05,
        }
    }

    /// The stage on Skill 18's twelve-rung ladder this corresponds to.
    ///
    /// `None` for `VehicleStateChanged`: the twelve stages stop at what
    /// happened outside the host, and none of them is a measurement of a
    /// physical machine. Inventing a stage for it would be a claim in the type
    /// system, which is the same objection Skill 22 raised for its physical
    /// rung.
    pub fn stage(self) -> Option<ExecutionStage> {
        match self {
            Self::AutonomyDecision => Some(ExecutionStage::ToolInvocation),
            Self::CommandTransmitted => Some(ExecutionStage::RuntimeExecution),
            // The flight controller is a device outside the companion computer
            // but inside the aircraft. Its acknowledgement reaches the host as
            // a message, which is the platform-interaction stage.
            Self::FlightControllerAccepted | Self::ActuatorCommanded => {
                Some(ExecutionStage::PlatformInteraction)
            }
            Self::VehicleStateChanged => None,
        }
    }

    /// Where a statement at this rung comes from.
    ///
    /// Note that `FlightControllerAccepted` and `ActuatorCommanded` are
    /// `SelfReported` **even though a different device authored them**. The
    /// flight controller is inside the system under scrutiny; a compromise
    /// that reaches the autonomy stack can usually reach the bus it speaks to
    /// the autopilot over, and a compromise of the autopilot itself needs no
    /// help from anyone. Treating an autopilot acknowledgement as independent
    /// evidence is the single most attractive mistake available in this
    /// domain.
    pub fn origin(self) -> EvidenceOrigin {
        match self {
            Self::AutonomyDecision
            | Self::CommandTransmitted
            | Self::FlightControllerAccepted
            | Self::ActuatorCommanded => EvidenceOrigin::SelfReported,
            // Not self-reported — but not observed either. Nothing authors it
            // in this build; physics does, and nothing here reads physics.
            Self::VehicleStateChanged => EvidenceOrigin::IndependentlyObserved,
        }
    }

    /// What could observe this rung in this build.
    ///
    /// The middle rungs return an empty slice: a flight controller's
    /// acknowledgement is a message on a bus this workspace has no mechanism
    /// for. `CommandTransmitted` is the one rung with real coverage, because
    /// the companion computer's socket observation sees that bytes left.
    pub fn observable_by(self) -> &'static [TelemetrySource] {
        match self {
            Self::AutonomyDecision => &[TelemetrySource::CompanionProcessObservation],
            Self::CommandTransmitted => &[TelemetrySource::CompanionNetworkObservation],
            Self::FlightControllerAccepted | Self::ActuatorCommanded => &[],
            Self::VehicleStateChanged => &[],
        }
    }

    /// Whether an anchored observer can establish this rung today.
    pub fn independently_observable(self) -> bool {
        self.observable_by()
            .iter()
            .any(|s| s.can_produce_observation_record() && s.is_independent())
    }

    /// What this rung is **not**, in one line.
    pub fn is_not(self) -> &'static str {
        match self {
            Self::AutonomyDecision => "a command having been sent",
            Self::CommandTransmitted => "a flight controller having received or accepted it",
            Self::FlightControllerAccepted => "an actuator having been driven",
            Self::ActuatorCommanded => "a control surface or motor having responded",
            Self::VehicleStateChanged => "a mission objective having been achieved",
        }
    }
}

/// The ladder, as a computed table for one report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightControlLadder {
    pub rungs: Vec<(CommandRung, bool)>,
}

impl FlightControlLadder {
    /// Compute which rungs this build can establish.
    ///
    /// Takes no arguments and reads no configuration on purpose: the answer is
    /// a property of the mechanisms that exist, and a version that could be
    /// parameterised would be a version someone could parameterise into
    /// optimism.
    pub fn current() -> Self {
        Self {
            rungs: CommandRung::ALL
                .iter()
                .map(|r| (*r, r.independently_observable()))
                .collect(),
        }
    }

    /// The highest rung this build can independently establish.
    pub fn highest_observable(&self) -> Option<CommandRung> {
        self.rungs
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(r, _)| *r)
            .next_back()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flight_controller_acknowledgement_is_a_self_report() {
        assert_eq!(
            CommandRung::FlightControllerAccepted.origin(),
            EvidenceOrigin::SelfReported
        );
        assert!(
            !CommandRung::FlightControllerAccepted
                .origin()
                .can_establish_occurrence(),
            "an autopilot acknowledgement must not establish that anything occurred"
        );
    }

    #[test]
    fn no_rung_beyond_command_transmission_is_observable() {
        for r in [
            CommandRung::FlightControllerAccepted,
            CommandRung::ActuatorCommanded,
            CommandRung::VehicleStateChanged,
        ] {
            assert!(
                !r.independently_observable(),
                "{r:?} became observable; no mechanism reads a flight controller or an airframe"
            );
            assert!(r.observable_by().is_empty(), "{r:?}");
        }
    }

    #[test]
    fn the_ladder_stops_at_command_transmission() {
        let ladder = FlightControlLadder::current();
        assert_eq!(
            ladder.highest_observable(),
            Some(CommandRung::CommandTransmitted),
            "this build sees the autonomy stack run and bytes leave, and nothing after that"
        );
    }

    #[test]
    fn the_vehicle_state_rung_has_no_stage() {
        assert!(
            CommandRung::VehicleStateChanged.stage().is_none(),
            "no stage on the twelve-rung ladder is a measurement of a physical machine"
        );
        // And every other rung does have one, so the `None` is a statement
        // rather than an omission.
        for r in CommandRung::ALL
            .iter()
            .filter(|r| **r != CommandRung::VehicleStateChanged)
        {
            assert!(r.stage().is_some(), "{r:?}");
        }
    }

    #[test]
    fn the_stages_are_non_decreasing_along_the_ladder() {
        let stages: Vec<ExecutionStage> =
            CommandRung::ALL.iter().filter_map(|r| r.stage()).collect();
        for w in stages.windows(2) {
            assert!(
                w[0] <= w[1],
                "the command path must not run backwards along the execution ladder: {w:?}"
            );
        }
    }

    #[test]
    fn a_self_reported_rung_may_not_establish_an_observed_one() {
        // Skill 18's own rule, applied to this ladder: the software rungs
        // cannot reach the platform-interaction stage on their own.
        let from = CommandRung::AutonomyDecision.stage().unwrap();
        let to = CommandRung::FlightControllerAccepted.stage().unwrap();
        assert!(
            !from.may_establish(to),
            "a decision to command must not establish a platform interaction"
        );
    }

    #[test]
    fn every_rung_states_what_it_is_not() {
        for r in CommandRung::ALL {
            assert!(!r.is_not().is_empty(), "{r:?}");
        }
    }
}
