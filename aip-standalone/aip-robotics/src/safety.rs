//! Safety and emergency actions, and what evidence exists for each.
//!
//! # This is not a second enforcement engine
//!
//! Nothing here stops a robot. `aip-warrant` and `aip-containment` remain the
//! only enforcement path in the workspace, and this module produces no warrant,
//! no severity and no action. It answers one question per safety action: **what
//! could be established about whether it happened?**
//!
//! # Why that question is worth asking
//!
//! A safety stop is the action most likely to be assumed effective. It is
//! commanded when something has already gone wrong, its acknowledgement is
//! immediate, and the alternative to believing it is unattractive. So it is
//! exactly where an accountability system should be least willing to infer.
//!
//! An emergency stop that a controller accepted, and that a seized brake, a
//! welded contactor or a stuck valve did not perform, produces the same
//! acknowledgement as one that worked.

use serde::{Deserialize, Serialize};

use crate::action::RobotAction;
use crate::embodiment::EmbodiedRung;
use crate::task::TaskEvidence;

/// A safety or emergency response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SafetyAction {
    /// Power removed from the drives.
    EmergencyStop,
    /// A controlled stop that keeps power.
    ProtectiveStop,
    /// A stop triggered by a detected collision.
    CollisionStop,
    /// A trajectory change to avoid an obstacle.
    ObstacleAvoidance,
    /// A response to entering or approaching a restricted zone.
    SafetyZoneResponse,
    /// A human took control.
    OperatorTakeover,
    /// Continued operation with reduced capability.
    DegradedOperation,
    /// An attempt to return to a known state.
    Recovery,
    /// A docking attempt that did not complete.
    DockingFailure,
}

impl SafetyAction {
    pub const ALL: [SafetyAction; 9] = [
        Self::EmergencyStop,
        Self::ProtectiveStop,
        Self::CollisionStop,
        Self::ObstacleAvoidance,
        Self::SafetyZoneResponse,
        Self::OperatorTakeover,
        Self::DegradedOperation,
        Self::Recovery,
        Self::DockingFailure,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::EmergencyStop => 0x01,
            Self::ProtectiveStop => 0x02,
            Self::CollisionStop => 0x03,
            Self::ObstacleAvoidance => 0x04,
            Self::SafetyZoneResponse => 0x05,
            Self::OperatorTakeover => 0x06,
            Self::DegradedOperation => 0x07,
            Self::Recovery => 0x08,
            Self::DockingFailure => 0x09,
        }
    }

    /// The corresponding authorizable action, when there is one.
    ///
    /// `None` for the responses that are not commands: a collision stop, an
    /// avoidance manoeuvre and a docking failure are things that *happen*, and
    /// authorizing them would be a category error.
    pub fn as_authorizable(self) -> Option<RobotAction> {
        match self {
            Self::EmergencyStop => Some(RobotAction::EmergencyStop),
            Self::ProtectiveStop => Some(RobotAction::ProtectiveStop),
            _ => None,
        }
    }

    /// Whether the *request* can be established.
    ///
    /// True for everything that begins as a command from the autonomy stack:
    /// the companion computer's process and socket observation see a decision
    /// taken and a command sent.
    pub fn request_establishable(self) -> bool {
        matches!(
            self,
            Self::EmergencyStop
                | Self::ProtectiveStop
                | Self::ObstacleAvoidance
                | Self::SafetyZoneResponse
                | Self::Recovery
                | Self::DegradedOperation
        )
    }

    /// Whether the *effect* can be established — whether the robot actually
    /// stopped, avoided, recovered.
    ///
    /// False for all nine, computed from the class table.
    pub fn effect_establishable(self) -> bool {
        aip_observation::ObservationClass::PhysicalEffect.is_implemented()
    }

    /// The evidence tier the effect would need.
    pub fn effect_evidence_required(self) -> TaskEvidence {
        TaskEvidence::PhysicallyObserved
    }

    /// The highest rung of the embodied chain reached for this action.
    pub fn highest_rung(self) -> EmbodiedRung {
        if self.request_establishable() {
            EmbodiedRung::TaskCommand
        } else {
            // Not a command at all: nothing in the chain is reached, because
            // the chain starts at a decision the autonomy stack took.
            EmbodiedRung::AutonomousDecision
        }
    }

    /// What a report may honestly say about this action.
    pub fn statement(self) -> &'static str {
        match self {
            Self::EmergencyStop => {
                "a stop was commanded; that power was removed and the machine stopped is not \
                 established"
            }
            Self::ProtectiveStop => "a stop was commanded; that motion ceased is not established",
            Self::CollisionStop => {
                "the autonomy stack reported a collision trigger; that a collision occurred is a \
                 semantic claim over a strain reading"
            }
            Self::ObstacleAvoidance => {
                "an avoidance manoeuvre was commanded; that an obstacle existed, and that it was \
                 avoided, are two further claims"
            }
            Self::SafetyZoneResponse => {
                "a zone response was commanded; that the robot was in the zone requires a \
                 position nothing establishes"
            }
            Self::OperatorTakeover => {
                "the runtime reported a takeover; that a human took control is outside every \
                 mechanism here"
            }
            Self::DegradedOperation => {
                "the deployment's observation coverage is reduced, which is a fact about the \
                 verifier and not about the robot"
            }
            Self::Recovery => {
                "a recovery was attempted; that a known state was reached is not established"
            }
            Self::DockingFailure => {
                "the runtime reported a failure; whether the connector mated is not established"
            }
        }
    }
}

/// What is known about one safety action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyEvidence {
    pub action: SafetyAction,
    /// Whether an anchored observer saw the command leave the autonomy stack.
    pub request_observed: bool,
    /// Whether the physical effect was established. Always false here.
    pub effect_observed: bool,
}

impl SafetyEvidence {
    /// Derive from whether the deployment has a companion observer.
    pub fn derive(action: SafetyAction, companion_observer: bool) -> Self {
        Self {
            action,
            request_observed: companion_observer && action.request_establishable(),
            effect_observed: action.effect_establishable(),
        }
    }

    /// Whether the safety action may be reported as having taken effect.
    ///
    /// False whenever the effect was not observed — which is always. A safety
    /// argument that needs this to be true needs a mechanism this build does
    /// not have.
    pub fn establishes_effect(&self) -> bool {
        self.effect_observed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_safety_action_has_an_establishable_effect() {
        for a in SafetyAction::ALL {
            assert!(!a.effect_establishable(), "{a:?}");
            assert_eq!(
                a.effect_evidence_required(),
                TaskEvidence::PhysicallyObserved
            );
            assert!(!a.effect_evidence_required().is_reachable());
            assert!(
                !SafetyEvidence::derive(a, true).establishes_effect(),
                "{a:?}"
            );
        }
    }

    #[test]
    fn an_emergency_stop_command_is_not_a_stop() {
        let e = SafetyEvidence::derive(SafetyAction::EmergencyStop, true);
        assert!(e.request_observed, "the command leaving is observable");
        assert!(!e.establishes_effect(), "the machine stopping is not");
        assert!(SafetyAction::EmergencyStop
            .statement()
            .contains("not established"));
    }

    #[test]
    fn without_a_companion_observer_even_the_request_is_unobserved() {
        for a in SafetyAction::ALL {
            assert!(!SafetyEvidence::derive(a, false).request_observed, "{a:?}");
        }
    }

    #[test]
    fn events_that_are_not_commands_are_not_authorizable() {
        for a in [
            SafetyAction::CollisionStop,
            SafetyAction::ObstacleAvoidance,
            SafetyAction::DockingFailure,
            SafetyAction::OperatorTakeover,
        ] {
            assert!(
                a.as_authorizable().is_none(),
                "{a:?} is something that happens, not something a decision point permits"
            );
        }
        assert_eq!(
            SafetyAction::EmergencyStop.as_authorizable(),
            Some(RobotAction::EmergencyStop)
        );
    }

    #[test]
    fn degraded_operation_is_a_fact_about_the_verifier() {
        assert!(SafetyAction::DegradedOperation
            .statement()
            .contains("about the verifier"));
    }

    #[test]
    fn every_safety_action_states_what_may_be_said() {
        let mut codes: Vec<u8> = SafetyAction::ALL.iter().map(|a| a.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), SafetyAction::ALL.len());
        for a in SafetyAction::ALL {
            assert!(!a.statement().is_empty(), "{a:?}");
        }
    }
}
