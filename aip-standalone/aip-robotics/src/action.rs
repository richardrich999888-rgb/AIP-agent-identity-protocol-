//! Robot actions, as ordinary entries in the existing authorization
//! vocabulary.
//!
//! # No parallel ladder
//!
//! Each action below is a `ScopeAction::Custom` a decision point authorizes
//! over and a `RequestedEffect` in Skill 18's model. `aip-authorize` needs no
//! change: it already accepts custom action kinds and the scope machinery
//! already matches them.
//!
//! What this module adds is the six-column question the brief asks — for each
//! action, what each rung would take — computed rather than written in a
//! comment. `EXECUTED` is the last column any of them reaches.

use aip_authorize::ActionParameters;
use aip_types::ScopeAction;
use serde::{Deserialize, Serialize};

use crate::embodiment::EmbodiedRung;
use crate::error::RoboticsError;
use crate::sensing::SensingSource;

/// Prefix of every action kind this profile defines.
///
/// Namespaced under `robot.` so it can never collide with the core's `ghost.*`
/// or the UAS profile's `uas.*` vocabulary, and so a verifier reading a scope
/// can tell which profile an action belongs to without a lookup table.
pub const ROBOT_ACTION_PREFIX: &str = "robot.";

/// Parameter keys. Values are raw bytes, so there is exactly one encoding.
pub const PARAM_GOAL_X_MM: &str = "goal_x_mm";
pub const PARAM_GOAL_Y_MM: &str = "goal_y_mm";
pub const PARAM_GOAL_Z_MM: &str = "goal_z_mm";
pub const PARAM_FRAME_ID: &str = "frame_id";
pub const PARAM_OBJECT_ID: &str = "object_id";
pub const PARAM_TOOL_ID: &str = "tool_id";

/// An action a robotics task may authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RobotAction {
    /// Move the base to a goal.
    NavigateTo,
    /// Move a manipulator to a pose.
    MoveTo,
    /// Close an end effector on an object.
    Pick,
    /// Open an end effector.
    Release,
    /// Put an object down at a goal.
    Place,
    /// Open a mechanism — a door, a latch, a drawer.
    OpenMechanism,
    /// Close one.
    CloseMechanism,
    /// Energise a tool.
    ActivateTool,
    /// De-energise it.
    DeactivateTool,
    /// Approach and engage a dock.
    Dock,
    /// Begin charging.
    Charge,
    /// Return to a home or park position.
    ReturnHome,
    /// Stop under a controlled profile.
    ProtectiveStop,
    /// Remove power to the drives.
    EmergencyStop,
}

impl RobotAction {
    pub const ALL: [RobotAction; 14] = [
        Self::NavigateTo,
        Self::MoveTo,
        Self::Pick,
        Self::Release,
        Self::Place,
        Self::OpenMechanism,
        Self::CloseMechanism,
        Self::ActivateTool,
        Self::DeactivateTool,
        Self::Dock,
        Self::Charge,
        Self::ReturnHome,
        Self::ProtectiveStop,
        Self::EmergencyStop,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::NavigateTo => 0x01,
            Self::MoveTo => 0x02,
            Self::Pick => 0x03,
            Self::Release => 0x04,
            Self::Place => 0x05,
            Self::OpenMechanism => 0x06,
            Self::CloseMechanism => 0x07,
            Self::ActivateTool => 0x08,
            Self::DeactivateTool => 0x09,
            Self::Dock => 0x0A,
            Self::Charge => 0x0B,
            Self::ReturnHome => 0x0C,
            Self::ProtectiveStop => 0x0D,
            Self::EmergencyStop => 0x0E,
        }
    }

    /// The action kind string a decision point authorizes over.
    pub fn kind(self) -> &'static str {
        match self {
            Self::NavigateTo => "robot.motion.navigate.v1",
            Self::MoveTo => "robot.motion.move.v1",
            Self::Pick => "robot.manipulation.pick.v1",
            Self::Release => "robot.manipulation.release.v1",
            Self::Place => "robot.manipulation.place.v1",
            Self::OpenMechanism => "robot.manipulation.open.v1",
            Self::CloseMechanism => "robot.manipulation.close.v1",
            Self::ActivateTool => "robot.tool.activate.v1",
            Self::DeactivateTool => "robot.tool.deactivate.v1",
            Self::Dock => "robot.motion.dock.v1",
            Self::Charge => "robot.power.charge.v1",
            Self::ReturnHome => "robot.motion.return_home.v1",
            Self::ProtectiveStop => "robot.safety.protective_stop.v1",
            Self::EmergencyStop => "robot.safety.emergency_stop.v1",
        }
    }

    /// Whether this action's completion is a claim about the robot's body.
    ///
    /// True for all fourteen. Even `EmergencyStop`: an emergency stop that a
    /// controller accepted and a seized brake did not perform is precisely the
    /// case a safety argument must not assume away.
    pub fn is_physical_action(self) -> bool {
        true
    }

    /// The highest rung of the embodied chain this action reaches in this
    /// build. `TaskCommand` for every action — the command left the autonomy
    /// stack, and nothing after that is observed.
    pub fn highest_established_rung(self) -> EmbodiedRung {
        crate::embodiment::EmbodiedChain::current()
            .highest_observable()
            .unwrap_or(EmbodiedRung::AutonomousDecision)
    }

    /// What could observe the software half of this action.
    pub fn observable_by(self) -> &'static [SensingSource] {
        &[
            SensingSource::CompanionProcessObservation,
            SensingSource::CompanionNetworkObservation,
        ]
    }

    /// Whether an anchored observer could establish that the effect occurred.
    ///
    /// False for all fourteen, computed from the class table.
    pub fn effect_observable(self) -> bool {
        aip_observation::ObservationClass::PhysicalEffect.is_implemented()
    }

    /// The gap between what the software did and what the robot did.
    pub fn effect_gap(self) -> &'static str {
        match self {
            Self::NavigateTo => "a navigation goal accepted is not a base that arrived",
            Self::MoveTo => "a pose command accepted is not an arm that reached it",
            Self::Pick => "a gripper that closed is not an object that is held",
            Self::Release => "a gripper that opened is not an object that was let go safely",
            Self::Place => "a place command completed is not an object where it should be",
            Self::OpenMechanism => "a motion executed is not a door that opened",
            Self::CloseMechanism => "a motion executed is not a latch that engaged",
            Self::ActivateTool => "a tool energised is not a tool that did its work",
            Self::DeactivateTool => "a de-energise command is not a tool that stopped",
            Self::Dock => "a dock approach completed is not a connector that mated",
            Self::Charge => "a charge command accepted is not current into a cell",
            Self::ReturnHome => "a return command accepted is not a robot at home",
            Self::ProtectiveStop => "a stop accepted is not motion that ceased",
            Self::EmergencyStop => {
                "a stop accepted is not power removed, and not a brake that held"
            }
        }
    }
}

/// The `ScopeAction` for a robot action. A convenience over
/// `ScopeAction::Custom`, not an extension of the authorization vocabulary.
pub fn robot_action(action: RobotAction) -> ScopeAction {
    ScopeAction::Custom(action.kind().to_string())
}

/// Parameters naming one goal pose, byte for byte.
///
/// The frame is a parameter rather than an assumption: a goal at "x = 1200"
/// authorized in one frame and executed in another is the coordinate-frame
/// confusion that puts an arm through a wall.
pub fn goal_parameters(
    x_mm: i64,
    y_mm: i64,
    z_mm: i64,
    frame_id: &str,
) -> Result<ActionParameters, RoboticsError> {
    if frame_id.is_empty() || frame_id.len() > 128 {
        return Err(RoboticsError::Malformed {
            reason: "frame id must be 1-128 bytes",
        });
    }
    Ok(ActionParameters::from_pairs([
        (PARAM_GOAL_X_MM, x_mm.to_le_bytes().to_vec()),
        (PARAM_GOAL_Y_MM, y_mm.to_le_bytes().to_vec()),
        (PARAM_GOAL_Z_MM, z_mm.to_le_bytes().to_vec()),
        (PARAM_FRAME_ID, frame_id.as_bytes().to_vec()),
    ])
    .expect("four distinct constant keys"))
}

/// Parameters naming one object.
pub fn object_parameters(object_id: &str) -> Result<ActionParameters, RoboticsError> {
    if object_id.is_empty() || object_id.len() > 128 {
        return Err(RoboticsError::Malformed {
            reason: "object id must be 1-128 bytes",
        });
    }
    Ok(
        ActionParameters::from_pairs([(PARAM_OBJECT_ID, object_id.as_bytes().to_vec())])
            .expect("one constant key"),
    )
}

/// Parameters naming one tool.
pub fn tool_parameters(tool_id: &str) -> Result<ActionParameters, RoboticsError> {
    if tool_id.is_empty() || tool_id.len() > 128 {
        return Err(RoboticsError::Malformed {
            reason: "tool id must be 1-128 bytes",
        });
    }
    Ok(
        ActionParameters::from_pairs([(PARAM_TOOL_ID, tool_id.as_bytes().to_vec())])
            .expect("one constant key"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_kind_is_namespaced_and_versioned() {
        for a in RobotAction::ALL {
            assert!(a.kind().starts_with(ROBOT_ACTION_PREFIX), "{a:?}");
            assert!(a.kind().ends_with(".v1"), "{a:?}");
        }
    }

    #[test]
    fn action_kinds_and_codes_are_unique() {
        let mut kinds: Vec<&str> = RobotAction::ALL.iter().map(|a| a.kind()).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), RobotAction::ALL.len());
        let mut codes: Vec<u8> = RobotAction::ALL.iter().map(|a| a.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), RobotAction::ALL.len());
    }

    #[test]
    fn no_robot_action_reaches_an_observable_effect() {
        for a in RobotAction::ALL {
            assert!(a.is_physical_action(), "{a:?}");
            assert!(!a.effect_observable(), "{a:?}");
            assert_eq!(
                a.highest_established_rung(),
                EmbodiedRung::TaskCommand,
                "{a:?}"
            );
            assert!(!a.effect_gap().is_empty(), "{a:?}");
        }
    }

    #[test]
    fn an_emergency_stop_is_a_physical_action_like_any_other() {
        // The temptation is to treat a safety command as self-evidently
        // effective. A seized brake accepts the command too.
        assert!(RobotAction::EmergencyStop.is_physical_action());
        assert!(!RobotAction::EmergencyStop.effect_observable());
        assert!(RobotAction::EmergencyStop.effect_gap().contains("brake"));
    }

    #[test]
    fn a_robot_action_is_an_ordinary_custom_scope_action() {
        match robot_action(RobotAction::Pick) {
            ScopeAction::Custom(s) => assert_eq!(s, "robot.manipulation.pick.v1"),
            other => panic!("expected a custom action, got {other:?}"),
        }
    }

    #[test]
    fn goal_parameters_are_sensitive_to_the_frame() {
        let a = goal_parameters(1, 2, 3, "base_link").unwrap();
        let b = goal_parameters(1, 2, 3, "world").unwrap();
        assert_ne!(
            a.digest(),
            b.digest(),
            "the same numbers in two frames are two different goals"
        );
    }

    #[test]
    fn goal_parameters_are_sensitive_to_every_coordinate_including_negatives() {
        let base = goal_parameters(1, 2, 3, "f").unwrap();
        for other in [
            goal_parameters(9, 2, 3, "f").unwrap(),
            goal_parameters(1, 9, 3, "f").unwrap(),
            goal_parameters(1, 2, 9, "f").unwrap(),
            goal_parameters(-1, 2, 3, "f").unwrap(),
        ] {
            assert_ne!(base.digest(), other.digest());
        }
    }

    #[test]
    fn identifiers_are_bounded() {
        assert!(goal_parameters(0, 0, 0, "").is_err());
        assert!(object_parameters("").is_err());
        assert!(tool_parameters(&"x".repeat(129)).is_err());
        assert!(object_parameters("widget-7").is_ok());
    }

    #[test]
    fn the_robot_namespace_does_not_collide_with_the_uas_one() {
        for a in RobotAction::ALL {
            assert!(!a.kind().starts_with("uas."), "{a:?}");
            assert!(!a.kind().starts_with("ghost."), "{a:?}");
        }
    }
}
