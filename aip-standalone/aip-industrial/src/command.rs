//! Industrial commands, as ordinary entries in the existing authorization
//! vocabulary.
//!
//! # No parallel ladder
//!
//! Each command below is a `ScopeAction::Custom` a decision point authorizes
//! over and a requested effect in Skill 18's model. `aip-authorize` needs no
//! change: it already accepts custom action kinds and the scope machinery
//! already matches them.
//!
//! # The point address is part of the command
//!
//! Writing `40001` on one controller and `40001` on another are two different
//! commands, and a plant with a hundred controllers has a hundred `40001`s.
//! [`point_parameters`] therefore commits the device, the address space, the
//! point and the value together, and any difference in any of them is a
//! different parameter digest. This is the industrial form of the
//! coordinate-frame confusion ADR-006 named for robotics: the same number,
//! authorized in one context and executed in another.
//!
//! # The unit is part of the value
//!
//! A setpoint of `50` is not a setpoint until someone says whether it is
//! percent, bar or degrees. The unit is committed with the value rather than
//! assumed from a point table the subject also owns.

use aip_authorize::ActionParameters;
use aip_types::ScopeAction;
use serde::{Deserialize, Serialize};

use crate::controlloop::ControlRung;
use crate::error::IndustrialError;
use crate::sensing::ProcessSensingSource;

/// Prefix of every action kind this profile defines.
///
/// Namespaced under `ics.` so it can never collide with the core's `ghost.*`,
/// the UAS profile's `uas.*` or the robotics profile's `robot.*` vocabulary,
/// and so a verifier reading a scope can tell which profile an action belongs
/// to without a lookup table.
pub const ICS_ACTION_PREFIX: &str = "ics.";

/// Parameter keys. Values are raw bytes, so there is exactly one encoding.
pub const PARAM_DEVICE_ID: &str = "device_id";
pub const PARAM_ADDRESS_SPACE: &str = "address_space";
pub const PARAM_POINT_ID: &str = "point_id";
pub const PARAM_VALUE: &str = "value";
pub const PARAM_UNIT: &str = "unit";
pub const PARAM_PROTOCOL: &str = "protocol";

/// A command an industrial or critical-edge deployment may authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IndustrialCommand {
    /// Write a control setpoint.
    WriteSetpoint,
    /// Write a discrete output: a coil, a relay, a command bit.
    WriteDiscreteOutput,
    /// Write an analogue output directly, bypassing the loop.
    WriteAnalogueOutput,
    /// Change a controller's operating mode: auto, manual, cascade.
    ChangeControlMode,
    /// Download a program or configuration to a controller.
    DownloadControllerProgram,
    /// Start a controller's execution.
    StartController,
    /// Stop it.
    StopController,
    /// Command a valve open.
    OpenValve,
    /// Command it closed.
    CloseValve,
    /// Start a motor or pump.
    StartRotatingEquipment,
    /// Stop one.
    StopRotatingEquipment,
    /// Open an electrical breaker.
    OpenBreaker,
    /// Close one.
    CloseBreaker,
    /// Acknowledge an alarm.
    AcknowledgeAlarm,
    /// Bypass an interlock. The command a plant should be least willing to
    /// take on trust, and the one with the shortest path to a fatality.
    BypassInterlock,
    /// Restore a bypassed interlock.
    RestoreInterlock,
    /// Trip a safety function deliberately.
    TripSafetyFunction,
    /// Shut the process down under an emergency procedure.
    EmergencyShutdown,
}

impl IndustrialCommand {
    pub const ALL: [IndustrialCommand; 18] = [
        Self::WriteSetpoint,
        Self::WriteDiscreteOutput,
        Self::WriteAnalogueOutput,
        Self::ChangeControlMode,
        Self::DownloadControllerProgram,
        Self::StartController,
        Self::StopController,
        Self::OpenValve,
        Self::CloseValve,
        Self::StartRotatingEquipment,
        Self::StopRotatingEquipment,
        Self::OpenBreaker,
        Self::CloseBreaker,
        Self::AcknowledgeAlarm,
        Self::BypassInterlock,
        Self::RestoreInterlock,
        Self::TripSafetyFunction,
        Self::EmergencyShutdown,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::WriteSetpoint => 0x01,
            Self::WriteDiscreteOutput => 0x02,
            Self::WriteAnalogueOutput => 0x03,
            Self::ChangeControlMode => 0x04,
            Self::DownloadControllerProgram => 0x05,
            Self::StartController => 0x06,
            Self::StopController => 0x07,
            Self::OpenValve => 0x08,
            Self::CloseValve => 0x09,
            Self::StartRotatingEquipment => 0x0A,
            Self::StopRotatingEquipment => 0x0B,
            Self::OpenBreaker => 0x0C,
            Self::CloseBreaker => 0x0D,
            Self::AcknowledgeAlarm => 0x0E,
            Self::BypassInterlock => 0x0F,
            Self::RestoreInterlock => 0x10,
            Self::TripSafetyFunction => 0x11,
            Self::EmergencyShutdown => 0x12,
        }
    }

    /// The action kind string a decision point authorizes over.
    pub fn kind(self) -> &'static str {
        match self {
            Self::WriteSetpoint => "ics.control.write_setpoint.v1",
            Self::WriteDiscreteOutput => "ics.control.write_discrete.v1",
            Self::WriteAnalogueOutput => "ics.control.write_analogue.v1",
            Self::ChangeControlMode => "ics.control.change_mode.v1",
            Self::DownloadControllerProgram => "ics.controller.download_program.v1",
            Self::StartController => "ics.controller.start.v1",
            Self::StopController => "ics.controller.stop.v1",
            Self::OpenValve => "ics.equipment.open_valve.v1",
            Self::CloseValve => "ics.equipment.close_valve.v1",
            Self::StartRotatingEquipment => "ics.equipment.start_rotating.v1",
            Self::StopRotatingEquipment => "ics.equipment.stop_rotating.v1",
            Self::OpenBreaker => "ics.electrical.open_breaker.v1",
            Self::CloseBreaker => "ics.electrical.close_breaker.v1",
            Self::AcknowledgeAlarm => "ics.alarm.acknowledge.v1",
            Self::BypassInterlock => "ics.safety.bypass_interlock.v1",
            Self::RestoreInterlock => "ics.safety.restore_interlock.v1",
            Self::TripSafetyFunction => "ics.safety.trip.v1",
            Self::EmergencyShutdown => "ics.safety.emergency_shutdown.v1",
        }
    }

    /// Whether this command's completion is a claim about a plant.
    ///
    /// True for seventeen of eighteen. `AcknowledgeAlarm` is the exception and
    /// it is worth stating why: acknowledging an alarm changes an annunciator
    /// and a log, both of which live in the control system, and it changes
    /// nothing in the process. It is a command whose whole effect is inside
    /// the boundary this profile can observe — the only one.
    pub fn is_process_affecting(self) -> bool {
        !matches!(self, Self::AcknowledgeAlarm)
    }

    /// Whether this command bears on a safety function.
    ///
    /// A separate question from `is_process_affecting`. These four are the
    /// commands a deployment must never allow to rest on a self-report, and
    /// [`crate::safety::SafetyBoundary`] requires each to be named explicitly
    /// rather than implied by a broader grant.
    pub fn is_safety_related(self) -> bool {
        matches!(
            self,
            Self::BypassInterlock
                | Self::RestoreInterlock
                | Self::TripSafetyFunction
                | Self::EmergencyShutdown
        )
    }

    /// The highest rung of the control chain this command reaches in this
    /// build. `CommandIssued` for every command — the command left the edge
    /// node, and nothing after that is observed.
    pub fn highest_established_rung(self) -> ControlRung {
        crate::controlloop::ControlLoopChain::current()
            .highest_observable()
            .unwrap_or(ControlRung::SupervisoryDecision)
    }

    /// What could observe the compute-and-network half of this command.
    pub fn observable_by(self) -> &'static [ProcessSensingSource] {
        match self {
            // A program download is the one command whose artefact touches the
            // edge node's filesystem before it touches a controller, so a
            // marked path adds a fourth source. It still says nothing about
            // what the controller loaded.
            Self::DownloadControllerProgram => &[
                ProcessSensingSource::EdgeProcessObservation,
                ProcessSensingSource::EdgeNetworkObservation,
                ProcessSensingSource::EdgeDataTransferObservation,
                ProcessSensingSource::EdgeConfigWriteObservation,
            ],
            _ => &[
                ProcessSensingSource::EdgeProcessObservation,
                ProcessSensingSource::EdgeNetworkObservation,
                ProcessSensingSource::EdgeDataTransferObservation,
            ],
        }
    }

    /// Whether an anchored observer could establish that the process effect
    /// occurred. False for all eighteen, computed from the class table.
    pub fn effect_observable(self) -> bool {
        aip_observation::ObservationClass::PhysicalEffect.is_implemented()
    }

    /// The gap between what the edge node did and what the plant did.
    pub fn effect_gap(self) -> &'static str {
        match self {
            Self::WriteSetpoint => "a setpoint written is not a controlled variable that moved",
            Self::WriteDiscreteOutput => "a coil set is not a contact that closed",
            Self::WriteAnalogueOutput => "an output written is not a signal at the field device",
            Self::ChangeControlMode => "a mode written is not a loop behaving differently",
            Self::DownloadControllerProgram => {
                "a transfer completed is not logic executing; the controller may be in program \
                 mode, may have rejected it, or may be running the previous image"
            }
            Self::StartController => "a start command is not a scan cycle running",
            Self::StopController => {
                "a stop command is not logic that stopped, and outputs hold their last state"
            }
            Self::OpenValve => {
                "a command accepted is not a plug off its seat; a stuck valve accepts the command"
            }
            Self::CloseValve => "a command accepted is not a tight shutoff",
            Self::StartRotatingEquipment => "a start is not a shaft turning or a fluid moving",
            Self::StopRotatingEquipment => "a stop is not a machine at rest",
            Self::OpenBreaker => {
                "a trip command is not an interrupted circuit; a welded contact reports open"
            }
            Self::CloseBreaker => "a close command is not an energised circuit",
            Self::AcknowledgeAlarm => {
                "an acknowledgement changes an annunciator and a log; it was never about the \
                 process"
            }
            Self::BypassInterlock => {
                "a bypass written is not a bypass in force, and a bypass in force is not a bypass \
                 that anyone will remember to remove"
            }
            Self::RestoreInterlock => {
                "a restore written is not a protective function that will act when needed"
            }
            Self::TripSafetyFunction => {
                "a trip commanded is not a final element that moved; the demand is exactly when \
                 a stuck element matters"
            }
            Self::EmergencyShutdown => {
                "a shutdown commanded is not a plant in a safe state, and a sequence that \
                 half-completed is worse than one that did not start"
            }
        }
    }
}

/// The `ScopeAction` for an industrial command. A convenience over
/// `ScopeAction::Custom`, not an extension of the authorization vocabulary.
pub fn ics_action(command: IndustrialCommand) -> ScopeAction {
    ScopeAction::Custom(command.kind().to_string())
}

fn bounded(field: &'static str, value: &str) -> Result<(), IndustrialError> {
    if value.is_empty() || value.len() > 128 {
        return Err(IndustrialError::Malformed { reason: field });
    }
    Ok(())
}

/// Parameters naming one point write, byte for byte.
///
/// The device, the address space, the point, the value and the unit all enter
/// the digest. A write authorized for one controller does not commit for
/// another, and a value authorized in one unit does not commit in another.
pub fn point_parameters(
    device_id: &str,
    address_space: &str,
    point_id: &str,
    value: &[u8],
    unit: &str,
) -> Result<ActionParameters, IndustrialError> {
    bounded("device id must be 1-128 bytes", device_id)?;
    bounded("address space must be 1-128 bytes", address_space)?;
    bounded("point id must be 1-128 bytes", point_id)?;
    bounded("unit must be 1-128 bytes", unit)?;
    if value.is_empty() || value.len() > 256 {
        return Err(IndustrialError::Malformed {
            reason: "a command value must be 1-256 bytes",
        });
    }
    Ok(ActionParameters::from_pairs([
        (PARAM_DEVICE_ID, device_id.as_bytes().to_vec()),
        (PARAM_ADDRESS_SPACE, address_space.as_bytes().to_vec()),
        (PARAM_POINT_ID, point_id.as_bytes().to_vec()),
        (PARAM_VALUE, value.to_vec()),
        (PARAM_UNIT, unit.as_bytes().to_vec()),
    ])
    .expect("five distinct constant keys"))
}

/// Parameters naming one controller and the protocol used to reach it.
///
/// For the commands that address a device rather than a point: start, stop,
/// program download.
pub fn device_parameters(
    device_id: &str,
    protocol: crate::protocol::IndustrialProtocol,
) -> Result<ActionParameters, IndustrialError> {
    bounded("device id must be 1-128 bytes", device_id)?;
    Ok(ActionParameters::from_pairs([
        (PARAM_DEVICE_ID, device_id.as_bytes().to_vec()),
        (PARAM_PROTOCOL, vec![protocol.code()]),
    ])
    .expect("two distinct constant keys"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::IndustrialProtocol;

    #[test]
    fn every_command_kind_is_namespaced_and_versioned() {
        for c in IndustrialCommand::ALL {
            assert!(c.kind().starts_with(ICS_ACTION_PREFIX), "{c:?}");
            assert!(c.kind().ends_with(".v1"), "{c:?}");
        }
    }

    #[test]
    fn command_kinds_and_codes_are_unique() {
        let mut kinds: Vec<&str> = IndustrialCommand::ALL.iter().map(|c| c.kind()).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), IndustrialCommand::ALL.len());
        let mut codes: Vec<u8> = IndustrialCommand::ALL.iter().map(|c| c.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), IndustrialCommand::ALL.len());
    }

    #[test]
    fn no_command_reaches_an_observable_process_effect() {
        for c in IndustrialCommand::ALL {
            assert!(!c.effect_observable(), "{c:?}");
            assert_eq!(
                c.highest_established_rung(),
                ControlRung::CommandIssued,
                "{c:?}"
            );
            assert!(!c.effect_gap().is_empty(), "{c:?}");
        }
    }

    #[test]
    fn an_emergency_shutdown_is_a_process_command_like_any_other() {
        // The temptation is to treat a safety command as self-evidently
        // effective. A stuck final element accepts the command too.
        let c = IndustrialCommand::EmergencyShutdown;
        assert!(c.is_process_affecting());
        assert!(c.is_safety_related());
        assert!(!c.effect_observable());
        assert!(c.effect_gap().contains("safe state"));
    }

    #[test]
    fn acknowledging_an_alarm_is_the_only_command_inside_the_boundary() {
        let inside: Vec<IndustrialCommand> = IndustrialCommand::ALL
            .iter()
            .copied()
            .filter(|c| !c.is_process_affecting())
            .collect();
        assert_eq!(inside, vec![IndustrialCommand::AcknowledgeAlarm]);
    }

    #[test]
    fn exactly_four_commands_are_safety_related() {
        let safety: Vec<IndustrialCommand> = IndustrialCommand::ALL
            .iter()
            .copied()
            .filter(|c| c.is_safety_related())
            .collect();
        assert_eq!(
            safety,
            vec![
                IndustrialCommand::BypassInterlock,
                IndustrialCommand::RestoreInterlock,
                IndustrialCommand::TripSafetyFunction,
                IndustrialCommand::EmergencyShutdown,
            ]
        );
    }

    #[test]
    fn an_industrial_command_is_an_ordinary_custom_scope_action() {
        match ics_action(IndustrialCommand::WriteSetpoint) {
            ScopeAction::Custom(s) => assert_eq!(s, "ics.control.write_setpoint.v1"),
            other => panic!("expected a custom action, got {other:?}"),
        }
    }

    #[test]
    fn the_same_point_on_two_devices_is_two_commands() {
        let a = point_parameters("plc-1", "holding", "40001", &50i64.to_le_bytes(), "pct").unwrap();
        let b = point_parameters("plc-2", "holding", "40001", &50i64.to_le_bytes(), "pct").unwrap();
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn the_same_number_in_two_units_is_two_commands() {
        let pct =
            point_parameters("plc-1", "holding", "40001", &50i64.to_le_bytes(), "pct").unwrap();
        let bar =
            point_parameters("plc-1", "holding", "40001", &50i64.to_le_bytes(), "bar").unwrap();
        assert_ne!(
            pct.digest(),
            bar.digest(),
            "fifty percent open and fifty bar are not the same authorization"
        );
    }

    #[test]
    fn point_parameters_are_sensitive_to_every_field() {
        let base = point_parameters("d", "space", "p", &1i64.to_le_bytes(), "u").unwrap();
        for other in [
            point_parameters("D", "space", "p", &1i64.to_le_bytes(), "u").unwrap(),
            point_parameters("d", "other", "p", &1i64.to_le_bytes(), "u").unwrap(),
            point_parameters("d", "space", "q", &1i64.to_le_bytes(), "u").unwrap(),
            point_parameters("d", "space", "p", &2i64.to_le_bytes(), "u").unwrap(),
            point_parameters("d", "space", "p", &(-1i64).to_le_bytes(), "u").unwrap(),
            point_parameters("d", "space", "p", &1i64.to_le_bytes(), "v").unwrap(),
        ] {
            assert_ne!(base.digest(), other.digest());
        }
    }

    #[test]
    fn the_protocol_is_part_of_a_device_command() {
        let a = device_parameters("plc-1", IndustrialProtocol::ModbusTcp).unwrap();
        let b = device_parameters("plc-1", IndustrialProtocol::OpcUa).unwrap();
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn identifiers_and_values_are_bounded() {
        assert!(point_parameters("", "s", "p", b"1", "u").is_err());
        assert!(point_parameters("d", "", "p", b"1", "u").is_err());
        assert!(point_parameters("d", "s", "", b"1", "u").is_err());
        assert!(point_parameters("d", "s", "p", b"", "u").is_err());
        assert!(point_parameters("d", "s", "p", b"1", "").is_err());
        assert!(point_parameters("d", "s", "p", &[0u8; 257], "u").is_err());
        assert!(point_parameters(&"x".repeat(129), "s", "p", b"1", "u").is_err());
        assert!(point_parameters("d", "s", "p", b"1", "u").is_ok());
        assert!(device_parameters("", IndustrialProtocol::ModbusTcp).is_err());
    }

    #[test]
    fn the_ics_namespace_does_not_collide_with_the_other_verticals() {
        for c in IndustrialCommand::ALL {
            assert!(!c.kind().starts_with("uas."), "{c:?}");
            assert!(!c.kind().starts_with("robot."), "{c:?}");
            assert!(!c.kind().starts_with("ghost."), "{c:?}");
        }
    }

    #[test]
    fn a_program_download_is_the_only_command_a_filesystem_mark_can_see() {
        assert!(IndustrialCommand::DownloadControllerProgram
            .observable_by()
            .contains(&ProcessSensingSource::EdgeConfigWriteObservation));
        for c in IndustrialCommand::ALL
            .iter()
            .filter(|c| **c != IndustrialCommand::DownloadControllerProgram)
        {
            assert!(
                !c.observable_by()
                    .contains(&ProcessSensingSource::EdgeConfigWriteObservation),
                "{c:?}"
            );
        }
    }
}
