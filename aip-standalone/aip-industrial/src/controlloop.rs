//! The eight boundaries between deciding a setpoint and having changed a plant.
//!
//! # Why the chain is longer here than in robotics
//!
//! A robot's controller is on a bus the robot owns. An industrial controller is
//! a separate certified device, on a separate network, running a separate
//! program written by a separate party, executing on a scan cycle nobody
//! outside it can see. Between "write 50" and "the flow changed" there are six
//! events that can each occur without the next, and every one of them produces
//! the same thing on the wire: a positive response code.
//!
//! ```text
//!   supervisory decision      the software chose a value
//!   command issued            the command left the edge node
//!   protocol accepted         something at that endpoint answered
//!   controller logic executed the controller says its scan ran the logic
//!   output energised          the controller says it drove an output
//!   actuator response         a final element moved
//!   process variable change   a transmitter reports a different value
//!   physical process effect   the plant is different
//! ```
//!
//! Two are observable in this build. Six are not, and the six are the ones a
//! safety case rests on.
//!
//! # The specific failures each boundary hides
//!
//! - **command → protocol accepted.** Something answered at an address. A
//!   simulator, a gateway, a stale cached session and a different device that
//!   inherited the address all answer.
//! - **protocol accepted → logic executed.** A controller in program mode
//!   accepts writes into memory that no scan reads. So does one whose relevant
//!   rung is short-circuited by a forced bit.
//! - **logic executed → output energised.** A forced output point reports the
//!   commanded state and drives nothing. A failed output card reports fine.
//! - **output energised → actuator response.** A signal at a terminal is not a
//!   moved final element. Air failed, the actuator seized, the stem sheared.
//! - **actuator response → process variable change.** A valve that moved is not
//!   a flow that changed: the line may be blocked, the pump may be off, the
//!   stream may be going somewhere else.
//! - **process variable change → physical process effect.** A transmitter is
//!   reading one tapping through one impulse line, and it is inside the control
//!   system.
//!
//! # Nothing in this module resolves any of it
//!
//! Each rung reports who authored it, whether that party is inside the control
//! system, what could observe it, and — the useful column — what it is *not*.

use aip_crypto::sha256;
use aip_execution::{EvidenceOrigin, ExecutionStage};
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::command::IndustrialCommand;
use crate::error::IndustrialError;
use crate::protocol::IndustrialProtocol;
use crate::sensing::ProcessSensingSource;
use crate::{INDUSTRIAL_PROFILE_DOMAIN, INDUSTRIAL_PROFILE_VERSION};

/// The reserved action-parameter key carrying the control-loop commitment.
///
/// Versioned in the key itself, so a decision point that signed a v1 control
/// loop can never be read as having signed a v2 one.
pub const CONTROL_LOOP_PARAMETER_KEY: &str = "aip.industrial.control_loop.v1";

/// One boundary on the path from a decision to a changed plant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ControlRung {
    /// The supervisory software chose a value.
    SupervisoryDecision,
    /// The command left the edge node.
    CommandIssued,
    /// Something at the controller's endpoint answered positively.
    ProtocolAccepted,
    /// The controller says its scan cycle executed the relevant logic.
    ControllerLogicExecuted,
    /// The controller says it drove an output.
    OutputEnergised,
    /// A final element moved.
    ActuatorResponse,
    /// A transmitter reports a different value.
    ProcessVariableChange,
    /// The plant is different.
    PhysicalProcessEffect,
}

impl ControlRung {
    /// Every rung, in order. The `Ord` derive follows declaration order, which
    /// is the causal order, deliberately.
    pub const ALL: [ControlRung; 8] = [
        Self::SupervisoryDecision,
        Self::CommandIssued,
        Self::ProtocolAccepted,
        Self::ControllerLogicExecuted,
        Self::OutputEnergised,
        Self::ActuatorResponse,
        Self::ProcessVariableChange,
        Self::PhysicalProcessEffect,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::SupervisoryDecision => 0x01,
            Self::CommandIssued => 0x02,
            Self::ProtocolAccepted => 0x03,
            Self::ControllerLogicExecuted => 0x04,
            Self::OutputEnergised => 0x05,
            Self::ActuatorResponse => 0x06,
            Self::ProcessVariableChange => 0x07,
            Self::PhysicalProcessEffect => 0x08,
        }
    }

    /// The stage on Skill 18's twelve-rung ladder this corresponds to.
    ///
    /// `None` for the last three. The twelve stages stop at what happened
    /// outside the host; none of them is a measurement of a final element, of a
    /// process variable, or of a plant. Inventing stages for them would be
    /// three claims in the type system.
    pub fn stage(self) -> Option<ExecutionStage> {
        match self {
            Self::SupervisoryDecision => Some(ExecutionStage::ToolInvocation),
            Self::CommandIssued => Some(ExecutionStage::RuntimeExecution),
            Self::ProtocolAccepted | Self::ControllerLogicExecuted | Self::OutputEnergised => {
                Some(ExecutionStage::PlatformInteraction)
            }
            Self::ActuatorResponse | Self::ProcessVariableChange | Self::PhysicalProcessEffect => {
                None
            }
        }
    }

    /// Where a statement at this rung comes from.
    ///
    /// Rungs three to five are `SelfReported` **even though a different, often
    /// certified, device authors them.** A controller's response arrives over a
    /// network the subject reaches and, for most of these protocols, that
    /// anything on the segment can write. Treating a controller acknowledgement
    /// as independent evidence is the mistake ADR-005 refuses for an autopilot
    /// and ADR-006 for a motion controller, and it is worse here, because the
    /// consequence is measured in tonnes and volts.
    pub fn origin(self) -> EvidenceOrigin {
        match self {
            Self::SupervisoryDecision
            | Self::CommandIssued
            | Self::ProtocolAccepted
            | Self::ControllerLogicExecuted
            | Self::OutputEnergised => EvidenceOrigin::SelfReported,
            // Not self-reported, and not observed either: nothing in this build
            // authors them. The plant does, and nothing here reads the plant.
            Self::ActuatorResponse | Self::ProcessVariableChange | Self::PhysicalProcessEffect => {
                EvidenceOrigin::IndependentlyObserved
            }
        }
    }

    /// What could observe this rung in this build.
    pub fn observable_by(self) -> &'static [ProcessSensingSource] {
        match self {
            Self::SupervisoryDecision => &[
                ProcessSensingSource::EdgeProcessObservation,
                ProcessSensingSource::EdgeLifecycleObservation,
            ],
            Self::CommandIssued => &[
                ProcessSensingSource::EdgeNetworkObservation,
                ProcessSensingSource::EdgeDataTransferObservation,
                ProcessSensingSource::ProtocolWireObservation,
            ],
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
            Self::SupervisoryDecision => "a command having been sent",
            Self::CommandIssued => "a controller having received or accepted it",
            Self::ProtocolAccepted => {
                "the right device having answered: a simulator, a gateway and a device that \
                 inherited the address all answer"
            }
            Self::ControllerLogicExecuted => {
                "an output having changed: a write into memory no scan reads changes nothing"
            }
            Self::OutputEnergised => {
                "a signal at the field device: a forced point reports the commanded state and \
                 drives nothing"
            }
            Self::ActuatorResponse => "a process that changed",
            Self::ProcessVariableChange => {
                "the quantity in the plant: a transmitter reads one tapping, from inside the \
                 control system"
            }
            Self::PhysicalProcessEffect => "a fact this build can establish",
        }
    }

    /// The failure this boundary exists to keep visible.
    pub fn hidden_failure(self) -> &'static str {
        match self {
            Self::SupervisoryDecision => "a decision recorded that no command followed",
            Self::CommandIssued => "a command sent into a link nothing was listening on",
            Self::ProtocolAccepted => "a stale session, a gateway cache, a device impersonation",
            Self::ControllerLogicExecuted => "a controller in program mode, or a forced rung",
            Self::OutputEnergised => "a forced output point, or a failed output card",
            Self::ActuatorResponse => "loss of instrument air, a seized stem, a sheared pin",
            Self::ProcessVariableChange => {
                "a blocked impulse line reading a steady, plausible, wrong value"
            }
            Self::PhysicalProcessEffect => {
                "everything measured going right and the process being somewhere else"
            }
        }
    }
}

/// The chain, computed for this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlLoopChain {
    pub rungs: Vec<(ControlRung, bool)>,
}

impl ControlLoopChain {
    /// Compute which rungs this build can establish.
    ///
    /// Takes no arguments and reads no configuration: the answer is a property
    /// of the mechanisms that exist, and a parameterised version would be a
    /// version someone could parameterise into optimism.
    pub fn current() -> Self {
        Self {
            rungs: ControlRung::ALL
                .iter()
                .map(|r| (*r, r.independently_observable()))
                .collect(),
        }
    }

    /// The highest rung this build can independently establish.
    pub fn highest_observable(&self) -> Option<ControlRung> {
        self.rungs
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(r, _)| *r)
            .next_back()
    }

    /// How many boundaries lie between the highest observable rung and a
    /// physical process effect.
    ///
    /// Reported because *"we verified the control system"* and *"we verified
    /// two of eight rungs and there are six boundaries before anything in the
    /// plant moved"* are the same run described honestly and dishonestly.
    pub fn unobserved_boundaries_to_effect(&self) -> usize {
        let highest = self.highest_observable().map(|r| r.code()).unwrap_or(0);
        ControlRung::ALL
            .iter()
            .filter(|r| r.code() > highest && r.code() <= ControlRung::PhysicalProcessEffect.code())
            .count()
    }
}

/// The interval a command is authorized for. Half-open `[from, until)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandWindow {
    pub from_ms: u64,
    pub until_ms: u64,
}

impl CommandWindow {
    pub fn contains(&self, t_ms: u64) -> bool {
        t_ms >= self.from_ms && t_ms < self.until_ms
    }
    pub fn is_valid(&self) -> bool {
        self.until_ms > self.from_ms
    }
}

/// Where a moment sits relative to a command's window.
///
/// Three states rather than a boolean, because a command offered early and a
/// command offered late are different failures: the first is a clock or a race,
/// the second is a capture-and-replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommandFreshness {
    NotYetValid,
    Fresh,
    Stale,
}

impl CommandFreshness {
    pub fn code(self) -> u8 {
        match self {
            Self::NotYetValid => 0x01,
            Self::Fresh => 0x02,
            Self::Stale => 0x03,
        }
    }

    /// Whether a command in this state may be acted on. True for `Fresh` alone.
    pub fn admissible(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// One execution of one control loop, as a document a decision point can commit
/// to.
///
/// # A loop is a mission
///
/// `loop_id` reuses `aip-system`'s mission identifier, exactly as the robotics
/// profile reuses it for a task: a control loop is the industrial word for the
/// context an execution served, and minting a second identifier for it would be
/// a parallel identity system.
///
/// # Cancellation
///
/// No revocation list. An expectation is bounded, so a control loop stops being
/// authorized when the last expectation committing to it expires and no further
/// one is issued. Cancelling is declining to authorize, which is a decision
/// point's existing power; a second cancellation channel would be a second
/// place for authority to live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlLoopExecution {
    pub version: u16,
    loop_id: aip_system::MissionId,
    /// The loop's revision. Two revisions are two documents with two digests.
    pub revision: u32,
    system_id: aip_system::SystemId,
    /// The edge node or cell, when the deployment names one.
    pub platform_id: Option<aip_system::PlatformId>,
    pub command: IndustrialCommand,
    pub protocol: IndustrialProtocol,
    pub window: CommandWindow,
    /// The loop's declared cycle period, in milliseconds.
    ///
    /// Carried because a command whose window is many cycles wide authorizes
    /// many writes, and a reviewer should be able to see that from the document
    /// rather than infer it. Nothing here enforces a relationship between the
    /// two: enforcing one would be this crate deciding a control-engineering
    /// question on a deployment's behalf.
    pub cycle_time_ms: u32,
    /// The controller addressed.
    device_id: String,
    /// The point written, within that controller's address space.
    point_id: String,
}

impl ControlLoopExecution {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        loop_id: aip_system::MissionId,
        revision: u32,
        system_id: aip_system::SystemId,
        command: IndustrialCommand,
        protocol: IndustrialProtocol,
        window: CommandWindow,
        cycle_time_ms: u32,
        device_id: &str,
        point_id: &str,
    ) -> Result<Self, IndustrialError> {
        if !window.is_valid() {
            return Err(IndustrialError::Malformed {
                reason: "a command window must be non-empty and forward in time",
            });
        }
        if cycle_time_ms == 0 {
            return Err(IndustrialError::Malformed {
                reason: "a control loop cycle time must be non-zero",
            });
        }
        for (field, v) in [
            ("device id must be 1-128 bytes", device_id),
            ("point id must be 1-128 bytes", point_id),
        ] {
            if v.is_empty() || v.len() > 128 {
                return Err(IndustrialError::Malformed { reason: field });
            }
        }
        Ok(Self {
            version: INDUSTRIAL_PROFILE_VERSION,
            loop_id,
            revision,
            system_id,
            platform_id: None,
            command,
            protocol,
            window,
            cycle_time_ms,
            device_id: device_id.to_owned(),
            point_id: point_id.to_owned(),
        })
    }

    pub fn on_platform(mut self, platform: aip_system::PlatformId) -> Self {
        self.platform_id = Some(platform);
        self
    }

    pub fn loop_id(&self) -> &aip_system::MissionId {
        &self.loop_id
    }
    pub fn system_id(&self) -> &aip_system::SystemId {
        &self.system_id
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub fn point_id(&self) -> &str {
        &self.point_id
    }

    /// Where `t_ms` sits relative to the authorized window.
    pub fn freshness(&self, t_ms: u64) -> CommandFreshness {
        if t_ms < self.window.from_ms {
            CommandFreshness::NotYetValid
        } else if t_ms < self.window.until_ms {
            CommandFreshness::Fresh
        } else {
            CommandFreshness::Stale
        }
    }

    /// Refuse a command offered outside its window.
    ///
    /// The stale-command defence, as a refusal rather than a weak finding: a
    /// captured write replayed onto a segment tomorrow is the cheapest attack
    /// on a control network with no session cryptography, which is most of them.
    pub fn admit_at(&self, t_ms: u64) -> Result<(), IndustrialError> {
        if self.freshness(t_ms).admissible() {
            return Ok(());
        }
        Err(IndustrialError::CommandNotFresh {
            at_ms: t_ms,
            from_ms: self.window.from_ms,
            until_ms: self.window.until_ms,
        })
    }

    /// The highest rung this execution establishes in this build.
    pub fn highest_established_rung(&self) -> Option<ControlRung> {
        ControlLoopChain::current().highest_observable()
    }

    /// Whether this execution establishes that the plant changed. Never.
    pub fn establishes_process_effect(&self) -> bool {
        aip_observation::ObservationClass::PhysicalEffect.is_implemented()
    }

    pub fn check_version(&self) -> Result<(), IndustrialError> {
        if self.version != INDUSTRIAL_PROFILE_VERSION {
            return Err(IndustrialError::UnsupportedVersion {
                found: self.version,
                supported: INDUSTRIAL_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, INDUSTRIAL_PROFILE_DOMAIN);
        // Structure discriminant inside the shared domain: 0x01 is a control
        // loop execution.
        put_u8(&mut buf, 0x01);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, self.loop_id.as_str());
        put_u32(&mut buf, self.revision);
        put_str(&mut buf, self.system_id.as_str());
        match &self.platform_id {
            Some(p) => {
                put_u8(&mut buf, 1);
                put_str(&mut buf, p.as_str());
            }
            None => put_u8(&mut buf, 0),
        }
        put_u8(&mut buf, self.command.code());
        put_u8(&mut buf, self.protocol.code());
        put_u64(&mut buf, self.window.from_ms);
        put_u64(&mut buf, self.window.until_ms);
        put_u32(&mut buf, self.cycle_time_ms);
        put_str(&mut buf, &self.device_id);
        put_str(&mut buf, &self.point_id);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The `(key, value)` pair to add to action parameters so a decision point
    /// commits to this control loop.
    pub fn authorization_parameter(&self) -> (String, Vec<u8>) {
        (
            CONTROL_LOOP_PARAMETER_KEY.to_owned(),
            self.digest().to_vec(),
        )
    }

    /// Whether `parameter_value` commits to this exact control loop.
    ///
    /// Checks nothing about a signature: the caller must already have checked
    /// the expectation carrying the parameter digest.
    pub fn is_committed_by(&self, parameter_value: Option<&[u8]>) -> bool {
        match parameter_value {
            Some(v) => v == self.digest(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loop_exec(revision: u32, device: &str, point: &str) -> ControlLoopExecution {
        ControlLoopExecution::new(
            aip_system::MissionId::parse("loop:fic-101").unwrap(),
            revision,
            aip_system::SystemId::parse("ics:unit-4-supervisor").unwrap(),
            IndustrialCommand::WriteSetpoint,
            IndustrialProtocol::ModbusTcp,
            CommandWindow {
                from_ms: 1_000,
                until_ms: 100_000,
            },
            250,
            device,
            point,
        )
        .unwrap()
    }

    #[test]
    fn the_chain_stops_at_the_command_leaving_the_edge_node() {
        let c = ControlLoopChain::current();
        assert_eq!(c.highest_observable(), Some(ControlRung::CommandIssued));
        assert_eq!(
            c.unobserved_boundaries_to_effect(),
            6,
            "six boundaries lie between a sent command and a changed plant"
        );
    }

    #[test]
    fn a_controller_response_is_a_self_report() {
        for r in [
            ControlRung::ProtocolAccepted,
            ControlRung::ControllerLogicExecuted,
            ControlRung::OutputEnergised,
        ] {
            assert_eq!(r.origin(), EvidenceOrigin::SelfReported, "{r:?}");
            assert!(!r.origin().can_establish_occurrence(), "{r:?}");
            assert!(!r.independently_observable(), "{r:?}");
        }
    }

    #[test]
    fn nothing_beyond_the_command_is_observable() {
        for r in ControlRung::ALL
            .iter()
            .filter(|r| **r > ControlRung::CommandIssued)
        {
            assert!(!r.independently_observable(), "{r:?}");
            assert!(r.observable_by().is_empty(), "{r:?}");
        }
    }

    #[test]
    fn the_last_three_rungs_have_no_stage() {
        for r in [
            ControlRung::ActuatorResponse,
            ControlRung::ProcessVariableChange,
            ControlRung::PhysicalProcessEffect,
        ] {
            assert!(
                r.stage().is_none(),
                "{r:?}: no stage on the twelve-rung ladder measures a plant"
            );
        }
        for r in ControlRung::ALL.iter().take(5) {
            assert!(r.stage().is_some(), "{r:?}");
        }
    }

    #[test]
    fn the_stages_are_non_decreasing_along_the_chain() {
        let stages: Vec<ExecutionStage> =
            ControlRung::ALL.iter().filter_map(|r| r.stage()).collect();
        for w in stages.windows(2) {
            assert!(w[0] <= w[1], "the chain must not run backwards: {w:?}");
        }
    }

    #[test]
    fn a_software_rung_may_not_establish_a_platform_rung() {
        let from = ControlRung::SupervisoryDecision.stage().unwrap();
        let to = ControlRung::OutputEnergised.stage().unwrap();
        assert!(
            !from.may_establish(to),
            "a decision must not establish that an output was energised"
        );
    }

    #[test]
    fn the_chain_is_strictly_ordered_and_every_rung_states_its_gaps() {
        let mut codes: Vec<u8> = ControlRung::ALL.iter().map(|r| r.code()).collect();
        let sorted = {
            let mut c = codes.clone();
            c.sort_unstable();
            c
        };
        assert_eq!(codes, sorted, "declaration order must be causal order");
        codes.dedup();
        assert_eq!(codes.len(), 8);
        for r in ControlRung::ALL {
            assert!(!r.is_not().is_empty(), "{r:?}");
            assert!(!r.hidden_failure().is_empty(), "{r:?}");
        }
    }

    #[test]
    fn a_stale_command_is_refused_rather_than_weakened() {
        let e = loop_exec(1, "plc-1", "40001");
        assert_eq!(e.freshness(999), CommandFreshness::NotYetValid);
        assert_eq!(e.freshness(1_000), CommandFreshness::Fresh);
        assert_eq!(e.freshness(99_999), CommandFreshness::Fresh);
        assert_eq!(e.freshness(100_000), CommandFreshness::Stale);
        assert!(e.admit_at(50_000).is_ok());
        assert!(matches!(
            e.admit_at(100_000),
            Err(IndustrialError::CommandNotFresh { .. })
        ));
        assert!(matches!(
            e.admit_at(0),
            Err(IndustrialError::CommandNotFresh { .. })
        ));
    }

    #[test]
    fn only_fresh_is_admissible() {
        assert!(CommandFreshness::Fresh.admissible());
        assert!(!CommandFreshness::Stale.admissible());
        assert!(!CommandFreshness::NotYetValid.admissible());
    }

    #[test]
    fn a_commitment_names_the_device_and_the_point() {
        let a = loop_exec(1, "plc-1", "40001");
        assert!(!a.is_committed_by(None));
        assert!(a.is_committed_by(Some(&a.digest())));
        assert!(!a.is_committed_by(Some(&loop_exec(1, "plc-2", "40001").digest())));
        assert!(!a.is_committed_by(Some(&loop_exec(1, "plc-1", "40002").digest())));
        assert!(!a.is_committed_by(Some(&loop_exec(2, "plc-1", "40001").digest())));
    }

    #[test]
    fn the_protocol_and_the_command_are_part_of_the_document() {
        let base = loop_exec(1, "plc-1", "40001");
        let other_protocol = ControlLoopExecution::new(
            aip_system::MissionId::parse("loop:fic-101").unwrap(),
            1,
            aip_system::SystemId::parse("ics:unit-4-supervisor").unwrap(),
            IndustrialCommand::WriteSetpoint,
            IndustrialProtocol::OpcUa,
            CommandWindow {
                from_ms: 1_000,
                until_ms: 100_000,
            },
            250,
            "plc-1",
            "40001",
        )
        .unwrap();
        let other_command = ControlLoopExecution::new(
            aip_system::MissionId::parse("loop:fic-101").unwrap(),
            1,
            aip_system::SystemId::parse("ics:unit-4-supervisor").unwrap(),
            IndustrialCommand::BypassInterlock,
            IndustrialProtocol::ModbusTcp,
            CommandWindow {
                from_ms: 1_000,
                until_ms: 100_000,
            },
            250,
            "plc-1",
            "40001",
        )
        .unwrap();
        assert_ne!(base.digest(), other_protocol.digest());
        assert_ne!(base.digest(), other_command.digest());
    }

    #[test]
    fn malformed_control_loops_are_refused() {
        let id = || aip_system::MissionId::parse("loop:x").unwrap();
        let sys = || aip_system::SystemId::parse("ics:y").unwrap();
        let win = CommandWindow {
            from_ms: 1,
            until_ms: 2,
        };
        let mk = |w: CommandWindow, cycle: u32, d: &str, p: &str| {
            ControlLoopExecution::new(
                id(),
                1,
                sys(),
                IndustrialCommand::WriteSetpoint,
                IndustrialProtocol::ModbusTcp,
                w,
                cycle,
                d,
                p,
            )
        };
        assert!(mk(win, 250, "", "p").is_err());
        assert!(mk(win, 250, "d", "").is_err());
        assert!(mk(win, 0, "d", "p").is_err());
        assert!(mk(
            CommandWindow {
                from_ms: 5,
                until_ms: 5
            },
            250,
            "d",
            "p"
        )
        .is_err());
        assert!(mk(win, 250, "d", "p").is_ok());
    }

    #[test]
    fn no_control_loop_establishes_a_process_effect() {
        let e = loop_exec(1, "plc-1", "40001");
        assert!(!e.establishes_process_effect());
        assert_eq!(
            e.highest_established_rung(),
            Some(ControlRung::CommandIssued)
        );
        assert!(e.check_version().is_ok());
    }
}
