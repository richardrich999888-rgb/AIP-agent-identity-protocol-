//! The physical process: what a plant instrument measures, and what people say
//! it means.
//!
//! # Why this module exists
//!
//! Industrial evidence is reported in language that outruns it, and the gap is
//! not academic — it is where plants burn:
//!
//! | measured | commonly said |
//! |---|---|
//! | a write returned a positive response code | the command executed |
//! | a limit switch closed | the valve opened |
//! | a breaker auxiliary contact reads open | the circuit is de-energised |
//! | a transmitter reads 4.2 bar | the pressure is 4.2 bar |
//! | a motor run feedback is on | the pump is delivering |
//! | a safety status bit is healthy | the interlock will act |
//!
//! Every left-hand column is a fact about a device inside the control system.
//! Every right-hand column is a claim about the plant, and each requires
//! something the measurement does not contain: a mechanical linkage that did
//! not fail, an impulse line that is not blocked, a point that is not forced,
//! or a demand that has not yet happened.
//!
//! # What this module does and does not do
//!
//! It does **not** decide whether a claim is true — nothing here reads an
//! instrument. It holds the gap open: each measurement names what it measures,
//! what it actually establishes, and the claim it is commonly mistaken for.
//! Each claim names what it would need.
//!
//! [`ProcessClaim::establishable_from_measurement`] is `false` for every claim
//! in this build, and it is computed from the source table rather than written
//! as a literal — so implementing a physical mechanism has to change the table
//! and fail this module's tests rather than leave a stale `false` behind.
//!
//! # The interlock case, specifically
//!
//! [`ProcessClaim::InterlockIntact`] is the one worth calling out. A safety
//! system reporting healthy is reporting that its logic solver is healthy. It
//! is not reporting that a bypass was removed, that a final element will move,
//! or that the trip amplifier is not saturated — and a protective function is
//! only ever tested by the demand it exists for. A safety case that rests on a
//! healthy status bit rests on the one measurement that is guaranteed to look
//! the same whether the function works or not.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::sensing::ProcessSensingSource;
use crate::state::ProcessEvidence;

/// A quantity an industrial process has.
///
/// Used by [`crate::safety::SafetyBoundary`] to name the variable a limit is
/// about, and by [`PhysicalProcessEffect`] to name what a claim is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProcessVariable {
    Flow,
    Pressure,
    Level,
    Temperature,
    ValvePosition,
    MotorState,
    BreakerState,
    Current,
    Voltage,
    Frequency,
    Concentration,
    Speed,
}

impl ProcessVariable {
    pub const ALL: [ProcessVariable; 12] = [
        Self::Flow,
        Self::Pressure,
        Self::Level,
        Self::Temperature,
        Self::ValvePosition,
        Self::MotorState,
        Self::BreakerState,
        Self::Current,
        Self::Voltage,
        Self::Frequency,
        Self::Concentration,
        Self::Speed,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Flow => 0x01,
            Self::Pressure => 0x02,
            Self::Level => 0x03,
            Self::Temperature => 0x04,
            Self::ValvePosition => 0x05,
            Self::MotorState => 0x06,
            Self::BreakerState => 0x07,
            Self::Current => 0x08,
            Self::Voltage => 0x09,
            Self::Frequency => 0x0A,
            Self::Concentration => 0x0B,
            Self::Speed => 0x0C,
        }
    }
}

/// Something a device in or around an industrial process actually produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProcessMeasurement {
    /// A protocol response code from a controller.
    ProtocolResponseCode,
    /// A status bit in a controller's memory.
    ControllerStatusBit,
    /// A valve limit or proximity switch.
    ValveLimitSwitch,
    /// A breaker's auxiliary contact.
    BreakerAuxiliaryContact,
    /// A process transmitter's output.
    TransmitterReading,
    /// A motor contactor's run feedback.
    MotorRunFeedback,
    /// A point stored in the historian.
    HistorianTrendPoint,
    /// A meter's accumulated total.
    MeterTotaliser,
    /// An alarm the annunciator raised.
    AlarmAnnunciation,
}

impl ProcessMeasurement {
    pub const ALL: [ProcessMeasurement; 9] = [
        Self::ProtocolResponseCode,
        Self::ControllerStatusBit,
        Self::ValveLimitSwitch,
        Self::BreakerAuxiliaryContact,
        Self::TransmitterReading,
        Self::MotorRunFeedback,
        Self::HistorianTrendPoint,
        Self::MeterTotaliser,
        Self::AlarmAnnunciation,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::ProtocolResponseCode => 0x01,
            Self::ControllerStatusBit => 0x02,
            Self::ValveLimitSwitch => 0x03,
            Self::BreakerAuxiliaryContact => 0x04,
            Self::TransmitterReading => 0x05,
            Self::MotorRunFeedback => 0x06,
            Self::HistorianTrendPoint => 0x07,
            Self::MeterTotaliser => 0x08,
            Self::AlarmAnnunciation => 0x09,
        }
    }

    pub fn measures(self) -> &'static str {
        match self {
            Self::ProtocolResponseCode => "a code in a reply frame from an endpoint",
            Self::ControllerStatusBit => "the value of one bit in a controller's memory",
            Self::ValveLimitSwitch => "that a switch at the actuator changed state",
            Self::BreakerAuxiliaryContact => {
                "the position of a contact mechanically linked to a \
                                             breaker's operating mechanism"
            }
            Self::TransmitterReading => "a transduced quantity at one tapping point",
            Self::MotorRunFeedback => "that a contactor auxiliary closed",
            Self::HistorianTrendPoint => "a value the control system previously reported",
            Self::MeterTotaliser => "an accumulated count at one meter",
            Self::AlarmAnnunciation => "that a configured condition evaluated true",
        }
    }

    pub fn actually_establishes(self) -> &'static str {
        match self {
            Self::ProtocolResponseCode => "that something at that endpoint answered",
            Self::ControllerStatusBit => "what the bit was when it was read",
            Self::ValveLimitSwitch => "that the stem reached the switch",
            Self::BreakerAuxiliaryContact => {
                "the auxiliary's position; the main contacts are elsewhere and can weld"
            }
            Self::TransmitterReading => "what the transmitter output; nothing about the tapping",
            Self::MotorRunFeedback => "that the contactor picked up",
            Self::HistorianTrendPoint => "what was reported, not what was true",
            Self::MeterTotaliser => "the count at that meter, in whatever stream it is in",
            Self::AlarmAnnunciation => "that the configured expression evaluated true",
        }
    }

    /// The claim this measurement is commonly read as establishing.
    ///
    /// Naming the mistake explicitly, per measurement, so it can be tested
    /// against rather than warned about.
    pub fn commonly_read_as(self) -> ProcessClaim {
        match self {
            Self::ProtocolResponseCode => ProcessClaim::CommandExecuted,
            Self::ControllerStatusBit | Self::AlarmAnnunciation => ProcessClaim::InterlockIntact,
            Self::ValveLimitSwitch => ProcessClaim::ValveMoved,
            Self::BreakerAuxiliaryContact => ProcessClaim::CircuitDeEnergised,
            Self::TransmitterReading | Self::HistorianTrendPoint => {
                ProcessClaim::ProcessVariableIsValue
            }
            Self::MotorRunFeedback => ProcessClaim::EquipmentRunning,
            Self::MeterTotaliser => ProcessClaim::QuantityDelivered,
        }
    }

    /// The sources that produce this measurement.
    pub fn produced_by(self) -> &'static [ProcessSensingSource] {
        match self {
            Self::ProtocolResponseCode | Self::ControllerStatusBit => {
                &[ProcessSensingSource::ControllerStatusReport]
            }
            Self::ValveLimitSwitch | Self::BreakerAuxiliaryContact | Self::MotorRunFeedback => {
                &[ProcessSensingSource::ActuatorPositionFeedback]
            }
            Self::TransmitterReading => &[
                ProcessSensingSource::ProcessTransmitter,
                ProcessSensingSource::IndependentPlantSensor,
            ],
            Self::HistorianTrendPoint => &[ProcessSensingSource::HistorianArchive],
            Self::MeterTotaliser => &[ProcessSensingSource::MeteringDevice],
            Self::AlarmAnnunciation => &[
                ProcessSensingSource::HmiOperatorLog,
                ProcessSensingSource::SafetySystemStatus,
            ],
        }
    }
}

/// A statement about the plant that someone wants to make from a measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProcessClaim {
    /// A command was carried out in the plant.
    CommandExecuted,
    /// A valve moved.
    ValveMoved,
    /// A circuit is de-energised.
    CircuitDeEnergised,
    /// A process variable has a particular value.
    ProcessVariableIsValue,
    /// A machine is running and doing its job.
    EquipmentRunning,
    /// A protective function is intact and will act on demand.
    InterlockIntact,
    /// A quantity was delivered.
    QuantityDelivered,
    /// A hazardous condition is absent.
    HazardAbsent,
}

impl ProcessClaim {
    pub const ALL: [ProcessClaim; 8] = [
        Self::CommandExecuted,
        Self::ValveMoved,
        Self::CircuitDeEnergised,
        Self::ProcessVariableIsValue,
        Self::EquipmentRunning,
        Self::InterlockIntact,
        Self::QuantityDelivered,
        Self::HazardAbsent,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::CommandExecuted => 0x01,
            Self::ValveMoved => 0x02,
            Self::CircuitDeEnergised => 0x03,
            Self::ProcessVariableIsValue => 0x04,
            Self::EquipmentRunning => 0x05,
            Self::InterlockIntact => 0x06,
            Self::QuantityDelivered => 0x07,
            Self::HazardAbsent => 0x08,
        }
    }

    /// What the claim needs beyond any measurement, in one line.
    pub fn requires_beyond_measurement(self) -> &'static str {
        match self {
            Self::CommandExecuted => {
                "a chain of six further events, each of which can fail while the response code \
                 stays positive"
            }
            Self::ValveMoved => {
                "that the linkage between stem and plug held, and that the plug left its seat"
            }
            Self::CircuitDeEnergised => {
                "the state of the main contacts, which an auxiliary does not measure; a welded \
                 pole reports open"
            }
            Self::ProcessVariableIsValue => {
                "an unblocked impulse line, a transmitter in calibration, and a tapping in the \
                 stream anyone means"
            }
            Self::EquipmentRunning => {
                "that the machine is doing work: a contactor closed on a sheared coupling reports \
                 running"
            }
            Self::InterlockIntact => {
                "the demand itself; a protective function is only tested by the event it exists \
                 for, and a bypass reports healthy"
            }
            Self::QuantityDelivered => {
                "a proved meter, in the right stream, with the right composition"
            }
            Self::HazardAbsent => {
                "coverage of everywhere the hazard could be, which no instrument set has"
            }
        }
    }

    /// Whether any measurement in this build establishes this claim.
    ///
    /// `false` for all eight, computed rather than asserted: a claim is
    /// establishable only if some source producing a bearing measurement is
    /// both independent of the control system and backed by an implemented
    /// mechanism. No plant instrument is, so the conjunction is empty — and if
    /// a future build implements one, this returns `true` and the tests below
    /// fail, which is the intended way to find out.
    pub fn establishable_from_measurement(self) -> bool {
        ProcessMeasurement::ALL
            .iter()
            .filter(|m| m.commonly_read_as() == self)
            .flat_map(|m| m.produced_by())
            .any(|s| s.is_independent() && s.can_produce_observation_record())
    }

    /// The measurements people reach for when making this claim.
    pub fn commonly_argued_from(self) -> Vec<ProcessMeasurement> {
        ProcessMeasurement::ALL
            .iter()
            .copied()
            .filter(|m| m.commonly_read_as() == self)
            .collect()
    }
}

/// What is known about one claimed effect in the plant.
///
/// # Distinct from a safety boundary, on purpose
///
/// The spec rule is that safety boundaries and process effects are separate
/// commitments and separate observations. A [`crate::safety::SafetyBoundary`]
/// is a *document a decision point commits to* — it says what was declared to
/// be in force. This is an *observation record's worth of nothing* — it says
/// what a deployment's sources could establish about what actually happened.
/// They have different encodings, different parameter keys and no method that
/// turns one into the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalProcessEffect {
    pub variable: ProcessVariable,
    pub claim: ProcessClaim,
    /// Sources inside the control system that report on it.
    pub self_reported_by: Vec<ProcessSensingSource>,
    /// Sources outside the control system that report on it.
    pub externally_reported_by: Vec<ProcessSensingSource>,
    /// Whether any reporting source is both outside the control system and
    /// backed by an implemented mechanism. Computed once, in `from_sources`,
    /// and never assigned anywhere else.
    independently_observed: bool,
}

impl PhysicalProcessEffect {
    /// Derive from a deployment's declared sources.
    ///
    /// The one place `independently_observed` is decided.
    pub fn from_sources(
        variable: ProcessVariable,
        claim: ProcessClaim,
        sources: &[ProcessSensingSource],
    ) -> Self {
        let reporting: Vec<ProcessSensingSource> = claim
            .commonly_argued_from()
            .into_iter()
            .flat_map(|m| m.produced_by().iter().copied())
            .filter(|s| sources.contains(s))
            .collect();
        let self_reported_by: Vec<ProcessSensingSource> = reporting
            .iter()
            .copied()
            .filter(|s| s.is_inside_control_system())
            .collect();
        let externally_reported_by: Vec<ProcessSensingSource> = reporting
            .iter()
            .copied()
            .filter(|s| s.is_independent())
            .collect();
        let independently_observed = externally_reported_by
            .iter()
            .any(|s| s.can_produce_observation_record());
        Self {
            variable,
            claim,
            self_reported_by,
            externally_reported_by,
            independently_observed,
        }
    }

    /// Whether an anchored, independent source established this effect.
    pub fn is_independently_observed(&self) -> bool {
        self.independently_observed
    }

    /// Whether this effect may be asserted.
    ///
    /// Requires an anchored independent observation **and** a claim the class
    /// table says is establishable. Both are false in this build, and the
    /// conjunction is written out rather than short-circuited so a future
    /// change to either has to be deliberate.
    pub fn establishes(&self) -> bool {
        self.independently_observed && self.claim.establishable_from_measurement()
    }

    /// The strongest evidence this effect could carry.
    pub fn ceiling(&self) -> EvidenceCeiling {
        self.self_reported_by
            .iter()
            .chain(self.externally_reported_by.iter())
            .map(|s| s.ceiling())
            .max()
            .unwrap_or(EvidenceCeiling::Corroborative)
    }

    /// The evidence tier this effect would need before a verifier may assert it.
    pub fn evidence_required(&self) -> ProcessEvidence {
        ProcessEvidence::PhysicallyObserved
    }
}

/// How a measurement relates to a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimSupport {
    /// The measurement establishes the claim. Unreachable in this build.
    Establishes,
    /// The measurement bears on the claim without establishing it — the honest
    /// answer for every pairing people actually use.
    Bears,
    /// The measurement has nothing to do with the claim.
    Unrelated,
}

impl ClaimSupport {
    /// Whether this support permits asserting the claim. True for
    /// `Establishes` alone; `Bears` is deliberately not a weak yes.
    pub fn permits_assertion(self) -> bool {
        matches!(self, Self::Establishes)
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Establishes => 0x01,
            Self::Bears => 0x02,
            Self::Unrelated => 0x03,
        }
    }
}

/// How `measurement` relates to `claim`.
pub fn support_for(measurement: ProcessMeasurement, claim: ProcessClaim) -> ClaimSupport {
    if measurement.commonly_read_as() != claim {
        return ClaimSupport::Unrelated;
    }
    if claim.establishable_from_measurement() {
        ClaimSupport::Establishes
    } else {
        ClaimSupport::Bears
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_process_claim_is_establishable_from_measurement_in_this_build() {
        for c in ProcessClaim::ALL {
            assert!(
                !c.establishable_from_measurement(),
                "{c:?} became establishable; no plant instrument is both independent and mechanised"
            );
            assert!(!c.requires_beyond_measurement().is_empty(), "{c:?}");
        }
    }

    #[test]
    fn a_positive_response_code_is_not_an_executed_command() {
        assert_eq!(
            ProcessMeasurement::ProtocolResponseCode.commonly_read_as(),
            ProcessClaim::CommandExecuted
        );
        assert_eq!(
            support_for(
                ProcessMeasurement::ProtocolResponseCode,
                ProcessClaim::CommandExecuted
            ),
            ClaimSupport::Bears
        );
        assert!(!ClaimSupport::Bears.permits_assertion());
    }

    #[test]
    fn a_healthy_safety_status_bit_does_not_establish_an_intact_interlock() {
        assert_eq!(
            support_for(
                ProcessMeasurement::ControllerStatusBit,
                ProcessClaim::InterlockIntact
            ),
            ClaimSupport::Bears
        );
        assert!(ProcessClaim::InterlockIntact
            .requires_beyond_measurement()
            .contains("bypass"));
    }

    #[test]
    fn an_unrelated_pairing_is_unrelated_rather_than_weak() {
        assert_eq!(
            support_for(
                ProcessMeasurement::MeterTotaliser,
                ProcessClaim::CircuitDeEnergised
            ),
            ClaimSupport::Unrelated
        );
    }

    #[test]
    fn a_hazard_claim_is_argued_from_nothing_and_still_establishes_nothing() {
        // No measurement maps to it, so the conjunction is empty for the most
        // literal possible reason.
        assert!(ProcessClaim::HazardAbsent.commonly_argued_from().is_empty());
        assert!(!ProcessClaim::HazardAbsent.establishable_from_measurement());
    }

    #[test]
    fn every_effect_is_unestablished_even_with_every_source_declared() {
        for v in ProcessVariable::ALL {
            for c in ProcessClaim::ALL {
                let e = PhysicalProcessEffect::from_sources(v, c, &ProcessSensingSource::ALL);
                assert!(!e.establishes(), "{v:?}/{c:?}");
                assert!(!e.is_independently_observed(), "{v:?}/{c:?}");
                assert_eq!(e.evidence_required(), ProcessEvidence::PhysicallyObserved);
                assert_ne!(e.ceiling(), EvidenceCeiling::Proven, "{v:?}/{c:?}");
            }
        }
    }

    #[test]
    fn an_independent_but_unanchored_sensor_does_not_make_an_effect_observed() {
        let e = PhysicalProcessEffect::from_sources(
            ProcessVariable::Pressure,
            ProcessClaim::ProcessVariableIsValue,
            &[ProcessSensingSource::IndependentPlantSensor],
        );
        assert_eq!(
            e.externally_reported_by,
            vec![ProcessSensingSource::IndependentPlantSensor]
        );
        assert!(
            !e.is_independently_observed(),
            "positional independence without a mechanism is nobody observing"
        );
        assert!(!e.establishes());
    }

    #[test]
    fn a_control_system_source_is_recorded_as_self_reported() {
        let e = PhysicalProcessEffect::from_sources(
            ProcessVariable::ValvePosition,
            ProcessClaim::ValveMoved,
            &[ProcessSensingSource::ActuatorPositionFeedback],
        );
        assert_eq!(
            e.self_reported_by,
            vec![ProcessSensingSource::ActuatorPositionFeedback]
        );
        assert!(e.externally_reported_by.is_empty());
        assert!(!e.establishes());
    }

    #[test]
    fn codes_are_unique_and_every_measurement_answers_its_columns() {
        let mut m: Vec<u8> = ProcessMeasurement::ALL.iter().map(|m| m.code()).collect();
        m.sort_unstable();
        m.dedup();
        assert_eq!(m.len(), ProcessMeasurement::ALL.len());
        let mut c: Vec<u8> = ProcessClaim::ALL.iter().map(|c| c.code()).collect();
        c.sort_unstable();
        c.dedup();
        assert_eq!(c.len(), ProcessClaim::ALL.len());
        let mut v: Vec<u8> = ProcessVariable::ALL.iter().map(|v| v.code()).collect();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), ProcessVariable::ALL.len());
        for meas in ProcessMeasurement::ALL {
            assert!(!meas.measures().is_empty(), "{meas:?}");
            assert!(!meas.actually_establishes().is_empty(), "{meas:?}");
            assert!(!meas.produced_by().is_empty(), "{meas:?}");
        }
    }
}
