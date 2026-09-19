//! Where an external validation tool's output came from, and what it could
//! ever be worth.
//!
//! # The one question
//!
//! Not "is this tool good?" — ROS 2, Gazebo, PX4 and OPC UA are all excellent
//! engineering. The question is:
//!
//! > **Does the actor control the evidence used to judge the actor?**
//!
//! A `/odom` topic is the robot describing its own position. A rosbag2 file is
//! that description recorded faithfully — recording a claim verbatim makes it
//! durable, not true. A PX4 telemetry stream is the autopilot's account of the
//! autopilot. A PLC's write-status is the controller's account of the
//! controller. None of them becomes independent by being binary, timestamped,
//! high-rate, or labelled "telemetry".
//!
//! # Ceilings are consumed, never defined here
//!
//! [`EvidenceCeiling`] is `aip-observation`'s type. This module maps a
//! provenance class onto it and adds no value of its own. A validation adapter
//! that defined its own ceiling would be the second evidence hierarchy the
//! whole exercise exists to prevent.

use aip_observation::{EvidenceCeiling, ObservationClass};
use aip_observe::SourceMechanism;
use serde::{Deserialize, Serialize};

/// The provenance of one external observation.
///
/// Closed on purpose. An open vocabulary could not carry a ceiling, and a
/// deployment that could name its own class could name a self-report as
/// something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProvenanceClass {
    /// The subject's own account of itself: a ROS 2 topic it publishes, a PX4
    /// telemetry stream, an autonomy runtime's log.
    SubjectSelfReport,
    /// A durable recording of a self-report: rosbag2, a historian, a flight
    /// log. Recording a claim verbatim makes it durable, not true.
    SubjectControlledRecording,
    /// A controller saying it accepted or executed something: a
    /// `ros2_control` acknowledgement, a PLC write status, an OPC UA good
    /// status code, a MAVLink `COMMAND_ACK`.
    ControllerAcknowledgement,
    /// Instrumentation of the subject's own middleware: `ros2_tracing`
    /// callbacks, DDS statistics. Independent of the *application* and inside
    /// the same host and trust boundary.
    SubjectMiddlewareInstrumentation,
    /// A simulator's physics state. Independent of the simulated robot **and
    /// only within the simulation**: it is not a fact about any world.
    SimulatorGroundTruth,
    /// A sensor outside the subject with no anchored collector behind it: an
    /// external camera whose frames arrive over an unauthenticated path.
    ExternalSensorUnanchored,
    /// A sensor outside the subject, measured by a collector that holds its
    /// own key and is not the subject.
    ExternalSensorAnchored,
    /// The existing host-runtime observation path: an anchored collector
    /// measuring a Linux facility. The only class with implemented mechanisms.
    HostRuntimeObservation,
}

impl ProvenanceClass {
    pub const ALL: [ProvenanceClass; 8] = [
        Self::SubjectSelfReport,
        Self::SubjectControlledRecording,
        Self::ControllerAcknowledgement,
        Self::SubjectMiddlewareInstrumentation,
        Self::SimulatorGroundTruth,
        Self::ExternalSensorUnanchored,
        Self::ExternalSensorAnchored,
        Self::HostRuntimeObservation,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::SubjectSelfReport => 0x01,
            Self::SubjectControlledRecording => 0x02,
            Self::ControllerAcknowledgement => 0x03,
            Self::SubjectMiddlewareInstrumentation => 0x04,
            Self::SimulatorGroundTruth => 0x05,
            Self::ExternalSensorUnanchored => 0x06,
            Self::ExternalSensorAnchored => 0x07,
            Self::HostRuntimeObservation => 0x08,
        }
    }

    /// Whether the subject can alter what this source says without
    /// compromising anything outside its own trust boundary.
    ///
    /// True for four of eight. `SubjectMiddlewareInstrumentation` is included:
    /// `ros2_tracing` is LTTng inside the subject's own process, and a
    /// compromised node writes its own trace points.
    pub fn subject_controls_source(self) -> bool {
        matches!(
            self,
            Self::SubjectSelfReport
                | Self::SubjectControlledRecording
                | Self::ControllerAcknowledgement
                | Self::SubjectMiddlewareInstrumentation
        )
    }

    /// Whether the source sits outside the subject's trust boundary.
    pub fn is_external_to_subject(self) -> bool {
        !self.subject_controls_source()
    }

    /// Whether an anchored collector — one holding its own key, and not the
    /// subject — stands behind this class.
    pub fn is_anchored(self) -> bool {
        matches!(
            self,
            Self::ExternalSensorAnchored | Self::HostRuntimeObservation
        )
    }

    /// The Linux mechanism backing this class, when one exists.
    ///
    /// `Some` for exactly one class, and only because the host-runtime path
    /// already existed. There is deliberately no mechanism for a camera: a
    /// camera is not a Linux kernel facility, and adding a `SourceMechanism`
    /// variant for one would put a device-specific value into signed bytes
    /// every verifier must understand — the schema fork ADR-003 exists to
    /// prevent.
    pub fn mechanism(self) -> Option<SourceMechanism> {
        match self {
            Self::HostRuntimeObservation => Some(SourceMechanism::PidFdAnchored),
            _ => None,
        }
    }

    /// The strongest evidence this class could ever contribute.
    ///
    /// Computed from the mechanism and the anchoring, not tabulated: a class
    /// with an implemented mechanism is capped by its observation class's own
    /// ceiling, and everything else at `Corroborative`.
    pub fn max_ceiling(self) -> EvidenceCeiling {
        match self.mechanism() {
            Some(m) => aip_observation::class_of(m).ceiling(),
            None => EvidenceCeiling::Corroborative,
        }
    }

    /// Whether this class could support a statement about **software
    /// execution** — that a process ran, that a command was sent.
    pub fn can_support_execution(self) -> bool {
        self.mechanism().is_some()
    }

    /// Whether this class could support a statement about **physical effect**.
    ///
    /// **False for all eight**, computed from the class table rather than
    /// written as a literal: it would take a class that is external to the
    /// subject, anchored, and backed by a mechanism in the physical-effect
    /// observation class. No class is all three, because
    /// `ObservationClass::PhysicalEffect` has no mechanism in this build. If
    /// one is ever implemented this returns `true` and the tests below fail,
    /// which is the intended way to find out.
    pub fn can_support_physical_effect(self) -> bool {
        ObservationClass::PhysicalEffect.is_implemented()
            && self.is_external_to_subject()
            && self.is_anchored()
            && self
                .mechanism()
                .is_some_and(|m| aip_observation::class_of(m) == ObservationClass::PhysicalEffect)
    }

    /// Whether naming this class grants any trust.
    ///
    /// `false` for all eight, unconditionally. Trust anchors are the
    /// verifier's, held in `aip-observe` and `aip-authorize`; a validation
    /// adapter that could mint one would be a second custody system.
    pub fn is_trust_anchor(self) -> bool {
        false
    }

    pub fn failure_mode(self) -> &'static str {
        match self {
            Self::SubjectSelfReport => {
                "silence, or a fluent and correctly formatted account of work that is not \
                 happening"
            }
            Self::SubjectControlledRecording => {
                "a faithful recording of a false claim; and a bag the subject could have edited \
                 before anyone read it"
            }
            Self::ControllerAcknowledgement => {
                "an acknowledgement from a controller in a fault state, with a forced output, or \
                 with no load attached"
            }
            Self::SubjectMiddlewareInstrumentation => {
                "trace points emitted by the same process whose behaviour is in question"
            }
            Self::SimulatorGroundTruth => {
                "perfect fidelity to a model that is not the world; and a simulator the same \
                 launch file configured"
            }
            Self::ExternalSensorUnanchored => {
                "a frame injected on an unauthenticated path, from a party the verifier cannot \
                 name"
            }
            Self::ExternalSensorAnchored => {
                "occlusion, a marker that came off, and a calibration nobody re-checked"
            }
            Self::HostRuntimeObservation => {
                "host root forging the measured content; and a foreign program gating the \
                 tracepoint, which is why observer integrity is carried separately"
            }
        }
    }

    /// What a reader must not conclude from this class.
    pub fn must_not_be_read_as(self) -> &'static str {
        match self {
            Self::SubjectSelfReport | Self::SubjectControlledRecording => {
                "evidence that what it describes occurred"
            }
            Self::ControllerAcknowledgement => "evidence that an actuator moved",
            Self::SubjectMiddlewareInstrumentation => {
                "an independent observer, because it runs inside the subject"
            }
            Self::SimulatorGroundTruth => {
                "a fact about the physical world; it is a fact about a model"
            }
            Self::ExternalSensorUnanchored => {
                "independent evidence, because independence without an anchor is nobody observing"
            }
            Self::ExternalSensorAnchored => {
                "proof of physical effect, because no mechanism in this build carries that class"
            }
            Self::HostRuntimeObservation => "evidence about anything outside the host",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_provenance_class_can_support_a_physical_effect_claim() {
        for c in ProvenanceClass::ALL {
            assert!(
                !c.can_support_physical_effect(),
                "{c:?} became able to support a physical-effect claim"
            );
        }
    }

    #[test]
    fn no_provenance_class_is_a_trust_anchor() {
        for c in ProvenanceClass::ALL {
            assert!(!c.is_trust_anchor(), "{c:?}");
        }
    }

    #[test]
    fn robot_telemetry_and_its_recording_are_both_self_reports() {
        for c in [
            ProvenanceClass::SubjectSelfReport,
            ProvenanceClass::SubjectControlledRecording,
        ] {
            assert!(c.subject_controls_source(), "{c:?}");
            assert!(!c.is_external_to_subject(), "{c:?}");
            assert!(!c.can_support_execution(), "{c:?}");
            assert_eq!(c.max_ceiling(), EvidenceCeiling::Corroborative, "{c:?}");
        }
    }

    #[test]
    fn ros2_tracing_is_inside_the_subject() {
        // The one people argue about: LTTng trace points are precise, and they
        // are emitted by the process under scrutiny.
        let c = ProvenanceClass::SubjectMiddlewareInstrumentation;
        assert!(c.subject_controls_source());
        assert!(c.must_not_be_read_as().contains("inside the subject"));
    }

    #[test]
    fn a_controller_acknowledgement_is_not_actuation() {
        let c = ProvenanceClass::ControllerAcknowledgement;
        assert!(c.subject_controls_source());
        assert!(!c.can_support_physical_effect());
        assert_eq!(c.must_not_be_read_as(), "evidence that an actuator moved");
    }

    #[test]
    fn simulator_ground_truth_is_external_and_still_proves_nothing_physical() {
        let c = ProvenanceClass::SimulatorGroundTruth;
        // It is genuinely not controlled by the simulated robot...
        assert!(c.is_external_to_subject());
        // ...and it is not anchored, has no mechanism, and is capped.
        assert!(!c.is_anchored());
        assert!(c.mechanism().is_none());
        assert_eq!(c.max_ceiling(), EvidenceCeiling::Corroborative);
        assert!(!c.can_support_execution());
        assert!(!c.can_support_physical_effect());
        assert!(c.must_not_be_read_as().contains("fact about a model"));
    }

    #[test]
    fn an_external_camera_is_capped_whether_anchored_or_not() {
        for c in [
            ProvenanceClass::ExternalSensorUnanchored,
            ProvenanceClass::ExternalSensorAnchored,
        ] {
            assert!(c.is_external_to_subject(), "{c:?}");
            assert!(c.mechanism().is_none(), "{c:?}");
            assert_eq!(
                c.max_ceiling(),
                EvidenceCeiling::Corroborative,
                "{c:?}: no mechanism in this build carries an optical observation"
            );
            assert!(!c.can_support_execution(), "{c:?}");
        }
        // Anchoring is real and changes something — just not the ceiling.
        assert!(ProvenanceClass::ExternalSensorAnchored.is_anchored());
        assert!(!ProvenanceClass::ExternalSensorUnanchored.is_anchored());
    }

    #[test]
    fn only_the_host_runtime_path_has_a_mechanism() {
        let with: Vec<ProvenanceClass> = ProvenanceClass::ALL
            .iter()
            .copied()
            .filter(|c| c.mechanism().is_some())
            .collect();
        assert_eq!(with, vec![ProvenanceClass::HostRuntimeObservation]);
        assert_eq!(
            ProvenanceClass::HostRuntimeObservation.max_ceiling(),
            EvidenceCeiling::Attested
        );
    }

    #[test]
    fn every_class_states_its_failure_mode_and_its_codes_are_unique() {
        let mut codes: Vec<u8> = ProvenanceClass::ALL.iter().map(|c| c.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), ProvenanceClass::ALL.len());
        for c in ProvenanceClass::ALL {
            assert!(!c.failure_mode().is_empty(), "{c:?}");
            assert!(!c.must_not_be_read_as().is_empty(), "{c:?}");
        }
    }
}
