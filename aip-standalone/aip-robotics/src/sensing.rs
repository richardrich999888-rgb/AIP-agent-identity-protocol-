//! Where a robot's reports come from, and what each source is worth.
//!
//! # The question, again
//!
//! Not "is this sensor accurate?" — accuracy is a specification and this layer
//! has no way to check one. The question is: **is the party producing this
//! report inside the thing being judged?**
//!
//! A wheel encoder reporting rotation is the robot reporting. A force sensor
//! reporting contact is the robot reporting. Both are excellent engineering and
//! neither is independent evidence, because a compromised autonomy stack, a
//! compromised controller, or an attacker on the robot's internal bus writes
//! all of them. The industry's habit of calling onboard sensor data "ground
//! truth" is the failure this taxonomy exists to prevent.
//!
//! # Six facts per source
//!
//! The treatment Skills 22 and 23 established: what it observes, what it
//! establishes, what it does not establish, its trust basis, its failure mode,
//! and its evidence ceiling. Methods rather than a comment table, so a source
//! added later cannot silently lack one.
//!
//! # The mechanism column is load-bearing
//!
//! [`SensingSource::mechanism`] returns `Some` for exactly two sources — the
//! companion computer's process and network observation, both real Linux
//! facilities an anchored collector already attests. The other twelve return
//! `None`, so [`SensingSource::can_produce_observation_record`] is false for
//! them. Not as policy: `ObservationRecord::from_attested` has no input it
//! could be given.

use aip_observation::{EvidenceCeiling, ObservationClass};
use aip_observe::SourceMechanism;
use serde::{Deserialize, Serialize};

/// A source of reports about a robot or its surroundings.
///
/// Closed on purpose, like `ObservationClass` and `SourceMechanism`. An open
/// vocabulary could not carry a trust basis, and two deployments would spell
/// the same source differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SensingSource {
    /// The autonomy stack's account of its own decisions and task state.
    AutonomyRuntimeReport,
    /// The motion or motor controller's telemetry: commanded and reported
    /// joint or wheel state, faults, mode.
    ControllerTelemetry,
    /// Joint or wheel encoders aboard the robot.
    EncoderOnboard,
    /// Wheel or joint odometry computed aboard the robot.
    OdometryOnboard,
    /// An inertial measurement unit aboard the robot.
    ImuOnboard,
    /// A force or torque sensor aboard the robot.
    ForceTorqueOnboard,
    /// A tactile or contact sensor aboard the robot.
    TactileOnboard,
    /// A camera aboard the robot, including a depth or stereo pair.
    CameraOnboard,
    /// A lidar or scanning rangefinder aboard the robot.
    LidarOnboard,
    /// A localisation estimate computed aboard the robot — SLAM, a particle
    /// filter, a fused pose.
    LocalizationEstimateOnboard,
    /// A camera or depth sensor mounted in the workspace, not on the robot.
    ExternalCamera,
    /// An external tracking system: motion capture, a survey total station, a
    /// UWB or laser tracker.
    ExternalTracking,
    /// An anchored observer measuring the companion computer's **process**:
    /// which autonomy binary ran, as which instance, on which boot.
    CompanionProcessObservation,
    /// An anchored observer measuring the companion computer's **sockets**:
    /// that a link to a named endpoint existed at a sampled moment.
    CompanionNetworkObservation,
}

impl SensingSource {
    pub const ALL: [SensingSource; 14] = [
        Self::AutonomyRuntimeReport,
        Self::ControllerTelemetry,
        Self::EncoderOnboard,
        Self::OdometryOnboard,
        Self::ImuOnboard,
        Self::ForceTorqueOnboard,
        Self::TactileOnboard,
        Self::CameraOnboard,
        Self::LidarOnboard,
        Self::LocalizationEstimateOnboard,
        Self::ExternalCamera,
        Self::ExternalTracking,
        Self::CompanionProcessObservation,
        Self::CompanionNetworkObservation,
    ];

    /// Stable wire code, assigned explicitly so reordering cannot change what
    /// previously encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::AutonomyRuntimeReport => 0x01,
            Self::ControllerTelemetry => 0x02,
            Self::EncoderOnboard => 0x03,
            Self::OdometryOnboard => 0x04,
            Self::ImuOnboard => 0x05,
            Self::ForceTorqueOnboard => 0x06,
            Self::TactileOnboard => 0x07,
            Self::CameraOnboard => 0x08,
            Self::LidarOnboard => 0x09,
            Self::LocalizationEstimateOnboard => 0x0A,
            Self::ExternalCamera => 0x0B,
            Self::ExternalTracking => 0x0C,
            Self::CompanionProcessObservation => 0x0D,
            Self::CompanionNetworkObservation => 0x0E,
        }
    }

    /// Whether the source sits **inside** the system being judged.
    ///
    /// Ten of fourteen. Note that an onboard camera is onboard: a picture taken
    /// by the robot, of the robot's own workspace, delivered through the
    /// robot's own software, is the robot's account of its surroundings.
    pub fn is_onboard_subject(self) -> bool {
        matches!(
            self,
            Self::AutonomyRuntimeReport
                | Self::ControllerTelemetry
                | Self::EncoderOnboard
                | Self::OdometryOnboard
                | Self::ImuOnboard
                | Self::ForceTorqueOnboard
                | Self::TactileOnboard
                | Self::CameraOnboard
                | Self::LidarOnboard
                | Self::LocalizationEstimateOnboard
        )
    }

    /// Whether this source is outside the subject.
    ///
    /// Positional independence only. It does not mean the report is verified:
    /// an independent source still has to be anchored, and being named is not
    /// being trusted.
    pub fn is_independent(self) -> bool {
        !self.is_onboard_subject()
    }

    /// The Linux mechanism backing this source, when one exists.
    ///
    /// `Some` for two sources. Adding a variant to `SourceMechanism` for an
    /// encoder or a force sensor would put a device-specific value into signed
    /// bytes every verifier must understand — the schema fork ADR-003 exists
    /// to prevent, and the reason ADR-005 refused the same move for avionics.
    pub fn mechanism(self) -> Option<SourceMechanism> {
        match self {
            Self::CompanionProcessObservation => Some(SourceMechanism::PidFdAnchored),
            Self::CompanionNetworkObservation => Some(SourceMechanism::ProcNetTable),
            _ => None,
        }
    }

    /// Whether an `ObservationRecord` can be built from this source at all.
    pub fn can_produce_observation_record(self) -> bool {
        self.mechanism().is_some()
    }

    /// The observation class this source would belong to, when a mechanism
    /// exists to produce it. `None` wherever `mechanism()` is `None`: a class
    /// without a mechanism is a claim.
    pub fn observation_class(self) -> Option<ObservationClass> {
        self.mechanism().map(aip_observation::class_of)
    }

    pub fn observes(self) -> &'static str {
        match self {
            Self::AutonomyRuntimeReport => "the autonomy stack's account of its own decisions",
            Self::ControllerTelemetry => "commanded and reported joint or wheel state, and faults",
            Self::EncoderOnboard => "shaft or joint angle at the encoder",
            Self::OdometryOnboard => "an integrated pose derived from wheel or joint motion",
            Self::ImuOnboard => "accelerations and angular rates at the sensor",
            Self::ForceTorqueOnboard => "strain at the sensing element",
            Self::TactileOnboard => "a switch closure or a pressure at a pad",
            Self::CameraOnboard => "light reaching a sensor mounted on the robot",
            Self::LidarOnboard => "ranges to surfaces from a scanner mounted on the robot",
            Self::LocalizationEstimateOnboard => "the output of an estimator running on the robot",
            Self::ExternalCamera => "light reaching a sensor mounted in the workspace",
            Self::ExternalTracking => "the position of a marker or target, from outside the robot",
            Self::CompanionProcessObservation => {
                "a process instance on the companion computer and its executable content"
            }
            Self::CompanionNetworkObservation => {
                "a socket owned by that instance, and the endpoint it reached at a sample"
            }
        }
    }

    pub fn establishes(self) -> &'static str {
        match self {
            Self::AutonomyRuntimeReport | Self::ControllerTelemetry => {
                "that the subject said so, and — if signed — that it is the subject that said it"
            }
            Self::EncoderOnboard
            | Self::OdometryOnboard
            | Self::ImuOnboard
            | Self::ForceTorqueOnboard
            | Self::TactileOnboard
            | Self::CameraOnboard
            | Self::LidarOnboard
            | Self::LocalizationEstimateOnboard => {
                "what a device inside the subject reported; the subject's own account of itself \
                 and its surroundings"
            }
            Self::ExternalCamera | Self::ExternalTracking => {
                "that a sensor outside the subject registered something, if the deployment \
                 anchored it — which this build has no mechanism to do"
            }
            Self::CompanionProcessObservation => {
                "that one process instance, running measured executable content, existed on a \
                 measured host-boot"
            }
            Self::CompanionNetworkObservation => {
                "that the instance held a socket to a named endpoint at the moment of the sample"
            }
        }
    }

    pub fn does_not_establish(self) -> &'static str {
        match self {
            Self::AutonomyRuntimeReport => "that anything it describes occurred",
            Self::ControllerTelemetry => {
                "that a joint moved, that a wheel turned, or that the robot did anything"
            }
            Self::EncoderOnboard => {
                "that the load moved: a shaft turns with a slipped belt, a stripped gear or a \
                 wheel off the ground"
            }
            Self::OdometryOnboard => {
                "a true pose: it integrates encoder counts, so slip, skid and drift accumulate \
                 without bound and are invisible to it"
            }
            Self::ImuOnboard => "an absolute pose: it integrates, so it drifts",
            Self::ForceTorqueOnboard => {
                "what was contacted, whether it was an object, or whether a grasp succeeded"
            }
            Self::TactileOnboard => "what touched the pad, or that anything was held",
            Self::CameraOnboard => {
                "what an object is, that a detection is a human, or that a scene is as labelled"
            }
            Self::LidarOnboard => "what a returning surface belongs to",
            Self::LocalizationEstimateOnboard => {
                "a true pose: an estimator's confidence is an output of its own model and not \
                 evidence about the world"
            }
            Self::ExternalCamera => "what an object is, absent a claim the sensor cannot make",
            Self::ExternalTracking => {
                "that the tracked marker is still attached to the robot, or that the robot's \
                 body followed it"
            }
            Self::CompanionProcessObservation => {
                "what the process did, any command it issued, or any physical effect"
            }
            Self::CompanionNetworkObservation => {
                "what the bytes were, that they arrived, or that a controller acted on them"
            }
        }
    }

    pub fn trust_basis(self) -> &'static str {
        match self {
            s if s.is_onboard_subject() => {
                "the subject itself, and everything with access to its internal buses: the party \
                 under scrutiny"
            }
            Self::ExternalCamera | Self::ExternalTracking => {
                "an operator-anchored external party; the verifier's trust model, not an \
                 improvement on it — and unanchored in this build"
            }
            Self::CompanionProcessObservation | Self::CompanionNetworkObservation => {
                "the companion computer's kernel for the measurement, and an off-host anchored \
                 collector for the attestation; host root forges the content"
            }
            // Unreachable: the first arm covers every onboard variant. Written
            // as a match rather than a fallback string so a new source has to
            // be classified.
            _ => "unclassified",
        }
    }

    pub fn failure_mode(self) -> &'static str {
        match self {
            Self::AutonomyRuntimeReport | Self::ControllerTelemetry => {
                "silence, or a fluent and correctly signed account of work that is not happening"
            }
            Self::EncoderOnboard => "a count that continues while the load does not move",
            Self::OdometryOnboard => "unbounded drift under slip, presented as a precise pose",
            Self::ImuOnboard => "drift, saturation, or a stuck output that looks calm",
            Self::ForceTorqueOnboard => "thermal drift and a zero that moves during the task",
            Self::TactileOnboard => "a latched switch, or contact outside the pad",
            Self::CameraOnboard | Self::ExternalCamera => {
                "occlusion, exposure, and a classifier that is confidently wrong"
            }
            Self::LidarOnboard => "reflective and transparent surfaces returning nothing",
            Self::LocalizationEstimateOnboard => {
                "divergence after a kidnap or a symmetric environment, reported with high \
                 confidence"
            }
            Self::ExternalTracking => "loss of line of sight, or a marker that came off",
            Self::CompanionProcessObservation => {
                "the instance ends between reads and the measurement is discarded rather than \
                 weakened"
            }
            Self::CompanionNetworkObservation => {
                "a socket opened and closed between samples is simply absent"
            }
        }
    }

    /// The strongest evidence this source could ever contribute.
    ///
    /// Nothing reaches `Proven`: that ceiling is for facts a third party
    /// recomputes from bytes it holds, and no sensor reading is recomputable —
    /// only re-checkable for who signed it.
    ///
    /// Onboard sources are capped at `Corroborative`, not `Attested`, for the
    /// reason ADR-005 gives: `Attested` means *an anchored observer measured
    /// this*, and no anchored observer measured anything the subject reported
    /// about itself.
    pub fn ceiling(self) -> EvidenceCeiling {
        match self {
            Self::CompanionProcessObservation | Self::CompanionNetworkObservation => {
                EvidenceCeiling::Attested
            }
            // Everything else: onboard, or outside the subject with no
            // implemented mechanism behind it. Both contribute corroboration
            // and no more.
            _ => EvidenceCeiling::Corroborative,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_two_sources_can_produce_an_observation_record() {
        let backed: Vec<SensingSource> = SensingSource::ALL
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect();
        assert_eq!(
            backed,
            vec![
                SensingSource::CompanionProcessObservation,
                SensingSource::CompanionNetworkObservation
            ]
        );
    }

    #[test]
    fn no_robot_sensor_has_a_mechanism() {
        for s in [
            SensingSource::EncoderOnboard,
            SensingSource::OdometryOnboard,
            SensingSource::ForceTorqueOnboard,
            SensingSource::TactileOnboard,
            SensingSource::LidarOnboard,
            SensingSource::CameraOnboard,
            SensingSource::LocalizationEstimateOnboard,
            SensingSource::ControllerTelemetry,
        ] {
            assert!(s.mechanism().is_none(), "{s:?}");
            assert!(s.observation_class().is_none(), "{s:?}");
            assert!(!s.can_produce_observation_record(), "{s:?}");
        }
    }

    #[test]
    fn an_onboard_camera_is_onboard() {
        // The one people argue about: a picture the robot took, of the robot's
        // workspace, delivered through the robot's software.
        assert!(SensingSource::CameraOnboard.is_onboard_subject());
        assert!(SensingSource::LidarOnboard.is_onboard_subject());
        assert!(SensingSource::ExternalCamera.is_independent());
    }

    #[test]
    fn no_source_reaches_proven() {
        for s in SensingSource::ALL {
            assert_ne!(s.ceiling(), EvidenceCeiling::Proven, "{s:?}");
        }
    }

    #[test]
    fn every_onboard_source_is_capped_at_corroborative() {
        for s in SensingSource::ALL
            .iter()
            .copied()
            .filter(|s| s.is_onboard_subject())
        {
            assert_eq!(s.ceiling(), EvidenceCeiling::Corroborative, "{s:?}");
        }
    }

    #[test]
    fn an_independent_source_with_no_mechanism_is_also_capped() {
        for s in [
            SensingSource::ExternalCamera,
            SensingSource::ExternalTracking,
        ] {
            assert!(s.is_independent(), "{s:?}");
            assert_eq!(
                s.ceiling(),
                EvidenceCeiling::Corroborative,
                "{s:?}: independence without an implemented mechanism is nobody observing"
            );
        }
    }

    #[test]
    fn no_source_claims_the_physical_effect_class() {
        for s in SensingSource::ALL {
            assert_ne!(
                s.observation_class(),
                Some(ObservationClass::PhysicalEffect),
                "{s:?}"
            );
        }
    }

    #[test]
    fn wire_codes_are_unique_and_pinned() {
        let mut codes: Vec<u8> = SensingSource::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), SensingSource::ALL.len());
        assert_eq!(SensingSource::AutonomyRuntimeReport.code(), 0x01);
        assert_eq!(SensingSource::CompanionNetworkObservation.code(), 0x0E);
    }

    #[test]
    fn every_source_answers_all_six_questions() {
        for s in SensingSource::ALL {
            for text in [
                s.observes(),
                s.establishes(),
                s.does_not_establish(),
                s.trust_basis(),
                s.failure_mode(),
            ] {
                assert!(!text.is_empty(), "{s:?} left a column blank");
            }
            assert_ne!(
                s.trust_basis(),
                "unclassified",
                "{s:?} fell through the trust-basis match"
            );
        }
    }
}
