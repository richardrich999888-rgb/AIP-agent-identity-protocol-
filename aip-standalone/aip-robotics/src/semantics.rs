//! The gap between what a transducer measured and what people say it means.
//!
//! # Why this module exists
//!
//! Robotics evidence is routinely reported in language that outruns it, and
//! the gap is not academic — it is where people get hurt.
//!
//! | measured | commonly said |
//! |---|---|
//! | a range sensor returned 1.0 m | safe separation was achieved |
//! | a motion field changed | a human is present |
//! | a joint current spiked | a collision occurred |
//! | a gripper aperture stopped closing | the object was grasped |
//! | wheel encoders counted 2.1 m | the robot travelled 2.1 m |
//!
//! Every left-hand column is a fact about a device. Every right-hand column is
//! a claim about the world, and each requires something the measurement does
//! not contain: a classification, a geometry, a model of what was supposed to
//! happen, or all three.
//!
//! # What this module does and does not do
//!
//! It does **not** decide whether a claim is true — nothing here reads a
//! sensor. It holds the gap open: each measurement names what it measures,
//! what it actually establishes, and the claim it is commonly mistaken for.
//! Each claim names what it would need.
//!
//! [`SemanticClaim::establishable_from_measurement`] is `false` for every
//! claim in this build, and it is computed from the class table rather than
//! written as a literal — so implementing a physical mechanism has to change
//! the table and fail this module's tests rather than leave a stale `false`
//! behind.
//!
//! # The human-presence case, specifically
//!
//! `SemanticClaim::HumanPresent` is the one worth calling out. No sensor here
//! detects a human. A camera detects light, a lidar detects returns, a
//! proximity sensor detects a field change; a *classifier* labels one of those
//! "person", and the label is a model output, not a measurement. A safety
//! argument that rests on it rests on the classifier's error rate under
//! conditions nobody characterised. This profile records the measurement and
//! refuses the label.

use serde::{Deserialize, Serialize};

use crate::sensing::SensingSource;

/// A physical quantity a transducer on or around a robot actually produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Measurement {
    /// A range to the nearest returning surface, along one ray.
    RangeReading,
    /// A change in a proximity or motion field.
    ProximityFieldChange,
    /// A switch closure or pad pressure.
    ContactSwitchClosure,
    /// A strain magnitude at a force or torque sensing element.
    ForceMagnitude,
    /// A current or torque command acknowledged by a drive.
    DriveCurrent,
    /// A shaft or joint angle at an encoder.
    ShaftAngle,
    /// A gripper's commanded-to-measured aperture.
    GripperAperture,
    /// Pixels. Light that reached a sensor.
    ImageFrame,
    /// An estimator's pose output.
    PoseEstimate,
    /// An integrated distance from wheel or joint counts.
    IntegratedOdometry,
}

impl Measurement {
    pub const ALL: [Measurement; 10] = [
        Self::RangeReading,
        Self::ProximityFieldChange,
        Self::ContactSwitchClosure,
        Self::ForceMagnitude,
        Self::DriveCurrent,
        Self::ShaftAngle,
        Self::GripperAperture,
        Self::ImageFrame,
        Self::PoseEstimate,
        Self::IntegratedOdometry,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::RangeReading => 0x01,
            Self::ProximityFieldChange => 0x02,
            Self::ContactSwitchClosure => 0x03,
            Self::ForceMagnitude => 0x04,
            Self::DriveCurrent => 0x05,
            Self::ShaftAngle => 0x06,
            Self::GripperAperture => 0x07,
            Self::ImageFrame => 0x08,
            Self::PoseEstimate => 0x09,
            Self::IntegratedOdometry => 0x0A,
        }
    }

    /// What the transducer produces.
    pub fn measures(self) -> &'static str {
        match self {
            Self::RangeReading => "a distance to the nearest returning surface along one ray",
            Self::ProximityFieldChange => "a change in a capacitive, infrared or radar field",
            Self::ContactSwitchClosure => "that a switch closed or a pad was pressed",
            Self::ForceMagnitude => "strain at the sensing element, in the sensor's own frame",
            Self::DriveCurrent => "a current a drive reports having been commanded",
            Self::ShaftAngle => "an angle at the encoder, upstream of the load",
            Self::GripperAperture => "the separation between two fingers",
            Self::ImageFrame => "light that reached a sensor during an exposure",
            Self::PoseEstimate => "the output of a filter running on the robot",
            Self::IntegratedOdometry => "a sum of encoder counts scaled by an assumed geometry",
        }
    }

    /// What it actually establishes, stated narrowly.
    pub fn actually_establishes(self) -> &'static str {
        match self {
            Self::RangeReading => "that something returned energy at that range, on that ray",
            Self::ProximityFieldChange => "that the field changed",
            Self::ContactSwitchClosure => "that the switch closed",
            Self::ForceMagnitude => "that the element was strained",
            Self::DriveCurrent => "that a drive reported a command; not that torque was produced",
            Self::ShaftAngle => "that the shaft turned; nothing downstream of the transmission",
            Self::GripperAperture => "how far apart the fingers are",
            Self::ImageFrame => "that light arrived; nothing about what it came from",
            Self::PoseEstimate => "what the estimator computed, under its own assumptions",
            Self::IntegratedOdometry => {
                "the sum, under an assumption of no slip that nothing checks"
            }
        }
    }

    /// The claim this measurement is commonly read as establishing.
    ///
    /// Naming the mistake explicitly, per measurement, so it can be tested
    /// against rather than warned about.
    pub fn commonly_read_as(self) -> SemanticClaim {
        match self {
            Self::RangeReading => SemanticClaim::SafeSeparationAchieved,
            Self::ProximityFieldChange => SemanticClaim::HumanPresent,
            Self::ContactSwitchClosure | Self::GripperAperture => SemanticClaim::ObjectGrasped,
            Self::ForceMagnitude => SemanticClaim::CollisionOccurred,
            Self::DriveCurrent | Self::ShaftAngle => SemanticClaim::RobotMoved,
            Self::ImageFrame => SemanticClaim::ObjectIdentified,
            Self::PoseEstimate | Self::IntegratedOdometry => SemanticClaim::GoalReached,
        }
    }

    /// The sources that produce this measurement.
    pub fn produced_by(self) -> &'static [SensingSource] {
        match self {
            Self::RangeReading => &[SensingSource::LidarOnboard, SensingSource::CameraOnboard],
            Self::ProximityFieldChange => &[SensingSource::TactileOnboard],
            Self::ContactSwitchClosure => &[SensingSource::TactileOnboard],
            Self::ForceMagnitude => &[SensingSource::ForceTorqueOnboard],
            Self::DriveCurrent => &[SensingSource::ControllerTelemetry],
            Self::ShaftAngle => &[SensingSource::EncoderOnboard],
            Self::GripperAperture => &[
                SensingSource::EncoderOnboard,
                SensingSource::ControllerTelemetry,
            ],
            Self::ImageFrame => &[SensingSource::CameraOnboard, SensingSource::ExternalCamera],
            Self::PoseEstimate => &[SensingSource::LocalizationEstimateOnboard],
            Self::IntegratedOdometry => &[SensingSource::OdometryOnboard],
        }
    }
}

/// A statement about the world that someone wants to make from a measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SemanticClaim {
    /// Something is at a place.
    ObjectPresent,
    /// The something is a particular thing.
    ObjectIdentified,
    /// The something is a person.
    HumanPresent,
    /// The distance kept was sufficient for safety.
    SafeSeparationAchieved,
    /// A collision happened.
    CollisionOccurred,
    /// The collision caused damage.
    DamageOccurred,
    /// An object is held.
    ObjectGrasped,
    /// The robot's body moved.
    RobotMoved,
    /// The robot's body arrived where it was going.
    GoalReached,
}

impl SemanticClaim {
    pub const ALL: [SemanticClaim; 9] = [
        Self::ObjectPresent,
        Self::ObjectIdentified,
        Self::HumanPresent,
        Self::SafeSeparationAchieved,
        Self::CollisionOccurred,
        Self::DamageOccurred,
        Self::ObjectGrasped,
        Self::RobotMoved,
        Self::GoalReached,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::ObjectPresent => 0x01,
            Self::ObjectIdentified => 0x02,
            Self::HumanPresent => 0x03,
            Self::SafeSeparationAchieved => 0x04,
            Self::CollisionOccurred => 0x05,
            Self::DamageOccurred => 0x06,
            Self::ObjectGrasped => 0x07,
            Self::RobotMoved => 0x08,
            Self::GoalReached => 0x09,
        }
    }

    /// What the claim needs beyond any measurement, in one line.
    pub fn requires_beyond_measurement(self) -> &'static str {
        match self {
            Self::ObjectPresent => "a rule mapping a return to an object rather than to noise",
            Self::ObjectIdentified => {
                "a classifier, whose output is a model result and not a reading"
            }
            Self::HumanPresent => {
                "a classifier asserting a category no transducer measures; a field change is not \
                 a person"
            }
            Self::SafeSeparationAchieved => {
                "a geometry over the whole body and the whole interval, not a range along one ray \
                 at one instant"
            }
            Self::CollisionOccurred => {
                "a model distinguishing an impact from an expected contact, a payload change or a \
                 thermal drift"
            }
            Self::DamageOccurred => "an inspection of the thing that was struck",
            Self::ObjectGrasped => {
                "evidence that the fingers stopped on an object rather than on each other, and \
                 that it is the intended object"
            }
            Self::RobotMoved => "a measurement downstream of the transmission, not upstream of it",
            Self::GoalReached => {
                "an external fix: an estimator that says it arrived is the thing being asked"
            }
        }
    }

    /// Whether any measurement in this build establishes this claim.
    ///
    /// `false` for all nine, computed rather than asserted: a claim is
    /// establishable only if some source producing a bearing measurement is
    /// both independent of the subject and backed by an implemented mechanism.
    /// No robot sensor is, so the conjunction is empty — and if a future build
    /// implements one, this returns `true` and the tests below fail, which is
    /// the intended way to find out.
    pub fn establishable_from_measurement(self) -> bool {
        Measurement::ALL
            .iter()
            .filter(|m| m.commonly_read_as() == self)
            .flat_map(|m| m.produced_by())
            .any(|s| s.is_independent() && s.can_produce_observation_record())
    }

    /// The measurements people reach for when making this claim.
    pub fn commonly_argued_from(self) -> Vec<Measurement> {
        Measurement::ALL
            .iter()
            .copied()
            .filter(|m| m.commonly_read_as() == self)
            .collect()
    }
}

/// How a measurement relates to a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimSupport {
    /// The measurement establishes the claim. Unreachable in this build.
    Establishes,
    /// The measurement bears on the claim without establishing it — the
    /// honest answer for every pairing people actually use.
    Bears,
    /// The measurement has nothing to do with the claim.
    Unrelated,
}

impl ClaimSupport {
    /// Whether this support permits asserting the claim.
    ///
    /// True for `Establishes` alone. `Bears` is deliberately not a weak yes.
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
pub fn support_for(measurement: Measurement, claim: SemanticClaim) -> ClaimSupport {
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
    fn no_semantic_claim_is_establishable_from_measurement_in_this_build() {
        for c in SemanticClaim::ALL {
            assert!(
                !c.establishable_from_measurement(),
                "{c:?} became establishable; no robot sensor is both independent and mechanised"
            );
        }
    }

    #[test]
    fn a_range_reading_does_not_establish_safe_separation() {
        assert_eq!(
            support_for(
                Measurement::RangeReading,
                SemanticClaim::SafeSeparationAchieved
            ),
            ClaimSupport::Bears
        );
        assert!(!support_for(
            Measurement::RangeReading,
            SemanticClaim::SafeSeparationAchieved
        )
        .permits_assertion());
    }

    #[test]
    fn a_field_change_does_not_establish_a_human() {
        assert_eq!(
            support_for(
                Measurement::ProximityFieldChange,
                SemanticClaim::HumanPresent
            ),
            ClaimSupport::Bears
        );
        assert!(
            SemanticClaim::HumanPresent
                .requires_beyond_measurement()
                .contains("classifier"),
            "the human-presence claim must name the classifier it depends on"
        );
    }

    #[test]
    fn a_gripper_aperture_does_not_establish_a_grasp() {
        for m in [
            Measurement::GripperAperture,
            Measurement::ContactSwitchClosure,
        ] {
            assert_eq!(m.commonly_read_as(), SemanticClaim::ObjectGrasped);
            assert_eq!(
                support_for(m, SemanticClaim::ObjectGrasped),
                ClaimSupport::Bears
            );
        }
    }

    #[test]
    fn an_encoder_does_not_establish_that_the_robot_moved() {
        assert_eq!(
            Measurement::ShaftAngle.commonly_read_as(),
            SemanticClaim::RobotMoved
        );
        assert_eq!(
            support_for(Measurement::ShaftAngle, SemanticClaim::RobotMoved),
            ClaimSupport::Bears
        );
        assert!(
            Measurement::ShaftAngle
                .actually_establishes()
                .contains("downstream of the transmission"),
            "the encoder's limit is that it sees nothing past the gearbox"
        );
    }

    #[test]
    fn a_force_reading_does_not_establish_a_collision_and_a_collision_is_not_damage() {
        assert_eq!(
            support_for(
                Measurement::ForceMagnitude,
                SemanticClaim::CollisionOccurred
            ),
            ClaimSupport::Bears
        );
        // And nothing bears on damage at all: no measurement is commonly read
        // as it, which is itself the finding — damage is asserted from a
        // collision claim that was itself asserted from a strain reading.
        assert!(SemanticClaim::DamageOccurred
            .commonly_argued_from()
            .is_empty());
        assert!(!SemanticClaim::DamageOccurred.establishable_from_measurement());
    }

    #[test]
    fn an_unrelated_pairing_is_unrelated_rather_than_weakly_supporting() {
        assert_eq!(
            support_for(Measurement::ImageFrame, SemanticClaim::ObjectGrasped),
            ClaimSupport::Unrelated
        );
    }

    #[test]
    fn every_measurement_and_claim_states_its_limits() {
        for m in Measurement::ALL {
            assert!(!m.measures().is_empty(), "{m:?}");
            assert!(!m.actually_establishes().is_empty(), "{m:?}");
            assert!(!m.produced_by().is_empty(), "{m:?}");
        }
        for c in SemanticClaim::ALL {
            assert!(!c.requires_beyond_measurement().is_empty(), "{c:?}");
        }
    }

    #[test]
    fn wire_codes_are_unique() {
        let mut m: Vec<u8> = Measurement::ALL.iter().map(|x| x.code()).collect();
        m.sort_unstable();
        m.dedup();
        assert_eq!(m.len(), Measurement::ALL.len());
        let mut c: Vec<u8> = SemanticClaim::ALL.iter().map(|x| x.code()).collect();
        c.sort_unstable();
        c.dedup();
        assert_eq!(c.len(), SemanticClaim::ALL.len());
    }
}
