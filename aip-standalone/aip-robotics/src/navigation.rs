//! Where the robot is, and the five separate questions to ask about it.
//!
//! # Not one confidence number
//!
//! The same argument Skill 23 makes for a UAS, with one addition that matters
//! more on the ground: a robot's localisation is usually an **estimator
//! output**, and an estimator reports a covariance. That covariance is a
//! property of the filter's own model — it is what the filter believes about
//! itself under assumptions nothing checks. A kidnapped robot in a symmetric
//! corridor is confidently, precisely wrong, and the covariance says so in
//! neither direction.
//!
//! So `LocalizationEstimateOnboard` is classified exactly like a wheel
//! encoder: inside the subject, capped at `Corroborative`, establishing
//! nothing about the world.
//!
//! # What this build can answer
//!
//! Nothing. Every pose quantity is unestablished for every realistic robot,
//! computed from the declared sources rather than written as prose — so a
//! deployment that anchors an external tracker with an implemented mechanism
//! gets a different answer with no change to this file.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::sensing::SensingSource;

/// A quantity describing where the robot is or how it is moving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PoseQuantity {
    /// Where the body is, in a stated frame.
    Position,
    /// How the body is oriented.
    Orientation,
    /// Body velocity.
    Velocity,
    /// The integrated path since a reference.
    Odometry,
    /// The path actually taken.
    Trajectory,
    /// Whether the body arrived at a commanded goal.
    GoalArrival,
    /// Whether an obstacle was interacted with.
    ObstacleInteraction,
}

impl PoseQuantity {
    pub const ALL: [PoseQuantity; 7] = [
        Self::Position,
        Self::Orientation,
        Self::Velocity,
        Self::Odometry,
        Self::Trajectory,
        Self::GoalArrival,
        Self::ObstacleInteraction,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Position => 0x01,
            Self::Orientation => 0x02,
            Self::Velocity => 0x03,
            Self::Odometry => 0x04,
            Self::Trajectory => 0x05,
            Self::GoalArrival => 0x06,
            Self::ObstacleInteraction => 0x07,
        }
    }

    /// The sources that bear on this quantity.
    ///
    /// Bearing is not establishing: an onboard SLAM estimate bears on position
    /// and establishes nothing, because it is inside the subject.
    pub fn candidate_sources(self) -> &'static [SensingSource] {
        use SensingSource::*;
        match self {
            Self::Position => &[
                LocalizationEstimateOnboard,
                OdometryOnboard,
                ExternalTracking,
                ExternalCamera,
            ],
            Self::Orientation => &[ImuOnboard, LocalizationEstimateOnboard, ExternalTracking],
            Self::Velocity => &[
                EncoderOnboard,
                ImuOnboard,
                ControllerTelemetry,
                ExternalTracking,
            ],
            Self::Odometry => &[OdometryOnboard, EncoderOnboard],
            Self::Trajectory => &[
                LocalizationEstimateOnboard,
                OdometryOnboard,
                ExternalTracking,
            ],
            Self::GoalArrival => &[
                LocalizationEstimateOnboard,
                AutonomyRuntimeReport,
                ExternalTracking,
            ],
            Self::ObstacleInteraction => &[LidarOnboard, CameraOnboard, ForceTorqueOnboard],
        }
    }
}

/// What is known about one pose quantity, from a declared set of sources.
///
/// Every field is computed by [`Self::from_sources`]. There is no constructor
/// that lets a caller assert `independently_observed` — the field an
/// integrator in a hurry would most want to set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigationEvidence {
    pub quantity: PoseQuantity,
    /// A source inside the subject reported it.
    pub self_reported: bool,
    /// That report carries an intact signature from the subject.
    ///
    /// Carried, never promoted: no method reads it when deciding what was
    /// established.
    pub cryptographically_authenticated: bool,
    /// A party outside the subject measured it, through a mechanism that can
    /// produce an observation record.
    pub independently_observed: bool,
    /// Two or more such parties did.
    pub cross_observed: bool,
    /// An independent physical mechanism measured it. False in this build.
    pub physically_measured: bool,
}

impl NavigationEvidence {
    /// Compute what is known about `quantity` from the sources a deployment
    /// declares.
    pub fn from_sources(
        quantity: PoseQuantity,
        declared: &[SensingSource],
        authenticated: bool,
    ) -> Self {
        let relevant: Vec<SensingSource> = quantity
            .candidate_sources()
            .iter()
            .copied()
            .filter(|s| declared.contains(s))
            .collect();
        let self_reported = relevant.iter().any(|s| s.is_onboard_subject());
        // Outside the subject AND backed by a mechanism. Dropping either half
        // is how an unanchored external tracker, or a signed encoder, gets
        // read as independent evidence.
        let independent: Vec<SensingSource> = relevant
            .iter()
            .copied()
            .filter(|s| s.is_independent() && s.can_produce_observation_record())
            .collect();
        Self {
            quantity,
            self_reported,
            cryptographically_authenticated: authenticated && self_reported,
            independently_observed: !independent.is_empty(),
            cross_observed: independent.len() >= 2,
            physically_measured: independent.iter().any(|s| {
                s.observation_class() == Some(aip_observation::ObservationClass::PhysicalEffect)
            }),
        }
    }

    /// Whether this quantity may be used as a fact about the world.
    ///
    /// Reads `independently_observed` alone. Neither `self_reported` nor
    /// `cryptographically_authenticated` appears, and the omission is the
    /// point.
    pub fn establishes(&self) -> bool {
        self.independently_observed
    }

    /// The strongest evidence this quantity could contribute. Never `Proven`:
    /// no pose quantity is recomputable from bytes a third party holds.
    pub fn ceiling(&self) -> EvidenceCeiling {
        if self.independently_observed {
            EvidenceCeiling::Attested
        } else {
            EvidenceCeiling::Corroborative
        }
    }

    pub fn statement(&self) -> &'static str {
        match (self.independently_observed, self.self_reported) {
            (true, _) => "independently observed; usable as a fact, ceilinged at Attested",
            (false, true) => {
                "self-reported only; establishes that the robot's own estimator said so, and \
                 nothing about the world, however it is signed"
            }
            (false, false) => "no source bears on this quantity in this deployment",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-equipped mobile robot. Every onboard sensor, nothing external.
    const ROBOT: [SensingSource; 9] = [
        SensingSource::AutonomyRuntimeReport,
        SensingSource::ControllerTelemetry,
        SensingSource::EncoderOnboard,
        SensingSource::OdometryOnboard,
        SensingSource::ImuOnboard,
        SensingSource::LidarOnboard,
        SensingSource::CameraOnboard,
        SensingSource::LocalizationEstimateOnboard,
        SensingSource::ForceTorqueOnboard,
    ];

    #[test]
    fn no_pose_quantity_is_established_by_a_fully_equipped_robot() {
        for q in PoseQuantity::ALL {
            let e = NavigationEvidence::from_sources(q, &ROBOT, true);
            assert!(!e.establishes(), "{q:?} was established by onboard sensors");
            assert_eq!(e.ceiling(), EvidenceCeiling::Corroborative, "{q:?}");
        }
    }

    #[test]
    fn odometry_is_not_ground_truth() {
        let e = NavigationEvidence::from_sources(
            PoseQuantity::Odometry,
            &[SensingSource::OdometryOnboard],
            true,
        );
        assert!(e.self_reported);
        assert!(!e.establishes());
    }

    #[test]
    fn slam_is_not_ground_truth() {
        let e = NavigationEvidence::from_sources(
            PoseQuantity::Position,
            &[SensingSource::LocalizationEstimateOnboard],
            true,
        );
        assert!(
            !e.establishes(),
            "an estimator's confidence is an output of its own model"
        );
    }

    #[test]
    fn signing_the_estimate_changes_nothing_about_what_is_established() {
        for q in PoseQuantity::ALL {
            let signed = NavigationEvidence::from_sources(q, &ROBOT, true);
            let unsigned = NavigationEvidence::from_sources(q, &ROBOT, false);
            assert_eq!(signed.establishes(), unsigned.establishes(), "{q:?}");
            assert_eq!(signed.ceiling(), unsigned.ceiling(), "{q:?}");
        }
    }

    #[test]
    fn an_unanchored_external_tracker_does_not_establish_a_pose_either() {
        let e = NavigationEvidence::from_sources(
            PoseQuantity::Position,
            &[SensingSource::ExternalTracking],
            false,
        );
        assert!(
            !e.establishes(),
            "positional independence without an implemented mechanism is nobody observing"
        );
    }

    #[test]
    fn no_quantity_reaches_proven_under_any_declared_source_set() {
        for q in PoseQuantity::ALL {
            let e = NavigationEvidence::from_sources(q, &SensingSource::ALL, true);
            assert_ne!(e.ceiling(), EvidenceCeiling::Proven, "{q:?}");
            assert!(!e.physically_measured, "{q:?}");
        }
    }

    #[test]
    fn goal_arrival_is_not_established_by_the_estimator_that_was_asked() {
        let e = NavigationEvidence::from_sources(
            PoseQuantity::GoalArrival,
            &[
                SensingSource::LocalizationEstimateOnboard,
                SensingSource::AutonomyRuntimeReport,
            ],
            true,
        );
        assert!(
            !e.establishes(),
            "asking the navigator whether it arrived is asking the thing under scrutiny"
        );
    }
}
