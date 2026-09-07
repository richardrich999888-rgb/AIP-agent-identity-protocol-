//! Grasping, moving and placing — and the five states between them.
//!
//! # The ladder
//!
//! ```text
//!   command issued      software
//!   actuator moved      a device reported a state
//!   contact made        something was touched
//!   object grasped      the something is an object, and it is held
//!   object relocated    it is somewhere else
//!   task achieved       somewhere else is where it was supposed to be
//! ```
//!
//! A gripper that closes on air, on the wrong object, or on an object it then
//! crushes produces the same wire traffic as one that succeeds. The controller
//! reports a completed motion; the encoder reports an aperture; the force
//! sensor reports a strain. All three are true and none of them is a grasp.
//!
//! # Why `ObjectStateClaim` is separate from the rung
//!
//! The rung is about the robot. The claim is about the object, and the object
//! is a third party to the whole transaction: it has a mass, a shape and a
//! position none of the robot's sensors measure. `ObjectStateClaim` therefore
//! carries its own evidence question, and every variant answers `false` in
//! this build.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::sensing::SensingSource;

/// A statement about an object the robot interacted with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObjectStateClaim {
    /// The gripper touched something.
    Contacted,
    /// The something is held.
    Grasped,
    /// It was lifted clear.
    Lifted,
    /// It is somewhere it was not.
    Relocated,
    /// It is where the task wanted it.
    Placed,
    /// It was let go deliberately.
    Released,
    /// It is undamaged.
    Undamaged,
}

impl ObjectStateClaim {
    pub const ALL: [ObjectStateClaim; 7] = [
        Self::Contacted,
        Self::Grasped,
        Self::Lifted,
        Self::Relocated,
        Self::Placed,
        Self::Released,
        Self::Undamaged,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Contacted => 0x01,
            Self::Grasped => 0x02,
            Self::Lifted => 0x03,
            Self::Relocated => 0x04,
            Self::Placed => 0x05,
            Self::Released => 0x06,
            Self::Undamaged => 0x07,
        }
    }

    /// The claim immediately below this one, which it does not follow from.
    ///
    /// Returned so a report can print the ladder rather than assert it.
    pub fn does_not_follow_from(self) -> Option<ObjectStateClaim> {
        match self {
            Self::Contacted => None,
            Self::Grasped => Some(Self::Contacted),
            Self::Lifted => Some(Self::Grasped),
            Self::Relocated => Some(Self::Lifted),
            Self::Placed => Some(Self::Relocated),
            Self::Released => Some(Self::Grasped),
            Self::Undamaged => None,
        }
    }

    /// What the claim would need.
    pub fn requires(self) -> &'static str {
        match self {
            Self::Contacted => "a measurement that something was touched, not that fingers stopped",
            Self::Grasped => {
                "evidence the fingers stopped on an object rather than on each other, and that it \
                 is the intended object"
            }
            Self::Lifted => "an observation of the object clear of its support",
            Self::Relocated => "an observation of the object at two places at two times",
            Self::Placed => "an observation of the object at the commanded place",
            Self::Released => "an observation the object stayed where it was let go",
            Self::Undamaged => "an inspection of the object, which no robot sensor performs",
        }
    }

    /// Sources that bear on this claim.
    pub fn candidate_sources(self) -> &'static [SensingSource] {
        use SensingSource::*;
        match self {
            Self::Contacted => &[TactileOnboard, ForceTorqueOnboard],
            Self::Grasped => &[ForceTorqueOnboard, EncoderOnboard, CameraOnboard],
            Self::Lifted | Self::Relocated | Self::Placed => &[CameraOnboard, ExternalCamera],
            Self::Released => &[EncoderOnboard, CameraOnboard],
            // Nothing bears on it. That absence is the finding: damage is
            // routinely asserted from the absence of a fault, which is not a
            // measurement of the object at all.
            Self::Undamaged => &[],
        }
    }
}

/// What is known about one object-state claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManipulationEvidence {
    pub claim: ObjectStateClaim,
    /// The robot reported it.
    pub self_reported: bool,
    /// Something outside the robot, through an implemented mechanism, measured
    /// it.
    pub independently_observed: bool,
}

impl ManipulationEvidence {
    pub fn from_sources(claim: ObjectStateClaim, declared: &[SensingSource]) -> Self {
        let relevant: Vec<SensingSource> = claim
            .candidate_sources()
            .iter()
            .copied()
            .filter(|s| declared.contains(s))
            .collect();
        Self {
            claim,
            self_reported: relevant.iter().any(|s| s.is_onboard_subject()),
            independently_observed: relevant
                .iter()
                .any(|s| s.is_independent() && s.can_produce_observation_record()),
        }
    }

    /// Whether the claim may be asserted.
    pub fn establishes(&self) -> bool {
        self.independently_observed
    }

    pub fn ceiling(&self) -> EvidenceCeiling {
        if self.independently_observed {
            EvidenceCeiling::Attested
        } else {
            EvidenceCeiling::Corroborative
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIPULATOR: [SensingSource; 6] = [
        SensingSource::AutonomyRuntimeReport,
        SensingSource::ControllerTelemetry,
        SensingSource::EncoderOnboard,
        SensingSource::ForceTorqueOnboard,
        SensingSource::TactileOnboard,
        SensingSource::CameraOnboard,
    ];

    #[test]
    fn no_object_state_claim_is_established_by_a_fully_sensored_manipulator() {
        for c in ObjectStateClaim::ALL {
            let e = ManipulationEvidence::from_sources(c, &MANIPULATOR);
            assert!(!e.establishes(), "{c:?} was established by onboard sensing");
            assert_eq!(e.ceiling(), EvidenceCeiling::Corroborative, "{c:?}");
        }
    }

    #[test]
    fn a_grasp_does_not_follow_from_contact() {
        assert_eq!(
            ObjectStateClaim::Grasped.does_not_follow_from(),
            Some(ObjectStateClaim::Contacted)
        );
        assert_eq!(
            ObjectStateClaim::Placed.does_not_follow_from(),
            Some(ObjectStateClaim::Relocated)
        );
    }

    #[test]
    fn nothing_bears_on_undamaged_at_all() {
        assert!(ObjectStateClaim::Undamaged.candidate_sources().is_empty());
        let e =
            ManipulationEvidence::from_sources(ObjectStateClaim::Undamaged, &SensingSource::ALL);
        assert!(!e.self_reported, "no source even reports it");
        assert!(!e.establishes());
    }

    #[test]
    fn no_claim_is_established_even_with_every_source_declared() {
        for c in ObjectStateClaim::ALL {
            let e = ManipulationEvidence::from_sources(c, &SensingSource::ALL);
            assert!(!e.establishes(), "{c:?}");
            assert_ne!(e.ceiling(), EvidenceCeiling::Proven, "{c:?}");
        }
    }

    #[test]
    fn the_ladder_is_a_chain_with_two_roots() {
        let roots: Vec<ObjectStateClaim> = ObjectStateClaim::ALL
            .iter()
            .copied()
            .filter(|c| c.does_not_follow_from().is_none())
            .collect();
        assert_eq!(
            roots,
            vec![ObjectStateClaim::Contacted, ObjectStateClaim::Undamaged],
            "contact starts the chain; damage is not on it at all"
        );
        for c in ObjectStateClaim::ALL {
            assert!(!c.requires().is_empty(), "{c:?}");
        }
    }
}
