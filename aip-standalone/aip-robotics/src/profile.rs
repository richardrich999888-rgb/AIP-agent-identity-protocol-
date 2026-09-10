//! The robotics profile document and its projections.
//!
//! Fills `ProfileKind::Environment`, the slot Skill 17 reserved for verticals.
//! A `ProfileRef` is a `(kind, id, digest)` commitment: the core names which
//! profile applied and pins its bytes without knowing what is in it.
//!
//! # Projections narrow, never widen
//!
//! [`RoboticsProfile::observation_profile`] projects **only** the sensing
//! sources backed by an implemented mechanism. A lidar is dropped, not
//! downgraded — which is what lets the resulting `ObservationProfile` say
//! `NotObservable` ("this deployment cannot look") rather than `NotObserved`
//! ("it looked and saw nothing"). `with_mechanism` derives the class and takes
//! the class's own ceiling, so the projection cannot inflate.

use aip_crypto::sha256;
use aip_observation::{ObservationClass, ObservationProfile};
use aip_system::{ProfileKind, ProfileRef};
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u8};
use serde::{Deserialize, Serialize};

use crate::embodiment::{EmbodiedChain, EmbodiedRung};
use crate::error::RoboticsError;
use crate::manipulation::{ManipulationEvidence, ObjectStateClaim};
use crate::navigation::{NavigationEvidence, PoseQuantity};
use crate::sensing::SensingSource;
use crate::{ROBOTICS_PROFILE_DOMAIN, ROBOTICS_PROFILE_VERSION};

/// The profile id this crate commits under.
///
/// A constant rather than a caller-supplied string: two deployments running
/// this build are running the same profile, and letting each name it
/// differently would make the `ProfileRef` id useless as a join key.
pub const ROBOTICS_PROFILE_ID: &str = "vanian.robotics.v1";

/// What a robotics deployment declares about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoboticsProfile {
    pub version: u16,
    observer_id: String,
    /// The sensing sources the deployment has. Sorted and deduplicated.
    sources: Vec<SensingSource>,
    /// Whether the robot signs its own reports.
    ///
    /// Used for exactly one field of [`NavigationEvidence`] and reaching no
    /// conclusion.
    pub telemetry_authenticated: bool,
}

impl RoboticsProfile {
    pub fn new(observer_id: &str, sources: &[SensingSource]) -> Result<Self, RoboticsError> {
        if observer_id.is_empty() || observer_id.len() > 128 {
            return Err(RoboticsError::Malformed {
                reason: "observer id must be 1-128 bytes",
            });
        }
        let mut sources = sources.to_vec();
        sources.sort_unstable();
        sources.dedup();
        Ok(Self {
            version: ROBOTICS_PROFILE_VERSION,
            observer_id: observer_id.to_owned(),
            sources,
            telemetry_authenticated: false,
        })
    }

    /// Named `authenticated` and not `trusted`, because that is what it is.
    pub fn with_authenticated_telemetry(mut self) -> Self {
        self.telemetry_authenticated = true;
        self
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }
    pub fn sources(&self) -> &[SensingSource] {
        &self.sources
    }

    /// The sources that can actually produce an observation record.
    pub fn mechanised_sources(&self) -> Vec<SensingSource> {
        self.sources
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect()
    }

    /// Project into the generic observation profile.
    pub fn observation_profile(&self) -> Result<ObservationProfile, RoboticsError> {
        let mut profile = ObservationProfile::new(&self.observer_id)?;
        for s in self.mechanised_sources() {
            if let Some(m) = s.mechanism() {
                profile = profile.with_mechanism(m);
            }
        }
        Ok(profile)
    }

    pub fn navigation_evidence(&self, quantity: PoseQuantity) -> NavigationEvidence {
        NavigationEvidence::from_sources(quantity, &self.sources, self.telemetry_authenticated)
    }

    pub fn navigation_table(&self) -> Vec<NavigationEvidence> {
        PoseQuantity::ALL
            .iter()
            .map(|q| self.navigation_evidence(*q))
            .collect()
    }

    pub fn manipulation_evidence(&self, claim: ObjectStateClaim) -> ManipulationEvidence {
        ManipulationEvidence::from_sources(claim, &self.sources)
    }

    pub fn manipulation_table(&self) -> Vec<ManipulationEvidence> {
        ObjectStateClaim::ALL
            .iter()
            .map(|c| self.manipulation_evidence(*c))
            .collect()
    }

    /// The embodied chain, and how far this deployment reaches along it.
    pub fn embodied_chain(&self) -> EmbodiedChain {
        EmbodiedChain::current()
    }

    /// The highest rung this deployment establishes.
    ///
    /// `None` when it has no companion observer: without one, not even the
    /// autonomy stack's execution is established.
    pub fn highest_established_rung(&self) -> Option<EmbodiedRung> {
        if self.mechanised_sources().is_empty() {
            return None;
        }
        self.embodied_chain().highest_observable()
    }

    /// Whether this deployment can establish any physical effect.
    pub fn establishes_physical_effect(&self) -> bool {
        ObservationClass::PhysicalEffect.is_implemented()
            && self
                .sources
                .iter()
                .any(|s| s.observation_class() == Some(ObservationClass::PhysicalEffect))
    }

    pub fn check_version(&self) -> Result<(), RoboticsError> {
        if self.version != ROBOTICS_PROFILE_VERSION {
            return Err(RoboticsError::UnsupportedVersion {
                found: self.version,
                supported: ROBOTICS_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ROBOTICS_PROFILE_DOMAIN);
        // Structure discriminant inside the shared domain: 0x01 is a task
        // plan, 0x02 is this.
        put_u8(&mut buf, 0x02);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u8(&mut buf, u8::from(self.telemetry_authenticated));
        put_u32(&mut buf, self.sources.len() as u32);
        for s in &self.sources {
            put_u8(&mut buf, s.code());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The commitment the core carries.
    pub fn profile_ref(&self) -> Result<ProfileRef, RoboticsError> {
        ProfileRef::new(ProfileKind::Environment, ROBOTICS_PROFILE_ID, self.digest()).map_err(
            |_| RoboticsError::Malformed {
                reason: "the robotics profile id is not a valid profile reference id",
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-equipped robot with no independent observer of anything.
    const ROBOT: [SensingSource; 10] = [
        SensingSource::AutonomyRuntimeReport,
        SensingSource::ControllerTelemetry,
        SensingSource::EncoderOnboard,
        SensingSource::OdometryOnboard,
        SensingSource::ImuOnboard,
        SensingSource::ForceTorqueOnboard,
        SensingSource::TactileOnboard,
        SensingSource::CameraOnboard,
        SensingSource::LidarOnboard,
        SensingSource::LocalizationEstimateOnboard,
    ];

    /// The same robot with an anchored observer on its companion computer.
    const WITH_OBSERVER: [SensingSource; 12] = [
        SensingSource::AutonomyRuntimeReport,
        SensingSource::ControllerTelemetry,
        SensingSource::EncoderOnboard,
        SensingSource::OdometryOnboard,
        SensingSource::ImuOnboard,
        SensingSource::ForceTorqueOnboard,
        SensingSource::TactileOnboard,
        SensingSource::CameraOnboard,
        SensingSource::LidarOnboard,
        SensingSource::LocalizationEstimateOnboard,
        SensingSource::CompanionProcessObservation,
        SensingSource::CompanionNetworkObservation,
    ];

    #[test]
    fn a_full_sensor_suite_projects_to_a_profile_that_observes_nothing() {
        let p = RoboticsProfile::new("obs", &ROBOT)
            .unwrap()
            .with_authenticated_telemetry();
        assert!(p.mechanised_sources().is_empty());
        let op = p.observation_profile().unwrap();
        for class in ObservationClass::ALL {
            assert!(!op.capability(class).is_observable(), "{class:?}");
        }
        assert_eq!(
            p.highest_established_rung(),
            None,
            "without a companion observer, not even the software is established"
        );
    }

    #[test]
    fn undeclared_classes_are_not_observable_rather_than_not_observed() {
        let p = RoboticsProfile::new("obs", &ROBOT).unwrap();
        let op = p.observation_profile().unwrap();
        for class in [
            ObservationClass::PhysicalEffect,
            ObservationClass::ProcessIdentity,
        ] {
            assert_eq!(
                op.completeness_without_evidence(class),
                aip_observation::Completeness::NotObservable,
                "{class:?}"
            );
        }
    }

    #[test]
    fn adding_a_companion_observer_makes_exactly_two_classes_observable() {
        let p = RoboticsProfile::new("obs", &WITH_OBSERVER).unwrap();
        let op = p.observation_profile().unwrap();
        let observable: Vec<ObservationClass> = ObservationClass::ALL
            .iter()
            .copied()
            .filter(|c| op.capability(*c).is_observable())
            .collect();
        assert_eq!(
            observable,
            vec![
                ObservationClass::ProcessIdentity,
                ObservationClass::NetworkSocket
            ]
        );
        assert_eq!(
            p.highest_established_rung(),
            Some(EmbodiedRung::TaskCommand)
        );
    }

    #[test]
    fn no_declared_source_set_makes_physical_effect_reachable() {
        for sources in [&ROBOT[..], &WITH_OBSERVER[..], &SensingSource::ALL[..]] {
            let p = RoboticsProfile::new("obs", sources).unwrap();
            assert!(!p.establishes_physical_effect());
            let op = p.observation_profile().unwrap();
            assert!(!op
                .capability(ObservationClass::PhysicalEffect)
                .is_observable());
        }
    }

    #[test]
    fn no_pose_or_object_claim_is_established_even_with_every_source_declared() {
        let p = RoboticsProfile::new("obs", &SensingSource::ALL).unwrap();
        for e in p.navigation_table() {
            assert!(!e.establishes(), "{:?}", e.quantity);
        }
        for e in p.manipulation_table() {
            assert!(!e.establishes(), "{:?}", e.claim);
        }
    }

    #[test]
    fn the_profile_ref_occupies_the_environment_slot() {
        let p = RoboticsProfile::new("obs", &ROBOT).unwrap();
        let r = p.profile_ref().unwrap();
        assert_eq!(r.kind, ProfileKind::Environment);
        assert_eq!(r.id(), ROBOTICS_PROFILE_ID);
        assert_eq!(r.digest, p.digest());
    }

    #[test]
    fn the_digest_is_order_independent_and_content_sensitive() {
        let a = RoboticsProfile::new(
            "obs",
            &[SensingSource::ImuOnboard, SensingSource::EncoderOnboard],
        )
        .unwrap();
        let b = RoboticsProfile::new(
            "obs",
            &[SensingSource::EncoderOnboard, SensingSource::ImuOnboard],
        )
        .unwrap();
        assert_eq!(a.digest(), b.digest());
        assert_ne!(
            a.digest(),
            RoboticsProfile::new("obs", &[SensingSource::ImuOnboard])
                .unwrap()
                .digest()
        );
    }

    #[test]
    fn the_robotics_profile_id_differs_from_the_uas_one() {
        // Both occupy ProfileKind::Environment; the id is what tells a verifier
        // which vertical a commitment is about.
        assert_ne!(ROBOTICS_PROFILE_ID, "vanian.uas.v1");
    }

    #[test]
    fn authentication_changes_the_document_but_not_what_is_established() {
        let plain = RoboticsProfile::new("obs", &ROBOT).unwrap();
        let signed = plain.clone().with_authenticated_telemetry();
        assert_ne!(plain.digest(), signed.digest());
        for q in PoseQuantity::ALL {
            assert_eq!(
                plain.navigation_evidence(q).establishes(),
                signed.navigation_evidence(q).establishes(),
                "{q:?}"
            );
        }
    }

    #[test]
    fn an_empty_observer_id_is_refused_and_an_empty_deployment_is_allowed() {
        assert!(RoboticsProfile::new("", &ROBOT).is_err());
        assert!(RoboticsProfile::new(&"x".repeat(129), &ROBOT).is_err());
        let empty = RoboticsProfile::new("obs", &[]).unwrap();
        assert!(empty.mechanised_sources().is_empty());
        assert!(empty.observation_profile().is_ok());
    }
}
