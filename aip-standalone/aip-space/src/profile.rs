//! The space execution profile document and its projections.
//!
//! Fills `ProfileKind::Environment`, the slot Skill 17 reserved for verticals —
//! the same slot `aip-uas`, `aip-robotics` and `aip-industrial` occupy, under a
//! fourth id.

use aip_crypto::sha256;
use aip_observation::{ObservationClass, ObservationProfile};
use aip_system::{ProfileKind, ProfileRef};
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u8};
use serde::{Deserialize, Serialize};

use crate::error::SpaceError;
use crate::link::LinkState;
use crate::mode::AutonomyMode;
use crate::sensing::SpaceSensingSource;
use crate::{SPACE_PROFILE_DOMAIN, SPACE_PROFILE_VERSION};

/// The profile id this crate commits under.
pub const SPACE_PROFILE_ID: &str = "vanian.space.v1";

/// What a disconnected or orbital deployment declares about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceExecutionProfile {
    pub version: u16,
    observer_id: String,
    /// The sources the deployment has. Sorted and deduplicated.
    sources: Vec<SpaceSensingSource>,
    /// The autonomy modes the deployment is configured to enter. Sorted and
    /// deduplicated.
    modes: Vec<AutonomyMode>,
    /// The longest outage the deployment is designed to survive, in
    /// milliseconds. Declared context: it changes no evidence question, and it
    /// is committed so a later claim about the design cannot be revised.
    pub max_planned_outage_ms: u64,
    /// Whether onboard telemetry is cryptographically authenticated.
    ///
    /// Named `authenticated` and not `trusted`: it establishes who spoke.
    pub telemetry_authenticated: bool,
}

impl SpaceExecutionProfile {
    pub fn new(
        observer_id: &str,
        sources: &[SpaceSensingSource],
        modes: &[AutonomyMode],
        max_planned_outage_ms: u64,
    ) -> Result<Self, SpaceError> {
        if observer_id.is_empty() || observer_id.len() > 128 {
            return Err(SpaceError::Malformed {
                reason: "observer id must be 1-128 bytes",
            });
        }
        let mut sources = sources.to_vec();
        sources.sort_unstable();
        sources.dedup();
        let mut modes = modes.to_vec();
        modes.sort_unstable();
        modes.dedup();
        Ok(Self {
            version: SPACE_PROFILE_VERSION,
            observer_id: observer_id.to_owned(),
            sources,
            modes,
            max_planned_outage_ms,
            telemetry_authenticated: false,
        })
    }

    pub fn with_authenticated_telemetry(mut self) -> Self {
        self.telemetry_authenticated = true;
        self
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }
    pub fn sources(&self) -> &[SpaceSensingSource] {
        &self.sources
    }
    pub fn modes(&self) -> &[AutonomyMode] {
        &self.modes
    }

    pub fn mechanised_sources(&self) -> Vec<SpaceSensingSource> {
        self.sources
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect()
    }

    /// Whether the deployment has an anchored observer aboard.
    pub fn has_onboard_observer(&self) -> bool {
        !self.mechanised_sources().is_empty()
    }

    /// Whether the deployment can collect evidence with no link.
    ///
    /// The Skill 26 first-class-offline property, computed: an anchored
    /// onboard observer works whether or not ground can hear it.
    pub fn collects_while_disconnected(&self) -> bool {
        self.mechanised_sources()
            .iter()
            .any(|s| s.available_while_disconnected())
    }

    /// The sources that keep producing evidence during an outage.
    pub fn offline_sources(&self) -> Vec<SpaceSensingSource> {
        self.sources
            .iter()
            .copied()
            .filter(|s| s.available_while_disconnected())
            .collect()
    }

    /// Project into the generic observation profile.
    ///
    /// Only mechanised sources contribute. A star tracker is dropped, not
    /// downgraded, which is what lets the result say `NotObservable` rather
    /// than `NotObserved`.
    pub fn observation_profile(&self) -> Result<ObservationProfile, SpaceError> {
        let mut profile = ObservationProfile::new(&self.observer_id)?;
        for s in self.mechanised_sources() {
            if let Some(m) = s.mechanism() {
                profile = profile.with_mechanism(m);
            }
        }
        Ok(profile)
    }

    /// Whether the deployment can establish any physical effect in orbit.
    pub fn establishes_physical_effect(&self) -> bool {
        ObservationClass::PhysicalEffect.is_implemented()
            && self
                .sources
                .iter()
                .any(|s| s.observation_class() == Some(ObservationClass::PhysicalEffect))
    }

    /// Whether a link state changes what this deployment can establish.
    ///
    /// **`false` for every state.** The Skill 26 rule that offline is a
    /// deployment mode and not a bypass, expressed as a property of the
    /// profile rather than a promise in prose.
    pub fn link_state_changes_capability(&self, _state: LinkState) -> bool {
        false
    }

    pub fn check_version(&self) -> Result<(), SpaceError> {
        if self.version != SPACE_PROFILE_VERSION {
            return Err(SpaceError::UnsupportedVersion {
                found: self.version,
                supported: SPACE_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, SPACE_PROFILE_DOMAIN);
        // Structure discriminant: 0x01 is the profile document, 0x02 a mode
        // transition, 0x03 a bundle.
        put_u8(&mut buf, 0x01);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u8(&mut buf, u8::from(self.telemetry_authenticated));
        aip_types::canonical::put_u64(&mut buf, self.max_planned_outage_ms);
        put_u32(&mut buf, self.sources.len() as u32);
        for s in &self.sources {
            put_u8(&mut buf, s.code());
        }
        put_u32(&mut buf, self.modes.len() as u32);
        for m in &self.modes {
            put_u8(&mut buf, m.code());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    pub fn profile_ref(&self) -> Result<ProfileRef, SpaceError> {
        ProfileRef::new(ProfileKind::Environment, SPACE_PROFILE_ID, self.digest()).map_err(|_| {
            SpaceError::Malformed {
                reason: "the space profile id is not a valid profile reference id",
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VEHICLE: [SpaceSensingSource; 6] = [
        SpaceSensingSource::OnboardAutonomyReport,
        SpaceSensingSource::HousekeepingTelemetry,
        SpaceSensingSource::AttitudeSolutionOnboard,
        SpaceSensingSource::NavigationSolutionOnboard,
        SpaceSensingSource::PayloadInstrument,
        SpaceSensingSource::OnboardEventLog,
    ];

    const WITH_OBSERVER: [SpaceSensingSource; 9] = [
        SpaceSensingSource::OnboardAutonomyReport,
        SpaceSensingSource::HousekeepingTelemetry,
        SpaceSensingSource::AttitudeSolutionOnboard,
        SpaceSensingSource::NavigationSolutionOnboard,
        SpaceSensingSource::PayloadInstrument,
        SpaceSensingSource::OnboardEventLog,
        SpaceSensingSource::OnboardProcessObservation,
        SpaceSensingSource::OnboardLifecycleObservation,
        SpaceSensingSource::OnboardLinkObservation,
    ];

    const MODES: [AutonomyMode; 3] = [
        AutonomyMode::SupervisedSequence,
        AutonomyMode::UnsupervisedSequence,
        AutonomyMode::SafeMode,
    ];

    fn profile(sources: &[SpaceSensingSource]) -> SpaceExecutionProfile {
        SpaceExecutionProfile::new("onboard-collector", sources, &MODES, 7 * 86_400_000).unwrap()
    }

    #[test]
    fn a_full_instrument_suite_projects_to_a_profile_that_observes_nothing() {
        let p = profile(&VEHICLE).with_authenticated_telemetry();
        assert!(p.mechanised_sources().is_empty());
        assert!(!p.has_onboard_observer());
        assert!(!p.collects_while_disconnected());
        let op = p.observation_profile().unwrap();
        for class in ObservationClass::ALL {
            assert!(!op.capability(class).is_observable(), "{class:?}");
        }
    }

    #[test]
    fn an_onboard_observer_makes_three_classes_observable_and_works_offline() {
        let p = profile(&WITH_OBSERVER);
        assert!(p.has_onboard_observer());
        assert!(
            p.collects_while_disconnected(),
            "an anchored onboard observer works whether or not ground can hear it"
        );
        let op = p.observation_profile().unwrap();
        let observable: Vec<ObservationClass> = ObservationClass::ALL
            .iter()
            .copied()
            .filter(|c| op.capability(*c).is_observable())
            .collect();
        assert_eq!(
            observable,
            vec![
                ObservationClass::ProcessLifecycle,
                ObservationClass::ProcessIdentity,
                ObservationClass::NetworkSocket,
            ]
        );
    }

    #[test]
    fn no_link_state_changes_what_the_deployment_can_establish() {
        let p = profile(&WITH_OBSERVER);
        for s in LinkState::ALL {
            assert!(!p.link_state_changes_capability(s), "{s:?}");
        }
    }

    #[test]
    fn no_deployment_establishes_a_physical_effect_in_orbit() {
        for sources in [
            &VEHICLE[..],
            &WITH_OBSERVER[..],
            &SpaceSensingSource::ALL[..],
        ] {
            let p = profile(sources);
            assert!(!p.establishes_physical_effect());
            let op = p.observation_profile().unwrap();
            assert!(!op
                .capability(ObservationClass::PhysicalEffect)
                .is_observable());
        }
    }

    #[test]
    fn undeclared_classes_are_not_observable_rather_than_not_observed() {
        let op = profile(&VEHICLE).observation_profile().unwrap();
        assert_eq!(
            op.completeness_without_evidence(ObservationClass::ProcessIdentity),
            aip_observation::Completeness::NotObservable
        );
        let op2 = profile(&WITH_OBSERVER).observation_profile().unwrap();
        assert_eq!(
            op2.completeness_without_evidence(ObservationClass::ProcessIdentity),
            aip_observation::Completeness::NotObserved
        );
    }

    #[test]
    fn the_profile_ref_occupies_the_environment_slot_under_a_fourth_id() {
        let r = profile(&VEHICLE).profile_ref().unwrap();
        assert_eq!(r.kind, ProfileKind::Environment);
        assert_eq!(r.id(), SPACE_PROFILE_ID);
        for other in [
            "vanian.uas.v1",
            "vanian.robotics.v1",
            "vanian.industrial.v1",
        ] {
            assert_ne!(SPACE_PROFILE_ID, other);
        }
    }

    #[test]
    fn the_digest_is_order_independent_and_content_sensitive() {
        let a = SpaceExecutionProfile::new(
            "obs",
            &[
                SpaceSensingSource::HousekeepingTelemetry,
                SpaceSensingSource::OnboardEventLog,
            ],
            &[AutonomyMode::SafeMode, AutonomyMode::SupervisedSequence],
            1,
        )
        .unwrap();
        let b = SpaceExecutionProfile::new(
            "obs",
            &[
                SpaceSensingSource::OnboardEventLog,
                SpaceSensingSource::HousekeepingTelemetry,
            ],
            &[AutonomyMode::SupervisedSequence, AutonomyMode::SafeMode],
            1,
        )
        .unwrap();
        assert_eq!(a.digest(), b.digest());
        let c = SpaceExecutionProfile::new(
            "obs",
            &[SpaceSensingSource::HousekeepingTelemetry],
            &[AutonomyMode::SafeMode, AutonomyMode::SupervisedSequence],
            1,
        )
        .unwrap();
        assert_ne!(a.digest(), c.digest());
        // The declared outage is part of the document.
        let d = SpaceExecutionProfile::new(
            "obs",
            &[
                SpaceSensingSource::HousekeepingTelemetry,
                SpaceSensingSource::OnboardEventLog,
            ],
            &[AutonomyMode::SafeMode, AutonomyMode::SupervisedSequence],
            2,
        )
        .unwrap();
        assert_ne!(a.digest(), d.digest());
    }

    #[test]
    fn authentication_changes_the_document_and_not_what_is_established() {
        let plain = profile(&WITH_OBSERVER);
        let signed = plain.clone().with_authenticated_telemetry();
        assert_ne!(plain.digest(), signed.digest());
        assert_eq!(
            plain.establishes_physical_effect(),
            signed.establishes_physical_effect()
        );
        assert_eq!(plain.mechanised_sources(), signed.mechanised_sources());
    }

    #[test]
    fn an_empty_observer_id_is_refused_and_an_empty_deployment_is_allowed() {
        assert!(SpaceExecutionProfile::new("", &VEHICLE, &MODES, 1).is_err());
        assert!(SpaceExecutionProfile::new(&"x".repeat(129), &VEHICLE, &MODES, 1).is_err());
        let empty = SpaceExecutionProfile::new("obs", &[], &[], 0).unwrap();
        assert!(empty.observation_profile().is_ok());
        assert!(empty.check_version().is_ok());
        assert!(empty.offline_sources().is_empty());
    }
}
