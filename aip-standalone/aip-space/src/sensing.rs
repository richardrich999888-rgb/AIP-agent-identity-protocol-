//! Where a disconnected vehicle's reports come from.
//!
//! The same question the other verticals ask: **is the party producing this
//! report inside the thing being judged?** With one difference that matters
//! more here than anywhere else — for most of a mission there is nobody else.
//!
//! A spacecraft out of contact is observed by exactly one party: itself, and
//! whatever anchored collector runs on its own onboard computer. Ground
//! tracking exists and is genuinely external, and this build has no mechanism
//! for it.

use aip_observation::{EvidenceCeiling, ObservationClass};
use aip_observe::SourceMechanism;
use serde::{Deserialize, Serialize};

/// A source of reports about a disconnected or orbital vehicle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SpaceSensingSource {
    /// The autonomy or sequencer software's account of its own decisions.
    OnboardAutonomyReport,
    /// Spacecraft housekeeping telemetry: power, thermal, attitude, mode.
    HousekeepingTelemetry,
    /// The attitude determination solution computed onboard.
    AttitudeSolutionOnboard,
    /// An onboard navigation solution — GNSS where available, or propagated.
    NavigationSolutionOnboard,
    /// A payload instrument's own data product.
    PayloadInstrument,
    /// The onboard event log, stored for later downlink.
    OnboardEventLog,
    /// An anchored observer measuring the onboard computer's **process
    /// identity**: which flight software ran, as which instance, on which boot.
    OnboardProcessObservation,
    /// An anchored observer measuring the onboard computer's **process
    /// lifecycle**, from a kernel-pushed event.
    OnboardLifecycleObservation,
    /// An anchored observer measuring the onboard computer's **sockets** —
    /// the bus or radio link endpoints it held at a sample.
    OnboardLinkObservation,
    /// Ground-based radiometric tracking: range, Doppler, angles.
    ///
    /// Genuinely outside the vehicle, and unmechanised in this build.
    GroundRadiometricTracking,
    /// An independent third-party sensor: another spacecraft, an optical
    /// tracking site, a space-surveillance network.
    ThirdPartyTracking,
}

impl SpaceSensingSource {
    pub const ALL: [SpaceSensingSource; 11] = [
        Self::OnboardAutonomyReport,
        Self::HousekeepingTelemetry,
        Self::AttitudeSolutionOnboard,
        Self::NavigationSolutionOnboard,
        Self::PayloadInstrument,
        Self::OnboardEventLog,
        Self::OnboardProcessObservation,
        Self::OnboardLifecycleObservation,
        Self::OnboardLinkObservation,
        Self::GroundRadiometricTracking,
        Self::ThirdPartyTracking,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::OnboardAutonomyReport => 0x01,
            Self::HousekeepingTelemetry => 0x02,
            Self::AttitudeSolutionOnboard => 0x03,
            Self::NavigationSolutionOnboard => 0x04,
            Self::PayloadInstrument => 0x05,
            Self::OnboardEventLog => 0x06,
            Self::OnboardProcessObservation => 0x07,
            Self::OnboardLifecycleObservation => 0x08,
            Self::OnboardLinkObservation => 0x09,
            Self::GroundRadiometricTracking => 0x0A,
            Self::ThirdPartyTracking => 0x0B,
        }
    }

    /// Whether the source sits inside the vehicle being judged.
    ///
    /// Six of eleven. The three onboard *observers* are treated as outside the
    /// **subject process** and inside the **vehicle** — exactly as the robotics
    /// companion computer and the industrial edge node are — because that is
    /// what an anchored collector on the same host is.
    pub fn is_onboard_subject(self) -> bool {
        matches!(
            self,
            Self::OnboardAutonomyReport
                | Self::HousekeepingTelemetry
                | Self::AttitudeSolutionOnboard
                | Self::NavigationSolutionOnboard
                | Self::PayloadInstrument
                | Self::OnboardEventLog
        )
    }

    pub fn is_independent(self) -> bool {
        !self.is_onboard_subject()
    }

    /// The Linux mechanism backing this source, when one exists.
    ///
    /// `Some` for three, all measurements of the onboard computer. There is
    /// deliberately no mechanism for a star tracker or a radiometric range
    /// measurement: adding one would put a device-specific value into signed
    /// bytes every verifier must understand — the schema fork ADR-003 exists
    /// to prevent, refused here for the same reason ADR-005 refused it for
    /// avionics.
    pub fn mechanism(self) -> Option<SourceMechanism> {
        match self {
            Self::OnboardProcessObservation => Some(SourceMechanism::PidFdAnchored),
            Self::OnboardLifecycleObservation => Some(SourceMechanism::ProcConnector),
            Self::OnboardLinkObservation => Some(SourceMechanism::ProcNetTable),
            _ => None,
        }
    }

    pub fn can_produce_observation_record(self) -> bool {
        self.mechanism().is_some()
    }

    pub fn observation_class(self) -> Option<ObservationClass> {
        self.mechanism().map(aip_observation::class_of)
    }

    /// Whether this source's mechanism survives an on-host adversary gating a
    /// perf tracepoint.
    pub fn is_gate_independent(self) -> bool {
        self.mechanism()
            .is_some_and(|m| m.is_gate_independent_kernel_pushed())
    }

    /// Whether the source can produce evidence while the link is down.
    ///
    /// The property that makes offline a first-class mode: nine of eleven keep
    /// working with no contact, and the two that do not are the ground-based
    /// ones. A mission is not unobserved during an outage — it is unobserved
    /// *by ground*, which is a different sentence.
    pub fn available_while_disconnected(self) -> bool {
        !matches!(
            self,
            Self::GroundRadiometricTracking | Self::ThirdPartyTracking
        )
    }

    /// The strongest evidence this source could ever contribute.
    ///
    /// Computed from the mechanism, never tabulated.
    pub fn ceiling(self) -> EvidenceCeiling {
        match self.observation_class() {
            Some(class) => class.ceiling(),
            None => EvidenceCeiling::Corroborative,
        }
    }

    pub fn does_not_establish(self) -> &'static str {
        match self {
            Self::OnboardAutonomyReport => "that anything it describes occurred",
            Self::HousekeepingTelemetry => {
                "the vehicle's true state: it is the vehicle's account of itself, and a \
                 compromised bus writes it"
            }
            Self::AttitudeSolutionOnboard | Self::NavigationSolutionOnboard => {
                "a true state: an estimator's own covariance is an output of its model, not \
                 evidence about the world"
            }
            Self::PayloadInstrument => "anything outside the instrument's own aperture",
            Self::OnboardEventLog => {
                "that the logged events happened; a log records what the software chose to write"
            }
            Self::OnboardProcessObservation => {
                "what the flight software did, any command it issued, or any effect in orbit"
            }
            Self::OnboardLifecycleObservation => "what ran between the events",
            Self::OnboardLinkObservation => {
                "what the bytes were, that they left the antenna, or that anyone received them"
            }
            Self::GroundRadiometricTracking => {
                "anything, absent an anchor: an unanchored ground measurement is a claim from a \
                 party the verifier cannot name"
            }
            Self::ThirdPartyTracking => "more than its own collection chain, which is not modelled",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_three_sources_can_produce_an_observation_record() {
        let backed: Vec<SpaceSensingSource> = SpaceSensingSource::ALL
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect();
        assert_eq!(
            backed,
            vec![
                SpaceSensingSource::OnboardProcessObservation,
                SpaceSensingSource::OnboardLifecycleObservation,
                SpaceSensingSource::OnboardLinkObservation,
            ]
        );
    }

    #[test]
    fn no_spacecraft_instrument_has_a_mechanism() {
        for s in [
            SpaceSensingSource::AttitudeSolutionOnboard,
            SpaceSensingSource::NavigationSolutionOnboard,
            SpaceSensingSource::PayloadInstrument,
            SpaceSensingSource::HousekeepingTelemetry,
            SpaceSensingSource::GroundRadiometricTracking,
            SpaceSensingSource::ThirdPartyTracking,
        ] {
            assert!(s.mechanism().is_none(), "{s:?}");
            assert!(!s.can_produce_observation_record(), "{s:?}");
            assert_eq!(s.ceiling(), EvidenceCeiling::Corroborative, "{s:?}");
        }
    }

    #[test]
    fn ground_tracking_is_independent_and_still_capped() {
        for s in [
            SpaceSensingSource::GroundRadiometricTracking,
            SpaceSensingSource::ThirdPartyTracking,
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
    fn nine_of_eleven_sources_keep_working_with_no_link() {
        let offline: Vec<SpaceSensingSource> = SpaceSensingSource::ALL
            .iter()
            .copied()
            .filter(|s| s.available_while_disconnected())
            .collect();
        assert_eq!(offline.len(), 9);
        assert!(!SpaceSensingSource::GroundRadiometricTracking.available_while_disconnected());
        assert!(!SpaceSensingSource::ThirdPartyTracking.available_while_disconnected());
    }

    #[test]
    fn no_source_reaches_proven_or_claims_the_physical_effect_class() {
        for s in SpaceSensingSource::ALL {
            assert_ne!(s.ceiling(), EvidenceCeiling::Proven, "{s:?}");
            assert_ne!(
                s.observation_class(),
                Some(ObservationClass::PhysicalEffect),
                "{s:?}"
            );
            assert!(!s.does_not_establish().is_empty(), "{s:?}");
        }
    }

    #[test]
    fn exactly_one_mechanised_source_is_gate_independent() {
        let independent: Vec<SpaceSensingSource> = SpaceSensingSource::ALL
            .iter()
            .copied()
            .filter(|s| s.is_gate_independent())
            .collect();
        assert_eq!(
            independent,
            vec![SpaceSensingSource::OnboardLifecycleObservation]
        );
    }

    #[test]
    fn codes_are_unique_and_pinned() {
        let mut codes: Vec<u8> = SpaceSensingSource::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), SpaceSensingSource::ALL.len());
        assert_eq!(SpaceSensingSource::OnboardAutonomyReport.code(), 0x01);
        assert_eq!(SpaceSensingSource::ThirdPartyTracking.code(), 0x0B);
    }
}
