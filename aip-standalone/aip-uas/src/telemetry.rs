//! Where a UAS's reports come from, and what each source is worth.
//!
//! # The question every row answers
//!
//! Not "is this data authentic?" — authenticity is a property of a signature
//! and says nothing about the world. The question is: **is the party
//! producing this report inside the thing being judged?**
//!
//! An autopilot signing its own altitude is precisely as informative as an
//! agent signing its own success report. Both establish authorship. Neither
//! establishes occurrence. The distinction is not pedantry: a UAS whose
//! autonomy stack is compromised will emit perfectly authenticated telemetry
//! describing a flight it is not making, and a system that reads a valid
//! signature as ground truth will believe it.
//!
//! # Six facts per source
//!
//! Each source below carries the treatment Skill 22 established for Linux
//! mechanisms: what it observes, what it establishes, what it does not
//! establish, its trust basis, its failure mode, and its evidence ceiling.
//! They are methods rather than a table in a comment, so a source added later
//! cannot silently lack one — the matches are exhaustive and the compiler
//! enforces it.
//!
//! # The mechanism column is the load-bearing one
//!
//! [`TelemetrySource::mechanism`] returns `Some` for exactly two sources: the
//! companion computer's process and network observation, which are real Linux
//! mechanisms an anchored collector already attests. Every other source
//! returns `None`, and [`TelemetrySource::can_produce_observation_record`] is
//! therefore false for it — not as policy, but because
//! `ObservationRecord::from_attested` has no input it could be given.

use aip_observation::{EvidenceCeiling, ObservationClass};
use aip_observe::SourceMechanism;
use serde::{Deserialize, Serialize};

/// A source of reports about a UAS.
///
/// Closed on purpose, like `ObservationClass` and `SourceMechanism`. An open
/// vocabulary could not carry a trust basis, and two deployments would spell
/// the same source differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TelemetrySource {
    /// The flight controller's own telemetry stream: attitude, position,
    /// mode, arming state, battery.
    FlightControllerTelemetry,
    /// The companion computer's autonomy software reporting on itself.
    CompanionAutonomyReport,
    /// A GNSS receiver aboard the aircraft.
    GnssReceiverOnboard,
    /// An inertial measurement unit aboard the aircraft.
    ImuOnboard,
    /// A barometric altimeter aboard the aircraft.
    BarometerOnboard,
    /// An airspeed probe aboard the aircraft.
    AirspeedProbeOnboard,
    /// A navigation receiver **not** aboard the aircraft — an RTK base
    /// station, a survey receiver, a differential correction source.
    ExternalNavigationReceiver,
    /// A ground station's own track of the aircraft: radar, optical, ADS-B
    /// receiver, or a range-safety tracker.
    GroundStationTrack,
    /// An independent receiver observing the command or telemetry radio link
    /// itself — that a link existed, not what it carried.
    IndependentRadioObservation,
    /// An anchored observer measuring the companion computer's **process**:
    /// which autonomy binary ran, as which instance, on which boot.
    CompanionProcessObservation,
    /// An anchored observer measuring the companion computer's **sockets**:
    /// that a link to a named endpoint existed at a sampled moment.
    CompanionNetworkObservation,
}

impl TelemetrySource {
    /// Every source, for exhaustive sweeps.
    pub const ALL: [TelemetrySource; 11] = [
        Self::FlightControllerTelemetry,
        Self::CompanionAutonomyReport,
        Self::GnssReceiverOnboard,
        Self::ImuOnboard,
        Self::BarometerOnboard,
        Self::AirspeedProbeOnboard,
        Self::ExternalNavigationReceiver,
        Self::GroundStationTrack,
        Self::IndependentRadioObservation,
        Self::CompanionProcessObservation,
        Self::CompanionNetworkObservation,
    ];

    /// Stable wire code, assigned explicitly so reordering the variants cannot
    /// change what previously encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::FlightControllerTelemetry => 0x01,
            Self::CompanionAutonomyReport => 0x02,
            Self::GnssReceiverOnboard => 0x03,
            Self::ImuOnboard => 0x04,
            Self::BarometerOnboard => 0x05,
            Self::AirspeedProbeOnboard => 0x06,
            Self::ExternalNavigationReceiver => 0x07,
            Self::GroundStationTrack => 0x08,
            Self::IndependentRadioObservation => 0x09,
            Self::CompanionProcessObservation => 0x0A,
            Self::CompanionNetworkObservation => 0x0B,
        }
    }

    /// Whether the source sits **inside** the system being judged.
    ///
    /// The single most important property here. Every onboard source — the
    /// autopilot, the GNSS receiver, the IMU, the barometer — is reachable by
    /// whatever compromised the aircraft. A report from inside the subject is
    /// a self-report regardless of how it is signed, and
    /// [`Self::is_independent`] is the negation a caller should be asking for.
    pub fn is_onboard_subject(self) -> bool {
        matches!(
            self,
            Self::FlightControllerTelemetry
                | Self::CompanionAutonomyReport
                | Self::GnssReceiverOnboard
                | Self::ImuOnboard
                | Self::BarometerOnboard
                | Self::AirspeedProbeOnboard
        )
    }

    /// Whether this source is outside the subject.
    ///
    /// Note that "independent" here means *positionally* independent — the
    /// party producing the report is not the party under scrutiny. It does not
    /// mean the report is verified: an independent source still has to be
    /// anchored, and being named is not being trusted.
    pub fn is_independent(self) -> bool {
        !self.is_onboard_subject()
    }

    /// The Linux mechanism backing this source, when one exists.
    ///
    /// `Some` for exactly two sources. This is not a limitation of the profile
    /// — it is the state of the workspace, stated: `SourceMechanism` is nine
    /// Linux facilities, and an avionics sensor is not one of them. Adding a
    /// variant for a GNSS receiver would put a device-specific value into
    /// signed bytes every verifier must understand, which is the schema fork
    /// ADR-003 exists to prevent.
    pub fn mechanism(self) -> Option<SourceMechanism> {
        match self {
            Self::CompanionProcessObservation => Some(SourceMechanism::PidFdAnchored),
            Self::CompanionNetworkObservation => Some(SourceMechanism::ProcNetTable),
            _ => None,
        }
    }

    /// Whether an `ObservationRecord` can be built from this source at all.
    ///
    /// False for nine of eleven sources. `from_attested` takes an
    /// `AttestedBatch` of `ObservedExecution`s, each carrying a
    /// `SourceMechanism`; a source with no mechanism has nothing to offer it.
    /// A deployment that needs one of the other nine must supply a mechanism,
    /// and this build has none.
    pub fn can_produce_observation_record(self) -> bool {
        self.mechanism().is_some()
    }

    /// The observation class this source would belong to, when a mechanism
    /// exists to produce it.
    ///
    /// Deliberately `None` wherever `mechanism()` is `None`. A class without a
    /// mechanism is a claim: it would let a profile declare capability for
    /// something nothing can observe, and `ObservationProfile` would then
    /// record a silent gap as `NotObserved` instead of `NotObservable`.
    pub fn observation_class(self) -> Option<ObservationClass> {
        self.mechanism().map(aip_observation::class_of)
    }

    /// What this source observes.
    pub fn observes(self) -> &'static str {
        match self {
            Self::FlightControllerTelemetry => {
                "the autopilot's own state: attitude, mode, arming, battery, its position solution"
            }
            Self::CompanionAutonomyReport => "the autonomy software's account of its own decisions",
            Self::GnssReceiverOnboard => {
                "a position and time solution from received satellite signals"
            }
            Self::ImuOnboard => "accelerations and angular rates at the sensor",
            Self::BarometerOnboard => "static pressure at the port",
            Self::AirspeedProbeOnboard => "differential pressure at the probe",
            Self::ExternalNavigationReceiver => {
                "a position solution at a location that is not the aircraft"
            }
            Self::GroundStationTrack => "a track of an object, from a sensor on the ground",
            Self::IndependentRadioObservation => "that a radio link existed between two points",
            Self::CompanionProcessObservation => {
                "a process instance on the companion computer and the content of its executable"
            }
            Self::CompanionNetworkObservation => {
                "a socket owned by that instance, and the endpoint it was connected to at a sample"
            }
        }
    }

    /// What this source establishes.
    pub fn establishes(self) -> &'static str {
        match self {
            Self::FlightControllerTelemetry | Self::CompanionAutonomyReport => {
                "that the subject said so, and — if signed — that it is the subject that said it"
            }
            Self::GnssReceiverOnboard
            | Self::ImuOnboard
            | Self::BarometerOnboard
            | Self::AirspeedProbeOnboard => {
                "what a device inside the subject reported; the subject's own account of its state"
            }
            Self::ExternalNavigationReceiver => {
                "a position at the receiver's own location, which is not the aircraft's"
            }
            Self::GroundStationTrack => {
                "that a sensor outside the subject detected an object on a track"
            }
            Self::IndependentRadioObservation => "that a link was present between two points",
            Self::CompanionProcessObservation => {
                "that one process instance, running measured executable content, existed on a \
                 measured host-boot"
            }
            Self::CompanionNetworkObservation => {
                "that the instance held a socket to a named endpoint at the moment of the sample"
            }
        }
    }

    /// What this source does **not** establish. The column operators skip and
    /// incident reviewers need.
    pub fn does_not_establish(self) -> &'static str {
        match self {
            Self::FlightControllerTelemetry => {
                "that the aircraft is where it says, at that attitude, or that any surface moved"
            }
            Self::CompanionAutonomyReport => "that anything it describes occurred",
            Self::GnssReceiverOnboard => {
                "a true position: the signal is unauthenticated for civil GNSS, spoofable at the \
                 antenna and forgeable at the bus"
            }
            Self::ImuOnboard => {
                "an absolute position or attitude: it integrates, so it drifts, and it is \
                 forgeable at the bus"
            }
            Self::BarometerOnboard => {
                "a geometric altitude: pressure is not height, and the reference is a setting"
            }
            Self::AirspeedProbeOnboard => "a ground speed, a track, or a position",
            Self::ExternalNavigationReceiver => "anything about the aircraft's own position",
            Self::GroundStationTrack => {
                "that the tracked object is this aircraft, absent a binding the tracker does not have"
            }
            Self::IndependentRadioObservation => {
                "what the link carried, or that the aircraft acted on any of it"
            }
            Self::CompanionProcessObservation => {
                "what the process did, any command it issued, or any physical effect"
            }
            Self::CompanionNetworkObservation => {
                "what the bytes were, that they arrived, or that a flight controller acted on them"
            }
        }
    }

    /// Who or what has to be trusted for this source to mean anything.
    pub fn trust_basis(self) -> &'static str {
        match self {
            Self::FlightControllerTelemetry
            | Self::CompanionAutonomyReport
            | Self::GnssReceiverOnboard
            | Self::ImuOnboard
            | Self::BarometerOnboard
            | Self::AirspeedProbeOnboard => {
                "the subject itself, and everything with access to its buses: the party under \
                 scrutiny"
            }
            Self::ExternalNavigationReceiver | Self::GroundStationTrack => {
                "an operator-anchored external party; the verifier's trust model, not an \
                 improvement on it"
            }
            Self::IndependentRadioObservation => "an operator-anchored radio observer",
            Self::CompanionProcessObservation | Self::CompanionNetworkObservation => {
                "the companion computer's kernel for the measurement, and an off-host anchored \
                 collector for the attestation; host root forges the content"
            }
        }
    }

    /// How this source fails, and what a verifier sees when it does.
    pub fn failure_mode(self) -> &'static str {
        match self {
            Self::FlightControllerTelemetry | Self::CompanionAutonomyReport => {
                "silence, or a fluent and correctly signed account of a flight that is not \
                 happening"
            }
            Self::GnssReceiverOnboard => "spoofing, meaconing, jamming, multipath, or a held fix",
            Self::ImuOnboard => "unbounded drift, saturation, or a stuck output that looks calm",
            Self::BarometerOnboard => "a pressure change mistaken for a height change",
            Self::AirspeedProbeOnboard => "blockage or icing, reported as a plausible number",
            Self::ExternalNavigationReceiver => "outage, or correct data about the wrong place",
            Self::GroundStationTrack => "loss of track, or a track swapped onto another object",
            Self::IndependentRadioObservation => "loss of reception, which is not loss of link",
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
    /// # Why nothing here reaches `Proven`
    ///
    /// `EvidenceCeiling::Proven` is reserved for facts a third party
    /// recomputes from bytes it holds — signature and chain arithmetic — and
    /// exactly one class reaches it: `ObserverIntegrity`. No telemetry source
    /// is that, because no telemetry is recomputable: a verifier holding a
    /// GNSS fix cannot re-derive it, only re-check who signed it.
    ///
    /// Onboard sources are capped at `Corroborative` here rather than at
    /// `Attested`, and the reason is not conservatism about sensor quality: an
    /// `Attested` ceiling means *an anchored observer measured this*, and no
    /// anchored observer measured anything a subject reported about itself.
    /// See `navigation` for what that means quantity by quantity.
    pub fn ceiling(self) -> EvidenceCeiling {
        match self {
            // Inside the subject. A self-report can corroborate an independent
            // observation; it can never carry a positive finding alone.
            Self::FlightControllerTelemetry
            | Self::CompanionAutonomyReport
            | Self::GnssReceiverOnboard
            | Self::ImuOnboard
            | Self::BarometerOnboard
            | Self::AirspeedProbeOnboard => EvidenceCeiling::Corroborative,
            // Outside the subject, but with no implemented mechanism in this
            // build: an operator could anchor one, and until they do these
            // contribute nothing beyond corroboration.
            Self::ExternalNavigationReceiver
            | Self::GroundStationTrack
            | Self::IndependentRadioObservation => EvidenceCeiling::Corroborative,
            // Backed by a real mechanism and a real attested batch. Capped at
            // `Attested` by the class table, because the content is measured
            // on the observed host and host root forges it.
            Self::CompanionProcessObservation | Self::CompanionNetworkObservation => {
                EvidenceCeiling::Attested
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_two_sources_can_produce_an_observation_record() {
        let backed: Vec<TelemetrySource> = TelemetrySource::ALL
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect();
        assert_eq!(
            backed,
            vec![
                TelemetrySource::CompanionProcessObservation,
                TelemetrySource::CompanionNetworkObservation
            ],
            "only the companion computer's Linux mechanisms are implemented"
        );
    }

    #[test]
    fn no_avionics_sensor_has_a_mechanism() {
        for s in [
            TelemetrySource::FlightControllerTelemetry,
            TelemetrySource::GnssReceiverOnboard,
            TelemetrySource::ImuOnboard,
            TelemetrySource::BarometerOnboard,
            TelemetrySource::AirspeedProbeOnboard,
        ] {
            assert!(s.mechanism().is_none(), "{s:?} must have no mechanism");
            assert!(s.observation_class().is_none(), "{s:?} must have no class");
            assert!(!s.can_produce_observation_record(), "{s:?}");
        }
    }

    #[test]
    fn no_source_reaches_proven() {
        for s in TelemetrySource::ALL {
            assert_ne!(
                s.ceiling(),
                EvidenceCeiling::Proven,
                "{s:?} reached Proven; only ObserverIntegrity may, and no telemetry is \
                 recomputable from held bytes"
            );
        }
    }

    #[test]
    fn every_onboard_source_is_capped_at_corroborative() {
        for s in TelemetrySource::ALL
            .iter()
            .copied()
            .filter(|s| s.is_onboard_subject())
        {
            assert_eq!(
                s.ceiling(),
                EvidenceCeiling::Corroborative,
                "{s:?} is inside the subject and must not carry a positive finding alone"
            );
        }
    }

    #[test]
    fn independence_is_the_negation_of_being_onboard() {
        for s in TelemetrySource::ALL {
            assert_eq!(s.is_independent(), !s.is_onboard_subject(), "{s:?}");
        }
    }

    #[test]
    fn a_sources_class_is_never_physical_effect() {
        for s in TelemetrySource::ALL {
            assert_ne!(
                s.observation_class(),
                Some(ObservationClass::PhysicalEffect),
                "{s:?} claimed the physical-effect class, which has no mechanism (ADR-003)"
            );
        }
    }

    #[test]
    fn wire_codes_are_unique_and_stable() {
        let mut codes: Vec<u8> = TelemetrySource::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), TelemetrySource::ALL.len());
        // Pin the first and last so a reorder is a test failure, not a silent
        // reinterpretation of previously encoded bytes.
        assert_eq!(TelemetrySource::FlightControllerTelemetry.code(), 0x01);
        assert_eq!(TelemetrySource::CompanionNetworkObservation.code(), 0x0B);
    }

    #[test]
    fn every_source_answers_all_six_questions() {
        for s in TelemetrySource::ALL {
            for text in [
                s.observes(),
                s.establishes(),
                s.does_not_establish(),
                s.trust_basis(),
                s.failure_mode(),
            ] {
                assert!(!text.is_empty(), "{s:?} left a column blank");
            }
        }
    }
}
