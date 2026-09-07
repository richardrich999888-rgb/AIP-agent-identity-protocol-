//! Navigation quantities, and the five separate questions to ask about each.
//!
//! # Why five questions and not one confidence number
//!
//! "How sure are we about the altitude?" has no useful answer, because the
//! ways of being sure are not commensurable. A signed barometric reading and a
//! ground radar track are both "evidence for altitude" and they fail in
//! completely unrelated ways; averaging them into a score destroys exactly the
//! information an incident review needs.
//!
//! So each quantity carries five independent booleans, and the interesting
//! ones are not the ones people reach for:
//!
//! | question | what a `true` means |
//! |---|---|
//! | self-reported | the subject said so |
//! | cryptographically authenticated | the subject's signature is intact |
//! | independently observed | a party outside the subject measured it |
//! | cross-observed | two or more *independent* parties measured it |
//! | physically measured | an independent physical mechanism measured it |
//!
//! **Authentication is deliberately not on the occurrence path.** A valid
//! signature over an altitude establishes that the autopilot said 100 m and
//! that the message was not altered. It establishes nothing whatsoever about
//! the aircraft's height. The two facts are routinely conflated, and the
//! conflation is why this field exists next to the others rather than above
//! them.
//!
//! # What this build can answer
//!
//! For every quantity below: `independently_observed` is false, because no
//! mechanism produces one. That is not a default — it is computed from the
//! declared sources through [`TelemetrySource::is_independent`] and
//! [`TelemetrySource::can_produce_observation_record`], so a deployment that
//! later anchors a ground tracker gets a different answer without editing this
//! file's prose.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::telemetry::TelemetrySource;

/// A quantity a UAS reports about its own state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NavigationQuantity {
    /// Horizontal position: latitude and longitude in a stated frame.
    Position,
    /// Vertical position, against a stated reference. See
    /// [`crate::geofence::AltitudeReference`] — "altitude" alone names nothing.
    Altitude,
    /// Velocity over ground, or airspeed. Two different quantities that share
    /// a word; a profile that conflated them would compare a headwind to a
    /// track.
    Velocity,
    /// Attitude: roll, pitch, yaw.
    Attitude,
    /// Heading, which is not track and not course.
    Heading,
    /// The time a report is about.
    ///
    /// Included because every other quantity is meaningless without it, and
    /// because an aircraft's clock is the aircraft's.
    Time,
    /// Whether a command or telemetry link was present.
    LinkState,
}

impl NavigationQuantity {
    pub const ALL: [NavigationQuantity; 7] = [
        Self::Position,
        Self::Altitude,
        Self::Velocity,
        Self::Attitude,
        Self::Heading,
        Self::Time,
        Self::LinkState,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Position => 0x01,
            Self::Altitude => 0x02,
            Self::Velocity => 0x03,
            Self::Attitude => 0x04,
            Self::Heading => 0x05,
            Self::Time => 0x06,
            Self::LinkState => 0x07,
        }
    }

    /// The sources that bear on this quantity at all.
    ///
    /// Bearing on a quantity is not the same as establishing it: a GNSS
    /// receiver bears on position and establishes nothing, because it is
    /// inside the subject.
    pub fn candidate_sources(self) -> &'static [TelemetrySource] {
        use TelemetrySource::*;
        match self {
            Self::Position => &[
                GnssReceiverOnboard,
                FlightControllerTelemetry,
                ExternalNavigationReceiver,
                GroundStationTrack,
            ],
            Self::Altitude => &[
                BarometerOnboard,
                GnssReceiverOnboard,
                FlightControllerTelemetry,
                GroundStationTrack,
            ],
            Self::Velocity => &[
                GnssReceiverOnboard,
                AirspeedProbeOnboard,
                ImuOnboard,
                FlightControllerTelemetry,
                GroundStationTrack,
            ],
            Self::Attitude => &[ImuOnboard, FlightControllerTelemetry],
            Self::Heading => &[ImuOnboard, GnssReceiverOnboard, FlightControllerTelemetry],
            Self::Time => &[
                GnssReceiverOnboard,
                FlightControllerTelemetry,
                ExternalNavigationReceiver,
            ],
            Self::LinkState => &[
                FlightControllerTelemetry,
                IndependentRadioObservation,
                CompanionNetworkObservation,
            ],
        }
    }
}

/// What is known about one quantity, from a declared set of sources.
///
/// Every field is **computed** by [`Self::from_sources`]. There is no
/// constructor that lets a caller assert `independently_observed`, because a
/// caller that could assert it would eventually assert it wrongly, and this is
/// the exact field a compromised integrator would want to set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigationEvidence {
    pub quantity: NavigationQuantity,
    /// A source inside the subject reported it.
    pub self_reported: bool,
    /// That report carries an intact signature from the subject.
    ///
    /// Supplied by the caller because it is a fact about a message this crate
    /// never sees. It is carried, never promoted: no method reads it when
    /// deciding what was established.
    pub cryptographically_authenticated: bool,
    /// A party outside the subject measured it **through a mechanism that can
    /// produce an observation record**.
    pub independently_observed: bool,
    /// Two or more independent parties measured it.
    pub cross_observed: bool,
    /// An independent *physical* mechanism measured it.
    ///
    /// False for every quantity in this build. `ObservationClass::PhysicalEffect`
    /// has no mechanism (ADR-003 decision 2), so there is nothing that could
    /// set it.
    pub physically_measured: bool,
}

impl NavigationEvidence {
    /// Compute what is known about `quantity` from the sources a deployment
    /// declares it has.
    ///
    /// `authenticated` says whether the subject's reports are signed. It moves
    /// exactly one field and reaches no conclusion.
    pub fn from_sources(
        quantity: NavigationQuantity,
        declared: &[TelemetrySource],
        authenticated: bool,
    ) -> Self {
        let relevant: Vec<TelemetrySource> = quantity
            .candidate_sources()
            .iter()
            .copied()
            .filter(|s| declared.contains(s))
            .collect();

        let self_reported = relevant.iter().any(|s| s.is_onboard_subject());

        // The load-bearing conjunction. A source must be *outside the subject*
        // AND *backed by a mechanism that can produce a record*. Dropping
        // either half is how an external source with no implementation, or an
        // onboard source with a signature, gets read as independent evidence.
        let independent: Vec<TelemetrySource> = relevant
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
            // No mechanism implements a physical measurement of any of these
            // quantities. Computed from the class table rather than written as
            // `false`, so implementing one has to change the table and fail
            // the test rather than leave a stale literal behind.
            physically_measured: independent.iter().any(|s| {
                s.observation_class() == Some(aip_observation::ObservationClass::PhysicalEffect)
            }),
        }
    }

    /// Whether this quantity is established well enough to be *used* as a fact
    /// about the world.
    ///
    /// True only when something outside the subject observed it. Neither
    /// `self_reported` nor `cryptographically_authenticated` appears in this
    /// expression, and that omission is the whole point.
    pub fn establishes(&self) -> bool {
        self.independently_observed
    }

    /// The strongest evidence this quantity could contribute.
    ///
    /// `Corroborative` when nothing independent bears on it — the honest
    /// floor, meaning *this cannot support a positive finding on its own*.
    /// `Attested` when something independent does. **Never `Proven`**: no
    /// navigation quantity is recomputable from bytes a third party holds, so
    /// the rung above `Attested` is unreachable for all seven, permanently, by
    /// the same argument ADR-003 makes for every host-measured class.
    pub fn ceiling(&self) -> EvidenceCeiling {
        if self.independently_observed {
            EvidenceCeiling::Attested
        } else {
            EvidenceCeiling::Corroborative
        }
    }

    /// One line for a report: what a verifier may say about this quantity.
    pub fn statement(&self) -> &'static str {
        match (self.independently_observed, self.self_reported) {
            (true, _) => "independently observed; usable as a fact, ceilinged at Attested",
            (false, true) => {
                "self-reported only; establishes that the subject said so, and nothing about \
                 the world, however it is signed"
            }
            (false, false) => "no source bears on this quantity in this deployment",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a realistic UAS actually carries today.
    const TYPICAL: [TelemetrySource; 6] = [
        TelemetrySource::FlightControllerTelemetry,
        TelemetrySource::GnssReceiverOnboard,
        TelemetrySource::ImuOnboard,
        TelemetrySource::BarometerOnboard,
        TelemetrySource::AirspeedProbeOnboard,
        TelemetrySource::CompanionAutonomyReport,
    ];

    #[test]
    fn no_navigation_quantity_is_established_by_a_typical_airframe() {
        for q in NavigationQuantity::ALL {
            let e = NavigationEvidence::from_sources(q, &TYPICAL, true);
            assert!(
                !e.establishes(),
                "{q:?} was established by onboard sensors alone"
            );
            assert_eq!(e.ceiling(), EvidenceCeiling::Corroborative, "{q:?}");
        }
    }

    #[test]
    fn signing_the_telemetry_changes_nothing_about_what_is_established() {
        for q in NavigationQuantity::ALL {
            let signed = NavigationEvidence::from_sources(q, &TYPICAL, true);
            let unsigned = NavigationEvidence::from_sources(q, &TYPICAL, false);
            assert_eq!(
                signed.establishes(),
                unsigned.establishes(),
                "{q:?}: a signature moved the occurrence answer"
            );
            assert_eq!(signed.ceiling(), unsigned.ceiling(), "{q:?}");
            // The one field it may move.
            assert!(signed.cryptographically_authenticated);
            assert!(!unsigned.cryptographically_authenticated);
        }
    }

    #[test]
    fn gnss_is_not_ground_truth() {
        let e = NavigationEvidence::from_sources(
            NavigationQuantity::Position,
            &[TelemetrySource::GnssReceiverOnboard],
            true,
        );
        assert!(e.self_reported);
        assert!(!e.independently_observed);
        assert!(!e.establishes());
        assert_eq!(e.ceiling(), EvidenceCeiling::Corroborative);
    }

    #[test]
    fn imu_is_not_ground_truth() {
        let e = NavigationEvidence::from_sources(
            NavigationQuantity::Attitude,
            &[TelemetrySource::ImuOnboard],
            true,
        );
        assert!(!e.establishes());
    }

    #[test]
    fn an_external_source_with_no_mechanism_does_not_establish_either() {
        // Positional independence is necessary and not sufficient. A ground
        // tracker nobody implemented is still nobody observing.
        let e = NavigationEvidence::from_sources(
            NavigationQuantity::Position,
            &[TelemetrySource::GroundStationTrack],
            false,
        );
        assert!(!e.independently_observed);
        assert!(!e.establishes());
    }

    #[test]
    fn the_link_state_is_the_one_quantity_with_a_real_mechanism() {
        // `CompanionNetworkObservation` is backed by `ProcNetTable`, which an
        // anchored collector really attests. It bears on link state and on
        // nothing else in this list.
        let e = NavigationEvidence::from_sources(
            NavigationQuantity::LinkState,
            &[TelemetrySource::CompanionNetworkObservation],
            false,
        );
        assert!(e.independently_observed);
        assert!(e.establishes());
        assert_eq!(e.ceiling(), EvidenceCeiling::Attested);
        assert!(!e.cross_observed, "one observer is not two");
    }

    #[test]
    fn nothing_is_physically_measured_in_this_build() {
        for q in NavigationQuantity::ALL {
            let e = NavigationEvidence::from_sources(q, &TelemetrySource::ALL, true);
            assert!(
                !e.physically_measured,
                "{q:?} claimed a physical measurement; no mechanism implements one"
            );
        }
    }

    #[test]
    fn no_quantity_can_reach_proven_under_any_declared_source_set() {
        for q in NavigationQuantity::ALL {
            let e = NavigationEvidence::from_sources(q, &TelemetrySource::ALL, true);
            assert_ne!(
                e.ceiling(),
                EvidenceCeiling::Proven,
                "{q:?} reached Proven; no navigation quantity is recomputable from held bytes"
            );
        }
    }

    #[test]
    fn cross_observation_needs_two_independent_mechanised_sources() {
        let e = NavigationEvidence::from_sources(
            NavigationQuantity::LinkState,
            &[
                TelemetrySource::CompanionNetworkObservation,
                TelemetrySource::IndependentRadioObservation,
            ],
            false,
        );
        // The radio observer is independent but has no mechanism, so it does
        // not count toward cross-observation.
        assert!(e.independently_observed);
        assert!(
            !e.cross_observed,
            "an unimplemented second observer must not create cross-observation"
        );
    }
}
