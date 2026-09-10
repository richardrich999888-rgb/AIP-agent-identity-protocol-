//! Link state, and the four sentences it must never be turned into.
//!
//! ```text
//!   no telemetry      is not      the aircraft did not move
//!   link lost         is not      the mission failed
//!   link lost         is not      the aircraft is lost
//!   telemetry present is not      the aircraft is where it says
//! ```
//!
//! Every one of those is an inference from *the observer's* state to *the
//! subject's* state, and each is wrong in the same way: a link is a property
//! of the path between two parties, and a break in it is a fact about the
//! path. An aircraft flying a perfect mission behind a hill produces exactly
//! the same telemetry as one that has been destroyed.
//!
//! This module therefore has no method that returns a conclusion about the
//! aircraft. [`LinkState::establishes_non_occurrence`] exists and always
//! returns `false`; it is a method rather than a constant so that a future
//! variant claiming otherwise has to change this function and fail its test.

use serde::{Deserialize, Serialize};

use crate::telemetry::TelemetrySource;

/// What is known about a command or telemetry link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinkState {
    /// Traffic was observed within the deployment's expectation.
    Nominal,
    /// Traffic was observed, with loss, delay or reordering.
    Degraded,
    /// No traffic was observed over a window the observer covered.
    ///
    /// Note the qualifier. Without coverage this is not `Lost`, it is
    /// `Unknown`: an observer that was not looking has not established silence.
    Lost,
    /// No observer covered the window. The default.
    Unknown,
}

impl LinkState {
    pub const ALL: [LinkState; 4] = [Self::Nominal, Self::Degraded, Self::Lost, Self::Unknown];

    pub fn code(self) -> u8 {
        match self {
            Self::Nominal => 0x01,
            Self::Degraded => 0x02,
            Self::Lost => 0x03,
            Self::Unknown => 0xFF,
        }
    }

    /// Whether this state asserts that the aircraft did **not** do something.
    ///
    /// Always `false`, for every variant, permanently.
    pub fn establishes_non_occurrence(self) -> bool {
        false
    }

    /// Whether this state asserts anything about the aircraft at all.
    ///
    /// Also always `false`. A link state is about the link.
    pub fn establishes_vehicle_state(self) -> bool {
        false
    }

    /// Whether the *observer's* coverage supports saying anything about the
    /// link.
    ///
    /// True for the three observed states and false for `Unknown`. This is the
    /// only genuine question a link state answers.
    pub fn is_established(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// One observation bearing on link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkObservation {
    pub source: TelemetrySource,
    /// Whether the observer covered the window in question. Absence of
    /// coverage is why `Unknown` exists.
    pub covered: bool,
    /// Whether traffic was seen.
    pub traffic_seen: bool,
    /// Whether the observer reported loss, delay or reordering.
    pub impaired: bool,
}

impl LinkObservation {
    /// Derive a link state from one observation.
    ///
    /// An observation from a source **inside the subject** yields `Unknown`
    /// whatever it says: the aircraft reporting that its own link is healthy
    /// is the aircraft reporting, and a compromised aircraft reports a healthy
    /// link exactly as a working one does.
    pub fn state(&self) -> LinkState {
        if self.source.is_onboard_subject() || !self.source.can_produce_observation_record() {
            return LinkState::Unknown;
        }
        if !self.covered {
            return LinkState::Unknown;
        }
        match (self.traffic_seen, self.impaired) {
            (true, false) => LinkState::Nominal,
            (true, true) => LinkState::Degraded,
            (false, _) => LinkState::Lost,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_link_state_ever_establishes_non_occurrence() {
        for s in LinkState::ALL {
            assert!(!s.establishes_non_occurrence(), "{s:?}");
            assert!(!s.establishes_vehicle_state(), "{s:?}");
        }
    }

    #[test]
    fn a_lost_link_says_nothing_about_the_aircraft() {
        assert!(
            LinkState::Lost.is_established(),
            "the link fact is established"
        );
        assert!(
            !LinkState::Lost.establishes_vehicle_state(),
            "and it is a fact about the link"
        );
    }

    #[test]
    fn an_uncovered_window_is_unknown_not_lost() {
        let o = LinkObservation {
            source: TelemetrySource::CompanionNetworkObservation,
            covered: false,
            traffic_seen: false,
            impaired: false,
        };
        assert_eq!(
            o.state(),
            LinkState::Unknown,
            "an observer that was not looking has not established silence"
        );
    }

    #[test]
    fn the_aircrafts_own_report_of_its_link_establishes_nothing() {
        for onboard in [
            TelemetrySource::FlightControllerTelemetry,
            TelemetrySource::CompanionAutonomyReport,
        ] {
            let o = LinkObservation {
                source: onboard,
                covered: true,
                traffic_seen: true,
                impaired: false,
            };
            assert_eq!(o.state(), LinkState::Unknown, "{onboard:?}");
        }
    }

    #[test]
    fn an_independent_source_with_no_mechanism_also_yields_unknown() {
        let o = LinkObservation {
            source: TelemetrySource::IndependentRadioObservation,
            covered: true,
            traffic_seen: true,
            impaired: false,
        };
        assert_eq!(
            o.state(),
            LinkState::Unknown,
            "independence without an implemented mechanism is nobody observing"
        );
    }

    #[test]
    fn the_companion_socket_observer_can_establish_all_three_link_states() {
        let base = LinkObservation {
            source: TelemetrySource::CompanionNetworkObservation,
            covered: true,
            traffic_seen: true,
            impaired: false,
        };
        assert_eq!(base.state(), LinkState::Nominal);
        assert_eq!(
            LinkObservation {
                impaired: true,
                ..base
            }
            .state(),
            LinkState::Degraded
        );
        assert_eq!(
            LinkObservation {
                traffic_seen: false,
                ..base
            }
            .state(),
            LinkState::Lost
        );
    }
}
