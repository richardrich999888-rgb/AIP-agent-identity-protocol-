//! UAS actions, mapped onto the existing execution model.
//!
//! # No parallel ladder
//!
//! Every action below is an ordinary `ScopeAction::Custom` in the decision
//! point's vocabulary and an ordinary `RequestedEffect` in Skill 18's model.
//! `aip-authorize` needs no change: it already accepts custom action kinds,
//! and the scope machinery already matches them.
//!
//! What this module adds is the six-column table the brief asks for, computed
//! rather than written in a comment — for each action, what each rung of the
//! ladder would take.
//!
//! ```text
//!   REQUEST     the autonomy stack asked for it            SelfReported
//!   AUTHORIZED  a decision point signed an expectation     Recomputable
//!   EXPECTED    the expectation names this action kind     Recomputable
//!   EXECUTED    the autonomy stack says its call returned  SelfReported
//!   OBSERVED    an anchored observer measured something    IndependentlyObserved
//!   EFFECT      the aircraft did the thing                 IndependentlyObserved
//! ```
//!
//! The last two columns are where every UAS action stops. `OBSERVED` is
//! reachable only for the part of an action that happens on the companion
//! computer — a process running, a link carrying bytes. `EFFECT` is reachable
//! for none of them, because no mechanism observes an aircraft.

use aip_authorize::ActionParameters;
use aip_types::ScopeAction;
use serde::{Deserialize, Serialize};

use crate::telemetry::TelemetrySource;

/// Prefix of every action kind this profile defines.
///
/// Namespaced under `uas.` so a UAS action can never collide with the core's
/// `ghost.*` vocabulary, and so a verifier reading a scope can tell which
/// profile an action belongs to without a lookup table.
pub const UAS_ACTION_PREFIX: &str = "uas.";

/// Parameter keys. Values are raw bytes rather than text, so there is exactly
/// one encoding of each.
pub const PARAM_WAYPOINT_LAT_UDEG: &str = "waypoint_lat_udeg";
pub const PARAM_WAYPOINT_LON_UDEG: &str = "waypoint_lon_udeg";
pub const PARAM_WAYPOINT_ALT_CM: &str = "waypoint_alt_cm";
pub const PARAM_ALTITUDE_REFERENCE: &str = "altitude_reference";
pub const PARAM_PAYLOAD_ID: &str = "payload_id";

/// An action a UAS mission may authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum UasAction {
    Takeoff,
    WaypointNavigate,
    Loiter,
    RouteChange,
    ReturnToHome,
    Land,
    PayloadEnable,
    PayloadRelease,
    EmergencyStop,
}

impl UasAction {
    pub const ALL: [UasAction; 9] = [
        Self::Takeoff,
        Self::WaypointNavigate,
        Self::Loiter,
        Self::RouteChange,
        Self::ReturnToHome,
        Self::Land,
        Self::PayloadEnable,
        Self::PayloadRelease,
        Self::EmergencyStop,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Takeoff => 0x01,
            Self::WaypointNavigate => 0x02,
            Self::Loiter => 0x03,
            Self::RouteChange => 0x04,
            Self::ReturnToHome => 0x05,
            Self::Land => 0x06,
            Self::PayloadEnable => 0x07,
            Self::PayloadRelease => 0x08,
            Self::EmergencyStop => 0x09,
        }
    }

    /// The action kind string a decision point authorizes over.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Takeoff => "uas.flight.takeoff.v1",
            Self::WaypointNavigate => "uas.flight.waypoint.v1",
            Self::Loiter => "uas.flight.loiter.v1",
            Self::RouteChange => "uas.flight.route_change.v1",
            Self::ReturnToHome => "uas.flight.return_to_home.v1",
            Self::Land => "uas.flight.land.v1",
            Self::PayloadEnable => "uas.payload.enable.v1",
            Self::PayloadRelease => "uas.payload.release.v1",
            Self::EmergencyStop => "uas.flight.emergency_stop.v1",
        }
    }

    /// Whether this action's completion is a claim about the **aircraft**
    /// rather than about software.
    ///
    /// True for all nine. That is not an oversight: every action a UAS mission
    /// authorizes is ultimately a claim about a physical machine, which is why
    /// the `EFFECT` column below is unreachable across the board.
    pub fn is_physical_action(self) -> bool {
        true
    }

    /// What could observe the software half of this action in this build.
    ///
    /// The companion computer's process and socket observation, for every
    /// action, and nothing more. An action's software half is "the autonomy
    /// stack ran and sent something"; its physical half is unobserved.
    pub fn observable_by(self) -> &'static [TelemetrySource] {
        &[
            TelemetrySource::CompanionProcessObservation,
            TelemetrySource::CompanionNetworkObservation,
        ]
    }

    /// Whether an anchored observer could establish that the **effect**
    /// occurred.
    ///
    /// False for all nine, computed from the class table so that implementing
    /// a physical mechanism has to change the table rather than leave this
    /// stale.
    pub fn effect_observable(self) -> bool {
        aip_observation::ObservationClass::PhysicalEffect.is_implemented()
    }

    /// The gap between what the software did and what the aircraft did, in one
    /// line, for a report.
    pub fn effect_gap(self) -> &'static str {
        match self {
            Self::Takeoff => "a takeoff command accepted is not an aircraft leaving the ground",
            Self::WaypointNavigate => {
                "a waypoint command accepted is not an aircraft arriving anywhere"
            }
            Self::Loiter => "a loiter command accepted is not an aircraft holding a pattern",
            Self::RouteChange => "a route uploaded is not a route flown",
            Self::ReturnToHome => {
                "a return-to-home command accepted is not an aircraft that returned"
            }
            Self::Land => "a landing command accepted is not an aircraft on the ground",
            Self::PayloadEnable => "a payload armed in software is not a payload armed in hardware",
            Self::PayloadRelease => {
                "a release command acknowledged is not a payload that left the aircraft"
            }
            Self::EmergencyStop => {
                "an emergency stop accepted is not motors that stopped producing thrust"
            }
        }
    }
}

/// The `ScopeAction` for a UAS action.
///
/// `ScopeAction::Custom` already exists and already works; this function is a
/// convenience over it, not an extension of the authorization vocabulary.
pub fn uas_action(action: UasAction) -> ScopeAction {
    ScopeAction::Custom(action.kind().to_string())
}

/// Parameters naming one waypoint, byte for byte.
///
/// The altitude reference is a parameter rather than an assumption: a waypoint
/// at "100" authorized against one reference and flown against another is the
/// coordinate-frame confusion this profile exists to make impossible to
/// perform silently.
pub fn waypoint_parameters(
    lat_udeg: i64,
    lon_udeg: i64,
    alt_cm: i64,
    reference: crate::geofence::AltitudeReference,
) -> ActionParameters {
    ActionParameters::from_pairs([
        (PARAM_WAYPOINT_LAT_UDEG, lat_udeg.to_le_bytes().to_vec()),
        (PARAM_WAYPOINT_LON_UDEG, lon_udeg.to_le_bytes().to_vec()),
        (PARAM_WAYPOINT_ALT_CM, alt_cm.to_le_bytes().to_vec()),
        (PARAM_ALTITUDE_REFERENCE, vec![reference.code()]),
    ])
    .expect("four distinct constant keys")
}

/// Parameters naming one payload.
pub fn payload_parameters(payload_id: &str) -> Result<ActionParameters, crate::error::UasError> {
    if payload_id.is_empty() || payload_id.len() > 128 {
        return Err(crate::error::UasError::Malformed {
            reason: "payload id must be 1-128 bytes",
        });
    }
    Ok(
        ActionParameters::from_pairs([(PARAM_PAYLOAD_ID, payload_id.as_bytes().to_vec())])
            .expect("one constant key"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_kind_is_namespaced_and_versioned() {
        for a in UasAction::ALL {
            assert!(
                a.kind().starts_with(UAS_ACTION_PREFIX),
                "{a:?} escaped the uas. namespace"
            );
            assert!(a.kind().ends_with(".v1"), "{a:?} is unversioned");
        }
    }

    #[test]
    fn action_kinds_are_unique() {
        let mut kinds: Vec<&str> = UasAction::ALL.iter().map(|a| a.kind()).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), UasAction::ALL.len());
    }

    #[test]
    fn no_uas_action_reaches_an_observable_effect() {
        for a in UasAction::ALL {
            assert!(a.is_physical_action(), "{a:?}");
            assert!(
                !a.effect_observable(),
                "{a:?} claimed an observable effect; no mechanism observes an aircraft"
            );
        }
    }

    #[test]
    fn an_actions_software_half_is_observable_and_its_physical_half_is_not() {
        for a in UasAction::ALL {
            let sources = a.observable_by();
            assert!(!sources.is_empty(), "{a:?}");
            for s in sources {
                assert!(
                    s.can_produce_observation_record(),
                    "{a:?} names {s:?}, which has no mechanism"
                );
                assert!(s.is_independent(), "{a:?} names an onboard source");
            }
        }
    }

    #[test]
    fn a_uas_action_is_an_ordinary_custom_scope_action() {
        // The point: `aip-authorize` needs no change.
        match uas_action(UasAction::PayloadRelease) {
            ScopeAction::Custom(s) => assert_eq!(s, "uas.payload.release.v1"),
            other => panic!("expected a custom action, got {other:?}"),
        }
    }

    #[test]
    fn waypoint_parameters_are_sensitive_to_the_altitude_reference() {
        use crate::geofence::AltitudeReference;
        let msl = waypoint_parameters(1, 2, 3, AltitudeReference::GeoidMsl);
        let agl = waypoint_parameters(1, 2, 3, AltitudeReference::AboveGroundLevel);
        assert_ne!(
            msl.digest(),
            agl.digest(),
            "the same number against two references is two different waypoints"
        );
    }

    #[test]
    fn waypoint_parameters_are_sensitive_to_every_coordinate() {
        use crate::geofence::AltitudeReference;
        let base = waypoint_parameters(1, 2, 3, AltitudeReference::GeoidMsl);
        for other in [
            waypoint_parameters(9, 2, 3, AltitudeReference::GeoidMsl),
            waypoint_parameters(1, 9, 3, AltitudeReference::GeoidMsl),
            waypoint_parameters(1, 2, 9, AltitudeReference::GeoidMsl),
        ] {
            assert_ne!(base.digest(), other.digest());
        }
    }

    #[test]
    fn a_negative_coordinate_encodes_distinctly() {
        use crate::geofence::AltitudeReference;
        assert_ne!(
            waypoint_parameters(-1, 0, 0, AltitudeReference::GeoidMsl).digest(),
            waypoint_parameters(1, 0, 0, AltitudeReference::GeoidMsl).digest(),
        );
    }

    #[test]
    fn an_empty_payload_id_is_refused() {
        assert!(payload_parameters("").is_err());
        assert!(payload_parameters(&"x".repeat(129)).is_err());
        assert!(payload_parameters("hopper-1").is_ok());
    }

    #[test]
    fn every_action_states_its_effect_gap() {
        for a in UasAction::ALL {
            assert!(!a.effect_gap().is_empty(), "{a:?}");
        }
    }
}
