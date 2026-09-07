//! `aip-uas` — the UAS accountability profile (Skill 23).
//!
//! # What this crate is, in one sentence
//!
//! It specialises the existing accountability core for uncrewed aerial
//! systems, and its central contribution is stating precisely how little that
//! core can honestly say about an aircraft.
//!
//! # The finding that shapes everything below
//!
//! `ObservationRecord::from_attested` — the only constructor of an observation
//! record anywhere in this workspace — requires an `AttestedBatch` whose
//! observations carry a [`aip_observe::SourceMechanism`]. That enum is a
//! closed set of **nine Linux mechanisms**. A GNSS receiver, an IMU, a
//! barometer, an airspeed probe and a MAVLink telemetry stream are none of
//! them, and `class_of` maps nothing to
//! `ObservationClass::PhysicalEffect` (ADR-003 decision 2).
//!
//! So in this build **no avionics sensor can produce an observation record at
//! all.** Not a weak one. None.
//!
//! What a UAS deployment *can* independently establish today is exactly what
//! the companion computer's Linux mechanisms establish: that an autonomy
//! software instance ran, which executable it was, and that it opened a link
//! and moved bytes. That is real evidence, and it is not the aircraft moving.
//!
//! ```text
//!   ESTABLISHED           the autonomy computer's execution
//!                         (ProcessIdentity, NetworkSocket, DataTransfer)
//!
//!   NOT ESTABLISHED       position · altitude · velocity · attitude ·
//!                         heading · that a control surface moved ·
//!                         that a payload released · that the aircraft
//!                         landed · that a mission was achieved
//! ```
//!
//! Representing that boundary — rather than papering it over with
//! authenticated telemetry — is this crate's deliverable. Authenticity is a
//! statement about a signature. It is never a statement about the world.
//!
//! # What this crate does not contain
//!
//! No identifier: `SystemId`, `PlatformId`, `HardwareId` and `MissionId`
//! already exist and are reused verbatim, with the profile expressing a flight
//! controller and a companion computer as two `HardwareId`s in different
//! namespaces under one `PlatformId`.
//!
//! No observation record, no platform binding, no execution model, no effect
//! assessment, no reconciler, no verifier, no trust anchor, no signing key and
//! no evidence-strength vocabulary. `tests/no_second_architecture.rs` asserts
//! that over this crate's own source.
//!
//! Mission authority is not a new authority system: a [`mission::MissionPlan`]
//! commits its digest into `ActionParameters`, which the decision point signs
//! as `ExpectedExecution.parameter_digest`. That is the same mechanism
//! `ExecutionProfile::authorization_parameter` uses, and it introduces no
//! signer.
//!
//! # Composition
//!
//! ```text
//!   generic accountability core      unchanged
//!            ↓
//!   generic observation (Skill 20)   unchanged
//!            ↓
//!   aip-uas                          this crate
//!            ↓
//!   telemetry adapters               the deployment's, not this crate's
//! ```
//!
//! Adding UGV, robotics, industrial, space or enterprise later requires no
//! change here and no change below. Nothing in the verdict path depends on
//! this crate.

#![forbid(unsafe_code)]

pub mod action;
pub mod corroborate;
pub mod error;
pub mod flightcontrol;
pub mod geofence;
pub mod link;
pub mod mission;
pub mod navigation;
pub mod profile;
pub mod state;
pub mod telemetry;

pub use action::{uas_action, UasAction, UAS_ACTION_PREFIX};
pub use corroborate::{Agreement, SensorAgreement};
pub use error::UasError;
pub use flightcontrol::{CommandRung, FlightControlLadder};
pub use geofence::{AltitudeReference, CoordinateFrame, GeofenceAssessment, GeofenceRegion};
pub use link::{LinkObservation, LinkState};
pub use mission::{MissionPlan, MissionWindow, MISSION_PARAMETER_KEY};
pub use navigation::{NavigationEvidence, NavigationQuantity};
pub use profile::{UasProfile, UAS_PROFILE_ID};
pub use state::{MissionState, StateEvidence};
pub use telemetry::TelemetrySource;

/// Domain tag leading every canonical encoding this crate produces.
///
/// One tag for one crate: the structures below are all parts of one profile
/// document, and each carries its own discriminant inside the encoding rather
/// than claiming a domain of its own. A profile that minted domain tags freely
/// would be a profile that could collide with the core's.
pub const UAS_PROFILE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/UAS_PROFILE/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const UAS_PROFILE_VERSION: u16 = 1;
