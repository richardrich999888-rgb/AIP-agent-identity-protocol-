//! `aip-robotics` — the robotics autonomy accountability profile (Skill 24).
//!
//! # The claim, in one sentence
//!
//! Vanian can account for a robot's **autonomy runtime execution**. It cannot
//! account for what the robot's body did, and every claim about motion,
//! contact, object state or task outcome resolves to `CANNOT_PROVE` unless a
//! deployment supplies an independent physical mechanism, which this build does
//! not have.
//!
//! # Why this is harder than the UAS case
//!
//! Skill 23 had to keep telemetry apart from truth. A robot adds a second
//! problem on top of that one: **it touches things.** An aircraft's honest
//! failure mode is being somewhere other than it says. A manipulator's is
//! reporting a successful grasp while holding nothing, having closed on air,
//! having crushed the object, or having grasped the wrong one — and every one
//! of those produces the same gripper-closed signal.
//!
//! So the chain has more rungs and each is a real boundary:
//!
//! ```text
//!   autonomous decision      software      observable here
//!   task command             software      observable here
//!   controller command       a message     not observed
//!   actuator execution       a device      not observed
//!   observed actuator state  a sensor      not observed
//!   contact interaction      the world     not observed
//!   physical outcome         the world     not observed
//!   task success             a judgement   not observed
//! ```
//!
//! Two of eight. The same two as the UAS profile, and for the same structural
//! reason: `ObservationRecord::from_attested` requires a `SourceMechanism`,
//! that enum is nine Linux facilities, and a wheel encoder is not one.
//!
//! # The second new problem: semantic drift
//!
//! Robotics measurements are routinely reported in language that outruns them,
//! and the gap is where people get hurt:
//!
//! | measured | said |
//! |---|---|
//! | a range sensor returned 1.0 m | safe separation was achieved |
//! | a motion field changed | a human is present |
//! | a current spike on a joint | a collision occurred |
//! | a gripper aperture stopped closing | the object was grasped |
//!
//! [`semantics`] holds that gap open: each measurement names what it measures,
//! what it actually establishes, and the claim it is commonly read as. None of
//! the interesting claims is establishable from measurement alone, and the
//! module says so per claim rather than in a comment.
//!
//! # What this crate does not contain
//!
//! No identifier — `SystemId`, `PlatformId`, `HardwareId` and `MissionId`
//! already exist and are reused, with a robot's controller and companion
//! computer expressed as two `HardwareId`s in different namespaces under one
//! `PlatformId`. No observation record, no platform binding, no execution
//! model, no effect assessment, no reconciler, no verifier, no trust anchor, no
//! signing key, no leaf kind and no evidence-strength vocabulary.
//! `tests/no_second_architecture.rs` asserts that over this crate's source.
//!
//! Task authority is not a new authorization engine: a [`task::TaskPlan`]
//! commits its digest into `ActionParameters`, which a decision point signs as
//! `ExpectedExecution.parameter_digest` — the mechanism Skills 18 and 23
//! already use.
//!
//! # Composition
//!
//! ```text
//!   generic accountability core      unchanged
//!            ↓
//!   generic observation (Skill 20)   unchanged
//!            ↓
//!   aip-robotics                     this crate
//!            ↓
//!   robotics adapters                the deployment's (ROS, controller buses)
//! ```
//!
//! No robotics framework is assumed. Adding industrial, space or enterprise
//! later requires no change here and none below.

#![forbid(unsafe_code)]

pub mod action;
pub mod corroborate;
pub mod embodiment;
pub mod error;
pub mod identity;
pub mod manipulation;
pub mod navigation;
pub mod profile;
pub mod safety;
pub mod semantics;
pub mod sensing;
pub mod task;

pub use action::{robot_action, RobotAction, ROBOT_ACTION_PREFIX};
pub use corroborate::{Agreement, SensorAgreement};
pub use embodiment::{EmbodiedChain, EmbodiedRung};
pub use error::RoboticsError;
pub use identity::{RobotIdentityKind, RobotIdentityStability};
pub use manipulation::{ManipulationEvidence, ObjectStateClaim};
pub use navigation::{NavigationEvidence, PoseQuantity};
pub use profile::{RoboticsProfile, ROBOTICS_PROFILE_ID};
pub use safety::{SafetyAction, SafetyEvidence};
pub use semantics::{ClaimSupport, Measurement, SemanticClaim};
pub use sensing::SensingSource;
pub use task::{TaskEvidence, TaskPlan, TaskState, TaskWindow, TASK_PARAMETER_KEY};

/// Domain tag leading every canonical encoding this crate produces.
///
/// One tag for the crate, with a structure discriminant inside each preimage,
/// so two profile structures can never collide and neither can collide with a
/// core structure or with the UAS profile's.
pub const ROBOTICS_PROFILE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/ROBOTICS_PROFILE/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const ROBOTICS_PROFILE_VERSION: u16 = 1;
