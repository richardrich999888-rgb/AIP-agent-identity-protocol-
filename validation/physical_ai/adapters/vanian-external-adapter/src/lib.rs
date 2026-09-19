//! `vanian-external-adapter` — the admission gate between external
//! robotics/UAS/industrial tooling and Vanian's evidence model.
//!
//! # What this is for
//!
//! The Skill 25 validation roadmap runs external tools — ROS 2, Gazebo,
//! `ros2_control`, Nav2, MoveIt 2, `rosbag2`, `ros2_tracing`, OpenCV, AprilTag,
//! PX4, MAVLink, MAVSDK, OPC UA, 4diac — as **subjects, environments, telemetry
//! sources and reference observers**. None of them is a trust anchor, and none
//! of them is automatically independent proof.
//!
//! Something has to enforce that, mechanically, at the point where an external
//! tool's output would enter the evidence model. This crate is that point.
//!
//! > **The actor must not control the evidence used to judge the actor.**
//!
//! # Three layers, kept apart
//!
//! ```text
//!   RAW             raw::RawCapture         bytes as emitted, hashed at capture
//!   NORMALIZED      normalize::ExternalObservation
//!   CLASSIFICATION  classify::Admission     the verdict, and its refusals
//! ```
//!
//! Each layer is a separate value derived from the one below it. The raw bytes
//! are never replaced, so a normalisation can be checked, and a classification
//! can be re-derived offline from the stored trace.
//!
//! # What it will not do
//!
//! It constructs no `ObservationRecord`, holds no key, signs nothing, defines no
//! evidence vocabulary and mints no identifier. `EvidenceCeiling` and
//! `SourceMechanism` are the production types, consumed and not extended —
//! reusing them is the point, because an adapter with its own ceiling would be
//! the second evidence hierarchy the exercise exists to prevent.
//!
//! The strongest verdict it can return is
//! [`classify::Admission::EligibleForObservationRecord`], which says the
//! production path *could* be handed this observation. That rung is unreachable
//! for every optical and simulator source in this build, computed rather than
//! asserted: it needs an implemented `SourceMechanism`, and a camera is not a
//! Linux kernel facility.
//!
//! # Nothing here is a production dependency
//!
//! This crate carries its own `[workspace]` table, is not a member of the
//! repository workspace, and nothing in `aip-*` depends on it. The dependency
//! points one way, so no validation tooling can cause a semantic regression in
//! the accountability model it is validating.

#![forbid(unsafe_code)]

pub mod agreement;
pub mod classify;
pub mod normalize;
pub mod observer;
pub mod provenance;
pub mod raw;

pub use agreement::{Agreement, SourceAgreement};
pub use classify::{admit, Admission, AdmissionLedger, AdmissionPolicy, RefusalReason};
pub use normalize::{EventType, ExternalObservation, ObservationNonce, SubjectIdentity};
pub use observer::ObserverPosture;
pub use provenance::ProvenanceClass;
pub use raw::{CaptureError, RawCapture};
