//! aip-containment — Ghost Skill 9: the containment boundary.
//!
//! ```text
//! signed Warrant ─┐
//! ExecutionBinding ─┤  contain()  ──▶  ContainmentDecision ──▶ Actuator ──▶ signed
//! SignedSensorHealth ┤   (17 gates,       (what, on whose        (cgroup v2   ContainmentRecord
//! ContainmentPolicy ─┘    §contain)        authority, whom)       freeze)      (what happened)
//! ```
//!
//! # What this crate never does
//!
//! It detects nothing, observes nothing, reconciles nothing and issues no
//! warrant. It cannot be reached with a finding, a severity, a strength, a
//! confidence, a boolean, a pid or a command string: [`contain`] takes a
//! signed [`aip_warrant::Warrant`], an [`aip_types::ExecutionBinding`], the
//! cited observer's current signed health and an explicit policy, and the
//! [`Actuator`] takes an [`Attributed`] instance and a closed
//! [`ContainmentAction`]. It never upgrades evidence, never turns
//! `CANNOT_PROVE`, an unavailable observer, a degraded sensor or a missing
//! citation into an action, and never reports `Applied` unless the kernel
//! confirmed the effect.
//!
//! # Posture
//!
//! `ContainmentPolicy::default()` is `Advisory` with `AdvisoryOnly`: every
//! gate runs, the decision is signed, nothing is done. Actuation requires
//! the operator to set `AutonomousEnabled` (and the warrant engine to have
//! issued the warrant under autonomous policy) or `OperatorEnabled` with an
//! acknowledgement naming the warrant. Failures fail open and are recorded.
//!
//! # The trust roots
//!
//! The warrant authority (Skill 8), the observers (Skill 6) and this
//! crate's own [`ContainmentAuthority`] are three key holders; the record
//! verifier can refuse a containment key that equals any other.

pub mod actuator;
pub mod attribution;
pub mod contain;
pub mod record;
pub mod replay;

pub use actuator::{ActuationFailure, Actuator, Applied, CgroupV2Freezer, Mechanism};
pub use attribution::{attribute, Attributed, AttributionFailure};
pub use contain::{contain, release, Containment, ContainmentAnchors, ContainmentRequest, Hold};
pub use record::{
    verify_containment_record, verify_containment_record_distinct, ContainmentAction,
    ContainmentAuthority, ContainmentDecision, ContainmentMode, ContainmentPolicy,
    ContainmentRecord, ContainmentTrustAnchors, OperatorAcknowledgement, Outcome,
    RecordVerifyError, Refusal, SignedContainmentRecord, TargetIdentity, CONTAINMENT_DOMAIN,
    CONTAINMENT_VERSION,
};
pub use replay::{FileReplayLedger, MemoryReplayLedger, ReplayLedger};
