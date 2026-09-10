//! Environment-neutral autonomous execution model.
//!
//! Execution is not one event. It is a sequence of epistemic boundaries, each
//! visible to a different party and forgeable by an attacker at a different
//! position:
//!
//! ```text
//! intent ≠ authorization ≠ expected execution ≠ AI claim
//!        ≠ runtime execution ≠ independent observation
//!        ≠ external effect ≠ proof
//! ```
//!
//! # What this crate adds
//!
//! Nine of the twelve stages already have authoritative types elsewhere. This
//! crate deliberately builds none of them again, and adds only what was
//! missing:
//!
//! 1. [`ExecutionStage`] and [`EvidenceOrigin`] — the ladder, executable.
//!    Before this it existed as prose across crate docs, which means nothing
//!    checked it.
//! 2. [`effect`] — the external-effect boundary. `aip-observe` models process
//!    presence and kernel sockets; there was no model of an effect *outside*
//!    the host at all.
//! 3. [`RuntimeDeclaration`] — declared, selected, observed and independently
//!    evidenced runtime as four separate facts, none implying another.
//! 4. [`ExecutionProfile`] — the composition, and the binding of Skill 17's
//!    unsigned descriptors into a DP-signed artifact without a new signer.
//!
//! # What this crate is not
//!
//! - **Not a verdict engine.** No result class, no severity, no
//!   `EvidenceStrength`. There remains exactly one reconciliation engine, and
//!   this model produces inputs to it.
//! - **Not a trust anchor.** No key, no signature, no verification. The
//!   binding in [`ExecutionProfile::authorization_parameter`] reuses the
//!   decision point's existing signature rather than adding one.
//! - **Not a vertical profile.** No UAS, UGV, robotics, industrial, space or
//!   enterprise type appears here, by design.
//!
//! # The one thing to take away
//!
//! [`EffectDisposition::Confirmed`] cannot be constructed from a
//! [`RuntimeAction`]. A 200 response reaches [`EffectDisposition::NotEvaluated`]
//! and stops there, because the constructor that produces `Confirmed` requires
//! an [`EffectEvidence`], and that cannot be built from agent-authored
//! material.

pub mod effect;
pub mod error;
pub mod profile;
pub mod runtime;
pub mod stage;

pub use effect::{
    EffectDisposition, EffectEvidence, EffectOutcome, RequestedEffect, RuntimeAction,
};
pub use error::ExecutionError;
pub use profile::{
    ExecutionProfile, BINDING_PARAMETER_KEY, EXECUTION_PROFILE_DOMAIN, EXECUTION_PROFILE_VERSION,
};
pub use runtime::RuntimeDeclaration;
pub use stage::{EvidenceOrigin, ExecutionStage};
