//! The universal conformance program (Skill 28).
//!
//! One invariant set, asked of every domain, emitted as an artifact a
//! reviewer can read without running anything.
//!
//! # What this crate is
//!
//! A *question asker*. Every invariant below is answered by calling the core
//! and reading what it says. Nothing here defines a verdict, an evidence
//! ceiling, an observation class or an identifier; nothing holds a key or
//! signs anything. `tests/no_second_architecture.rs` asserts that over this
//! crate's own source, and asserts that no crate in the workspace depends on
//! it — a conformance program anything could depend on could change what it
//! is checking.
//!
//! # What the vocabulary deliberately lacks
//!
//! There is no `Waived`. The specification's second non-negotiable rule is
//! that a green adapter-specific suite cannot waive a failed core invariant.
//! The way to guarantee that is to give the vocabulary no word for it:
//! [`Conformance`] is `Satisfied`, `NotApplicable` or `Unknown`, and the
//! matrix counts the last two separately from the first.

pub mod domain;
pub mod evidence;
pub mod invariant;
pub mod matrix;

pub use domain::{Domain, Realisation};
pub use evidence::EvidenceClass;
pub use invariant::{Invariant, InvariantCode};
pub use matrix::{Cell, Conformance, ConformanceMatrix};

/// The version of the conformance program's own artifact schema.
///
/// Bumping this changes the shape of the emitted matrix, so a reviewer
/// diffing two artifacts can tell a semantic change from a schema change.
pub const CONFORMANCE_SCHEMA_VERSION: u16 = 1;

/// Domain tag for anything this crate ever hashes. It hashes nothing today;
/// the tag exists so that if it ever does, the value is not invented under
/// time pressure by whoever adds the first one.
pub const CONFORMANCE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/CONFORMANCE/v1";
