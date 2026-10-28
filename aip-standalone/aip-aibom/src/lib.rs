//! # AI Agent Bill of Materials
//!
//! An inventory of an autonomous agent — identity, models, tools, permissions,
//! environment, relationships, controls — in which **every field says who
//! vouches for it**.
//!
//! The manifest ([`model::Manifest`]) is what the agent's author declares. It
//! has no field in which a standing can be written. The assessment
//! ([`assess::assess`]) computes a [`standing::Standing`] for each field, and
//! only from evidence that a verifier already in this workspace accepts:
//!
//! | standing | from |
//! |---|---|
//! | `Verified` | `aip_core` identity and delegation verification, `aip_authorize` decision-point signatures |
//! | `Observed` | `aip_nexora::verify_nexora_proof`, at the strength NEXORA re-derived |
//! | `Discovered` | a discovery the assessor itself ran |
//! | `SelfReported` | the author's word, which is the default |
//! | `Unknowable` | a non-establishment that no evidence can discharge |
//!
//! What it does **not** do: establish what an agent actually did. That is
//! runtime evidence, and NEXORA is its verifier. This crate reads NEXORA's
//! output; it never reconciles (ADR-017).

pub mod adapters;
pub mod assess;
pub mod canonical;
pub mod diff;
pub mod evidence;
pub mod finding;
pub mod model;
pub mod ports;
pub mod report;
pub mod seal;
pub mod standing;

pub use assess::{assess, Assessment, Inputs};
pub use model::{Component, Manifest};
pub use standing::Standing;

/// The schema of every artifact this crate emits.
pub const AIBOM_REPORT_SCHEMA_VERSION: u16 = 1;
