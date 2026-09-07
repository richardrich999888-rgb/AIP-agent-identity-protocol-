//! Environment-neutral autonomous observation profile.
//!
//! > How can Vanian independently observe autonomous-system execution without
//! > allowing the autonomous system itself to manufacture, modify, suppress or
//! > reinterpret the observation used to judge it?
//!
//! # What already exists, and is not rebuilt here
//!
//! `aip-observe` already carries the independence boundary: the probe runs on
//! the observed host and has **no key field and no signing method**, the
//! collector holds the key off-host and assigns chain position, nine Linux
//! mechanisms are each documented with what they establish and do not,
//! coverage is a signed declaration, and completeness has five observer states
//! and six unavailability reasons. Skill 19 added [`aip_platform`]'s anchored
//! host-boot boundary. `aip-reconcile` caps every content-dependent verdict at
//! `Attested`.
//!
//! # What this crate adds
//!
//! 1. [`ObservationClass`] — the environment-neutral layer above
//!    `SourceMechanism`. That enum is nine *Linux* mechanisms; a UAS
//!    altimeter, a UGV wheel encoder or a spacecraft attitude sensor cannot
//!    acquire one without forking a core-protocol enum per vertical. Classes
//!    are what a later profile reasons about (ADR-003).
//! 2. [`EvidenceCeiling`] — each class's declared maximum contribution.
//!    Declared, not computed; an upper bound only; asserted consistent with
//!    the reconciler rather than substituted for it.
//! 3. [`ObservationProfile`] — what a deployment is *provisioned* to observe,
//!    so a class nobody can observe is explicitly unobservable rather than
//!    silently absent.
//! 4. [`ObservationRecord`] — one verified observation, bound to the system,
//!    execution and host-boot it describes.
//!
//! # What it is not
//!
//! - **Not a verdict engine.** No `EvidenceStrength`, no result class, no
//!   severity. `aip-reconcile` remains the only thing that decides `Proven`.
//! - **Not a trust anchor.** No key, no signature. Observer key custody stays
//!   in `aip-observe`.
//! - **Not an attestation consumer.** No class accepts a TPM quote or any
//!   attestation-shaped material. ADR-002 remains PROPOSED, and an observer
//!   relaying an attestation is relaying an attestation.
//! - **Not physical-effect observation.** The class is declared with its
//!   ceiling and has no mechanism (ADR-003 §2). Declared is not implemented.
//!
//! # The one thing to take away
//!
//! An [`ObservationRecord`] can only be constructed by verifying an attested
//! batch against the verifier's own anchors. There is no constructor that
//! accepts an AIRI event, a self-reported binding or an attestation — so a
//! compromised agent on the normal SDK path has nothing to call.

pub mod class;
pub mod completeness;
pub mod error;
pub mod profile;
pub mod record;

pub use class::{class_of, EvidenceCeiling, ObservationClass};
pub use completeness::Completeness;
pub use error::ObservationError;
pub use profile::{
    ClassCapability, ObservationProfile, OBSERVATION_PROFILE_DOMAIN, OBSERVATION_PROFILE_VERSION,
};
pub use record::{
    ObservationCorrelation, ObservationRecord, OBSERVATION_RECORD_DOMAIN,
    OBSERVATION_RECORD_VERSION,
};
