//! `aip-edge` — the Linux autonomous edge reference (Skill 22).
//!
//! # What this crate is for
//!
//! Before it, the workspace held two towers that had never met.
//!
//! ```text
//!   TOWER A — live                        TOWER B — Skills 17-21
//!   ─────────────────────────             ─────────────────────────
//!   a real Linux process                  SystemExecution
//!   aip-observe mechanisms                ExecutionProfile
//!   CollectorSigner / AttestedBatch       PlatformBinding
//!   reconcile_expectation → verdict       ObservationProfile / ObservationRecord
//!                                         EffectAssessment
//! ```
//!
//! Tower A runs and produces verdicts from real kernel evidence. Tower B was
//! proven against fixtures and had, at baseline `607f7fd`, **no caller outside
//! its own crates** — `PlatformBinding::resolve`, `EffectAssessment::assess`
//! and `ExecutionProfile` had zero call sites anywhere else in the workspace.
//! Its invariants were sound and its inputs were imaginary.
//!
//! This crate is the adapter between them, and it is deliberately *only* an
//! adapter:
//!
//! * It defines **no identifier**. `system_id`, `execution_id`, `boot_id`,
//!   `decision_id` and `parameter_commitment` are all reused verbatim from the
//!   crates that own them.
//! * It defines **no verdict class and no strength**. Every judgement in the
//!   reference comes from `aip_reconcile::reconcile_expectation`. There is no
//!   expression in this crate that constructs a `ReconciliationResult` or an
//!   `EvidenceStrength`, which `tests/no_second_engine.rs` checks against the
//!   source rather than trusting.
//! * It defines **no trust anchor**. Observer anchors are
//!   `ObserverTrustAnchors`, decision-point anchors are
//!   `DecisionPointTrustAnchors`, and the platform map is `PlatformRegistry`.
//! * It **cannot manufacture an observation**. The only route from bytes to an
//!   `ObservationRecord` is [`correlate::observation_record`], which verifies
//!   an `AttestedBatch` against the verifier's anchors and then calls
//!   `ObservationRecord::from_attested`. There is no other constructor and
//!   this crate does not add one.
//!
//! # The reference is three processes
//!
//! ```text
//!   aip-edge-workload   subject   agent key      no aip-observe
//!   aip-edge-observer   witness   collector key  no aip-airi
//!   aip-edge            verifier  anchors only   signs nothing
//! ```
//!
//! The two absences are enforced by the dependency graph and asserted by
//! `tests/dependency_isolation.rs`. That is the difference between a boundary
//! and a convention.
//!
//! # What the reference does not establish
//!
//! Running the collector as a second process on the observed host establishes
//! a **process** boundary. It does not establish the **host** boundary that
//! `OBSERVER_ATTESTATION.md` §3 requires of production, where the collector is
//! off-host entirely. Host root reaches both processes here. Every positive
//! finding the reference produces is therefore ceilinged at `Attested` and
//! never `Proven`, which is the existing model's answer and not a new one.
//!
//! Nothing here observes, claims, or enables a claim about physical effect.
//! `ObservationClass::PhysicalEffect` remains without a mechanism (ADR-003),
//! and [`effect::physical_effect_finding`] states that in the reference's own
//! output rather than leaving a silent hole.

#![forbid(unsafe_code)]

pub mod correlate;
pub mod effect;
pub mod error;
pub mod identity;
pub mod orchestrate;
pub mod platform;
pub mod profile;
pub mod reference;
pub mod transport;

pub use correlate::{observation_record, ObservationSubject};
pub use effect::{
    physical_effect_finding, requested_effect, stance_of, EffectInputs, PhysicalEffectStatus,
};
pub use error::EdgeError;
pub use identity::{IdentityKind, IdentityStability};
pub use orchestrate::{run, RunConfig, RunOutcome, Scenario};
pub use platform::{bind_platform, register_measured_host};
pub use profile::{mechanism_from_code, profile_from_codes, profile_from_mechanisms};
pub use reference::{EdgeReference, ReferenceLadder};

/// Domain tag for this crate's own canonical bytes.
///
/// It leads exactly one preimage — [`reference::EdgeReference::canonical_bytes`]
/// — and exists so a reference report committed into NEXORA cannot be replayed
/// as any other structure. This crate signs nothing; integrity comes from a
/// consumer committing to these bytes inside something already signed, exactly
/// as in Skills 17-21.
pub const EDGE_REFERENCE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/EDGE_REFERENCE/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const EDGE_REFERENCE_VERSION: u16 = 1;
