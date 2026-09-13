//! The approval tier of Sniffer Dog 3.0: **shown-versus-authorized**.
//!
//! # The failure this exists for
//!
//! An agent narrates one thing to a human, a different thing is authorized,
//! and afterwards the agent reports a third thing. The human's approval was
//! genuine; it was simply an approval of something other than what was
//! sealed. Nothing in the existing stack can see this, because every artifact
//! it holds describes the *system's* side: the decision point's
//! `ExpectedExecution`, the observer's batches, the agent's own AIRI claims.
//! What the human was shown is not among them.
//!
//! ```text
//!   human ◄── rendered bytes ── approval surface ──► ApprovalArtifact (signed)
//!                                                            │
//!                                                            │  arithmetic
//!                                                            ▼
//!   decision point ──► ExpectedExecution (signed) ──► compare_shown_to_authorized
//!                                                            │
//!                                        ShownVsAuthorized { divergence, basis }
//! ```
//!
//! # Why this tier is different from every other claim in the system
//!
//! Both inputs are **signed artifacts**. The comparison is therefore a pure
//! function of held bytes: a third party with the two artifacts and the two
//! anchors recomputes the same answer, offline, with no clock and no network.
//! It reads nothing from the observed host.
//!
//! That matters because of the rule the reconciler already enforces. Every
//! content-derived workload verdict is pinned at `strength == Attested`
//! **exactly**, and the code says why: *"the content is procfs-read and can
//! never be `Proven`"*. `Proven` is reserved for facts a third party can
//! recompute from held bytes — which is why `classify_observer_error` grants
//! it for signature arithmetic and refuses it for a bad local trust anchor.
//!
//! A shown-versus-authorized divergence is signature arithmetic. It is
//! therefore the **first workload-directed divergence class in this system
//! that could legitimately carry `Proven` without weakening that rule.**
//! [`Basis::Recomputable`] is the marker; §"The gate" below is what would
//! still have to happen first.
//!
//! # What this crate does not do
//!
//! - **It does not produce a verdict.** No `ReconciliationResult`, no
//!   `EvidenceStrength`. It cannot name `aip-reconcile`, and a test reads
//!   this crate's manifest to keep it that way.
//! - **It does not make containment reachable.** Audit blocker B-3 stands as
//!   ACCEPTED/JUSTIFIED. This crate supplies a divergence class whose basis is
//!   arithmetic; wiring one into the engine is a separate, gated decision.
//! - **It does not judge the human.** `approver_ref` is an opaque reference
//!   the surface chooses. Nothing here authenticates a person.
//! - **It does not read the observed host.** If it did, it would forfeit the
//!   only property that makes it interesting.
//!
//! # Absence is not an accusation
//!
//! A decision with no approval artifact is [`ShownVsAuthorized::NotEvaluated`]
//! with a reason — never a divergence. Most decisions are never shown to a
//! human at all, and treating that as a finding would be the worst false
//! positive this system can make. The same rule the observer applies to an
//! uncovered window applies here.
//!
//! # The gate — what would have to be true before a verdict could use this
//!
//! Recorded so that nobody later mistakes "the basis is arithmetic" for "the
//! engine may accuse on it". A `reconcile_approval_divergence` entry point
//! would need, at minimum:
//!
//! 1. The same choke point: `Draft`, `prologue`, and `precondition_holds`, so
//!    it cannot bypass the single authority.
//! 2. A structural precondition at least as strict as `PhantomClaim`'s — here
//!    that means both artifacts verified under **anchors the verifier chose**,
//!    a matched `decision_id`, and [`Basis::Recomputable`].
//! 3. An adversarial suite of comparable depth to
//!    `aip-reconcile/tests/adversarial.rs`, specifically covering a surface
//!    that signs a false artifact, a replayed artifact from an earlier
//!    decision, and a rendering whose digest is honest but whose *meaning*
//!    differs — which this comparison cannot see and must not claim to.
//! 4. A false-positive budget agreed with whoever operates it.
//!
//! Until all four exist, the finding is surfaced beside a reconciliation, in
//! the shape `aip-airi` already established for annotations.

pub mod artifact;
pub mod compare;

pub use artifact::{
    verify_artifact, ApprovalArtifact, ApprovalSurfaceAnchors, ArtifactError, RenderedForm,
    SignedApprovalArtifact, VerifiedApprovalArtifact, APPROVAL_ARTIFACT_DOMAIN,
    APPROVAL_ARTIFACT_VERSION,
};
pub use compare::{
    compare_shown_to_authorized, Basis, Divergence, NotEvaluatedReason, ShownVsAuthorized,
};
