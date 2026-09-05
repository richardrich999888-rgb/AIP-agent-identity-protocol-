//! aip-agent — Sniffer Dog 2.0, Phase B: validated agent identity and a
//! dimension-separated profile view.
//!
//! ```text
//! AgentIdentityDocument / AgentIdentitySummary ──► AgentIdentity   (re-derived, self-signature verified)
//! ScopedToken + DelegationToken chains          ──► AuthorityProjection (decision-point rules, named exclusions)
//! ExpectedExecution (DP-signed)                 ──► ExecutionInstance::AuthorizedTarget
//! ExecutionBinding from packets                 ──► ExecutionInstance::Claimed
//! Reconciliation (verifier-local)               ──► ReconciledRecord, joined by decision_id
//!                                                    ↓
//!                                               AgentProfile  (a view; unsigned; no summary field)
//! ```
//!
//! # What this crate never does
//!
//! It holds no key and signs nothing. It creates no identity, issues no
//! authority, observes nothing and reconciles nothing. It reads artifacts
//! other authorities signed, re-verifies each one with the anchors the
//! builder supplies, and lays the results out by partition with the
//! authority behind each named. Where an artifact does not verify it is
//! recorded as excluded with the reason — never dropped, never downgraded
//! into a weaker partition.
//!
//! It computes no scalar summary of any kind across partitions (spec rule
//! E1, invariant I12) and links none of the experimental aggregation
//! machinery in `aip-core`; `tests/profile.rs` p16 pins this textually
//! against the crate's own sources.
//!
//! # What remains outside
//!
//! There is no identity issuer and no lifecycle authority in the repository,
//! so `lifecycle` is the agent's self-assertion and nothing else. Lineage
//! is three-kind (identity / authority / process) with no reconciled
//! verdict yet (Phase C2); experience (Phase F) is an explicit placeholder.
//! Reconciliation records are unsigned; the profile therefore admits only
//! records from the builder's own verifier run (`RecordSource::VerifierLocal`).

pub mod authority;
pub mod graph;
pub mod identity;
pub mod lineage;
pub mod profile;

pub use authority::{
    project_authority, AuthorityChain, AuthorityProjection, AuthorizedCapability,
    ExcludedAuthority, ExclusionReason, IssuerAssertion, IssuerKeys, Standing,
};
pub use graph::{
    DanglingHop, DelegationGraph, DelegationSummary, GraphNode, GraphPath, OutgoingDelegation,
    PathStanding,
};
pub use identity::{
    AgentIdentity, IdentityError, IdentitySource, LifecycleAssertion, LineageProofState,
};
pub use lineage::{
    Ancestor, AncestorLink, AuthorityHop, AuthorityPath, ChildAttribution, ExcludedDocument,
    ExcludedPeerExpectation, IdentityLineage, IdentityParent, Lineage, ObservedSpawn,
    ObservedSpawnedBy, ProcessLineage, ReconciledLineage,
};
pub use profile::{
    build_profile, AgentProfile, ExcludedExpectation, ExcludedReconciliation, ExecutionInstance,
    ExpectationExclusion, ExperienceSection, IdentityInput, InstanceAssertion, ProfileError,
    ProfileInputs, ReconciledRecord, ReconciliationExclusion, RecordSource, SelfDeclared,
    SELF_DECLARED_LABEL,
};
