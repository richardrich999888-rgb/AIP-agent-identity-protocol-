//! aip-warrant — Ghost Skill 8: the warrant engine.
//!
//! ```text
//! Reconciliation record (typed result, strength, availability, evidence refs)
//!        + operator policy (severity per result, enablement, protected identities)
//!        ↓
//! evaluate()  — response ceiling = min(result cap, strength cap, severity cap),
//!               lowered by unavailability, missing citation, protection,
//!               and by autonomous containment being off
//!        ↓
//! Warrant     — response ∈ {Observe, Alert, Constrain, Contain}, target
//!               ∈ {Workload, Observer}, every input recorded, evidence refs
//!               verbatim, signed by a distinct warrant authority
//! ```
//!
//! # What this crate never does
//!
//! It observes nothing, authorizes nothing, reconciles nothing and actuates
//! nothing: no process is signalled, frozen, isolated or filtered here; the
//! output is a `Warrant` that Skill 9 may later consume. It never upgrades
//! evidence strength, never reads process ids or addresses, and never turns
//! `CANNOT_PROVE`, an unavailable observer, a degraded sensor or a missing
//! citation into containment. Containment requires `EvidenceStrength::Proven`
//! by an explicit `match`, plus operator enablement, a cited finding, a
//! covered window, an unprotected subject and a workload-violation result.
//!
//! Design lineage: the two-axis response standard of the unmerged OrbitalTrust
//! sentinel (`OUT_OF_TREE_HARVEST_REVIEW.md` §2.2), rebuilt over this
//! repository's `EvidenceStrength`, `ReconciliationResult` and `EvidenceRef`
//! with a signed, canonically encoded warrant.

pub mod policy;
pub mod warrant;

pub use policy::{ProtectedIdentitySet, Severity, SeverityAssignment, WarrantPolicy};
pub use warrant::{
    evaluate, verify_warrant, verify_warrant_distinct, Finding, Refusal, ResponseClass,
    ResponseTarget, Warrant, WarrantAuthority, WarrantTrustAnchors, WarrantVerifyError,
    WARRANT_DOMAIN, WARRANT_VERSION,
};
