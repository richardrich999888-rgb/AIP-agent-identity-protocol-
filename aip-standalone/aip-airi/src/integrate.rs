//! Integration with the existing reconciler.
//!
//! # The design decision, and why
//!
//! AIRI does **not** introduce a second reconciliation system, and it does
//! not add an entry point to the first one. It produces an
//! [`AiriAnnotation`] that sits *beside* a `Reconciliation` the existing
//! engine produced, carrying what the AI-stack evidence showed and nothing
//! else.
//!
//! The alternative — a `reconcile_airi_claim` entry point that could reach
//! `PHANTOM_CLAIM` from an uncorroborated AIRI claim — was considered and
//! rejected for this stage. It is a new way to *accuse*, and the existing
//! phantom-claim path required recomputed coverage, a sealed identity
//! comparison and 1,419 lines of adversarial tests before it was trusted to
//! say "this did not happen". A second accusation path built without that
//! depth is how a detection system starts producing false positives and gets
//! switched off in its first production week.
//!
//! What that entry point would need is specified in
//! `docs/architecture/AIRI_MIGRATION.md` §4. Until it exists, AIRI's
//! contribution to a verdict is exactly zero, which is the safe direction.
//!
//! # What this module guarantees
//!
//! [`annotate`] takes a `Reconciliation` **by reference** and returns a new
//! value. It cannot mutate a verdict because it is never handed a mutable
//! one, and it constructs no `ReconciliationResult` and no
//! `EvidenceStrength` — there is no expression in this file that produces
//! either type. The composition tests in `tests/reconcile_integration.rs`
//! drive the real engine and assert the verdict and strength are identical
//! with and without AIRI evidence present.

use aip_reconcile::{EvidenceStrength, Reconciliation, ReconciliationResult};

use crate::corroborate::Corroboration;
use crate::event::AiriEvent;

/// What the AI-stack evidence showed, alongside a reconciliation.
///
/// Deliberately carries no result and no strength. A consumer that wants to
/// act on `uncorroborated_claims` must make that decision in policy, where it
/// is visible, rather than receiving it pre-baked as a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AiriAnnotation {
    /// Claims the agent made that independent evidence agreed with.
    pub corroborated: usize,
    /// Claims the observer covered and did not see. The interesting number:
    /// non-zero here means the agent described actions that a watching
    /// collector has no record of.
    pub uncorroborated: usize,
    /// Claims that could not be compared at all — no coverage, no binding,
    /// not externally observable, or an action class with no mapping.
    /// Counted separately so "we did not look" is never read as "clean".
    pub not_evaluated: usize,
    /// Claims where observation contradicted the agent's own account.
    pub contradicted: usize,
    /// Whether the presented events formed one intact chain. `None` when no
    /// chain check was run.
    pub chain_intact: Option<bool>,
}

impl AiriAnnotation {
    /// Did the agent describe actions the observer was watching for and did
    /// not see? This is a question, not a verdict: the answer feeds a policy
    /// decision, and the policy — not this crate — decides what it means.
    pub fn has_unexplained_claims(&self) -> bool {
        self.uncorroborated > 0 || self.contradicted > 0
    }

    /// Total claims considered.
    pub fn total(&self) -> usize {
        self.corroborated + self.uncorroborated + self.not_evaluated + self.contradicted
    }
}

/// Summarise a set of corroboration outcomes alongside a reconciliation.
///
/// `rec` is taken by shared reference and is never modified. It is a
/// parameter at all only so a caller cannot accidentally pair an annotation
/// with the wrong reconciliation, and so this signature documents that the
/// verdict is an input here, never an output.
pub fn annotate(
    _rec: &Reconciliation,
    corroborations: &[Corroboration],
    chain_intact: Option<bool>,
) -> AiriAnnotation {
    let mut a = AiriAnnotation {
        chain_intact,
        ..Default::default()
    };
    for c in corroborations {
        match c {
            Corroboration::Corroborated(_) => a.corroborated += 1,
            Corroboration::Uncorroborated { .. } => a.uncorroborated += 1,
            Corroboration::NotEvaluated(_) => a.not_evaluated += 1,
            Corroboration::Contradicted { .. } => a.contradicted += 1,
        }
    }
    a
}

/// The verdict and strength a reconciliation carries, unchanged.
///
/// Exists so a caller can assert — and a reader can see — that passing
/// through this module is the identity function on the pair that matters.
/// If a future edit ever makes AIRI able to move a verdict, the composition
/// tests that call this will fail.
pub fn verdict_of(rec: &Reconciliation) -> (ReconciliationResult, EvidenceStrength) {
    (rec.result, rec.strength)
}

/// Does an AIRI event claim to be authorized by a given expectation?
///
/// A join key, not a check: it compares the `decision_id` the agent wrote
/// into its own event against the one the decision point signed. Agreement
/// means the agent named that authorization, never that the authorization
/// covers what the agent did.
pub fn claims_decision(event: &AiriEvent, decision_id: &[u8; 16]) -> bool {
    event.decision_id.as_ref() == Some(decision_id)
}
