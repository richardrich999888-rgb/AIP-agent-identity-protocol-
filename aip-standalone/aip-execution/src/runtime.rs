//! The runtime ladder: four separate facts about "what ran this".
//!
//! # Why four fields and not one
//!
//! The failure this prevents is specific and common. A framework reports
//! `accelerator: "cuda:0 NVIDIA H100"`; three layers later a dashboard says
//! "the execution ran on a GPU". Nothing lied — a self-report was quietly
//! promoted to a measurement because there was only one field to put it in.
//!
//! Four fields with four sources make the promotion impossible to perform by
//! accident: reading `evidenced` when only `selected` was populated returns
//! `None`, not the selected value.
//!
//! The chain this encodes, which the audit treats as NOT ESTABLISHED at every
//! rung except the last:
//!
//! ```text
//! model requested ≠ model served ≠ weights loaded ≠ accelerator executed
//! ```

use aip_types::canonical::{put_opt_str, put_u8};
use serde::{Deserialize, Serialize};

use crate::stage::EvidenceOrigin;

/// What is known about the runtime an execution used, by source.
///
/// Every field is independently optional. A populated `selected` says nothing
/// about `observed`, and there is deliberately no method that falls back from
/// one to another.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDeclaration {
    /// What the deployment's configuration said would run. `Declared`.
    pub declared: Option<String>,
    /// What the agent says it chose. `SelfReported`.
    pub selected: Option<String>,
    /// What a measurement of the host found. `IndependentlyObserved`.
    ///
    /// Populated only by something outside the subject. This crate provides no
    /// way to fill it from `selected`, because that is exactly the move the
    /// type exists to prevent.
    pub observed: Option<String>,
    /// What an *anchored* observer attested. `IndependentlyObserved`, and the
    /// only field that survives an untrusted collector.
    pub evidenced: Option<String>,
}

impl RuntimeDeclaration {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn declared(mut self, v: &str) -> Self {
        self.declared = Some(v.to_owned());
        self
    }
    pub fn selected(mut self, v: &str) -> Self {
        self.selected = Some(v.to_owned());
        self
    }
    pub fn observed(mut self, v: &str) -> Self {
        self.observed = Some(v.to_owned());
        self
    }
    pub fn evidenced(mut self, v: &str) -> Self {
        self.evidenced = Some(v.to_owned());
        self
    }

    /// The strongest origin actually populated, or `None` if nothing is.
    ///
    /// Returns the *origin*, never the value, so a caller cannot use this to
    /// read a self-report while believing it read a measurement. A caller that
    /// wants the evidenced runtime asks for `evidenced` and accepts `None`.
    pub fn best_origin(&self) -> Option<EvidenceOrigin> {
        // `evidenced` and `observed` share an origin — both are measurements
        // from outside the subject — but they are separate *fields* because
        // only one of them survives an untrusted collector. Clippy sees
        // identical arms; the distinction is in which field a caller may read,
        // not in the origin either reports.
        if self.evidenced.is_some() || self.observed.is_some() {
            Some(EvidenceOrigin::IndependentlyObserved)
        } else if self.selected.is_some() {
            Some(EvidenceOrigin::SelfReported)
        } else if self.declared.is_some() {
            Some(EvidenceOrigin::Declared)
        } else {
            None
        }
    }

    /// Whether the agent's choice and an independent measurement disagree.
    ///
    /// `None` when there is nothing to compare — which is not agreement.
    /// Returning `Some(false)` for a missing measurement would be the same
    /// error as treating absence as proof.
    pub fn selection_matches_observation(&self) -> Option<bool> {
        match (
            &self.selected,
            self.evidenced.as_ref().or(self.observed.as_ref()),
        ) {
            (Some(s), Some(o)) => Some(s == o),
            _ => None,
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        // Fixed field order with presence bytes: the four slots must not be
        // able to shift into one another, or a self-report could encode
        // identically to a measurement.
        put_opt_str(buf, &self.declared);
        put_opt_str(buf, &self.selected);
        put_opt_str(buf, &self.observed);
        put_opt_str(buf, &self.evidenced);
        // A trailing marker so a declaration cannot be a prefix of a longer
        // structure appended after it.
        put_u8(buf, 0xFF);
    }
}
