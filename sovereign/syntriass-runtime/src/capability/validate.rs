//! Independent validation of a capability. Pure: the caller decides where it
//! runs (the CLI runs it in a fresh user + network namespace).
//!
//! A capability never certifies itself:
//! - only cases from a [`ExpertSuite`] signed by a trusted expert count, and
//!   only when the expert is not the proposer and the suite belongs to the
//!   capability's tenant;
//! - every case inside the artifact is run as *generated* regardless of the
//!   source it declares: it can fail the capability, never make it pass;
//! - at least [`MIN_EXPERT_TESTS`] suite cases and at least
//!   [`MIN_COUNTEREXAMPLES`] counterexamples must exist and all must pass;
//! - every evidence document must belong to the capability's own tenant.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::artifact::{Capability, Execution, TestSource};
use super::suite::ExpertSuite;

/// Minimum independent expert cases. Rationale: one case per decision band
/// plus boundary cases; fewer than eight cannot cover a four-band procedure
/// with its scope and validity guards.
pub const MIN_EXPERT_TESTS: usize = 8;
/// At least one case designed to break a naive procedure.
pub const MIN_COUNTEREXAMPLES: usize = 1;

/// Expected-label spellings for non-decision outcomes.
pub const NOT_APPLICABLE: &str = "NOT_APPLICABLE";
pub const AMBIGUOUS: &str = "AMBIGUOUS";

/// Where a failed case came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOrigin {
    /// Signed expert suite.
    Suite,
    /// Carried inside the artifact (treated as generated).
    Artifact,
}

/// One failed case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub id: String,
    pub expected: String,
    pub got: String,
    pub origin: CaseOrigin,
}

/// Validation result, bound to the exact artifact and suite content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub capability_hash: String,
    pub suite_hash: String,
    pub suite_expert: String,
    pub suite_signature_ok: bool,
    /// Suite expert ≠ proposer and suite tenant = capability tenant.
    pub suite_independent: bool,
    pub compiled: bool,
    pub compile_error: Option<String>,
    pub expert_cases: usize,
    pub expert_passed: usize,
    pub counterexamples: usize,
    pub counterexamples_passed: usize,
    /// Cases inside the artifact (all run as generated).
    pub artifact_cases: usize,
    pub artifact_passed: usize,
    /// Artifact cases that *claimed* to be expert-authored (claim ignored).
    pub artifact_claimed_expert: usize,
    pub evidence_scope_ok: bool,
    pub failures: Vec<Failure>,
    pub passed: bool,
    pub wall_micros: u128,
}

/// Label an execution the way test expectations are written.
pub fn label(e: &Execution) -> String {
    match e {
        Execution::NotApplicable => NOT_APPLICABLE.into(),
        Execution::Ambiguous { .. } => AMBIGUOUS.into(),
        Execution::Decided { outcome, .. } => outcome.clone(),
        Execution::Failed(m) => format!("FAILED:{m}"),
        Execution::EvidenceRequired => "EVIDENCE_REQUIRED".into(),
    }
}

/// Validate `cap` against a signed expert suite. `expert_public_key` is the
/// operator's trust anchor for `suite.expert_id`; `evidence_tenant_of(doc)`
/// returns the tenant owning an evidence document, or `None` if unknown.
pub fn validate(
    cap: &Capability,
    suite: &ExpertSuite,
    expert_public_key: &[u8],
    evidence_tenant_of: &dyn Fn(&str) -> Option<String>,
) -> ValidationReport {
    let t0 = Instant::now();
    let mut r = ValidationReport {
        capability_hash: cap.content_hash(),
        suite_hash: suite.hash(),
        suite_expert: suite.expert_id.clone(),
        suite_signature_ok: suite.verify(expert_public_key),
        suite_independent: suite.expert_id != cap.proposed_by
            && suite.tenant == cap.required.tenant,
        compiled: false,
        compile_error: None,
        expert_cases: 0,
        expert_passed: 0,
        counterexamples: 0,
        counterexamples_passed: 0,
        artifact_cases: 0,
        artifact_passed: 0,
        artifact_claimed_expert: 0,
        evidence_scope_ok: false,
        failures: vec![],
        passed: false,
        wall_micros: 0,
    };
    r.evidence_scope_ok = !cap.dependencies.knowledge.is_empty()
        && cap
            .dependencies
            .knowledge
            .keys()
            .all(|d| evidence_tenant_of(d).as_deref() == Some(cap.required.tenant.as_str()));
    let compiled = match cap.compile() {
        Ok(c) => c,
        Err(e) => {
            r.compile_error = Some(format!("{e:?}"));
            r.wall_micros = t0.elapsed().as_micros();
            return r;
        }
    };
    r.compiled = true;
    // Suite cases count only when the suite is authentic and independent.
    if r.suite_signature_ok && r.suite_independent {
        for t in &suite.cases {
            let got = label(&cap.execute_attested_text(&compiled, &t.text));
            let ok = got == t.expected;
            r.expert_cases += 1;
            r.expert_passed += ok as usize;
            if t.counterexample {
                r.counterexamples += 1;
                r.counterexamples_passed += ok as usize;
            }
            if !ok {
                r.failures.push(Failure {
                    id: t.id.clone(),
                    expected: t.expected.clone(),
                    got,
                    origin: CaseOrigin::Suite,
                });
            }
        }
    }
    for t in &cap.tests {
        r.artifact_claimed_expert += (t.source == TestSource::Expert) as usize;
        let got = label(&cap.execute_attested_text(&compiled, &t.text));
        let ok = got == t.expected;
        r.artifact_cases += 1;
        r.artifact_passed += ok as usize;
        if !ok {
            r.failures.push(Failure {
                id: t.id.clone(),
                expected: t.expected.clone(),
                got,
                origin: CaseOrigin::Artifact,
            });
        }
    }
    r.passed = r.compiled
        && r.evidence_scope_ok
        && r.suite_signature_ok
        && r.suite_independent
        && r.expert_cases >= MIN_EXPERT_TESTS
        && r.expert_passed == r.expert_cases
        && r.counterexamples >= MIN_COUNTEREXAMPLES
        && r.counterexamples_passed == r.counterexamples
        && r.artifact_passed == r.artifact_cases;
    r.wall_micros = t0.elapsed().as_micros();
    r
}
