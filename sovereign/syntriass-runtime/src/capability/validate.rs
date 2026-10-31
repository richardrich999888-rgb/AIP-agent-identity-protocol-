//! Independent validation of a capability. Pure: the caller decides where it
//! runs (the CLI runs it in a fresh user + network namespace).
//!
//! A capability never certifies itself:
//! - only `TestSource::Expert` cases count, and only when their author is
//!   not the proposer;
//! - at least [`MIN_EXPERT_TESTS`] such cases and at least
//!   [`MIN_COUNTEREXAMPLES`] counterexamples must exist and all must pass;
//! - generated cases are run and reported but can only *fail* a capability,
//!   never make it pass;
//! - every evidence document must belong to the capability's own tenant.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::artifact::{Capability, Execution, TestSource};

/// Minimum independent expert cases. Rationale: one case per decision band
/// plus boundary cases; fewer than eight cannot cover a four-band procedure
/// with its scope and validity guards.
pub const MIN_EXPERT_TESTS: usize = 8;
/// At least one case designed to break a naive procedure.
pub const MIN_COUNTEREXAMPLES: usize = 1;

/// Expected-label spellings for non-decision outcomes.
pub const NOT_APPLICABLE: &str = "NOT_APPLICABLE";
pub const AMBIGUOUS: &str = "AMBIGUOUS";

/// One failed case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub id: String,
    pub expected: String,
    pub got: String,
    pub source: TestSource,
}

/// Validation result, bound to the exact artifact content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub capability_hash: String,
    pub compiled: bool,
    pub compile_error: Option<String>,
    pub expert_cases: usize,
    pub expert_passed: usize,
    pub counterexamples: usize,
    pub counterexamples_passed: usize,
    pub generated_cases: usize,
    pub generated_passed: usize,
    /// Expert cases ignored because the expert *is* the proposer.
    pub self_authored_ignored: usize,
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
    }
}

/// Validate `cap`. `evidence_tenant_of(doc_id)` returns the tenant that owns
/// an evidence document, or `None` if it is unknown to the corpus.
pub fn validate(
    cap: &Capability,
    evidence_tenant_of: &dyn Fn(&str) -> Option<String>,
) -> ValidationReport {
    let t0 = Instant::now();
    let mut r = ValidationReport {
        capability_hash: cap.content_hash(),
        compiled: false,
        compile_error: None,
        expert_cases: 0,
        expert_passed: 0,
        counterexamples: 0,
        counterexamples_passed: 0,
        generated_cases: 0,
        generated_passed: 0,
        self_authored_ignored: 0,
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
    for t in &cap.tests {
        let independent = t.source == TestSource::Expert && t.author != cap.proposed_by;
        if t.source == TestSource::Expert && !independent {
            r.self_authored_ignored += 1;
            continue;
        }
        let got = label(&cap.execute(&compiled, &t.text));
        let ok = got == t.expected;
        match t.source {
            TestSource::Expert => {
                r.expert_cases += 1;
                r.expert_passed += ok as usize;
                if t.counterexample {
                    r.counterexamples += 1;
                    r.counterexamples_passed += ok as usize;
                }
            }
            TestSource::Generated => {
                r.generated_cases += 1;
                r.generated_passed += ok as usize;
            }
        }
        if !ok {
            r.failures.push(Failure {
                id: t.id.clone(),
                expected: t.expected.clone(),
                got,
                source: t.source,
            });
        }
    }
    r.passed = r.compiled
        && r.evidence_scope_ok
        && r.expert_cases >= MIN_EXPERT_TESTS
        && r.expert_passed == r.expert_cases
        && r.counterexamples >= MIN_COUNTEREXAMPLES
        && r.counterexamples_passed == r.counterexamples
        && r.generated_passed == r.generated_cases;
    r.wall_micros = t0.elapsed().as_micros();
    r
}
