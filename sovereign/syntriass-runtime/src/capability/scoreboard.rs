//! Teaching homework, recomputed from the capability and an expert-signed suite.
//!
//! This is a diagnostic view, not a second validator or an approval. The
//! unchanged validator supplies the verdict and counts; no imported report is
//! accepted. Counterexamples are a subset of expert cases, never extra passes.
//! The trace names the branch that ran. Review prompts are suggestions, not a
//! claim that the fired branch is the root cause (an earlier guard may be absent).

use serde::Serialize;
use serde_json::{json, Value};

use super::artifact::{Capability, Compiled, Execution};
use super::suite::ExpertSuite;
use super::validate::{self, CaseOrigin, ValidationReport, MIN_COUNTEREXAMPLES, MIN_EXPERT_TESTS};

#[derive(Debug, Serialize)]
pub struct Gate {
    pub name: &'static str,
    pub passed: bool,
    pub remedy: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ReviewQuestion {
    /// B1 field family; a UI can offer every matching question, not guess a qid.
    pub field_path: &'static str,
    pub question: &'static str,
}

#[derive(Debug, Serialize)]
pub struct CaseRow {
    pub origin: CaseOrigin,
    /// Position preserves identity even if artifact case IDs repeat.
    pub index: usize,
    pub id: String,
    pub input: String,
    pub expected: String,
    pub counterexample: bool,
    /// None means NOT RUN, not a pass or a model abstention.
    pub got: Option<String>,
    pub passed: Option<bool>,
    pub not_run_reason: Option<&'static str>,
    pub fired_step: Option<String>,
    pub fired_rule: Option<Value>,
    pub review_questions: Vec<ReviewQuestion>,
}

#[derive(Debug, Serialize)]
pub struct Scoreboard {
    pub schema: &'static str,
    pub summary: String,
    pub validation: ValidationReport,
    pub gates: Vec<Gate>,
    pub cases: Vec<CaseRow>,
    pub model_calls: usize,
    pub activation_performed: bool,
    pub evidence_kind: &'static str,
    pub limitation: &'static str,
}

fn review_fields(cap: &Capability, expected: &str, step: Option<&str>) -> Vec<ReviewQuestion> {
    let mut fields = std::collections::BTreeSet::new();
    // A missed scope/validity guard can fall through to a perfectly correct
    // final rule. Include expected guard outcomes as well as the fired step.
    if cap
        .procedure
        .text_guards
        .iter()
        .any(|g| g.outcome == expected)
        || step.is_some_and(|s| s.starts_with("text_guards["))
    {
        fields.insert("scope_exclusion_terms.*");
    }
    if cap
        .procedure
        .numeric_guards
        .iter()
        .any(|g| g.outcome == expected)
        || step.is_some_and(|s| s.starts_with("numeric_guards["))
    {
        fields.extend([
            "scope_limit.*",
            "validity[].ref",
            "validity[].min/max",
            "validity[].outcome",
        ]);
    }
    match step {
        Some("not_applicable") => {
            fields.extend(["scope_subject.*", "required_inputs.*"]);
        }
        Some("missing_input" | "ambiguous") => {
            fields.extend(["required_inputs.*", "missing_input_outcome"]);
        }
        Some("default") => {
            fields.extend(["default_outcome", "rules[].op", "rules[].number"]);
        }
        Some(s) if s.starts_with("rules[") || s == "evaluation_error" => {
            fields.extend([
                "rules[].value",
                "rules[].op",
                "rules[].number",
                "rules[].outcome",
                "correction.*",
                "limit.*",
            ]);
        }
        _ => {}
    }
    fields.into_iter().map(|field_path| ReviewQuestion {
        field_path,
        question: match field_path {
            "scope_exclusion_terms.*" => "What equipment does this procedure exclude? Check exact whole-word forms in the failed input.",
            "scope_subject.*" => "What equipment does this procedure cover? Check the topic words in the failed input.",
            "scope_limit.*" => "Which measured limits put this request outside the procedure?",
            "validity[].ref" => "Which reading does the validity range constrain?",
            "validity[].min/max" => "What are the inclusive lower and upper bounds and units?",
            "validity[].outcome" => "What result is required outside the valid range?",
            "required_inputs.*" => "Which readings, units and unambiguous names are required?",
            "missing_input_outcome" => "What result is required when a reading is missing?",
            "default_outcome" => "What result is required when no earlier rule matches?",
            "rules[].value" => "Which raw or corrected reading should this rule compare?",
            "rules[].op" => "Which comparison should the rule use, including equality at the boundary?",
            "rules[].number" => "What number or fraction of the limit should the rule compare against?",
            "rules[].outcome" => "What result should this condition produce?",
            "correction.*" => "How should the reading be corrected, using the cited formula?",
            "limit.*" => "How should the acceptance limit be calculated?",
            _ => unreachable!("only known review fields are inserted"),
        },
    }).collect()
}

fn rule_at(cap: &Capability, step: &str) -> Option<Value> {
    fn index(step: &str, prefix: &str) -> Option<usize> {
        step.strip_prefix(prefix)?.strip_suffix(']')?.parse().ok()
    }
    if let Some(i) = index(step, "rules[") {
        return cap.procedure.rules.get(i).map(|r| json!(r));
    }
    if let Some(i) = index(step, "text_guards[") {
        return cap.procedure.text_guards.get(i).map(|r| json!(r));
    }
    if let Some(i) = index(step, "numeric_guards[") {
        return cap.procedure.numeric_guards.get(i).map(|r| json!(r));
    }
    match step {
        "default" => Some(json!({"outcome": cap.procedure.default_outcome})),
        "missing_input" => Some(json!({"outcome": cap.procedure.missing_input_outcome})),
        _ => None,
    }
}

impl CaseRow {
    fn execute(&mut self, cap: &Capability, compiled: Option<&Compiled>) {
        if self.not_run_reason.is_some() {
            return;
        }
        let Some(compiled) = compiled else {
            return;
        };
        let execution = cap.execute_attested_text(compiled, &self.input);
        let got = validate::label(&execution);
        let step = match execution {
            Execution::Decided { step, .. } => step,
            Execution::NotApplicable => "not_applicable".into(),
            Execution::Ambiguous { .. } => "ambiguous".into(),
            Execution::Failed(_) => "evaluation_error".into(),
            Execution::EvidenceRequired => "evidence_required".into(),
        };
        let ok = got == self.expected;
        if !ok {
            self.review_questions = review_fields(cap, &self.expected, Some(&step));
        }
        self.fired_rule = rule_at(cap, &step);
        self.fired_step = Some(step);
        self.passed = Some(ok);
        self.got = Some(got);
    }
}

/// Run the existing validator, then replay its deterministic cases solely for
/// explanations. No model, imported verdict, store write, signing or activation.
pub fn check(
    cap: &Capability,
    suite: &ExpertSuite,
    expert_public_key: &[u8],
    evidence_tenant_of: &dyn Fn(&str) -> Option<String>,
) -> Scoreboard {
    let report = validate::validate(cap, suite, expert_public_key, evidence_tenant_of);
    let compiled = cap.compile().ok();
    let suite_reason = if !report.compiled {
        Some("The capability does not compile; fix the reported compile error.")
    } else if !report.suite_signature_ok {
        Some("The suite signature or structure is invalid; supply an authentic expert suite.")
    } else if !report.suite_independent {
        Some("The suite must belong to this tenant and be signed by an expert other than the proposer.")
    } else {
        None
    };
    let artifact_reason = if !report.compiled { suite_reason } else { None };
    let mut cases = Vec::new();
    for (index, t) in suite.cases.iter().enumerate() {
        cases.push(CaseRow {
            origin: CaseOrigin::Suite,
            index,
            id: t.id.clone(),
            input: t.text.clone(),
            expected: t.expected.clone(),
            counterexample: t.counterexample,
            got: None,
            passed: None,
            not_run_reason: suite_reason,
            fired_step: None,
            fired_rule: None,
            review_questions: vec![],
        });
    }
    for (index, t) in cap.tests.iter().enumerate() {
        cases.push(CaseRow {
            origin: CaseOrigin::Artifact,
            index,
            id: t.id.clone(),
            input: t.text.clone(),
            expected: t.expected.clone(),
            counterexample: t.counterexample,
            got: None,
            passed: None,
            not_run_reason: artifact_reason,
            fired_step: None,
            fired_rule: None,
            review_questions: vec![],
        });
    }
    for case in &mut cases {
        case.execute(cap, compiled.as_ref());
    }
    let gate = |name, passed, remedy| Gate {
        name,
        passed,
        remedy,
    };
    let gates = vec![
        gate(
            "compilation",
            report.compiled,
            "Fix the compile error before testing.",
        ),
        gate(
            "evidence_tenant",
            report.evidence_scope_ok,
            "Use readable evidence owned by this capability's tenant.",
        ),
        gate(
            "expert_signature",
            report.suite_signature_ok,
            "Supply a structurally valid suite signed by a configured expert.",
        ),
        gate(
            "independent_expert",
            report.suite_independent,
            "Use the same tenant and an expert other than the proposer.",
        ),
        gate(
            "minimum_expert_cases",
            report.expert_cases >= MIN_EXPERT_TESTS,
            "Provide at least eight independently signed expert cases.",
        ),
        gate(
            "expert_cases",
            report.expert_cases > 0 && report.expert_passed == report.expert_cases,
            "Revisit failed expert cases; do not change expected results to make them pass.",
        ),
        gate(
            "minimum_counterexamples",
            report.counterexamples >= MIN_COUNTEREXAMPLES,
            "Include at least one signed counterexample or boundary probe.",
        ),
        gate(
            "counterexamples",
            report.counterexamples > 0 && report.counterexamples_passed == report.counterexamples,
            "Correct the rule that fails the signed counterexample.",
        ),
        gate(
            "generated_cases",
            report.compiled && report.artifact_passed == report.artifact_cases,
            "Fix every failed generated case; these cases can veto, never certify.",
        ),
    ];
    let summary = format!(
        "Passed {} of {} executed expert checks ({} submitted); {} of {} counterexamples (a subset); {} of {} generated checks. {}",
        report.expert_passed, report.expert_cases, suite.cases.len(),
        report.counterexamples_passed, report.counterexamples, report.artifact_passed, report.artifact_cases,
        if report.passed { "Validation passed. Signed approval and activation are still required." }
        else { "NOT READY: validation failed. See failed gates and cases." }
    );
    Scoreboard {
        schema: "syntriass.teach.scoreboard/v1", summary, validation: report, gates, cases,
        model_calls: 0, activation_performed: false,
        evidence_kind: "UNSIGNED_LOCAL_VALIDATION_DIAGNOSTIC",
        limitation: "Review questions suggest fields to inspect, not a proven root cause. This read-only check does not approve, activate, revalidate stored state, or prove network isolation.",
    }
}
