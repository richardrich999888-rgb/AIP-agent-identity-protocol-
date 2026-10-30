//! Structured answer validation.
//!
//! The model is constrained (by a JSON schema compiled to a grammar in the
//! inference server) to emit exactly:
//!
//! ```json
//! {"insufficient": bool, "answer": "<text>", "citations": [k, ...]}
//! ```
//!
//! The grammar guarantees *shape*, not *truth*. This module decides, with no
//! model involvement, whether an answer may be released:
//!
//! 1. Strict parse; unknown fields rejected.
//! 2. `insufficient = true` → [`Validation::Abstained`] (a safe outcome).
//! 3. At least one citation; every citation in `1..=supplied`.
//! 4. Any inline `[S<k>]` marker in the text must also be in `citations`.
//! 5. **Numeric support:** every number in the answer must occur as a number
//!    in the title, id or text of a *cited* source. Numbers in uncited
//!    sources do not count — citing S1 while quoting S2's figure is refused.
//!
//! 6. **Support** ([`super::support`]): number+unit claims stated with that
//!    unit in a cited source; a unit the question asks for is present;
//!    equipment codes and names from the question appear in a cited source;
//!    the cited sources cover most of the question; most of the answer's
//!    wording appears in them.
//!
//! # What this does not establish
//!
//! Non-numeric claims are not checked for entailment. "Seal replacement
//! within one week" vs a source saying "48 hours" contains no shared number
//! to compare when written in words, and passes. Number words ("five
//! hundred") are not normalised. Units are not compared: "7.1 bar" passes if
//! the cited source says "7.1 mm/s". These are stated limits.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::citation::extract_citations;
use super::support;

/// Maximum characters accepted in a released answer.
pub const MAX_ANSWER_CHARS: usize = 1200;

/// The constrained output shape.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredAnswer {
    pub insufficient: bool,
    pub answer: String,
    pub citations: Vec<usize>,
}

/// Why an answer was withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WithholdReason {
    /// Output was not the required JSON shape.
    Malformed(String),
    NoCitation,
    /// Citation indices outside `1..=supplied`.
    InvalidCitation(BTreeSet<usize>),
    /// Inline `[S<k>]` markers that are not in `citations`.
    InlineMarkerNotCited(BTreeSet<usize>),
    /// Numbers in the answer absent from every cited source.
    UnsupportedNumbers(BTreeSet<String>),
    EmptyAnswer,
    TooLong(usize),
    /// Number+unit claims no cited source states with that unit.
    UnsupportedQuantities(BTreeSet<String>),
    /// The question asked for a unit the answer does not give.
    RequestedUnitMissing(String),
    /// Equipment codes / proper names from the question absent from every
    /// cited source.
    EntityNotInCitedSources(BTreeSet<String>),
    /// Cited sources cover too little of the question (permille).
    QuestionNotCovered(u32),
    /// Too little of the answer's wording appears in the cited sources
    /// (permille).
    AnswerNotInSources(u32),
}

fn permille(x: f64) -> u32 {
    (x * 1000.0).round() as u32
}

/// Release decision for one answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Validation {
    Released {
        answer: String,
        citations: BTreeSet<usize>,
    },
    /// The model declared the sources insufficient.
    Abstained,
    Withheld(WithholdReason),
}

/// The text a cited source contributes to numeric support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceText<'a> {
    pub doc_id: &'a str,
    pub title: &'a str,
    pub text: &'a str,
}

/// JSON schema for the constrained output, given `n` supplied sources.
/// Property order is the generation order: decide sufficiency, write, cite.
pub fn response_schema(n: usize) -> String {
    let max = n.max(1);
    // Written as text, not via `serde_json::json!`: without serde_json's
    // `preserve_order` feature (not enabled; it would change map ordering for
    // every crate in the workspace) object keys are sorted alphabetically,
    // which silently reordered generation to answer → citations →
    // insufficient. Grammar property order is the generation order.
    format!(
        concat!(
            r#"{{"type":"object","properties":{{"#,
            r#""insufficient":{{"type":"boolean"}},"#,
            r#""answer":{{"type":"string","maxLength":{max_chars}}},"#,
            r#""citations":{{"type":"array","items":{{"type":"integer","minimum":1,"maximum":{max}}},"maxItems":{max}}}"#,
            r#"}},"required":["insufficient","answer","citations"],"additionalProperties":false}}"#
        ),
        max_chars = MAX_ANSWER_CHARS,
        max = max
    )
}

/// Normalise a decimal literal so "7.10", "07.1" and "7.1" compare equal.
/// Input is `\d+(\.\d+)?` by construction of [`extract_numbers`].
fn normalise(lit: &str) -> String {
    let (int, frac) = match lit.split_once('.') {
        Some((i, f)) => (i, f.trim_end_matches('0')),
        None => (lit, ""),
    };
    let int = int.trim_start_matches('0');
    let int = if int.is_empty() { "0" } else { int };
    if frac.is_empty() {
        int.to_string()
    } else {
        format!("{int}.{frac}")
    }
}

/// Extract decimal number literals: maximal runs of ASCII digits, with one
/// optional `.digits` fraction. `P-7` yields `7`; `4.5-7.1` yields `4.5`,
/// `7.1`; `1,200` yields `1` and `200` (thousands separators are not
/// interpreted, so they must appear identically in the source to pass).
pub fn extract_numbers(s: &str) -> BTreeSet<String> {
    let b = s.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i + 1 < b.len() && b[i] == b'.' && b[i + 1].is_ascii_digit() {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            out.insert(normalise(&s[start..i]));
        } else {
            i += 1;
        }
    }
    out
}

/// Remove `[S<k>]` markers so their digits are not treated as claims.
fn strip_markers(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("[S") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && after.as_bytes().get(digits) == Some(&b']') {
            rest = &after[digits + 1..];
        } else {
            out.push_str("[S");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Parse and validate raw model output against the supplied sources.
pub fn validate(raw: &str, question: &str, sources: &[SourceText<'_>]) -> Validation {
    let parsed: StructuredAnswer = match serde_json::from_str(raw.trim()) {
        Ok(p) => p,
        Err(e) => return Validation::Withheld(WithholdReason::Malformed(e.to_string())),
    };
    if parsed.insufficient {
        return Validation::Abstained;
    }
    let answer = parsed.answer.trim().to_string();
    if answer.is_empty() {
        return Validation::Withheld(WithholdReason::EmptyAnswer);
    }
    let chars = answer.chars().count();
    if chars > MAX_ANSWER_CHARS {
        return Validation::Withheld(WithholdReason::TooLong(chars));
    }
    let cited: BTreeSet<usize> = parsed.citations.iter().copied().collect();
    if cited.is_empty() {
        return Validation::Withheld(WithholdReason::NoCitation);
    }
    let n = sources.len();
    let invalid: BTreeSet<usize> = cited
        .iter()
        .copied()
        .filter(|k| *k == 0 || *k > n)
        .collect();
    if !invalid.is_empty() {
        return Validation::Withheld(WithholdReason::InvalidCitation(invalid));
    }
    let inline: BTreeSet<usize> = extract_citations(&answer).into_iter().collect();
    let stray: BTreeSet<usize> = inline.difference(&cited).copied().collect();
    if !stray.is_empty() {
        return Validation::Withheld(WithholdReason::InlineMarkerNotCited(stray));
    }
    let mut supported = BTreeSet::new();
    for k in &cited {
        let s = &sources[k - 1];
        for part in [s.doc_id, s.title, s.text] {
            supported.extend(support::numeric_claims(part));
        }
    }
    let unsupported: BTreeSet<String> = support::numeric_claims(&strip_markers(&answer))
        .into_iter()
        .filter(|x| !supported.contains(x))
        .collect();
    if !unsupported.is_empty() {
        return Validation::Withheld(WithholdReason::UnsupportedNumbers(unsupported));
    }
    // Cited material, concatenated per source, for the support checks.
    let cited_text: Vec<String> = cited
        .iter()
        .map(|k| {
            let s = &sources[k - 1];
            format!("{} {} {}", s.doc_id, s.title, s.text)
        })
        .collect();
    let cited_refs: Vec<&str> = cited_text.iter().map(String::as_str).collect();
    let clean = strip_markers(&answer);
    let bad_units = support::unsupported_quantities(&clean, &cited_refs);
    if !bad_units.is_empty() {
        return Validation::Withheld(WithholdReason::UnsupportedQuantities(bad_units));
    }
    if let Some(u) = support::missing_requested_unit(question, &clean) {
        return Validation::Withheld(WithholdReason::RequestedUnitMissing(u.to_string()));
    }
    let missing = support::missing_entities(question, &cited_refs);
    if !missing.is_empty() {
        return Validation::Withheld(WithholdReason::EntityNotInCitedSources(missing));
    }
    let qc = support::coverage(question, &cited_refs);
    if qc <= support::QUESTION_COVERAGE_MIN {
        return Validation::Withheld(WithholdReason::QuestionNotCovered(permille(qc)));
    }
    let ac = support::coverage(&clean, &cited_refs);
    if ac < support::ANSWER_SUPPORT_MIN {
        return Validation::Withheld(WithholdReason::AnswerNotInSources(permille(ac)));
    }
    Validation::Released {
        answer,
        citations: cited,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> Vec<SourceText<'static>> {
        vec![
            SourceText {
                doc_id: "sop-cp-210",
                title: "SOP CP-210 Pump P-7 Vibration",
                text: "limit 7.1 mm/s; 4.5 to 7.1 within one week",
            },
            SourceText {
                doc_id: "sop-cp-104",
                title: "SOP CP-104",
                text: "inspect every 500 hours; above 85 C remove",
            },
        ]
    }

    /// A question with no content words: support checks that depend on the
    /// question are neutral, isolating the answer-side rules under test.
    fn validate_q(raw: &str, s: &[SourceText<'_>]) -> Validation {
        validate(raw, "?", s)
    }

    fn j(ins: bool, a: &str, c: &[usize]) -> String {
        serde_json::json!({"insufficient": ins, "answer": a, "citations": c}).to_string()
    }

    #[test]
    fn numbers_extracted_and_normalised() {
        let n = extract_numbers("P-7 at 7.10 mm/s, 007 units, 4.5-7.1, v2., 1,200");
        let want: BTreeSet<String> = ["7", "7.1", "4.5", "2", "1", "200"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(n, want);
    }

    #[test]
    fn supported_answer_released() {
        let v = validate_q(&j(false, "The P-7 limit is 7.1 mm/s [S1].", &[1]), &src());
        assert!(matches!(v, Validation::Released { .. }), "{v:?}");
    }

    #[test]
    fn number_from_uncited_source_is_refused() {
        // 500 is in S2, but only S1 is cited.
        assert_eq!(
            validate_q(&j(false, "Inspect every 500 hours.", &[1]), &src()),
            Validation::Withheld(WithholdReason::UnsupportedNumbers(
                ["500".to_string()].into()
            ))
        );
    }

    #[test]
    fn fabricated_number_refused_even_with_valid_citation() {
        assert!(matches!(
            validate_q(&j(false, "Flow rate is 340 L/min.", &[1, 2]), &src()),
            Validation::Withheld(WithholdReason::UnsupportedNumbers(_))
        ));
    }

    #[test]
    fn citation_rules() {
        assert_eq!(
            validate_q(&j(false, "Text.", &[]), &src()),
            Validation::Withheld(WithholdReason::NoCitation)
        );
        assert!(matches!(
            validate_q(&j(false, "Text.", &[3]), &src()),
            Validation::Withheld(WithholdReason::InvalidCitation(_))
        ));
        assert!(matches!(
            validate_q(&j(false, "Text.", &[0]), &src()),
            Validation::Withheld(WithholdReason::InvalidCitation(_))
        ));
        assert!(matches!(
            validate_q(&j(false, "Limit 7.1 [S2].", &[1]), &src()),
            Validation::Withheld(WithholdReason::InlineMarkerNotCited(_))
        ));
    }

    #[test]
    fn abstention_is_not_release() {
        assert_eq!(validate_q(&j(true, "", &[]), &src()), Validation::Abstained);
    }

    #[test]
    fn malformed_and_extra_fields_withheld() {
        for raw in [
            "not json",
            "{}",
            r#"{"insufficient":false,"answer":"x","citations":[1],"note":"y"}"#,
        ] {
            assert!(
                matches!(
                    validate_q(raw, &src()),
                    Validation::Withheld(WithholdReason::Malformed(_))
                ),
                "{raw}"
            );
        }
    }

    #[test]
    fn empty_and_overlong_withheld() {
        assert_eq!(
            validate_q(&j(false, "  ", &[1]), &src()),
            Validation::Withheld(WithholdReason::EmptyAnswer)
        );
        let long = "a".repeat(MAX_ANSWER_CHARS + 1);
        assert!(matches!(
            validate_q(&j(false, &long, &[1]), &src()),
            Validation::Withheld(WithholdReason::TooLong(_))
        ));
    }

    #[test]
    fn marker_digits_are_not_claims() {
        // [S2]'s "2" must not be treated as a numeric claim.
        assert!(matches!(
            validate_q(&j(false, "Above 85 C remove the pump [S2].", &[2]), &src()),
            Validation::Released { .. }
        ));
    }

    #[test]
    fn schema_property_order_is_generation_order() {
        let s = response_schema(2);
        let (a, b, c) = (
            s.find("\"insufficient\"").unwrap(),
            s.find("\"answer\"").unwrap(),
            s.find("\"citations\"").unwrap(),
        );
        assert!(a < b && b < c, "{s}");
    }

    #[test]
    fn schema_bounds_citations_to_supplied_sources() {
        let s: serde_json::Value = serde_json::from_str(&response_schema(3)).unwrap();
        assert_eq!(s["properties"]["citations"]["items"]["maximum"], 3);
        assert_eq!(s["additionalProperties"], false);
    }

    #[test]
    fn wrong_unit_withheld() {
        let s = [SourceText {
            doc_id: "sop-g-2",
            title: "G-2",
            text: "G-2 runs 30 minutes weekly",
        }];
        assert!(matches!(
            validate(
                &j(false, "30 kW", &[1]),
                "What is the G-2 output in kW?",
                &s
            ),
            Validation::Withheld(WithholdReason::UnsupportedQuantities(_))
        ));
    }

    #[test]
    fn requested_unit_absent_withheld() {
        let s = [SourceText {
            doc_id: "fp",
            title: "FP-1",
            text: "FP-1 flow test at 150 percent of rated flow",
        }];
        assert!(matches!(
            validate(
                &j(false, "150 percent of rated flow", &[1]),
                "What is the FP-1 flow in litres per minute?",
                &s
            ),
            Validation::Withheld(WithholdReason::RequestedUnitMissing(_))
        ));
    }

    #[test]
    fn other_entity_withheld() {
        let s = [SourceText {
            doc_id: "tx",
            title: "Transformer T-3",
            text: "T-3 trips at 105 degrees",
        }];
        assert!(matches!(
            validate(
                &j(false, "105 degrees", &[1]),
                "What is the trip temperature for Plant Beta transformers?",
                &s
            ),
            Validation::Withheld(WithholdReason::EntityNotInCitedSources(_))
        ));
    }

    #[test]
    fn off_topic_and_non_answers_withheld() {
        let s = [SourceText {
            doc_id: "loto",
            title: "Lockout",
            text: "the shift supervisor may remove a lock before work starts",
        }];
        assert!(matches!(
            validate(
                &j(false, "The shift supervisor", &[1]),
                "Who approves hot work permits?",
                &s
            ),
            Validation::Withheld(WithholdReason::QuestionNotCovered(_))
        ));
        assert!(matches!(
            validate(&j(false, "Unknown", &[1]), "Who may remove a lock?", &s),
            Validation::Withheld(WithholdReason::AnswerNotInSources(_))
        ));
    }

    #[test]
    fn on_topic_supported_answer_released() {
        let s = [SourceText {
            doc_id: "loto",
            title: "Lockout",
            text: "A lock may be removed only by the person who applied it",
        }];
        assert!(matches!(
            validate(
                &j(false, "Only the person who applied it", &[1]),
                "Who is allowed to remove a lockout lock?",
                &s
            ),
            Validation::Released { .. }
        ));
    }

    #[test]
    fn digit_inside_equipment_code_is_not_evidence() {
        // Held-out finding hu2: "How many cells in BT-4?" answered "4",
        // "supported" by the 4 in "BT-4".
        let s = [SourceText {
            doc_id: "sop-bt-4",
            title: "SOP BT-4 Battery Bank",
            text: "Battery bank BT-4 float voltage is checked monthly.",
        }];
        assert_eq!(
            validate(
                &j(false, "4", &[1]),
                "How many cells are in battery bank BT-4?",
                &s
            ),
            Validation::Withheld(WithholdReason::UnsupportedNumbers(["4".to_string()].into()))
        );
    }
}
