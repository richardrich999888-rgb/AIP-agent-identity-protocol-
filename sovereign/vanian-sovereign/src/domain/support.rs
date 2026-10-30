//! Deterministic support checks between a question, an answer and the
//! sources the answer cites. Pure functions; no model involvement.
//!
//! Each check targets one failure class observed in the 2026-10-31 dev
//! evaluation (44 questions), not individual questions:
//!
//! | Check | Failure class it closes |
//! |---|---|
//! | [`unsupported_quantities`] | right number, wrong unit ("30 kW" from "30 minutes") |
//! | [`missing_requested_unit`] | question asks "in bar", answer gives a percentage |
//! | [`missing_entities`] | question about "Plant Beta" / "B-9" answered from other equipment |
//! | [`coverage`] (question) | off-topic but well-cited answers |
//! | [`coverage`] (answer) | non-answers such as "Unknown" released as answers |
//!
//! All thresholds are constants with a stated rationale. They were fixed
//! before the held-out set was run and were not changed afterwards.

use std::collections::BTreeSet;

use super::grounding::extract_numbers;

/// A question's content words must be more than half covered by the cited
/// sources: the cited material has to be *about* most of what was asked.
pub const QUESTION_COVERAGE_MIN: f64 = 0.5;
/// At least two thirds of an answer's content words must appear in the cited
/// sources. Allows light paraphrase; refuses text the sources do not contain.
pub const ANSWER_SUPPORT_MIN: f64 = 2.0 / 3.0;
/// Words of this length or more match on a shared prefix of this length
/// ("percentage" ~ "percent", "inspected" ~ "inspection").
const STEM_PREFIX: usize = 5;

/// Function words and question words carrying no topical content.
const STOPWORDS: &[&str] = &[
    "the",
    "and",
    "for",
    "with",
    "what",
    "which",
    "who",
    "whom",
    "whose",
    "how",
    "when",
    "where",
    "why",
    "does",
    "did",
    "done",
    "are",
    "was",
    "were",
    "has",
    "have",
    "had",
    "must",
    "should",
    "can",
    "could",
    "would",
    "will",
    "shall",
    "may",
    "might",
    "often",
    "many",
    "much",
    "long",
    "each",
    "every",
    "any",
    "all",
    "this",
    "that",
    "these",
    "those",
    "from",
    "into",
    "onto",
    "about",
    "according",
    "there",
    "their",
    "its",
    "than",
    "then",
    "also",
    "only",
    "not",
    "use",
    "used",
    "uses",
    "using",
    "need",
    "needed",
    "needs",
    "required",
    "requires",
    "allowed",
    "after",
    "before",
    "during",
    "under",
    "over",
    "between",
    "per",
    "time",
    "times",
    "kept",
    "say",
    "says",
    "said",
    "tell",
    "list",
    "describe",
    "please",
    "you",
    "your",
    "our",
    "out",
    "set",
    "get",
    "some",
    "value",
    "number",
    "amount",
    "level",
    "latest",
    "approximately",
    "exactly",
    "always",
    "ever",
];

/// Canonical unit for a unit word, if it is one. Deliberately small; an
/// unknown word is simply not a unit.
pub fn canonical_unit(word: &str) -> Option<&'static str> {
    Some(match word {
        "%" | "percent" | "percentage" | "pct" => "percent",
        "hour" | "hours" | "hr" | "hrs" | "h" => "hour",
        "minute" | "minutes" | "min" | "mins" => "minute",
        "second" | "seconds" | "sec" | "secs" => "second",
        "day" | "days" => "day",
        "week" | "weeks" => "week",
        "month" | "months" => "month",
        "year" | "years" => "year",
        "degree" | "degrees" | "celsius" | "°c" => "degc",
        "bar" | "bars" => "bar",
        "kw" | "kilowatt" | "kilowatts" => "kw",
        "kva" => "kva",
        "kg" | "kilogram" | "kilograms" => "kg",
        "tonne" | "tonnes" | "ton" | "tons" | "t" => "tonne",
        "litre" | "litres" | "liter" | "liters" | "l" => "litre",
        "volt" | "volts" | "v" => "volt",
        "nm" => "nm",
        "mm" | "millimetre" | "millimetres" | "millimeter" | "millimeters" => "mm",
        "metre" | "metres" | "meter" | "meters" | "m" => "metre",
        "drop" | "drops" | "dpm" => "drop",
        _ => return None,
    })
}

/// Lowercased word tokens. Hyphenated codes ("p-7") stay one token.
pub fn tokens(s: &str) -> Vec<String> {
    // '%' is split into its own token so "75%" yields "75" then "%".
    let spaced = s.replace('%', " % ");
    spaced
        .split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '.' || c == '%' || c == '°'))
        .map(|t| t.trim_matches(|c| c == '.' || c == '-').to_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Purely numeric token, allowing ranges and separators ("4.5-7.1",
/// "48-19-77"). Codes such as "p-7" contain letters and are not numbers.
fn is_number(t: &str) -> bool {
    t.chars().any(|c| c.is_ascii_digit())
        && t.chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
}

/// Numeric claims: numbers from purely numeric tokens only. Digits inside
/// codes ("BT-4", "CP-210", "IR-77") identify equipment and are neither
/// claims in an answer nor evidence in a source.
pub fn numeric_claims(s: &str) -> BTreeSet<String> {
    tokens(s)
        .iter()
        .filter(|t| is_number(t))
        .flat_map(|t| extract_numbers(t))
        .collect()
}

/// (number, canonical unit) pairs: a number literal immediately followed by
/// a unit word. A number followed by anything else yields `(n, None)`.
pub fn quantities(s: &str) -> BTreeSet<(String, Option<&'static str>)> {
    let t = tokens(s);
    let mut out = BTreeSet::new();
    for (i, tok) in t.iter().enumerate() {
        if !is_number(tok) {
            continue;
        }
        for n in extract_numbers(tok) {
            let unit = t.get(i + 1).and_then(|u| canonical_unit(u));
            out.insert((n, unit));
        }
    }
    out
}

/// Units present anywhere in a text.
fn units_in(s: &str) -> BTreeSet<&'static str> {
    tokens(s).iter().filter_map(|t| canonical_unit(t)).collect()
}

/// Answer quantities with a unit that no cited source supports.
///
/// `(n, u)` is supported by a source that states `n u`, or that states `n`
/// with no unit after it while mentioning unit `u` elsewhere ("between 2.20
/// and 2.30 volts" supports "2.2 V"). A source stating `n` with a
/// *different* unit does not support it.
pub fn unsupported_quantities(answer: &str, cited: &[&str]) -> BTreeSet<String> {
    let mut bad = BTreeSet::new();
    for (n, u) in quantities(answer) {
        let Some(u) = u else { continue };
        let ok = cited.iter().any(|src| {
            let q = quantities(src);
            q.contains(&(n.clone(), Some(u)))
                || (q.contains(&(n.clone(), None)) && units_in(src).contains(u))
        });
        if !ok {
            bad.insert(format!("{n} {u}"));
        }
    }
    bad
}

/// The unit a question explicitly asks for ("in bar", "how many kilograms").
pub fn requested_unit(question: &str) -> Option<&'static str> {
    let t = tokens(question);
    t.windows(2).find_map(|w| match w[0].as_str() {
        "in" | "many" => canonical_unit(&w[1]),
        _ => None,
    })
}

/// If the question asks for a unit, the answer must state a quantity in it.
pub fn missing_requested_unit(question: &str, answer: &str) -> Option<&'static str> {
    let u = requested_unit(question)?;
    let has = quantities(answer).iter().any(|(_, au)| *au == Some(u));
    (!has).then_some(u)
}

/// Equipment codes ("P-7", "IR-77", "BETA-OIL-7") and mid-sentence proper
/// names ("Plant", "Beta") in the question, lowercased.
pub fn entities(question: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut sentence_start = true;
    for raw in question.split_whitespace() {
        let w = raw.trim_matches(|c: char| !(c.is_alphanumeric() || c == '-'));
        let ends = raw.ends_with(['.', '?', '!', ':']);
        let is_code = w.contains('-')
            && w.chars().any(|c| c.is_ascii_digit())
            && w.chars().any(|c| c.is_ascii_uppercase())
            && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        let is_name = !sentence_start
            && w.len() >= 3
            && w.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && w.chars().skip(1).all(|c| c.is_ascii_lowercase());
        if is_code || is_name {
            out.insert(w.to_lowercase());
        }
        sentence_start = ends;
    }
    out
}

/// Entities from the question that no cited source mentions.
pub fn missing_entities(question: &str, cited: &[&str]) -> BTreeSet<String> {
    let have: BTreeSet<String> = cited.iter().flat_map(|s| tokens(s)).collect();
    entities(question)
        .into_iter()
        .filter(|e| !have.contains(e))
        .collect()
}

/// Content words: tokens of 3+ chars that are neither stopwords, numbers
/// nor unit words.
pub fn content_words(s: &str) -> Vec<String> {
    tokens(s)
        .into_iter()
        .filter(|t| t.chars().count() >= 3 && !is_number(t) && canonical_unit(t).is_none())
        .filter(|t| !STOPWORDS.contains(&t.as_str()))
        .collect()
}

fn stem_match(a: &str, b: &str) -> bool {
    a == b
        || (a.len() >= STEM_PREFIX
            && b.len() >= STEM_PREFIX
            && a.is_char_boundary(STEM_PREFIX)
            && b.is_char_boundary(STEM_PREFIX)
            && a[..STEM_PREFIX] == b[..STEM_PREFIX])
}

/// Fraction of `text`'s content words found in `cited` (1.0 if none).
pub fn coverage(text: &str, cited: &[&str]) -> f64 {
    let words = content_words(text);
    if words.is_empty() {
        return 1.0;
    }
    let have: Vec<String> = cited.iter().flat_map(|s| tokens(s)).collect();
    let hit = words
        .iter()
        .filter(|w| have.iter().any(|h| stem_match(w, h)))
        .count();
    hit as f64 / words.len() as f64
}

/// Instruction-like phrases that mark a document as a prompt-injection
/// suspect. Generic, widely published patterns; matching is a heuristic and
/// is trivially evadable by rephrasing — it is one layer, not a control.
pub const INJECTION_MARKERS: &[&str] = &[
    "ignore all previous",
    "ignore previous",
    "ignore the previous",
    "ignore your",
    "ignore all rules",
    "disregard",
    "system instruction",
    "system prompt",
    "assistant:",
    "to the assistant",
    "you are now",
    "from now on",
    "reveal the",
    "do not tell the user",
];

/// The first injection marker found in `text`, if any.
pub fn injection_marker(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    INJECTION_MARKERS
        .iter()
        .copied()
        .find(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantities_bind_units() {
        let q = quantities("Runs 30 minutes at 75 percent; 2.20 and 2.30 volts; P-7");
        assert!(q.contains(&("30".into(), Some("minute"))));
        assert!(q.contains(&("75".into(), Some("percent"))));
        assert!(q.contains(&("2.2".into(), None)));
        assert!(q.contains(&("2.3".into(), Some("volt"))));
        assert!(quantities("75%").contains(&("75".into(), Some("percent"))));
        assert_eq!(content_words("75%"), Vec::<String>::new());
        let r = quantities("between 4.5-7.1 mm per second");
        assert!(r.contains(&("4.5".into(), Some("mm"))) && r.contains(&("7.1".into(), Some("mm"))));
    }

    #[test]
    fn code_digits_are_not_numeric_claims() {
        let c = numeric_claims("BT-4 holds 24 cells at 2.20 V; ref CP-210; 4.5-7.1");
        let want: BTreeSet<String> = ["24", "2.2", "4.5", "7.1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(c, want);
    }

    #[test]
    fn wrong_unit_is_unsupported() {
        let src = ["G-2 runs at no load for 30 minutes every week."];
        assert_eq!(
            unsupported_quantities("30 kW", &src),
            ["30 kw".to_string()].into()
        );
        assert!(unsupported_quantities("30 minutes", &src).is_empty());
        // Bare answer numbers are left to the numeric check.
        assert!(unsupported_quantities("30", &src).is_empty());
    }

    #[test]
    fn unit_elsewhere_in_source_supports_bare_source_number() {
        let src = ["Each cell must read between 2.20 and 2.30 volts."];
        assert!(unsupported_quantities("2.2 V to 2.3 V", &src).is_empty());
    }

    #[test]
    fn requested_unit_enforced() {
        assert_eq!(requested_unit("What is the pressure in bar?"), Some("bar"));
        assert_eq!(
            requested_unit("How many kilograms does it hold?"),
            Some("kg")
        );
        assert_eq!(requested_unit("How many bolts are there?"), None);
        assert_eq!(requested_unit("How long does G-2 run each week?"), None);
        assert_eq!(
            missing_requested_unit("Flow in litres per minute?", "150 percent"),
            Some("litre")
        );
        assert_eq!(missing_requested_unit("Pressure in bar?", "0.8 bar"), None);
    }

    #[test]
    fn entities_extracted_and_checked() {
        let e = entities("What is the oil trip temperature for Plant Beta transformers?");
        assert_eq!(e, ["beta".to_string(), "plant".to_string()].into());
        let e = entities("Ignore this. How often is boiler B-9 blown down?");
        assert_eq!(e, ["b-9".to_string()].into());
        assert!(missing_entities("Where is pump P-7?", &["pump P-7 is in bay 2"]).is_empty());
        assert_eq!(
            missing_entities("Where is pump P-77?", &["pump P-7"]),
            ["p-77".to_string()].into()
        );
    }

    #[test]
    fn coverage_uses_prefix_stems() {
        let src = ["inspect every 500 hours; inspection checks bearings"];
        assert!(coverage("How often is it inspected?", &src) >= 1.0);
        assert!(
            coverage("Which chemical treats cooling tower water?", &src) < QUESTION_COVERAGE_MIN
        );
        assert!(coverage("Unknown", &src) < ANSWER_SUPPORT_MIN);
        assert_eq!(coverage("500", &src), 1.0);
    }

    #[test]
    fn injection_markers_detected_case_insensitively() {
        assert_eq!(
            injection_marker("Note. IGNORE ALL PREVIOUS rules"),
            Some("ignore all previous")
        );
        assert_eq!(injection_marker("Pump runs 500 hours."), None);
    }

    #[test]
    fn non_ascii_input_does_not_panic() {
        let s = "तापमान 85 °C पर पंप P-7";
        let _ = (
            quantities(s),
            entities(s),
            coverage(s, &[s]),
            content_words(s),
        );
        assert!(stem_match("नमस्ते", "नमस्ते"));
    }
}
