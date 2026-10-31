//! Grounded-answer completeness check (pure).
//!
//! Defect fixed (demo Scene 1): asked for the minimum insulation resistance
//! of a 6.6 kV motor, the model answered "10 times (rated kV plus 1)
//! megohms" — the rule, supported by the source, but not the requested value.
//! The citation validator correctly found it supported and released it.
//!
//! Rule: when the request names a specific quantity (a number with a unit the
//! runtime parses) and the answer states an arithmetic rule (operator words)
//! without a computed result ("="), the requested calculation was not done.
//! The runtime then withholds the answer and says so explicitly, quoting the
//! rule, instead of presenting it as an answer. It never computes a value
//! itself from model text; exact arithmetic is the job of validated
//! capabilities.

use crate::capability::quantity::quantities;

/// Words that mark an arithmetic rule rather than a value.
const OPERATOR_WORDS: &[&str] = &[
    "times",
    "plus",
    "minus",
    "multiplied",
    "multiply",
    "divided",
    "raised",
    "power",
];

/// True when `answer` restates a rule instead of the value `question` asks for.
pub fn unfinished_calculation(question: &str, answer: &str) -> bool {
    if quantities(question).is_empty() || answer.contains('=') {
        return false;
    }
    answer
        .split(|c: char| !c.is_alphanumeric())
        .any(|w| OPERATOR_WORDS.contains(&w.to_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: &str = "What is the minimum insulation resistance for a 6.6 kV motor under EP-114?";

    #[test]
    fn rule_without_value_is_unfinished() {
        assert!(unfinished_calculation(
            Q,
            "10 times (rated kV plus 1) megohms"
        ));
    }

    #[test]
    fn computed_values_and_general_questions_pass() {
        assert!(!unfinished_calculation(Q, "76 megohms"));
        assert!(!unfinished_calculation(
            Q,
            "10 times (6.6 plus 1) = 76 megohms"
        ));
        // No specific quantity in the request: stating the rule is the answer.
        assert!(!unfinished_calculation(
            "What is the minimum insulation resistance rule under EP-114?",
            "10 times (rated kV plus 1) megohms"
        ));
    }
}
