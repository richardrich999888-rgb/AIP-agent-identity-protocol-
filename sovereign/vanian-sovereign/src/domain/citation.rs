//! Citation extraction and grounding classification.
//!
//! The prompt numbers each authorized passage `[S1]..[Sn]`. After generation
//! we parse every `[S<k>]` marker in the answer and classify it:
//!
//! - **Grounded**: at least one valid citation, and no citation outside
//!   `1..=n`.
//! - **Ungrounded**: no citation at all. The answer is returned but labelled;
//!   it is never presented as source-backed.
//! - **InvalidCitation**: a marker names a source that was not supplied. This
//!   is a fabricated reference and the answer is withheld.
//!
//! This checks that citations *point at* supplied sources. It does not check
//! that the cited passage *supports* the sentence — that is entailment, an
//! open problem, and it is not claimed here.

use std::collections::BTreeSet;

/// Grounding outcome for one generated answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grounding {
    /// Distinct, valid 1-based source indices that the answer cites.
    Grounded(BTreeSet<usize>),
    Ungrounded,
    /// Indices cited that were never supplied (fabricated references).
    InvalidCitation(BTreeSet<usize>),
}

/// Extract every `[S<digits>]` marker. Deterministic, linear time; ignores
/// malformed markers (`[S]`, `[Sx]`) and caps digit length to avoid overflow.
pub fn extract_citations(answer: &str) -> Vec<usize> {
    const MAX_DIGITS: usize = 4;
    let bytes = answer.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() + 1 {
        if bytes[i] == b'[' && i + 1 < bytes.len() && bytes[i + 1] == b'S' {
            let start = i + 2;
            let mut j = start;
            while j < bytes.len() && bytes[j].is_ascii_digit() && j - start < MAX_DIGITS {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b']' {
                // SAFETY of unwrap: 1..=4 ASCII digits always parse into usize.
                out.push(answer[start..j].parse::<usize>().unwrap());
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Classify an answer against the number of sources that were supplied.
pub fn classify(answer: &str, supplied: usize) -> Grounding {
    let cited: BTreeSet<usize> = extract_citations(answer).into_iter().collect();
    if cited.is_empty() {
        return Grounding::Ungrounded;
    }
    let invalid: BTreeSet<usize> = cited
        .iter()
        .copied()
        .filter(|k| *k == 0 || *k > supplied)
        .collect();
    if !invalid.is_empty() {
        return Grounding::InvalidCitation(invalid);
    }
    Grounding::Grounded(cited)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_valid_markers_only() {
        assert_eq!(
            extract_citations("a [S1] b [S12] c [S] [Sx] [S3"),
            vec![1, 12]
        );
        assert_eq!(extract_citations(""), Vec::<usize>::new());
        assert_eq!(extract_citations("[S1][S2]"), vec![1, 2]);
    }

    #[test]
    fn overlong_digits_are_ignored_not_overflowed() {
        assert!(extract_citations("[S99999999999999999999999]").is_empty());
    }

    #[test]
    fn grounded_when_all_citations_in_range() {
        assert_eq!(
            classify("x [S1] y [S2] [S1]", 2),
            Grounding::Grounded([1, 2].into_iter().collect())
        );
    }

    #[test]
    fn ungrounded_when_no_citation() {
        assert_eq!(classify("plain answer", 3), Grounding::Ungrounded);
    }

    #[test]
    fn fabricated_reference_detected() {
        assert_eq!(
            classify("x [S1] [S4] [S0]", 3),
            Grounding::InvalidCitation([0, 4].into_iter().collect())
        );
        // Any citation when nothing was supplied is fabricated.
        assert_eq!(
            classify("[S1]", 0),
            Grounding::InvalidCitation([1].into_iter().collect())
        );
    }

    #[test]
    fn non_ascii_text_does_not_panic() {
        assert_eq!(
            classify("नमस्ते [S1] ✓", 1),
            Grounding::Grounded([1].into_iter().collect())
        );
    }
}
