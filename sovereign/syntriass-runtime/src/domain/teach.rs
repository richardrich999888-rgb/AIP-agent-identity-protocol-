//! Teach sessions: what an expert said, bound to what the document says.
//!
//! A teach session is the first artifact in the teaching flow. It is *not* a
//! capability and carries no procedure: it records, for one task in one
//! tenant, the clauses an expert cited, the rule they stated in their own
//! words, and the handful of labelled examples they gave with reasons. A3
//! turns a session into a candidate capability; nothing here can execute.
//!
//! Pure: no IO, no clock, no randomness. The wall clock arrives as the
//! `now_ms` argument so a session is a deterministic function of its inputs,
//! and the content hash is reproducible from the stored file alone.
//!
//! What a session refuses to be, by construction:
//! - **unbound from the document.** Every cited clause must carry the same
//!   document name *and* the same SHA-256 as the session, and the caller is
//!   expected to have hashed the file on disk (see `teach start`). A clause
//!   set from a different revision of the document is not a citation.
//! - **unverifiable as a span.** A clause's `text` must be exactly as long as
//!   its `[char_start, char_end)` span claims, in characters. The A1 ingester
//!   emits spans that slice exactly; a clause file that does not satisfy that
//!   came from somewhere else.
//! - **one-sided.** At least one `allowed` and one `not_allowed` example are
//!   required. An example set of a single class cannot distinguish a rule
//!   from a constant, so it is worthless as validation evidence downstream —
//!   a suite built from it would pass a procedure that always answers the one
//!   label it ever saw.
//! - **silent about OCR.** Clauses recovered by OCR are listed in
//!   `ocr_cited`. OCR misreads digits, and the drafting step in A3 takes
//!   thresholds from clause text, so a value read this way belongs in the
//!   class that is put back to the expert rather than asserted.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for the session content hash (version-tagged).
const DOMAIN: &[u8] = b"syntriass-teach-session/v1\n";
/// Schema tag written into every session file.
pub const SCHEMA: &str = "syntriass.teach-session/v1";

/// Fewest labelled examples an expert must give.
pub const MIN_EXAMPLES: usize = 2;
/// Most labelled examples a session will hold. Beyond a handful the expert is
/// writing a test suite, which is a signed object of its own (`suite-sign`).
pub const MAX_EXAMPLES: usize = 5;
/// Most clauses one session may cite.
pub const MAX_CLAUSES: usize = 32;
/// Bounds on free text (characters, not bytes).
pub const MAX_RULE_CHARS: usize = 2_000;
pub const MAX_EXAMPLE_CHARS: usize = 2_000;
pub const MAX_REASON_CHARS: usize = 500;
pub const MAX_CLAUSE_CHARS: usize = 8_000;
/// Bound on identifier fields (tenant, task, expert, example and clause ids).
pub const MAX_IDENT_CHARS: usize = 64;

/// The two labels an expert may attach to an example.
///
/// Deliberately closed. A third value would have to mean something to the
/// drafting step, and inventing one here would let an unreviewed label reach
/// a capability's outcome set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Label {
    #[serde(rename = "allowed")]
    Allowed,
    #[serde(rename = "not_allowed")]
    NotAllowed,
}

impl Label {
    pub fn as_str(&self) -> &'static str {
        match self {
            Label::Allowed => "allowed",
            Label::NotAllowed => "not_allowed",
        }
    }
}

/// How a clause's text was obtained. Closed set: an unknown extractor's
/// output must not become evidence without review, so it is refused rather
/// than carried through with a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Extraction {
    #[serde(rename = "pdf_text")]
    PdfText,
    #[serde(rename = "pdf_ocr")]
    PdfOcr,
    #[serde(rename = "docx")]
    Docx,
    #[serde(rename = "txt")]
    Txt,
}

impl Extraction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Extraction::PdfText => "pdf_text",
            Extraction::PdfOcr => "pdf_ocr",
            Extraction::Docx => "docx",
            Extraction::Txt => "txt",
        }
    }

    /// True when a numeric value taken from this text is a hypothesis to be
    /// confirmed rather than a reading to be trusted.
    pub fn needs_confirmation(&self) -> bool {
        matches!(self, Extraction::PdfOcr)
    }
}

/// One citable span of the session's document, as emitted by the A1 ingester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitedClause {
    pub document: String,
    pub document_sha256: String,
    /// 1-based page number.
    pub page: u32,
    /// 0-based position of this clause within its page.
    pub index: u32,
    pub text: String,
    /// Character offsets into the page's extracted text; `text` is exactly
    /// `char_end - char_start` characters long.
    pub char_start: u32,
    pub char_end: u32,
    pub extraction: Extraction,
}

impl CitedClause {
    /// Stable identifier of this clause within the session: page and index
    /// are enough, because the ingester emits one clause per (page, index).
    pub fn id(&self) -> String {
        format!("p{}#{}", self.page, self.index)
    }

    /// `document p.N [start:end]`, the form a reviewer can look up.
    pub fn citation(&self) -> String {
        format!(
            "{} p.{} [{}:{}]",
            self.document, self.page, self.char_start, self.char_end
        )
    }
}

/// One labelled example with the expert's reason for the label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Example {
    pub id: String,
    pub text: String,
    pub label: Label,
    /// Why this label. Required: a label without a reason cannot be reviewed,
    /// and the question generator in B1 has nothing to quote back.
    pub reason: String,
}

/// Everything the caller must supply to open a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInput {
    pub tenant: String,
    pub task: String,
    pub expert_id: String,
    pub document: String,
    /// SHA-256 of the document's bytes as the caller read them from disk.
    pub document_sha256: String,
    /// 1-based pages the expert asked to teach from.
    pub pages: Vec<u32>,
    pub clauses: Vec<CitedClause>,
    pub rule: String,
    pub examples: Vec<Example>,
}

/// A teach session. `session_id` is the content hash of every other field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeachSession {
    pub schema: String,
    pub session_id: String,
    pub tenant: String,
    pub task: String,
    pub expert_id: String,
    pub document: String,
    pub document_sha256: String,
    pub pages: Vec<u32>,
    pub clauses: Vec<CitedClause>,
    pub rule: String,
    pub examples: Vec<Example>,
    /// Ids of cited clauses whose text came from OCR. Empty is the normal
    /// case and is *measured*, not assumed: it is derived from the clauses.
    pub ocr_cited: Vec<String>,
    pub created_ms: u64,
}

/// The hashed content: every field except `session_id`, in fixed order.
#[derive(Serialize)]
struct Unsigned<'a> {
    schema: &'a str,
    tenant: &'a str,
    task: &'a str,
    expert_id: &'a str,
    document: &'a str,
    document_sha256: &'a str,
    pages: &'a [u32],
    clauses: &'a [CitedClause],
    rule: &'a str,
    examples: &'a [Example],
    ocr_cited: &'a [String],
    created_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeachError {
    /// An identifier field is empty, too long, or has a character outside
    /// `[A-Za-z0-9._:-]`.
    BadIdent {
        field: &'static str,
        value: String,
    },
    NotHex64 {
        field: &'static str,
        value: String,
    },
    EmptyText {
        field: &'static str,
    },
    TooLong {
        field: &'static str,
        chars: usize,
        max: usize,
    },
    TooManyClauses(usize),
    /// A clause cites a different document, or a different revision of it.
    ClauseDocumentMismatch {
        clause: String,
        found: String,
        expected: String,
    },
    /// `text` is not as long as `[char_start, char_end)` claims.
    ClauseSpanMismatch {
        clause: String,
        span: usize,
        text_chars: usize,
    },
    /// `char_start >= char_end`, or `page` is 0.
    ClauseSpanInvalid {
        clause: String,
    },
    DuplicateClause(String),
    NoPages,
    /// A requested page has no clause in the supplied clause set.
    PageNotCited(u32),
    /// A clause was supplied for a page that was not requested.
    ClausePageNotRequested {
        clause: String,
        page: u32,
    },
    TooFewExamples(usize),
    TooManyExamples(usize),
    DuplicateExampleId(String),
    /// Two examples say the same thing once whitespace and case are
    /// normalised. If their labels differ the session is self-contradictory;
    /// if they agree, one of them is padding toward `MIN_EXAMPLES`.
    DuplicateExampleText {
        first: String,
        second: String,
    },
    /// Every example carries the same label.
    SingleClassExamples(Label),
    ZeroClock,
}

impl std::fmt::Display for TeachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeachError::BadIdent { field, value } => {
                write!(f, "{field}: not a valid identifier: {value:?}")
            }
            TeachError::NotHex64 { field, value } => {
                write!(
                    f,
                    "{field}: expected 64 lowercase hex characters, got {value:?}"
                )
            }
            TeachError::EmptyText { field } => write!(f, "{field}: must not be empty"),
            TeachError::TooLong { field, chars, max } => {
                write!(f, "{field}: {chars} characters, limit {max}")
            }
            TeachError::TooManyClauses(n) => {
                write!(f, "clauses: {n} cited, limit {MAX_CLAUSES}")
            }
            TeachError::ClauseDocumentMismatch {
                clause,
                found,
                expected,
            } => write!(
                f,
                "clause {clause}: cites {found}, session document is {expected}"
            ),
            TeachError::ClauseSpanMismatch {
                clause,
                span,
                text_chars,
            } => write!(
                f,
                "clause {clause}: span claims {span} characters, text has {text_chars}"
            ),
            TeachError::ClauseSpanInvalid { clause } => {
                write!(
                    f,
                    "clause {clause}: page must be >= 1 and char_start < char_end"
                )
            }
            TeachError::DuplicateClause(id) => write!(f, "clause {id}: cited twice"),
            TeachError::NoPages => write!(f, "pages: at least one page must be requested"),
            TeachError::PageNotCited(p) => {
                write!(
                    f,
                    "page {p}: requested, but no clause was extracted from it"
                )
            }
            TeachError::ClausePageNotRequested { clause, page } => write!(
                f,
                "clause {clause}: on page {page}, which was not requested"
            ),
            TeachError::TooFewExamples(n) => {
                write!(f, "examples: {n} given, at least {MIN_EXAMPLES} required")
            }
            TeachError::TooManyExamples(n) => {
                write!(f, "examples: {n} given, limit {MAX_EXAMPLES}")
            }
            TeachError::DuplicateExampleId(id) => write!(f, "example {id}: duplicate id"),
            TeachError::DuplicateExampleText { first, second } => write!(
                f,
                "examples {first} and {second}: same text once whitespace and case are normalised"
            ),
            TeachError::SingleClassExamples(l) => write!(
                f,
                "examples: every example is labelled {}; one of each label is required",
                l.as_str()
            ),
            TeachError::ZeroClock => write!(f, "created_ms: must be non-zero"),
        }
    }
}

impl std::error::Error for TeachError {}

/// Identifier grammar shared by tenant, task, expert and example ids. Kept
/// deliberately narrow: these values become path components and JSON keys.
fn check_ident(field: &'static str, value: &str) -> Result<(), TeachError> {
    let chars = value.chars().count();
    if chars == 0 {
        return Err(TeachError::EmptyText { field });
    }
    if chars > MAX_IDENT_CHARS {
        return Err(TeachError::TooLong {
            field,
            chars,
            max: MAX_IDENT_CHARS,
        });
    }
    let ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    // A leading dot would make a hidden file; "." and ".." would escape the
    // tenant directory. Refused here rather than in the store, so the core
    // owns the rule and the store cannot be handed an unsafe name at all.
    if !ok || value.starts_with('.') {
        return Err(TeachError::BadIdent {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn check_hex64(field: &'static str, value: &str) -> Result<(), TeachError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Ok(());
    }
    Err(TeachError::NotHex64 {
        field,
        value: value.to_string(),
    })
}

fn check_text(field: &'static str, value: &str, max: usize) -> Result<(), TeachError> {
    if value.trim().is_empty() {
        return Err(TeachError::EmptyText { field });
    }
    let chars = value.chars().count();
    if chars > max {
        return Err(TeachError::TooLong { field, chars, max });
    }
    Ok(())
}

/// Compare example texts for sameness, not for equality of bytes.
///
/// Whitespace is collapsed because the PDF text layer puts line breaks inside
/// phrases (A1 finding: a clause reads `between 10\nC and 25 C`), so two
/// examples pasted from different places in the same document can differ only
/// by a newline. Case is folded because a label must not depend on it.
fn normalise(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn check_clauses(input: &SessionInput) -> Result<Vec<String>, TeachError> {
    // No separate "no clauses" error: `pages` is already known to be
    // non-empty, so an empty clause set means every requested page is
    // uncited, and the page-coverage check below names the page. That is the
    // diagnostic the expert can act on; "no clauses were cited" is not.
    if input.clauses.len() > MAX_CLAUSES {
        return Err(TeachError::TooManyClauses(input.clauses.len()));
    }
    let requested: std::collections::BTreeSet<u32> = input.pages.iter().copied().collect();
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut cited_pages = std::collections::BTreeSet::new();
    let mut ocr = Vec::new();
    for clause in &input.clauses {
        let id = clause.id();
        if !seen_ids.insert(id.clone()) {
            return Err(TeachError::DuplicateClause(id));
        }
        if clause.document != input.document {
            return Err(TeachError::ClauseDocumentMismatch {
                clause: id,
                found: clause.document.clone(),
                expected: input.document.clone(),
            });
        }
        if clause.document_sha256 != input.document_sha256 {
            return Err(TeachError::ClauseDocumentMismatch {
                clause: id,
                found: clause.document_sha256.clone(),
                expected: input.document_sha256.clone(),
            });
        }
        if clause.page == 0 || clause.char_start >= clause.char_end {
            return Err(TeachError::ClauseSpanInvalid { clause: id });
        }
        if !requested.contains(&clause.page) {
            return Err(TeachError::ClausePageNotRequested {
                clause: id,
                page: clause.page,
            });
        }
        check_text("clause.text", &clause.text, MAX_CLAUSE_CHARS)?;
        // The span is the citation. If the recorded text is not the length the
        // span claims, one of the two is wrong and the citation cannot be
        // checked against the document by anyone reading the session later.
        let span = (clause.char_end - clause.char_start) as usize;
        let text_chars = clause.text.chars().count();
        if span != text_chars {
            return Err(TeachError::ClauseSpanMismatch {
                clause: id,
                span,
                text_chars,
            });
        }
        cited_pages.insert(clause.page);
        if clause.extraction.needs_confirmation() {
            ocr.push(id);
        }
    }
    for page in &requested {
        if !cited_pages.contains(page) {
            return Err(TeachError::PageNotCited(*page));
        }
    }
    ocr.sort();
    Ok(ocr)
}

fn check_examples(examples: &[Example]) -> Result<(), TeachError> {
    if examples.len() < MIN_EXAMPLES {
        return Err(TeachError::TooFewExamples(examples.len()));
    }
    if examples.len() > MAX_EXAMPLES {
        return Err(TeachError::TooManyExamples(examples.len()));
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut texts: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut allowed = 0usize;
    let mut not_allowed = 0usize;
    for example in examples {
        check_ident("example.id", &example.id)?;
        if !ids.insert(example.id.clone()) {
            return Err(TeachError::DuplicateExampleId(example.id.clone()));
        }
        check_text("example.text", &example.text, MAX_EXAMPLE_CHARS)?;
        check_text("example.reason", &example.reason, MAX_REASON_CHARS)?;
        if let Some(first) = texts.insert(normalise(&example.text), example.id.clone()) {
            return Err(TeachError::DuplicateExampleText {
                first,
                second: example.id.clone(),
            });
        }
        match example.label {
            Label::Allowed => allowed += 1,
            Label::NotAllowed => not_allowed += 1,
        }
    }
    if not_allowed == 0 {
        return Err(TeachError::SingleClassExamples(Label::Allowed));
    }
    if allowed == 0 {
        return Err(TeachError::SingleClassExamples(Label::NotAllowed));
    }
    Ok(())
}

impl TeachSession {
    /// Validate the expert's input and open a session.
    ///
    /// `now_ms` is supplied by the caller so this function stays pure; the
    /// CLI passes the wall clock. Every check fails closed: a session that
    /// cannot be fully verified is not created in a degraded form.
    pub fn open(input: SessionInput, now_ms: u64) -> Result<Self, TeachError> {
        if now_ms == 0 {
            return Err(TeachError::ZeroClock);
        }
        check_ident("tenant", &input.tenant)?;
        check_ident("task", &input.task)?;
        check_ident("expert_id", &input.expert_id)?;
        check_text("document", &input.document, MAX_IDENT_CHARS)?;
        check_hex64("document_sha256", &input.document_sha256)?;
        check_text("rule", &input.rule, MAX_RULE_CHARS)?;
        if input.pages.is_empty() {
            return Err(TeachError::NoPages);
        }
        let ocr_cited = check_clauses(&input)?;
        check_examples(&input.examples)?;

        let mut pages = input.pages.clone();
        pages.sort_unstable();
        pages.dedup();

        let mut session = Self {
            schema: SCHEMA.to_string(),
            session_id: String::new(),
            tenant: input.tenant,
            task: input.task,
            expert_id: input.expert_id,
            document: input.document,
            document_sha256: input.document_sha256,
            pages,
            clauses: input.clauses,
            rule: input.rule,
            examples: input.examples,
            ocr_cited,
            created_ms: now_ms,
        };
        session.session_id = session.content_hash();
        Ok(session)
    }

    /// Domain-separated canonical encoding of everything but `session_id`.
    ///
    /// `serde_json` emits struct fields in declaration order and the
    /// collections are `Vec`s, so the encoding is byte-identical for
    /// identical content.
    fn canonical(&self) -> Vec<u8> {
        let body = serde_json::to_vec(&Unsigned {
            schema: &self.schema,
            tenant: &self.tenant,
            task: &self.task,
            expert_id: &self.expert_id,
            document: &self.document,
            document_sha256: &self.document_sha256,
            pages: &self.pages,
            clauses: &self.clauses,
            rule: &self.rule,
            examples: &self.examples,
            ocr_cited: &self.ocr_cited,
            created_ms: self.created_ms,
        })
        .unwrap_or_default();
        [DOMAIN, body.as_slice()].concat()
    }

    /// SHA-256 of the canonical encoding, lowercase hex.
    pub fn content_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.canonical());
        hex::encode(h.finalize())
    }

    /// True when `session_id` still matches the content it names.
    pub fn intact(&self) -> bool {
        self.session_id == self.content_hash()
    }

    /// Clauses whose numeric values must be confirmed with the expert rather
    /// than asserted, by clause id. A3 reads this to class those fields.
    pub fn needs_confirmation(&self) -> &[String] {
        &self.ocr_cited
    }

    /// Human-readable citations, in the order the clauses were cited.
    pub fn citations(&self) -> Vec<String> {
        self.clauses.iter().map(CitedClause::citation).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_SHA: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const NOW: u64 = 1_762_000_000_000;

    /// A clause whose span matches its text, which every valid clause must.
    fn clause(page: u32, index: u32, text: &str, extraction: Extraction) -> CitedClause {
        let start = 100 * index;
        CitedClause {
            document: "policy.pdf".into(),
            document_sha256: SHA.into(),
            page,
            index,
            text: text.into(),
            char_start: start,
            char_end: start + text.chars().count() as u32,
            extraction,
        }
    }

    fn example(id: &str, text: &str, label: Label) -> Example {
        Example {
            id: id.into(),
            text: text.into(),
            label,
            reason: format!("because of clause {id}"),
        }
    }

    fn input() -> SessionInput {
        SessionInput {
            tenant: "acme".into(),
            task: "storage_temperature".into(),
            expert_id: "expert:qa-lead".into(),
            document: "policy.pdf".into(),
            document_sha256: SHA.into(),
            pages: vec![4],
            clauses: vec![clause(
                4,
                0,
                "Samples must be stored between 10 C and 25 C.",
                Extraction::PdfText,
            )],
            rule: "Reject anything stored outside 10 to 25 degrees.".into(),
            examples: vec![
                example("e1", "Stored at 18 C for two days.", Label::Allowed),
                example("e2", "Stored at 31 C overnight.", Label::NotAllowed),
            ],
        }
    }

    // ---------- happy path ----------

    #[test]
    fn a_valid_session_opens_and_is_named_by_its_content() {
        let s = TeachSession::open(input(), NOW).expect("valid");
        assert_eq!(s.schema, SCHEMA);
        assert_eq!(s.session_id.len(), 64);
        assert_eq!(s.session_id, s.content_hash());
        assert!(s.intact());
        assert_eq!(s.created_ms, NOW);
    }

    #[test]
    fn the_session_id_is_a_deterministic_function_of_its_inputs() {
        let a = TeachSession::open(input(), NOW).expect("valid");
        let b = TeachSession::open(input(), NOW).expect("valid");
        assert_eq!(a.session_id, b.session_id);
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_clock_gives_a_different_session() {
        let a = TeachSession::open(input(), NOW).expect("valid");
        let b = TeachSession::open(input(), NOW + 1).expect("valid");
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn changing_the_rule_changes_the_hash() {
        let a = TeachSession::open(input(), NOW).expect("valid");
        let mut i = input();
        i.rule = "Reject anything stored outside 10 to 24 degrees.".into();
        let b = TeachSession::open(i, NOW).expect("valid");
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn editing_a_stored_session_breaks_its_hash() {
        let mut s = TeachSession::open(input(), NOW).expect("valid");
        assert!(s.intact());
        s.examples[0].label = Label::NotAllowed;
        assert!(
            !s.intact(),
            "a flipped label must not keep the same session_id"
        );
    }

    #[test]
    fn pages_are_sorted_and_deduplicated() {
        let mut i = input();
        i.pages = vec![5, 4, 5];
        i.clauses
            .push(clause(5, 0, "Annex A applies.", Extraction::PdfText));
        let s = TeachSession::open(i, NOW).expect("valid");
        assert_eq!(s.pages, vec![4, 5]);
    }

    #[test]
    fn citations_name_the_document_page_and_span() {
        let s = TeachSession::open(input(), NOW).expect("valid");
        assert_eq!(s.citations(), vec!["policy.pdf p.4 [0:45]".to_string()]);
    }

    #[test]
    fn a_session_round_trips_through_json_unchanged() {
        let s = TeachSession::open(input(), NOW).expect("valid");
        let text = serde_json::to_string(&s).expect("encode");
        let back: TeachSession = serde_json::from_str(&text).expect("decode");
        assert_eq!(s, back);
        assert!(back.intact());
    }

    // ---------- OCR provenance is measured, not assumed ----------

    #[test]
    fn a_text_layer_session_needs_no_confirmation() {
        let s = TeachSession::open(input(), NOW).expect("valid");
        assert!(s.needs_confirmation().is_empty());
        assert!(s.ocr_cited.is_empty());
    }

    #[test]
    fn an_ocr_clause_is_listed_for_confirmation() {
        let mut i = input();
        i.clauses
            .push(clause(4, 1, "Table 3: 11.0 maximum.", Extraction::PdfOcr));
        let s = TeachSession::open(i, NOW).expect("valid");
        assert_eq!(s.needs_confirmation(), ["p4#1"]);
    }

    #[test]
    fn only_ocr_needs_confirmation() {
        assert!(Extraction::PdfOcr.needs_confirmation());
        for e in [Extraction::PdfText, Extraction::Docx, Extraction::Txt] {
            assert!(!e.needs_confirmation(), "{}", e.as_str());
        }
    }

    #[test]
    fn extraction_and_label_use_the_ingesters_spelling() {
        // The clause file is written by the Python ingester; a mismatch here
        // would make every real clause file fail to parse.
        for (e, want) in [
            (Extraction::PdfText, "\"pdf_text\""),
            (Extraction::PdfOcr, "\"pdf_ocr\""),
            (Extraction::Docx, "\"docx\""),
            (Extraction::Txt, "\"txt\""),
        ] {
            assert_eq!(serde_json::to_string(&e).unwrap(), want);
        }
        assert_eq!(
            serde_json::to_string(&Label::Allowed).unwrap(),
            "\"allowed\""
        );
        assert_eq!(
            serde_json::to_string(&Label::NotAllowed).unwrap(),
            "\"not_allowed\""
        );
    }

    #[test]
    fn an_unknown_label_is_refused_by_the_decoder() {
        assert!(serde_json::from_str::<Label>("\"maybe\"").is_err());
        assert!(serde_json::from_str::<Extraction>("\"pdf_guess\"").is_err());
    }

    // ---------- identifiers ----------

    #[test]
    fn an_empty_or_unsafe_identifier_is_refused() {
        for (field, value) in [
            ("tenant", ""),
            ("tenant", "../etc"),
            ("tenant", ".hidden"),
            ("tenant", "two words"),
            ("task", "a/b"),
            ("expert_id", "e\0x"),
        ] {
            let mut i = input();
            match field {
                "tenant" => i.tenant = value.into(),
                "task" => i.task = value.into(),
                _ => i.expert_id = value.into(),
            }
            let err = TeachSession::open(i, NOW).expect_err(value);
            assert!(
                matches!(
                    err,
                    TeachError::BadIdent { .. } | TeachError::EmptyText { .. }
                ),
                "{value:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn an_over_long_identifier_is_refused() {
        let mut i = input();
        i.tenant = "a".repeat(MAX_IDENT_CHARS + 1);
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("too long"),
            TeachError::TooLong {
                field: "tenant",
                ..
            }
        ));
    }

    #[test]
    fn a_digest_that_is_not_64_lowercase_hex_is_refused() {
        for bad in [
            "",
            "abc",
            &"A".repeat(64),
            &"g".repeat(64),
            &"1".repeat(63),
            &"1".repeat(65),
        ] {
            let mut i = input();
            i.document_sha256 = bad.to_string();
            for c in &mut i.clauses {
                c.document_sha256 = bad.to_string();
            }
            assert!(
                matches!(
                    TeachSession::open(i, NOW).expect_err(bad),
                    TeachError::NotHex64 { .. }
                ),
                "{bad:?} was accepted"
            );
        }
    }

    // ---------- clause binding ----------

    #[test]
    fn a_session_with_no_clause_names_the_page_that_was_not_cited() {
        // Regression (found by tests/teach_cli.rs): this used to answer
        // "at least one clause must be cited", which does not tell the expert
        // that the page they asked for yielded nothing.
        let mut i = input();
        i.clauses.clear();
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("no clauses"),
            TeachError::PageNotCited(4)
        );
    }

    #[test]
    fn too_many_clauses_is_refused() {
        let mut i = input();
        i.clauses = (0..=MAX_CLAUSES as u32)
            .map(|n| clause(4, n, "A clause.", Extraction::PdfText))
            .collect();
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("too many"),
            TeachError::TooManyClauses(MAX_CLAUSES + 1)
        );
    }

    #[test]
    fn a_clause_from_another_document_is_refused() {
        let mut i = input();
        i.clauses[0].document = "other.pdf".into();
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("other document"),
            TeachError::ClauseDocumentMismatch { .. }
        ));
    }

    #[test]
    fn a_clause_from_another_revision_of_the_document_is_refused() {
        // Same file name, different bytes. This is the case that silently
        // produces a citation into text that no longer exists.
        let mut i = input();
        i.clauses[0].document_sha256 = OTHER_SHA.into();
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("other revision"),
            TeachError::ClauseDocumentMismatch { .. }
        ));
    }

    #[test]
    fn a_clause_whose_text_is_not_as_long_as_its_span_is_refused() {
        let mut i = input();
        i.clauses[0].char_end += 3;
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("span"),
            TeachError::ClauseSpanMismatch {
                clause: "p4#0".into(),
                span: 48,
                text_chars: 45,
            }
        );
    }

    #[test]
    fn the_span_is_counted_in_characters_not_bytes() {
        // A multi-byte character would make a byte-length check fail here.
        let mut i = input();
        i.clauses[0] = clause(4, 0, "Store at 10 °C to 25 °C.", Extraction::PdfText);
        let s = TeachSession::open(i, NOW).expect("valid");
        assert_eq!(s.clauses[0].char_end - s.clauses[0].char_start, 24);
    }

    #[test]
    fn an_inverted_or_empty_span_is_refused() {
        for (start, end) in [(10u32, 10u32), (20, 10)] {
            let mut i = input();
            i.clauses[0].char_start = start;
            i.clauses[0].char_end = end;
            assert_eq!(
                TeachSession::open(i, NOW).expect_err("span"),
                TeachError::ClauseSpanInvalid {
                    clause: "p4#0".into()
                }
            );
        }
    }

    #[test]
    fn page_zero_is_refused_because_pages_are_one_based() {
        let mut i = input();
        i.pages = vec![0];
        i.clauses[0].page = 0;
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("page 0"),
            TeachError::ClauseSpanInvalid {
                clause: "p0#0".into()
            }
        );
    }

    #[test]
    fn an_empty_clause_text_is_refused() {
        let mut i = input();
        i.clauses[0].text = "   ".into();
        i.clauses[0].char_end = i.clauses[0].char_start + 3;
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("empty"),
            TeachError::EmptyText {
                field: "clause.text"
            }
        );
    }

    #[test]
    fn the_same_clause_cited_twice_is_refused() {
        let mut i = input();
        let dup = i.clauses[0].clone();
        i.clauses.push(dup);
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("duplicate"),
            TeachError::DuplicateClause("p4#0".into())
        );
    }

    // ---------- page selection ----------

    #[test]
    fn no_requested_page_is_refused() {
        let mut i = input();
        i.pages.clear();
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("no pages"),
            TeachError::NoPages
        );
    }

    #[test]
    fn a_requested_page_with_no_clause_is_refused() {
        // The expert asked to teach from page 9; nothing was extracted from
        // it. Silently teaching from page 4 alone would be a lie about what
        // the session cites.
        let mut i = input();
        i.pages = vec![4, 9];
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("page 9"),
            TeachError::PageNotCited(9)
        );
    }

    #[test]
    fn a_clause_from_a_page_that_was_not_requested_is_refused() {
        let mut i = input();
        i.clauses
            .push(clause(7, 0, "Unrelated clause.", Extraction::PdfText));
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("page 7"),
            TeachError::ClausePageNotRequested {
                clause: "p7#0".into(),
                page: 7,
            }
        );
    }

    // ---------- the rule ----------

    #[test]
    fn an_empty_rule_is_refused() {
        for blank in ["", "   ", "\n\t "] {
            let mut i = input();
            i.rule = blank.into();
            assert_eq!(
                TeachSession::open(i, NOW).expect_err(blank),
                TeachError::EmptyText { field: "rule" }
            );
        }
    }

    #[test]
    fn an_over_long_rule_is_refused() {
        let mut i = input();
        i.rule = "x".repeat(MAX_RULE_CHARS + 1);
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("long rule"),
            TeachError::TooLong {
                field: "rule",
                chars: MAX_RULE_CHARS + 1,
                max: MAX_RULE_CHARS,
            }
        );
    }

    // ---------- examples ----------

    #[test]
    fn fewer_than_two_examples_is_refused() {
        for n in 0..MIN_EXAMPLES {
            let mut i = input();
            i.examples.truncate(n);
            assert_eq!(
                TeachSession::open(i, NOW).expect_err("too few"),
                TeachError::TooFewExamples(n)
            );
        }
    }

    #[test]
    fn more_than_five_examples_is_refused() {
        let mut i = input();
        i.examples = (0..=MAX_EXAMPLES)
            .map(|n| {
                example(
                    &format!("e{n}"),
                    &format!("Stored at {} C.", 10 + n),
                    if n % 2 == 0 {
                        Label::Allowed
                    } else {
                        Label::NotAllowed
                    },
                )
            })
            .collect();
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("too many"),
            TeachError::TooManyExamples(MAX_EXAMPLES + 1)
        );
    }

    #[test]
    fn exactly_five_examples_is_accepted() {
        let mut i = input();
        i.examples = (0..MAX_EXAMPLES)
            .map(|n| {
                example(
                    &format!("e{n}"),
                    &format!("Stored at {} C.", 10 + n),
                    if n % 2 == 0 {
                        Label::Allowed
                    } else {
                        Label::NotAllowed
                    },
                )
            })
            .collect();
        let s = TeachSession::open(i, NOW).expect("valid");
        assert_eq!(s.examples.len(), MAX_EXAMPLES);
    }

    #[test]
    fn a_duplicate_example_id_is_refused() {
        let mut i = input();
        i.examples[1].id = "e1".into();
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("duplicate id"),
            TeachError::DuplicateExampleId("e1".into())
        );
    }

    #[test]
    fn two_examples_with_the_same_text_are_refused_whatever_their_labels() {
        // Same label: padding to reach the minimum of two.
        let mut i = input();
        i.examples[1].text = i.examples[0].text.clone();
        i.examples[1].label = Label::Allowed;
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("same text, same label"),
            TeachError::DuplicateExampleText { .. }
        ));
        // Different labels: the session contradicts itself.
        let mut i = input();
        i.examples[1].text = i.examples[0].text.clone();
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("same text, opposite labels"),
            TeachError::DuplicateExampleText { .. }
        ));
    }

    #[test]
    fn sameness_of_example_text_ignores_case_and_line_breaks() {
        // The A1 finding: the PDF text layer puts newlines inside phrases, so
        // two examples pasted from the same clause can differ only by one.
        let mut i = input();
        i.examples[1].text = "stored at   18\nC for  TWO days.".into();
        i.examples[0].text = "Stored at 18 C for two days.".into();
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("same once normalised"),
            TeachError::DuplicateExampleText { .. }
        ));
    }

    #[test]
    fn examples_of_a_single_class_are_refused() {
        let mut i = input();
        i.examples[1].label = Label::Allowed;
        i.examples[1].text = "Stored at 12 C.".into();
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("all allowed"),
            TeachError::SingleClassExamples(Label::Allowed)
        );

        let mut i = input();
        i.examples[0].label = Label::NotAllowed;
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("all not_allowed"),
            TeachError::SingleClassExamples(Label::NotAllowed)
        );
    }

    #[test]
    fn an_example_without_a_reason_is_refused() {
        let mut i = input();
        i.examples[0].reason = "  ".into();
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("no reason"),
            TeachError::EmptyText {
                field: "example.reason"
            }
        );
    }

    #[test]
    fn an_empty_example_text_is_refused() {
        let mut i = input();
        i.examples[0].text = "".into();
        assert_eq!(
            TeachSession::open(i, NOW).expect_err("no text"),
            TeachError::EmptyText {
                field: "example.text"
            }
        );
    }

    #[test]
    fn an_over_long_example_or_reason_is_refused() {
        let mut i = input();
        i.examples[0].text = "x".repeat(MAX_EXAMPLE_CHARS + 1);
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("long text"),
            TeachError::TooLong {
                field: "example.text",
                ..
            }
        ));

        let mut i = input();
        i.examples[0].reason = "x".repeat(MAX_REASON_CHARS + 1);
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("long reason"),
            TeachError::TooLong {
                field: "example.reason",
                ..
            }
        ));
    }

    #[test]
    fn an_unsafe_example_id_is_refused() {
        let mut i = input();
        i.examples[0].id = "../e1".into();
        assert!(matches!(
            TeachSession::open(i, NOW).expect_err("unsafe id"),
            TeachError::BadIdent {
                field: "example.id",
                ..
            }
        ));
    }

    // ---------- clock ----------

    #[test]
    fn a_zero_clock_is_refused() {
        assert_eq!(
            TeachSession::open(input(), 0).expect_err("zero clock"),
            TeachError::ZeroClock
        );
    }

    // ---------- error text ----------

    #[test]
    fn every_error_prints_what_was_wrong() {
        // The expert reads these. An error that does not name the field and
        // the value is not actionable, and the loop rule is that a failure
        // must say which question to revisit.
        let cases = vec![
            TeachError::BadIdent {
                field: "tenant",
                value: "../x".into(),
            },
            TeachError::NotHex64 {
                field: "document_sha256",
                value: "abc".into(),
            },
            TeachError::EmptyText { field: "rule" },
            TeachError::TooLong {
                field: "rule",
                chars: 9,
                max: 8,
            },
            TeachError::TooManyClauses(99),
            TeachError::ClauseDocumentMismatch {
                clause: "p1#0".into(),
                found: "a.pdf".into(),
                expected: "b.pdf".into(),
            },
            TeachError::ClauseSpanMismatch {
                clause: "p1#0".into(),
                span: 5,
                text_chars: 4,
            },
            TeachError::ClauseSpanInvalid {
                clause: "p1#0".into(),
            },
            TeachError::DuplicateClause("p1#0".into()),
            TeachError::NoPages,
            TeachError::PageNotCited(9),
            TeachError::ClausePageNotRequested {
                clause: "p7#0".into(),
                page: 7,
            },
            TeachError::TooFewExamples(1),
            TeachError::TooManyExamples(6),
            TeachError::DuplicateExampleId("e1".into()),
            TeachError::DuplicateExampleText {
                first: "e1".into(),
                second: "e2".into(),
            },
            TeachError::SingleClassExamples(Label::Allowed),
            TeachError::ZeroClock,
        ];
        for c in cases {
            let text = c.to_string();
            assert!(!text.is_empty(), "{c:?} printed nothing");
            assert!(
                text.chars().next().is_some_and(|ch| !ch.is_whitespace()),
                "{c:?} printed {text:?}"
            );
        }
    }
}
