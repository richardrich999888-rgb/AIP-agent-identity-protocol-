//! Ports: the only interfaces orchestration code depends on.
//!
//! Adapters implement these; tests substitute deterministic fakes.

use crate::domain::corpus::{Document, Passage, Principal};

/// Error from any port, carried as text plus a stable kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortError {
    pub kind: PortErrorKind,
    pub detail: String,
}

/// Stable error classification for callers that must branch on cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortErrorKind {
    Storage,
    Inference,
    InvalidInput,
    /// A component broke its contract (e.g. returned unauthorized rows).
    ContractViolation,
}

impl PortError {
    /// Construct an error.
    pub fn new(kind: PortErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for PortError {}

/// What ingestion did with a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Stored and retrievable.
    Indexed,
    /// Stored but excluded from retrieval: an instruction-like phrase was
    /// found. The document is not deleted; an operator can review it.
    Quarantined { marker: &'static str },
}

/// Access-controlled document store.
pub trait CorpusStore {
    /// Insert or replace a document version.
    fn ingest(&mut self, doc: &Document) -> Result<IngestOutcome, PortError>;

    /// Full-text search restricted **inside the query** to documents the
    /// principal may read. Returns at most `limit` passages, best first.
    fn search(
        &self,
        principal: &Principal,
        query: &str,
        limit: usize,
    ) -> Result<Vec<Passage>, PortError>;
}

/// One chat turn for the inference engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: &'static str,
    pub content: String,
}

/// Deterministic generation parameters. Defaults are greedy decoding with a
/// fixed seed so the same model + prompt reproduces the same answer.
#[derive(Debug, Clone, PartialEq)]
pub struct GenerationParams {
    pub max_tokens: u32,
    pub temperature: f32,
    pub seed: u32,
    /// JSON schema (as JSON text) the output must conform to. The inference
    /// server compiles it to a grammar; the caller still validates.
    pub response_schema: Option<String>,
}

impl Default for GenerationParams {
    fn default() -> Self {
        // 384 tokens bounds latency on CPU-only hosts; temperature 0 is greedy.
        Self {
            max_tokens: 384,
            temperature: 0.0,
            seed: 42,
            response_schema: None,
        }
    }
}

/// A local language model.
pub trait InferencePort {
    /// Generate a completion for the conversation.
    fn chat(
        &self,
        messages: &[ChatMessage],
        params: &GenerationParams,
    ) -> Result<String, PortError>;
}
