//! Ports: the only interfaces the controller and orchestration depend on.

use std::cell::RefCell;

use serde::{Deserialize, Serialize};
use vanian_sovereign::ports::{ChatMessage, GenerationParams, InferencePort, PortError};

use crate::capability::lifecycle::Record;
use crate::domain::maintenance::Reading;
use crate::domain::scope::CacheScope;

/// Model-free interpretation of a maintenance report (System One reference
/// interpreters behind the sidecar).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Interpretation {
    /// Exact equipment-code + unit rules.
    pub rules: Vec<Reading>,
    /// Compact learned interpreter (TF-IDF quantity classifier).
    pub interp: Vec<Reading>,
    pub interp_top_prob: f64,
    /// Equipment-family codes that are not registered assets.
    pub unregistered: Vec<String>,
    /// Distinct registered assets named.
    pub registered_codes: usize,
}

/// A prepared SLM extraction request (prompt owned by the reference code).
#[derive(Debug, Clone, PartialEq)]
pub struct SlmRequest {
    pub messages: Vec<ChatMessage>,
    pub max_tokens: u32,
    pub schema: String,
}

/// Interpretation sidecar.
pub trait InterpreterPort {
    fn interpret(&self, text: &str) -> Result<Interpretation, PortError>;
    fn slm_request(&self, text: &str) -> Result<SlmRequest, PortError>;
    /// `None` when the model output did not parse.
    fn slm_parse(&self, raw: &str) -> Result<Option<Vec<Reading>>, PortError>;
}

/// Measured cost of one model call.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GenStats {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// Prompt tokens served from the (scoped) cache.
    pub cached_tokens: u64,
    pub wall_ms: f64,
    pub slot: usize,
    pub slot_erased: bool,
}

/// A local model whose prompt cache is bound to a [`CacheScope`].
pub trait ScopedGenerator {
    fn generate(
        &self,
        scope: &CacheScope,
        messages: &[ChatMessage],
        params: &GenerationParams,
    ) -> Result<(String, GenStats), PortError>;
    /// SHA-256 (hex) of the loaded weights.
    fn model_sha256(&self) -> String;
}

/// Adapter so the unchanged Sovereign RAG path (`rag::answer`, which takes an
/// [`InferencePort`]) runs through the scoped cache. Records every call.
pub struct ScopedInference<'a> {
    pub generator: &'a dyn ScopedGenerator,
    pub scope: CacheScope,
    pub calls: RefCell<Vec<GenStats>>,
}

impl InferencePort for ScopedInference<'_> {
    fn chat(
        &self,
        messages: &[ChatMessage],
        params: &GenerationParams,
    ) -> Result<String, PortError> {
        let (out, st) = self.generator.generate(&self.scope, messages, params)?;
        self.calls.borrow_mut().push(st);
        Ok(out)
    }
}

/// Persistent capability records.
pub trait CapabilityStore {
    fn all(&self) -> Result<Vec<Record>, PortError>;
    fn put(&mut self, r: &Record) -> Result<(), PortError>;
}

/// Process resource snapshot (canonical units: seconds, MiB).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub cpu_s: f64,
    pub rss_mib: f64,
    pub hwm_mib: f64,
}

/// Reads resource use of the runtime and its helper processes.
pub trait Meter {
    /// One snapshot per component name ("runtime", "sidecar", "llama").
    fn snapshot(&self) -> Vec<(String, ResourceSnapshot)>;
}
