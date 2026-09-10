//! Opaque identifiers.
//!
//! Newtypes rather than bare arrays and strings, so that an execution id
//! cannot be passed where a decision id belongs and a tool-call id cannot be
//! passed where an inference-request id belongs. The compiler catches at the
//! call site what would otherwise be a silent cross-binding bug.

use serde::{Deserialize, Serialize};

/// An AIRI execution instance: one logical agent run, chosen by the SDK.
///
/// Distinct from three things it is often confused with:
/// * the **process instance** (`aip_types::ProcessInstance`) — one process
///   may host many executions and one execution may span processes;
/// * the **decision id** — the authorization an execution runs under, which
///   may be absent or shared;
/// * the **framework's own run id** — vendor-specific, carried as context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExecutionId(pub [u8; 16]);

impl ExecutionId {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ExecutionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// The inference-request correlation id issued by a model runtime or
/// provider. Free-form because every provider spells it differently; it is
/// context for a human tracing a call, never a trust input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InferenceRequestId(pub String);

/// The tool-call id a model emits alongside a function/tool call. Also
/// provider-specific, also context only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ToolCallId(pub String);
