//! The MCP tool boundary — a gateway that countersigns what it received.
//!
//! # The question this answers
//!
//! The kernel observer sees a socket from the agent to the gateway. It cannot
//! see *what tool was called with what arguments* inside that TLS session, and
//! it must not guess. The only party that can answer is the gateway itself:
//! it terminates the MCP request, so it holds the canonical arguments before
//! they reach the upstream tool server. This crate has the gateway state, in a
//! [`aip_airi::ToolReceipt`], **signed with the gateway's own key** — never
//! the agent's — over its own recomputation of the argument commitment.
//!
//! # Why this is not "trust the gateway"
//!
//! The receipt is one signed document among several the reconciler compares:
//! the decision point's `ExpectedExecution` (what was authorised), the
//! gateway's `ToolReceipt` (what the gateway received), and, when present, the
//! agent's own signed claim. [`aip_airi::compare_tool_boundary`] recomputes
//! the parameter digest from the receipt and checks it against the digest the
//! decision point sealed. A mis-parameterised call — what reached the tool is
//! not what was authorised — is `Diverges`, **whatever the agent said about
//! it**, because the finding rests on the gateway's receipt versus the
//! decision, not on the agent's account.
//!
//! # The 2026-07-28 MCP spec, and why the body is the source of truth
//!
//! That spec adds `Mcp-Method` and `Mcp-Name` headers so a gateway can route
//! and authorise on headers without parsing the JSON-RPC body, and requires a
//! server to reject a request whose headers and body disagree. This gateway
//! routes on the headers but **commits over the body**: [`check_header_body`]
//! rejects a mismatch before any receipt is signed, so a receipt is never
//! issued for a request whose header lied about its body.
//!
//! # Relationship to IBM ContextForge
//!
//! ContextForge (Apache-2.0) is the production gateway named in the pilot
//! plan; its plugin pipeline is where this logic runs in a deployment. The
//! receipt-signing core is intentionally here, in the crate that owns the
//! `ToolReceipt` format, so the ContextForge plugin is a thin adapter that
//! canonicalises the call and calls [`issue_receipt`] rather than a
//! reimplementation of the cryptography. See `integrations/mcp-gateway/`.

use aip_airi::{GatewayDisposition, GatewaySigner, SignedToolReceipt, ToolCallId, ToolReceipt};
use aip_crypto::sha256;
use serde_json::Value;

pub mod canonical;

pub use canonical::{args_commitment, canonical_json_bytes};

/// The AIRI protocol version a receipt is stamped with is owned by `aip-airi`;
/// nothing here sets it. This constant is only the MCP method this gateway
/// countersigns, so a request for any other method is not receipted.
pub const MCP_TOOLS_CALL: &str = "tools/call";

/// One parsed MCP `tools/call` the gateway is about to receipt.
///
/// Deliberately not the raw JSON-RPC frame: the fields the receipt commits to,
/// pulled out and validated, so the receipt logic never touches untyped JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// The MCP method from the request body (`tools/call`).
    pub method: String,
    /// The tool name from the request body (`params.name`).
    pub tool_name: String,
    /// The decision the request cited, from its authorisation. A join key to
    /// the `ExpectedExecution`, copied, never trusted as proof of coverage.
    pub decision_id: [u8; 16],
    /// The agent the request identified itself as.
    pub agent_id: String,
    /// The model's tool-call id, when the request carried one.
    pub tool_call_id: Option<String>,
    /// The tool arguments (`params.arguments`), verbatim. The commitment is
    /// computed over the *canonical* form of this, so key order and
    /// whitespace in transit cannot change it.
    pub arguments: Value,
}

/// Why the gateway refused to issue a receipt. A refusal is a `Refused`
/// receipt or no receipt; it is never a silent forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// The `Mcp-Method` / `Mcp-Name` headers disagree with the body. Per the
    /// 2026-07-28 spec the body is the source of truth and the request is
    /// rejected rather than guessed at.
    HeaderBodyMismatch {
        header_method: String,
        body_method: String,
        header_name: String,
        body_name: String,
    },
    /// The request is not a `tools/call`; this gateway does not receipt it.
    NotAToolsCall { method: String },
    /// The receipt could not be signed.
    Sign(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for GatewayError {}

/// Enforce the spec's header/body agreement before anything is signed.
///
/// `Mcp-Method` must be the body's method and `Mcp-Name` must be the body's
/// tool name. A mismatch is rejected: a gateway that routed on a header while
/// the body did something else would issue a receipt that describes neither.
pub fn check_header_body(
    header_method: &str,
    header_name: &str,
    call: &ToolCall,
) -> Result<(), GatewayError> {
    if header_method != call.method || header_name != call.tool_name {
        return Err(GatewayError::HeaderBodyMismatch {
            header_method: header_method.to_string(),
            body_method: call.method.clone(),
            header_name: header_name.to_string(),
            body_name: call.tool_name.clone(),
        });
    }
    Ok(())
}

/// Commit to a response body the same way arguments are committed.
pub fn response_commitment(response: &Value) -> [u8; 32] {
    args_commitment(response)
}

/// Issue a signed receipt for one tool call.
///
/// `parameter_commitment` is the gateway's **own** recomputation over the
/// canonical arguments — never copied from the request — so a client that
/// sent one commitment and different arguments is caught here, at the
/// gateway, before the receipt exists.
///
/// `received_at_ms` is passed in rather than read from a clock so the function
/// is pure and testable; a daemon supplies its own wall clock.
pub fn issue_receipt(
    signer: &GatewaySigner,
    call: &ToolCall,
    disposition: GatewayDisposition,
    response: Option<&Value>,
    received_at_ms: u64,
) -> Result<SignedToolReceipt, GatewayError> {
    if call.method != MCP_TOOLS_CALL {
        return Err(GatewayError::NotAToolsCall {
            method: call.method.clone(),
        });
    }
    let receipt = ToolReceipt {
        version: 0,                // set by the signer to TOOL_RECEIPT_VERSION
        gateway_id: String::new(), // set by the signer
        key_version: 0,            // set by the signer
        decision_id: call.decision_id,
        agent_id: call.agent_id.clone(),
        tool_id: call.tool_name.clone(),
        parameter_commitment: args_commitment(&call.arguments),
        tool_call_id: call.tool_call_id.clone().map(ToolCallId),
        disposition,
        response_commitment: response.map(response_commitment),
        received_at_ms,
    };
    signer
        .sign(receipt)
        .map_err(|e| GatewayError::Sign(format!("{e:?}")))
}

/// The gateway's parameter commitment for an argument value, exposed so the
/// **decision point** can seal the same commitment when it authorises a call.
/// The decision point and the gateway must call this same function, or their
/// digests will never match even for an honest request.
pub fn parameter_commitment(arguments: &Value) -> [u8; 32] {
    args_commitment(arguments)
}

/// SHA-256 of arbitrary bytes, re-exported for callers assembling their own
/// commitments in the same domain.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}
