//! Admission, and the receipt that follows it.
//!
//! # The two-step shape, and why it is not one function
//!
//! A receipt states the request **and** what the gateway did with it, and the
//! second half is not known until the upstream has answered. So admission is
//! decided before the request is forwarded ([`admit`]) and the receipt is
//! written after ([`receipt_for_admitted`]). The admitted call is carried
//! between them as a value, so a transport that forwards a request and forgets
//! to receipt it has dropped something visible rather than skipped a step
//! nobody can see.
//!
//! Both halves are pure: the clock, the socket and the file are the binary's.
//!
//! # Which refusals are receipted, and why the line falls there
//!
//! A receipt is a signed sentence of the form *"agent A, citing decision D,
//! asked for tool T with arguments committing to X, and I did Y"*. Three of
//! those four are needed before the sentence can be written at all:
//!
//! * **No route matched.** There is no T. The gateway has no name for what was
//!   asked, so it has nothing to sign a statement about. The request is refused
//!   and counted; nothing reaches the upstream, so there is no effect to be
//!   unaccounted for.
//! * **No agent identity, or no decision cited.** There is no A or no D. A
//!   receipt with an invented agent or a zero decision id would be a document
//!   that joins to the wrong expectation, which is worse than no document.
//! * **Arguments could not be canonicalised.** Here A, D and T all exist, so
//!   the sentence *can* be written and must be: this is the case where an
//!   agent sent something the gateway refused, and a gap in the receipt stream
//!   would hide exactly that. The receipt carries `Refused` and commits to
//!   `null` arguments — a commitment to *"nothing I could read"*, which will
//!   not match any expectation, which is the correct downstream outcome.
//!
//! # The gateway commits to what it received, never to what it was told
//!
//! `parameter_commitment` is computed here from the arguments the gateway
//! assembled itself. A client that sends one commitment and different
//! arguments is caught at this line, before the receipt exists. The commitment
//! function is the **same one** `aip-mcp-gateway` uses, so a receipt for the
//! same arguments is byte-identical whichever boundary issued it — an
//! institution that moves a tool from an HTTP route to an MCP server does not
//! invalidate its own history.

use aip_airi::{GatewayDisposition, GatewaySigner, SignedToolReceipt, ToolCallId, ToolReceipt};
use aip_mcp_gateway::{args_commitment, response_commitment};
use serde_json::Value;

use crate::request::{assemble_arguments, ArgumentError};
use crate::routemap::{Resolution, RouteMap};

/// The parts of an HTTP request this gateway reads. Deliberately not a
/// framework's request type: the core never touches one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestParts {
    /// Upper-case HTTP method.
    pub method: String,
    /// Path, without the query string.
    pub path: String,
    /// Query string, without its leading `?`.
    pub query: Option<String>,
    /// `X-AIP-Agent-Id`. A claim the request made about itself, never proof.
    pub agent_id: Option<String>,
    /// `X-AIP-Decision-Id`, 32 hex characters. The decision the request cited;
    /// a join key to an expectation, not evidence that one covers it.
    pub decision_id: Option<String>,
    /// `X-AIP-Tool-Call-Id`, when the model's runtime supplied one.
    pub tool_call_id: Option<String>,
    /// The request body, if any.
    pub body: Option<Vec<u8>>,
}

/// A request that may be forwarded, with everything the receipt will need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedCall {
    pub tool_id: String,
    pub agent_id: String,
    pub decision_id: [u8; 16],
    pub tool_call_id: Option<String>,
    /// The gateway's own assembly of the arguments.
    pub arguments: Value,
}

/// A request that named a tool and an identity but could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedCall {
    pub tool_id: String,
    pub agent_id: String,
    pub decision_id: [u8; 16],
    pub tool_call_id: Option<String>,
    pub reason: ArgumentError,
}

/// Why a request was refused before any receipt could exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreceiptable {
    /// No route named this request, so there is no tool to sign about.
    Unrouted { method: String, path: String },
    /// No `X-AIP-Agent-Id`, or it was empty.
    NoAgentId,
    /// No `X-AIP-Decision-Id`.
    NoDecisionId,
    /// Present but not 32 hex characters.
    MalformedDecisionId,
}

/// What the gateway decided before forwarding anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Forward it, then receipt it.
    Admit(AdmittedCall),
    /// Refuse it, and receipt the refusal.
    RefuseWithReceipt(RefusedCall),
    /// Refuse it. Nothing reached the upstream and no receipt is possible.
    RefuseWithoutReceipt(Unreceiptable),
}

/// Decide what to do with a request, before it is forwarded.
///
/// The map must already have been verified; see
/// [`RouteMap::verify`](crate::routemap::RouteMap::verify). Order of checks is
/// deliberate and is the subject of its own tests: a request that fails more
/// than one is reported by the first, because the later checks would be
/// answering questions about a request that already has no name.
pub fn admit(map: &RouteMap, parts: &RequestParts) -> Admission {
    let Resolution::Named {
        route,
        path_arguments,
    } = map.resolve(&parts.method, &parts.path)
    else {
        return Admission::RefuseWithoutReceipt(Unreceiptable::Unrouted {
            method: parts.method.clone(),
            path: parts.path.clone(),
        });
    };

    let Some(agent_id) = parts.agent_id.as_deref().filter(|a| !a.is_empty()) else {
        return Admission::RefuseWithoutReceipt(Unreceiptable::NoAgentId);
    };

    let Some(raw) = parts.decision_id.as_deref() else {
        return Admission::RefuseWithoutReceipt(Unreceiptable::NoDecisionId);
    };
    let Some(decision_id) = parse_decision_id(raw) else {
        return Admission::RefuseWithoutReceipt(Unreceiptable::MalformedDecisionId);
    };

    match assemble_arguments(
        &path_arguments,
        parts.query.as_deref(),
        parts.body.as_deref(),
    ) {
        Ok(arguments) => Admission::Admit(AdmittedCall {
            tool_id: route.tool_id.clone(),
            agent_id: agent_id.to_string(),
            decision_id,
            tool_call_id: parts.tool_call_id.clone(),
            arguments,
        }),
        Err(reason) => Admission::RefuseWithReceipt(RefusedCall {
            tool_id: route.tool_id.clone(),
            agent_id: agent_id.to_string(),
            decision_id,
            tool_call_id: parts.tool_call_id.clone(),
            reason,
        }),
    }
}

/// 32 lower- or upper-case hex characters, or nothing.
fn parse_decision_id(raw: &str) -> Option<[u8; 16]> {
    if raw.len() != 32 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// The receipt for a request that was forwarded.
///
/// `response` is the upstream's answer when it was JSON. A non-JSON or absent
/// response commits to nothing rather than to a digest of a guess — see the
/// note in [`crate`] on what that costs.
pub fn receipt_for_admitted(
    signer: &GatewaySigner,
    call: &AdmittedCall,
    disposition: GatewayDisposition,
    response: Option<&Value>,
    received_at_ms: u64,
) -> Result<SignedToolReceipt, aip_airi::ReceiptError> {
    signer.sign(ToolReceipt {
        version: 0,                // set by the signer
        gateway_id: String::new(), // set by the signer
        key_version: 0,            // set by the signer
        decision_id: call.decision_id,
        agent_id: call.agent_id.clone(),
        tool_id: call.tool_id.clone(),
        // The gateway's own recomputation, never the client's.
        parameter_commitment: args_commitment(&call.arguments),
        tool_call_id: call.tool_call_id.clone().map(ToolCallId),
        disposition,
        response_commitment: response.map(response_commitment),
        received_at_ms,
    })
}

/// The receipt for a request the gateway refused before forwarding it.
///
/// The parameter commitment is over `null`: a commitment to *"nothing I could
/// read"*. It will not match any expectation, which is the correct outcome —
/// the alternative, committing to a partial reading, would be the gateway
/// asserting a request it explicitly refused to understand.
pub fn receipt_for_refused(
    signer: &GatewaySigner,
    call: &RefusedCall,
    received_at_ms: u64,
) -> Result<SignedToolReceipt, aip_airi::ReceiptError> {
    signer.sign(ToolReceipt {
        version: 0,
        gateway_id: String::new(),
        key_version: 0,
        decision_id: call.decision_id,
        agent_id: call.agent_id.clone(),
        tool_id: call.tool_id.clone(),
        parameter_commitment: args_commitment(&Value::Null),
        tool_call_id: call.tool_call_id.clone().map(ToolCallId),
        disposition: GatewayDisposition::Refused,
        response_commitment: None,
        received_at_ms,
    })
}
