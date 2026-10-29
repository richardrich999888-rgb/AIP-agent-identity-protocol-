//! Compare an explicit request with a cryptographically verified gateway receipt.
//! This is content correlation, not authorization or proof of downstream execution.
use aip_airi::{GatewayDisposition, VerifiedToolReceipt};
use serde::Serialize;

use crate::{args_commitment, ToolCall, MCP_TOOLS_CALL};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RequestDifference {
    AgentId,
    DecisionId,
    ToolId,
    ToolCallId,
    Arguments,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RequestAgreement {
    Matches,
    Differs,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceivedCallComparison {
    pub agreement: RequestAgreement,
    pub differences: Vec<RequestDifference>,
    pub expected_parameter_commitment: [u8; 32],
    pub receipt_digest: [u8; 32],
    pub gateway_disposition: GatewayDisposition,
}

/// The caller must establish the request's source and tenant separately.
/// Agent/decision/call IDs are correlation values, not authenticated identity.
/// A matching Refused receipt still describes a refusal, never execution.
pub fn compare_received_call(
    call: &ToolCall,
    verified: &VerifiedToolReceipt,
) -> Result<ReceivedCallComparison, &'static str> {
    if call.method != MCP_TOOLS_CALL
        || call.tool_name.is_empty()
        || call.agent_id.is_empty()
        || call.tool_call_id.as_ref().is_none_or(String::is_empty)
        || !call.arguments.is_object()
    {
        return Err("explicit tools/call, agent, tool, call ID and object arguments required");
    }
    let receipt = verified.receipt();
    let mut differences = Vec::new();
    if call.agent_id != receipt.agent_id {
        differences.push(RequestDifference::AgentId);
    }
    if call.decision_id != receipt.decision_id {
        differences.push(RequestDifference::DecisionId);
    }
    if call.tool_name != receipt.tool_id {
        differences.push(RequestDifference::ToolId);
    }
    if call.tool_call_id.as_deref() != receipt.tool_call_id.as_ref().map(|id| id.0.as_str()) {
        differences.push(RequestDifference::ToolCallId);
    }
    let expected_parameter_commitment = args_commitment(&call.arguments);
    if expected_parameter_commitment != receipt.parameter_commitment {
        differences.push(RequestDifference::Arguments);
    }
    Ok(ReceivedCallComparison {
        agreement: if differences.is_empty() {
            RequestAgreement::Matches
        } else {
            RequestAgreement::Differs
        },
        differences,
        expected_parameter_commitment,
        receipt_digest: receipt.digest(),
        gateway_disposition: receipt.disposition,
    })
}
