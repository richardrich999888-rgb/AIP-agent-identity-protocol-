//! Receipt-only interface for real gateways. Never forwards or imitates a tool.
//!
//! `check` validates a call, the signing key against an independently configured
//! public anchor, and the sink before dispatch. `issue` signs the gateway's
//! explicit disposition after dispatch/refusal. `verify` needs only the public
//! anchor. The original reference stdio gateway and ToolReceipt v1 are unchanged.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use aip_airi::{
    compare_tool_boundary, verify_tool_receipt, GatewayDisposition, GatewaySigner,
    GatewayTrustAnchors, SignedToolReceipt,
};
use aip_authorize::{DecisionPointTrustAnchors, ExpectedExecution};
use aip_mcp_gateway::{check_header_body, issue_receipt, ToolCall, MCP_TOOLS_CALL};
use serde::Deserialize;
use serde_json::{json, Value};

const MAX_INPUT: u64 = 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    method: String,
    tool_name: String,
    arguments: Value,
    agent_id: String,
    decision_id: String,
    tool_call_id: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    disposition: Option<GatewayDisposition>,
    response: Option<Value>,
    received_at_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Comparison {
    signed_receipt: SignedToolReceipt,
    expectation: ExpectedExecution,
}

fn hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let value = value.trim();
    if !value.is_ascii() || value.len() != N * 2 {
        return Err(format!("expected {N}-byte hex"));
    }
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("expected {N}-byte hex"))?;
    }
    Ok(bytes)
}

fn private_key() -> Result<[u8; 32], String> {
    let path =
        std::env::var("AIP_GATEWAY_KEY_FILE").map_err(|_| "AIP_GATEWAY_KEY_FILE is required")?;
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| "cannot inspect gateway key file")?;
    if !metadata.is_file() || metadata.len() > 256 {
        return Err("gateway key must be a regular hex file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("gateway key file must not be accessible to group or other users".into());
        }
    }
    let key = std::fs::read_to_string(path).map_err(|_| "cannot read gateway key file")?;
    hex(&key)
}

fn sink() -> Result<std::fs::File, String> {
    let path =
        std::env::var("AIP_GATEWAY_RECEIPTS").map_err(|_| "AIP_GATEWAY_RECEIPTS is required")?;
    // The parent directory is gateway-admin controlled. Reject links/devices,
    // including /dev/full, rather than treating a non-file as a durable sink.
    if let Ok(metadata) = std::fs::symlink_metadata(Path::new(&path)) {
        if !metadata.is_file() {
            return Err("receipt sink must be a regular file".into());
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|_| "cannot open receipt sink")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect receipt sink")?
        .is_file()
    {
        return Err("receipt sink must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file
            .metadata()
            .map_err(|_| "cannot inspect receipt sink")?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("receipt sink must not be accessible to group or other users".into());
        }
    }
    file.sync_all().map_err(|_| "cannot sync receipt sink")?;
    Ok(file)
}

fn run() -> Result<Value, String> {
    let mode = std::env::args()
        .nth(1)
        .ok_or("expected check, issue, verify, or compare")?;
    if !["check", "issue", "verify", "compare"].contains(&mode.as_str()) {
        return Err("expected check, issue, verify, or compare".into());
    }
    let gateway_id = std::env::var("AIP_GATEWAY_ID").map_err(|_| "AIP_GATEWAY_ID is required")?;
    let key_version = std::env::var("AIP_GATEWAY_KEY_VERSION")
        .map_err(|_| "AIP_GATEWAY_KEY_VERSION is required")?
        .parse::<u32>()
        .map_err(|_| "invalid gateway key version")?;
    let public_key = hex::<32>(
        &std::env::var("AIP_GATEWAY_PUBLIC_KEY")
            .map_err(|_| "AIP_GATEWAY_PUBLIC_KEY is required")?,
    )?;
    let anchors = GatewayTrustAnchors::new().trust(&gateway_id, key_version, &public_key);
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut input)
        .map_err(|_| "cannot read request")?;
    if input.len() as u64 > MAX_INPUT {
        return Err("request exceeds 1 MiB".into());
    }
    if mode == "verify" {
        let signed: SignedToolReceipt =
            serde_json::from_slice(&input).map_err(|_| "invalid signed receipt")?;
        verify_tool_receipt(&signed, &anchors, None)
            .map_err(|error| format!("receipt: {error}"))?;
        return Ok(json!({"verified": true, "receipt": signed.receipt}));
    }
    if mode == "compare" {
        let comparison: Comparison =
            serde_json::from_slice(&input).map_err(|_| "invalid tool-boundary comparison")?;
        let decision_point_id = std::env::var("AIP_DECISION_POINT_ID")
            .map_err(|_| "AIP_DECISION_POINT_ID is required")?;
        let decision_point_key = hex::<32>(
            &std::env::var("AIP_DECISION_POINT_PUBLIC_KEY")
                .map_err(|_| "AIP_DECISION_POINT_PUBLIC_KEY is required")?,
        )?;
        let decision_anchors =
            DecisionPointTrustAnchors::new().trust(&decision_point_id, &decision_point_key);
        let receipt = verify_tool_receipt(&comparison.signed_receipt, &anchors, None)
            .map_err(|error| format!("receipt: {error}"))?;
        let boundary = compare_tool_boundary(
            &comparison.expectation,
            &decision_anchors,
            Some(&receipt),
            None,
        );
        return Ok(json!({"tool_boundary": boundary}));
    }

    let request: Request = serde_json::from_slice(&input).map_err(|_| "invalid receipt request")?;
    if request.method != MCP_TOOLS_CALL || !request.arguments.is_object() {
        return Err("expected tools/call with object arguments".into());
    }
    let call = ToolCall {
        method: request.method,
        tool_name: request.tool_name,
        decision_id: hex(&request.decision_id)?,
        agent_id: request.agent_id,
        tool_call_id: request.tool_call_id,
        arguments: request.arguments,
    };
    let header = |name: &str| {
        request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let header_check = check_header_body(
        header("mcp-method").unwrap_or(MCP_TOOLS_CALL),
        header("mcp-name").unwrap_or(&call.tool_name),
        &call,
    );
    let disposition = if mode == "check" {
        // Only used to exercise the existing signer's structural validation.
        // This transient signature is neither returned nor persisted.
        GatewayDisposition::Refused
    } else {
        request
            .disposition
            .ok_or("issue requires an explicit disposition")?
    };
    if header_check.is_err() && (mode == "check" || disposition != GatewayDisposition::Refused) {
        return Err("Mcp-Method/Mcp-Name disagrees with the received call".into());
    }
    let key = private_key()?;
    let actual_key =
        aip_crypto::public_key_from_private(&key).map_err(|_| "invalid signing key")?;
    if actual_key != public_key {
        return Err("gateway signing key does not match the configured public anchor".into());
    }
    let signer =
        GatewaySigner::new(&gateway_id, key_version, &key).map_err(|_| "invalid gateway signer")?;
    let signed = issue_receipt(
        &signer,
        &call,
        disposition,
        request.response.as_ref(),
        request.received_at_ms,
    )
    .map_err(|error| format!("receipt: {error}"))?;
    verify_tool_receipt(&signed, &anchors, None).map_err(|error| format!("receipt: {error}"))?;
    let mut file = sink()?;
    if mode == "check" {
        return Ok(
            json!({"ready": true, "parameter_commitment": signed.receipt.parameter_commitment}),
        );
    }
    // Multiple ContextForge calls/workers may invoke the signer concurrently.
    // Serialize complete JSONL records and sync before reporting success.
    file.lock().map_err(|_| "cannot lock receipt sink")?;
    let mut line = serde_json::to_vec(&signed).map_err(|_| "cannot encode receipt")?;
    line.push(b'\n');
    file.write_all(&line)
        .map_err(|_| "cannot persist receipt")?;
    file.sync_all().map_err(|_| "cannot sync receipt")?;
    file.unlock().map_err(|_| "cannot unlock receipt sink")?;
    Ok(json!({"signed_receipt": signed}))
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            // Diagnostics never include the input, key bytes, or tool payload.
            eprintln!("aip-tool-receipt: {error}");
            std::process::exit(1);
        }
    }
}
