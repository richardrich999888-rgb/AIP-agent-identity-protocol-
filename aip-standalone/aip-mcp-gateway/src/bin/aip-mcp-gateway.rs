//! `aip-mcp-gateway` — a minimal MCP gateway that countersigns every
//! `tools/call` with a signed [`aip_airi::ToolReceipt`] before forwarding it.
//!
//! It speaks JSON-RPC over stdio (one JSON object per line), the transport an
//! MCP client already uses for a stdio server. For each `tools/call` it:
//!   1. enforces the 2026-07-28 spec's header/body agreement;
//!   2. computes the parameter commitment over the canonical body arguments;
//!   3. signs a `ToolReceipt` with the gateway's own key and appends it to the
//!      receipt sink (`AIP_GATEWAY_RECEIPTS`, one JSON object per line);
//!   4. forwards to a stub upstream (an echo tool) and returns its result.
//!
//! This is the reference gateway. In a deployment the same steps 1–3 run as an
//! IBM ContextForge plugin (`integrations/mcp-gateway/`); the receipt-signing
//! is identical because it is this crate's `issue_receipt`.
//!
//! It never holds an evidence-signing key and never holds the agent's key: its
//! only key is the gateway's own, loaded from `AIP_GATEWAY_KEY` (32-byte hex).
//! Fail closed: a request it cannot receipt is answered with a JSON-RPC error,
//! not forwarded unrecorded.

use std::io::{BufRead, Write};

use aip_airi::GatewayDisposition;
use aip_airi::GatewaySigner;
use aip_mcp_gateway::{check_header_body, issue_receipt, GatewayError, ToolCall, MCP_TOOLS_CALL};
use serde_json::{json, Value};

fn main() {
    std::process::exit(match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("aip-mcp-gateway: {e}");
            1
        }
    });
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let raw = decode_hex(s.trim()).map_err(|e| format!("key is not hex: {e}"))?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| "gateway key must be 32 bytes".to_string())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn decision_id_from(auth: &Value) -> [u8; 16] {
    // The request's authorisation carries the decision id as hex; absent or
    // malformed, the gateway records all-zero (a join key that will not match
    // any real expectation, which is the correct fail-closed default).
    auth.get("decision_id")
        .and_then(Value::as_str)
        .and_then(|h| decode_hex(h).ok())
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .unwrap_or([0u8; 16])
}

fn run() -> Result<(), String> {
    let key = hex32(&std::env::var("AIP_GATEWAY_KEY").map_err(|_| "AIP_GATEWAY_KEY not set")?)?;
    let gateway_id = std::env::var("AIP_GATEWAY_ID").unwrap_or_else(|_| "gateway.local".into());
    let key_version: u32 = std::env::var("AIP_GATEWAY_KEY_VERSION")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let signer = GatewaySigner::new(&gateway_id, key_version, &key)
        .map_err(|e| format!("gateway signer: {e:?}"))?;

    let receipts_path = std::env::var("AIP_GATEWAY_RECEIPTS")
        .map_err(|_| "AIP_GATEWAY_RECEIPTS (receipt sink path) not set")?;
    let mut receipts = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&receipts_path)
        .map_err(|e| format!("open {receipts_path}: {e}"))?;

    eprintln!("aip-mcp-gateway: id={gateway_id} v{key_version}; receipts -> {receipts_path}");

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("stdin: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                write_line(
                    &mut stdout,
                    &rpc_error(Value::Null, -32700, &format!("parse: {e}")),
                )?;
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let response = handle(&signer, &req, &mut receipts);
        let out = match response {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, msg)) => rpc_error(id, code, &msg),
        };
        write_line(&mut stdout, &out)?;
    }
    Ok(())
}

/// Handle one JSON-RPC request. Returns the `result` value or a `(code, msg)`
/// JSON-RPC error. Only `tools/call` is receipted; other methods pass through
/// with a minimal stub, since this reference gateway has no real upstream.
fn handle(
    signer: &GatewaySigner,
    req: &Value,
    receipts: &mut std::fs::File,
) -> Result<Value, (i64, String)> {
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    if method != MCP_TOOLS_CALL {
        // Not a tool call: nothing to countersign. A real gateway forwards
        // these to the upstream; the reference one acknowledges them.
        return Ok(json!({"stub": true, "method": method}));
    }

    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "tools/call missing params.name".to_string()))?
        .to_string();
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
    let auth = req.get("authorization").cloned().unwrap_or(Value::Null);
    let agent_id = auth
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown-agent")
        .to_string();
    let tool_call_id = params
        .get("tool_call_id")
        .and_then(Value::as_str)
        .map(str::to_string);

    let call = ToolCall {
        method: method.to_string(),
        tool_name,
        decision_id: decision_id_from(&auth),
        agent_id,
        tool_call_id,
        arguments,
    };

    // The spec's header/body check. Headers arrive in the request's `headers`
    // object for this stdio transport; a mismatch is refused before signing.
    let headers = req.get("headers").cloned().unwrap_or(Value::Null);
    let hm = headers
        .get("Mcp-Method")
        .and_then(Value::as_str)
        .unwrap_or(MCP_TOOLS_CALL);
    let hn = headers
        .get("Mcp-Name")
        .and_then(Value::as_str)
        .unwrap_or(&call.tool_name);
    if let Err(GatewayError::HeaderBodyMismatch { .. }) = check_header_body(hm, hn, &call) {
        // Sign a Refused receipt so the refusal is itself evidence, then error.
        let refused = issue_receipt(signer, &call, GatewayDisposition::Refused, None, now_ms());
        if let Ok(r) = refused {
            let _ = append_receipt(receipts, &r);
        }
        return Err((
            -32600,
            "Mcp-Method/Mcp-Name header disagrees with the body".to_string(),
        ));
    }

    // The stub upstream: echo the arguments. A real gateway forwards here.
    let response = json!({"echo": call.arguments});
    let signed = issue_receipt(
        signer,
        &call,
        GatewayDisposition::Forwarded,
        Some(&response),
        now_ms(),
    )
    .map_err(|e| (-32603, format!("receipt: {e}")))?;
    append_receipt(receipts, &signed).map_err(|e| (-32603, e))?;

    Ok(json!({
        "content": [{"type": "text", "text": "ok"}],
        "aip_receipt": {
            "gateway_id": signed.receipt.gateway_id,
            "decision_id": to_hex(&signed.receipt.decision_id),
            "parameter_commitment": to_hex(&signed.receipt.parameter_commitment),
        }
    }))
}

fn append_receipt(f: &mut std::fs::File, r: &aip_airi::SignedToolReceipt) -> Result<(), String> {
    let mut line = serde_json::to_vec(r).map_err(|e| format!("encode receipt: {e}"))?;
    line.push(b'\n');
    f.write_all(&line)
        .map_err(|e| format!("write receipt: {e}"))?;
    f.sync_all().map_err(|e| format!("flush receipt: {e}"))
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rpc_error(id: Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

fn write_line(out: &mut std::io::Stdout, v: &Value) -> Result<(), String> {
    let mut s = serde_json::to_string(v).map_err(|e| e.to_string())?;
    s.push('\n');
    out.write_all(s.as_bytes()).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}
