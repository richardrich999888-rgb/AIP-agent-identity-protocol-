//! `aip-http-gateway` — the reverse proxy that issues the receipts.
//!
//! This binary is the adapter. Every decision it makes is made by the pure
//! core (`admit`, `receipt_for_*`); what lives here is the socket, the clock,
//! the upstream client and the sink. That split is why the security properties
//! are testable without a network.
//!
//! # Fail closed, at startup and per request
//!
//! The gateway refuses to start if the route map does not verify under the
//! institution's anchored key. A gateway running on an unverified map would
//! be naming routes on its own authority, which is the thing the map exists to
//! prevent — and starting anyway with a warning is how that becomes permanent.
//!
//! Per request: nothing is forwarded that the gateway cannot name, cannot
//! attribute and cannot read. A refusal that can be receipted is receipted
//! before the response is written, so an agent cannot learn the outcome of a
//! refused call without that refusal existing in the stream.
//!
//! # The receipt is written before the response is returned
//!
//! Not after. If the sink fails, the request fails: a forwarded call whose
//! receipt was lost is exactly the unaccounted effect this system exists to
//! make impossible. Availability is deliberately traded for accountability,
//! and an operator who needs the other trade needs a different tool.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aip_airi::{GatewayDisposition, GatewaySigner, SignedToolReceipt};
use aip_http_gateway::{
    admit, receipt_for_admitted, receipt_for_refused, Admission, RequestParts, RouteMap,
    RouteMapAnchors, Unreceiptable,
};
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use http_body_util::BodyExt;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use serde_json::Value;

/// Largest request body the gateway will read. A body it cannot hold is a body
/// it cannot commit to, so the cap is a refusal rather than a truncation.
const MAX_BODY: usize = 1 << 20;

const USAGE: &str = "\
aip-http-gateway — issue gateway-signed ToolReceipts at an HTTP API boundary

USAGE:
    aip-http-gateway --listen <ADDR> --upstream <URL>
                     --route-map <FILE> --issuer-id <ID> --issuer-pubkey <FILE>
                     --gateway-id <ID> --key-version <N> --gateway-key <FILE>
                     --receipts <FILE>

    --route-map     the institution's signed route map (JSON)
    --issuer-id     the institution identity whose key signs that map
    --issuer-pubkey hex ed25519 public key for --issuer-id
    --gateway-key   hex ed25519 PRIVATE key this gateway signs receipts with
    --receipts      JSONL sink; one signed receipt per line

The gateway refuses to start if the route map does not verify.
";

struct Gate {
    map: RouteMap,
    signer: GatewaySigner,
    upstream: String,
    receipts: std::sync::Mutex<std::fs::File>,
    client: Client<HttpConnector, Body>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn val(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn need(args: &[String], flag: &str) -> Result<String, String> {
    val(args, flag).ok_or_else(|| format!("{flag} is required"))
}

fn read_hex(path: &str) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let text = text.trim();
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{path} is not hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("aip-http-gateway: {message}\n\n{USAGE}");
            std::process::ExitCode::from(2)
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    let listen: SocketAddr = need(&args, "--listen")?
        .parse()
        .map_err(|e| format!("--listen: {e}"))?;
    let upstream = need(&args, "--upstream")?.trim_end_matches('/').to_string();
    let map_path = need(&args, "--route-map")?;
    let issuer_id = need(&args, "--issuer-id")?;
    let issuer_key = read_hex(&need(&args, "--issuer-pubkey")?)?;
    let gateway_id = need(&args, "--gateway-id")?;
    let key_version: u32 = need(&args, "--key-version")?
        .parse()
        .map_err(|e| format!("--key-version: {e}"))?;
    let gateway_key = read_hex(&need(&args, "--gateway-key")?)?;
    let receipts_path = need(&args, "--receipts")?;

    let map: RouteMap = serde_json::from_str(
        &std::fs::read_to_string(&map_path).map_err(|e| format!("cannot read {map_path}: {e}"))?,
    )
    .map_err(|e| format!("{map_path} is not a route map: {e}"))?;

    // The startup gate. A gateway running on an unverified map names routes on
    // its own authority, which is what the map exists to prevent.
    let anchors = RouteMapAnchors::new().trust(&issuer_id, &issuer_key);
    map.verify(&anchors)
        .map_err(|e| format!("{map_path} does not verify under {issuer_id}: {e:?}"))?;

    let signer = GatewaySigner::new(&gateway_id, key_version, &gateway_key)
        .map_err(|e| format!("gateway key: {e:?}"))?;

    let receipts = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&receipts_path)
        .map_err(|e| format!("cannot open {receipts_path}: {e}"))?;

    let gate = Arc::new(Gate {
        map,
        signer,
        upstream: upstream.clone(),
        receipts: std::sync::Mutex::new(receipts),
        client: Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new()),
    });

    eprintln!(
        "aip-http-gateway: map {} revision {} ({} routes) verified under {issuer_id}; \
         gateway {gateway_id} key {key_version}; {listen} -> {upstream}; receipts -> {receipts_path}",
        gate.map.map_id,
        gate.map.revision,
        gate.map.routes.len(),
    );

    let app = Router::new().fallback(handle).with_state(Arc::clone(&gate));
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("cannot bind {listen}: {e}"))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("serve: {e}"))
}

/// Header value as an owned string, or `None` when absent or not ASCII.
fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

async fn handle(State(gate): State<Arc<Gate>>, request: Request<Body>) -> Response {
    let (head, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_BODY).await else {
        // A body the gateway cannot hold is one it cannot commit to.
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "body exceeds the gateway limit\n",
        )
            .into_response();
    };

    let parts = RequestParts {
        method: head.method.as_str().to_ascii_uppercase(),
        path: head.uri.path().to_string(),
        query: head.uri.query().map(str::to_string),
        agent_id: header(&head.headers, "x-aip-agent-id"),
        decision_id: header(&head.headers, "x-aip-decision-id"),
        tool_call_id: header(&head.headers, "x-aip-tool-call-id"),
        body: (!bytes.is_empty()).then(|| bytes.to_vec()),
    };

    match admit(&gate.map, &parts) {
        Admission::RefuseWithoutReceipt(why) => refuse_unreceipted(why),
        Admission::RefuseWithReceipt(call) => {
            let Ok(receipt) = receipt_for_refused(&gate.signer, &call, now_ms()) else {
                return internal("could not sign the refusal receipt");
            };
            // Sealed before the agent learns the outcome.
            if let Err(e) = seal(&gate, &receipt) {
                return internal(&e);
            }
            (
                StatusCode::BAD_REQUEST,
                format!("refused: {:?}\n", call.reason),
            )
                .into_response()
        }
        Admission::Admit(call) => {
            let forwarded = forward(
                &gate,
                &head.method,
                &head.uri,
                &head.headers,
                bytes.to_vec(),
            )
            .await;
            let (disposition, response_json, out) = match forwarded {
                Ok((status, headers, body)) => {
                    let json: Option<Value> = serde_json::from_slice(&body).ok();
                    (
                        GatewayDisposition::Forwarded,
                        json,
                        Some((status, headers, body)),
                    )
                }
                Err(e) => {
                    eprintln!("aip-http-gateway: upstream failed: {e}");
                    (GatewayDisposition::Failed, None, None)
                }
            };
            let Ok(receipt) = receipt_for_admitted(
                &gate.signer,
                &call,
                disposition,
                response_json.as_ref(),
                now_ms(),
            ) else {
                return internal("could not sign the receipt");
            };
            // Before the response, always: a forwarded call whose receipt was
            // lost is the unaccounted effect this system exists to prevent.
            if let Err(e) = seal(&gate, &receipt) {
                return internal(&e);
            }
            match out {
                Some((status, headers, body)) => {
                    let mut response = Response::new(Body::from(body));
                    *response.status_mut() = status;
                    *response.headers_mut() = headers;
                    response
                }
                None => (StatusCode::BAD_GATEWAY, "upstream did not answer\n").into_response(),
            }
        }
    }
}

fn refuse_unreceipted(why: Unreceiptable) -> Response {
    match why {
        // No name, so no receipt, and nothing reached the upstream.
        Unreceiptable::Unrouted { method, path } => (
            StatusCode::NOT_FOUND,
            format!("no route names {method} {path}\n"),
        )
            .into_response(),
        Unreceiptable::NoAgentId => {
            (StatusCode::UNAUTHORIZED, "X-AIP-Agent-Id is required\n").into_response()
        }
        Unreceiptable::NoDecisionId => {
            (StatusCode::UNAUTHORIZED, "X-AIP-Decision-Id is required\n").into_response()
        }
        Unreceiptable::MalformedDecisionId => (
            StatusCode::BAD_REQUEST,
            "X-AIP-Decision-Id must be 32 hex characters\n",
        )
            .into_response(),
    }
}

fn internal(message: &str) -> Response {
    eprintln!("aip-http-gateway: {message}");
    (StatusCode::INTERNAL_SERVER_ERROR, "gateway error\n").into_response()
}

/// Append one signed receipt to the sink, flushed before returning.
fn seal(gate: &Gate, receipt: &SignedToolReceipt) -> Result<(), String> {
    use std::io::Write;
    let line = serde_json::to_string(receipt).map_err(|e| format!("receipt encode: {e}"))?;
    let mut file = gate
        .receipts
        .lock()
        .map_err(|_| "receipt sink poisoned".to_string())?;
    writeln!(file, "{line}").map_err(|e| format!("receipt write: {e}"))?;
    file.flush().map_err(|e| format!("receipt flush: {e}"))
}

type Upstream = (StatusCode, HeaderMap, Vec<u8>);

async fn forward(
    gate: &Gate,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<Upstream, String> {
    let target = format!(
        "{}{}",
        gate.upstream,
        uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    );
    let mut builder = Request::builder().method(method).uri(&target);
    for (name, value) in headers {
        // `host` belongs to the upstream connection, not the original request.
        if name.as_str() != "host" {
            builder = builder.header(name, value);
        }
    }
    let request = builder
        .body(Body::from(body))
        .map_err(|e| format!("build upstream request: {e}"))?;

    let response = gate
        .client
        .request(request)
        .await
        .map_err(|e| format!("{target}: {e}"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read upstream body: {e}"))?
        .to_bytes()
        .to_vec();
    Ok((status, headers, bytes))
}
