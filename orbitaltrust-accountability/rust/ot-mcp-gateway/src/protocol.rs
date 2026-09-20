//! JSON-RPC 2.0 framing and the slice of MCP this gateway speaks.
//!
//! Deliberately hand-rolled rather than pulled from an SDK: the gateway's
//! whole job is to be the thing that cannot be bypassed, and a dependency
//! that silently gains a passthrough path for an unrecognised method would
//! be a hole in exactly the wrong place. Everything here is explicit, and
//! [`Method::Other`] is the one door — closed by default in the gateway.

use serde_json::{json, Value};

/// Parse error: the peer sent bytes that are not JSON.
pub const PARSE_ERROR: i64 = -32700;
/// The JSON was valid but is not a JSON-RPC request.
pub const INVALID_REQUEST: i64 = -32600;
/// The method is not one this gateway proxies.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// The params are missing something the method requires.
pub const INVALID_PARAMS: i64 = -32602;
/// The gateway or the upstream failed.
pub const INTERNAL_ERROR: i64 = -32603;

/// Application-level: governance refused the call. Distinct from
/// [`INTERNAL_ERROR`] so a client can tell "you may not" from "it broke" —
/// an agent that retries a policy denial is misbehaving, and the code says so.
pub const POLICY_DENIED: i64 = -32001;

/// A parsed JSON-RPC request.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonRpcRequest {
    /// Request id. `None` for a notification, which takes no response.
    pub id: Option<Value>,
    /// The method name.
    pub method: String,
    /// The params object; `Value::Null` when absent.
    pub params: Value,
}

impl JsonRpcRequest {
    /// Parses one JSON-RPC request from a message.
    ///
    /// Returns the error a peer should receive, so the transport never has to
    /// invent one.
    pub fn parse(raw: &str) -> Result<Self, JsonRpcError> {
        let value: Value = serde_json::from_str(raw)
            .map_err(|e| JsonRpcError::new(PARSE_ERROR, format!("invalid JSON: {e}")))?;
        let obj = value
            .as_object()
            .ok_or_else(|| JsonRpcError::new(INVALID_REQUEST, "request must be a JSON object"))?;
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(JsonRpcError::new(
                INVALID_REQUEST,
                "jsonrpc must be exactly \"2.0\"",
            ));
        }
        let method = obj
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::new(INVALID_REQUEST, "method must be a string"))?
            .to_string();
        Ok(Self {
            id: obj.get("id").filter(|v| !v.is_null()).cloned(),
            method,
            params: obj.get("params").cloned().unwrap_or(Value::Null),
        })
    }

    /// Builds a request for sending upstream.
    pub fn new(id: Option<Value>, method: impl Into<String>, params: Value) -> Self {
        Self {
            id,
            method: method.into(),
            params,
        }
    }

    /// The wire form.
    pub fn to_json(&self) -> Value {
        let mut out = json!({ "jsonrpc": "2.0", "method": self.method });
        if let Some(id) = &self.id {
            out["id"] = id.clone();
        }
        if !self.params.is_null() {
            out["params"] = self.params.clone();
        }
        out
    }

    /// True when no response is expected.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// The classified method.
    pub fn classify(&self) -> Method<'_> {
        Method::classify(&self.method)
    }

    /// A `params` field as a string.
    pub fn param_str(&self, key: &str) -> Option<&str> {
        self.params.get(key).and_then(Value::as_str)
    }

    /// The governance envelope a client attaches under `params._meta.governance`.
    ///
    /// MCP reserves `_meta` for exactly this kind of out-of-band annotation,
    /// so a governed call stays a well-formed MCP call: an upstream server
    /// that knows nothing about NEXORA still understands the request.
    pub fn governance_meta(&self) -> &Value {
        self.params
            .get("_meta")
            .and_then(|m| m.get("governance"))
            .unwrap_or(&Value::Null)
    }
}

/// The MCP methods the gateway distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method<'a> {
    /// Session handshake.
    Initialize,
    /// Post-handshake notification.
    Initialized,
    /// Catalogue enumeration — filtered by effective authority.
    ToolsList,
    /// Tool invocation — adjudicated and sealed.
    ToolsCall,
    /// Resource enumeration.
    ResourcesList,
    /// Resource read — taints the session with what it returns.
    ResourcesRead,
    /// Prompt enumeration.
    PromptsList,
    /// Prompt retrieval.
    PromptsGet,
    /// Liveness.
    Ping,
    /// Anything else.
    Other(&'a str),
}

impl<'a> Method<'a> {
    /// Classifies a method name.
    pub fn classify(name: &'a str) -> Self {
        match name {
            "initialize" => Self::Initialize,
            "notifications/initialized" => Self::Initialized,
            "tools/list" => Self::ToolsList,
            "tools/call" => Self::ToolsCall,
            "resources/list" => Self::ResourcesList,
            "resources/read" => Self::ResourcesRead,
            "prompts/list" => Self::PromptsList,
            "prompts/get" => Self::PromptsGet,
            "ping" => Self::Ping,
            other => Self::Other(other),
        }
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcError {
    /// Numeric code.
    pub code: i64,
    /// Human-readable message.
    pub message: String,
    /// Structured detail, when there is any.
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// An error with no structured data.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Attaches structured detail.
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// The wire form.
    pub fn to_json(&self) -> Value {
        let mut out = json!({ "code": self.code, "message": self.message });
        if let Some(data) = &self.data {
            out["data"] = data.clone();
        }
        out
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

/// A JSON-RPC response: a result or an error, never both.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonRpcResponse {
    /// The id of the request being answered.
    pub id: Value,
    /// The outcome.
    pub outcome: Result<Value, JsonRpcError>,
}

impl JsonRpcResponse {
    /// A successful response.
    pub fn result(id: Value, result: Value) -> Self {
        Self {
            id,
            outcome: Ok(result),
        }
    }

    /// An error response.
    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            id,
            outcome: Err(error),
        }
    }

    /// Parses a response received from upstream, reducing it to its outcome.
    pub fn parse_outcome(raw: &str) -> Result<Value, JsonRpcError> {
        let value: Value = serde_json::from_str(raw).map_err(|e| {
            JsonRpcError::new(INTERNAL_ERROR, format!("upstream sent invalid JSON: {e}"))
        })?;
        if let Some(err) = value.get("error") {
            return Err(JsonRpcError {
                code: err
                    .get("code")
                    .and_then(Value::as_i64)
                    .unwrap_or(INTERNAL_ERROR),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("upstream error")
                    .to_string(),
                data: err.get("data").cloned(),
            });
        }
        value.get("result").cloned().ok_or_else(|| {
            JsonRpcError::new(
                INTERNAL_ERROR,
                "upstream response had neither result nor error",
            )
        })
    }

    /// The wire form.
    pub fn to_json(&self) -> Value {
        match &self.outcome {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": self.id, "result": result }),
            Err(error) => json!({ "jsonrpc": "2.0", "id": self.id, "error": error.to_json() }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_request_parses_with_its_governance_envelope() {
        let req = JsonRpcRequest::parse(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call",
                "params":{"name":"fly","arguments":{"q":1},
                          "_meta":{"governance":{"rawPrompt":"go"}}}}"#,
        )
        .unwrap();
        assert_eq!(req.id, Some(json!(7)));
        assert_eq!(req.classify(), Method::ToolsCall);
        assert_eq!(req.param_str("name"), Some("fly"));
        assert_eq!(req.governance_meta()["rawPrompt"], json!("go"));
        assert!(!req.is_notification());
    }

    #[test]
    fn malformed_requests_are_refused_with_the_code_the_peer_should_see() {
        assert_eq!(JsonRpcRequest::parse("{").unwrap_err().code, PARSE_ERROR);
        assert_eq!(
            JsonRpcRequest::parse(r#"{"jsonrpc":"1.0","method":"ping"}"#)
                .unwrap_err()
                .code,
            INVALID_REQUEST
        );
        assert_eq!(
            JsonRpcRequest::parse(r#"{"jsonrpc":"2.0","id":1}"#)
                .unwrap_err()
                .code,
            INVALID_REQUEST
        );
        assert_eq!(
            JsonRpcRequest::parse("[]").unwrap_err().code,
            INVALID_REQUEST
        );
    }

    #[test]
    fn a_missing_id_is_a_notification_and_survives_the_round_trip() {
        let req = JsonRpcRequest::parse(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","id":null}"#,
        )
        .unwrap();
        assert!(req.is_notification());
        assert_eq!(req.classify(), Method::Initialized);
        assert_eq!(
            req.to_json(),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
        );
    }

    #[test]
    fn upstream_outcomes_reduce_to_a_result_or_a_faithful_error() {
        assert_eq!(
            JsonRpcResponse::parse_outcome(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#),
            Ok(json!({ "ok": true }))
        );
        let err = JsonRpcResponse::parse_outcome(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"upstream said no"}}"#,
        )
        .unwrap_err();
        assert_eq!(err.code, -32000);
        assert_eq!(err.message, "upstream said no");
        // Neither field: a protocol violation, reported rather than guessed at.
        assert_eq!(
            JsonRpcResponse::parse_outcome(r#"{"jsonrpc":"2.0","id":1}"#)
                .unwrap_err()
                .code,
            INTERNAL_ERROR
        );
    }
}
