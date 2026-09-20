//! The real MCP server behind the gateway.
//!
//! A trait, because "where the tools actually live" varies — a child process
//! over stdio, another HTTP endpoint, an in-process shim in a test — while
//! the governed dispatch above it does not care.
//!
//! # Why calls are serialised
//!
//! [`StdioUpstream`] writes a request and reads the next line as its reply.
//! That is only correct if one call is in flight at a time: JSON-RPC ids
//! would let a server interleave responses, and a server that does would hand
//! one caller another's result. Rather than build id-correlation the stdio
//! protocol does not require, the transport holds a lock across the round
//! trip. Concurrency belongs to the connection layer, which can front several
//! upstreams.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, INTERNAL_ERROR};

/// Something that answers MCP requests.
pub trait Upstream: Send {
    /// Sends a request and returns the outcome.
    ///
    /// A notification (no id) expects no reply and should return
    /// `Ok(Value::Null)` once written.
    fn round_trip(&mut self, request: &JsonRpcRequest) -> Result<Value, JsonRpcError>;
}

/// An MCP server launched as a child process, spoken to over its stdio.
pub struct StdioUpstream {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl StdioUpstream {
    /// Launches `command` and takes its stdio.
    ///
    /// The child's stderr passes through to ours: a tool server's diagnostics
    /// belong in the operator's log, not swallowed by the thing whose job is
    /// making its behaviour visible.
    pub fn launch(command: &[String]) -> Result<Self, String> {
        let Some((program, args)) = command.split_first() else {
            return Err("no upstream command given".to_string());
        };
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot launch upstream {program:?}: {e}"))?;
        let stdin = child.stdin.take().ok_or("upstream has no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("upstream has no stdout")?);
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }

    /// Terminates the child.
    pub fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Upstream for StdioUpstream {
    fn round_trip(&mut self, request: &JsonRpcRequest) -> Result<Value, JsonRpcError> {
        let line = request.to_json().to_string();
        writeln!(self.stdin, "{line}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| {
                JsonRpcError::new(INTERNAL_ERROR, format!("cannot write upstream: {e}"))
            })?;
        if request.is_notification() {
            return Ok(Value::Null);
        }
        let mut reply = String::new();
        match self.stdout.read_line(&mut reply) {
            Ok(0) => Err(JsonRpcError::new(
                INTERNAL_ERROR,
                "upstream closed its stdout",
            )),
            Ok(_) => JsonRpcResponse::parse_outcome(reply.trim()),
            Err(e) => Err(JsonRpcError::new(
                INTERNAL_ERROR,
                format!("cannot read upstream: {e}"),
            )),
        }
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// An upstream that answers from a fixed table. For tests and for running a
/// gateway with no server behind it.
#[derive(Debug, Default)]
pub struct ScriptedUpstream {
    /// Method name → canned result.
    pub replies: std::collections::BTreeMap<String, Value>,
    /// Requests seen, in order — so a test can assert what did *not* arrive.
    pub seen: Vec<String>,
}

impl ScriptedUpstream {
    /// An upstream with no scripted replies.
    pub fn new() -> Self {
        Self::default()
    }

    /// Scripts a reply for a method.
    pub fn replying(mut self, method: &str, result: Value) -> Self {
        self.replies.insert(method.to_string(), result);
        self
    }
}

impl Upstream for ScriptedUpstream {
    fn round_trip(&mut self, request: &JsonRpcRequest) -> Result<Value, JsonRpcError> {
        self.seen.push(request.method.clone());
        self.replies
            .get(&request.method)
            .cloned()
            .ok_or_else(|| JsonRpcError::new(INTERNAL_ERROR, "no scripted reply"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_stdio_upstream_round_trips_a_request_through_a_real_child() {
        // `cat` echoes the request back; not a valid JSON-RPC response, so
        // this asserts the framing and the error path rather than a result.
        let mut up = StdioUpstream::launch(&["cat".to_string()]).expect("launch");
        let request = JsonRpcRequest::new(Some(json!(1)), "ping", json!({}));
        let outcome = up.round_trip(&request);
        // `cat` returns the request verbatim: valid JSON with neither result
        // nor error, which the protocol layer reports rather than guesses at.
        assert!(outcome.is_err());
        assert_eq!(outcome.unwrap_err().code, INTERNAL_ERROR);
    }

    #[test]
    fn a_notification_expects_no_reply() {
        let mut up = StdioUpstream::launch(&["cat".to_string()]).expect("launch");
        let note = JsonRpcRequest::new(None, "notifications/initialized", Value::Null);
        assert_eq!(up.round_trip(&note), Ok(Value::Null));
    }

    #[test]
    fn launching_nothing_is_an_error_rather_than_a_panic() {
        assert!(StdioUpstream::launch(&[]).is_err());
        assert!(StdioUpstream::launch(&["definitely-not-a-real-binary-xyz".to_string()]).is_err());
    }

    #[test]
    fn a_scripted_upstream_records_what_reached_it() {
        let mut up = ScriptedUpstream::new().replying("tools/list", json!({ "tools": [] }));
        let listed = JsonRpcRequest::new(Some(json!(1)), "tools/list", Value::Null);
        assert_eq!(up.round_trip(&listed), Ok(json!({ "tools": [] })));
        assert!(up
            .round_trip(&JsonRpcRequest::new(
                Some(json!(2)),
                "tools/call",
                Value::Null
            ))
            .is_err());
        assert_eq!(up.seen, ["tools/list", "tools/call"]);
    }
}
