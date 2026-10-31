//! Interpretation sidecar adapter: a child Python process speaking JSON lines
//! over stdin/stdout. No sockets. The child's stderr goes to a log file.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};
use vanian_sovereign::ports::{ChatMessage, PortError, PortErrorKind};

use crate::domain::maintenance::{known_metric, Reading};
use crate::ports::{Interpretation, InterpreterPort, SlmRequest};

/// Upper bound on one reply line.
const MAX_REPLY_BYTES: u64 = 1 << 20;

struct Io {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// Running sidecar.
pub struct Sidecar {
    child: RefCell<Child>,
    io: RefCell<Io>,
}

fn perr(m: impl Into<String>) -> PortError {
    PortError::new(PortErrorKind::Inference, m)
}

impl Sidecar {
    /// Start `python -I <script>`; blocks until the health reply arrives.
    pub fn start(
        python: &Path,
        script: &Path,
        stderr_log: &Path,
    ) -> Result<(Self, Value), PortError> {
        let log = std::fs::File::create(stderr_log).map_err(|e| perr(e.to_string()))?;
        let mut child = Command::new(python)
            .arg("-I")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .spawn()
            .map_err(|e| perr(format!("sidecar spawn: {e}")))?;
        let io = Io {
            stdin: child.stdin.take().ok_or_else(|| perr("no stdin"))?,
            stdout: BufReader::new(child.stdout.take().ok_or_else(|| perr("no stdout"))?),
        };
        let s = Self {
            child: RefCell::new(child),
            io: RefCell::new(io),
        };
        let h = s.call(&json!({"op": "health"}))?;
        Ok((s, h))
    }

    /// Process id (for the meter).
    pub fn pid(&self) -> u32 {
        self.child.borrow().id()
    }

    fn call(&self, req: &Value) -> Result<Value, PortError> {
        let mut io = self.io.borrow_mut();
        writeln!(io.stdin, "{req}").map_err(|e| perr(format!("sidecar write: {e}")))?;
        io.stdin.flush().map_err(|e| perr(e.to_string()))?;
        let mut line = String::new();
        (&mut io.stdout)
            .take(MAX_REPLY_BYTES)
            .read_line(&mut line)
            .map_err(|e| perr(e.to_string()))?;
        if !line.ends_with('\n') {
            return Err(perr("sidecar reply missing or oversized"));
        }
        let v: Value =
            serde_json::from_str(&line).map_err(|e| perr(format!("sidecar reply: {e}")))?;
        if let Some(e) = v.get("error") {
            return Err(PortError::new(
                PortErrorKind::InvalidInput,
                format!("sidecar: {e}"),
            ));
        }
        Ok(v)
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        let mut c = self.child.borrow_mut();
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// Parse `[[key, value], ...]`; unknown metric keys are a contract violation.
fn readings(v: &Value) -> Result<Vec<Reading>, PortError> {
    let arr = v.as_array().ok_or_else(|| perr("readings not an array"))?;
    arr.iter()
        .map(|p| {
            let key = p
                .get(0)
                .and_then(Value::as_str)
                .ok_or_else(|| perr("reading key"))?;
            let value = p
                .get(1)
                .and_then(Value::as_f64)
                .ok_or_else(|| perr("reading value"))?;
            if !known_metric(key) {
                return Err(PortError::new(
                    PortErrorKind::ContractViolation,
                    format!("unknown metric {key}"),
                ));
            }
            Ok(Reading {
                key: key.into(),
                value,
            })
        })
        .collect()
}

impl InterpreterPort for Sidecar {
    fn interpret(&self, text: &str) -> Result<Interpretation, PortError> {
        let v = self.call(&json!({"op": "interpret", "text": text}))?;
        Ok(Interpretation {
            rules: readings(&v["rules"])?,
            interp: readings(&v["interp"])?,
            interp_top_prob: v["interp_top_prob"].as_f64().unwrap_or(0.0),
            unregistered: v["unregistered"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            registered_codes: v["registered_codes"].as_u64().unwrap_or(0) as usize,
        })
    }

    fn slm_request(&self, text: &str) -> Result<SlmRequest, PortError> {
        let v = self.call(&json!({"op": "slm_request", "text": text}))?;
        let role = |r: &str| -> &'static str {
            match r {
                "system" => "system",
                _ => "user",
            }
        };
        let messages = v["messages"]
            .as_array()
            .ok_or_else(|| perr("messages"))?
            .iter()
            .map(|m| ChatMessage {
                role: role(m["role"].as_str().unwrap_or("user")),
                content: m["content"].as_str().unwrap_or("").into(),
            })
            .collect();
        Ok(SlmRequest {
            messages,
            max_tokens: v["max_tokens"].as_u64().unwrap_or(120) as u32,
            schema: v["schema"].to_string(),
        })
    }

    fn slm_parse(&self, raw: &str) -> Result<Option<Vec<Reading>>, PortError> {
        let v = self.call(&json!({"op": "slm_parse", "raw": raw}))?;
        if v["readings"].is_null() {
            return Ok(None);
        }
        readings(&v["readings"]).map(Some)
    }
}
