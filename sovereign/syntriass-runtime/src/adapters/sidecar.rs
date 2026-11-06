//! Interpretation sidecar adapter: a child Python process speaking JSON lines
//! over stdin/stdout. No sockets. The child's stderr goes to a log file.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::path::PathBuf;
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

/// Upper bound on the stderr tail quoted in an error. The sidecar's stderr is
/// our own script's traceback, not third-party output, but it is still bounded
/// so a runaway log cannot be pasted whole into an error message.
const MAX_STDERR_TAIL: usize = 2048;

/// Running sidecar.
pub struct Sidecar {
    child: RefCell<Child>,
    io: RefCell<Io>,
    /// Retained so a missing reply can point at the cause instead of only
    /// reporting the symptom. Without it the operator sees "reply missing"
    /// and has no way to learn that, for example, the training data is absent.
    stderr_log: PathBuf,
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
            stderr_log: stderr_log.to_path_buf(),
        };
        let h = s.call(&json!({"op": "health"}))?;
        Ok((s, h))
    }

    /// Process id (for the meter).
    pub fn pid(&self) -> u32 {
        self.child.borrow().id()
    }

    /// Why no reply arrived, as far as this process can tell.
    ///
    /// A bare "reply missing" is unactionable: the sidecar writes its failure
    /// to a log file this process owns, so the path and a bounded tail of it
    /// are the whole diagnosis. The child's exit status separates "died at
    /// startup" from "alive but silent", which have different causes.
    fn missing_reply_message(&self) -> String {
        let mut message = String::from("sidecar reply missing or oversized");
        match self.child.borrow_mut().try_wait() {
            Ok(Some(status)) => {
                message.push_str(&format!("; the sidecar exited ({status})"));
            }
            Ok(None) => message.push_str("; the sidecar is still running"),
            Err(error) => message.push_str(&format!("; exit status unavailable ({error})")),
        }
        message.push_str(&format!("\n  stderr log: {}", self.stderr_log.display()));
        match std::fs::read_to_string(&self.stderr_log) {
            Ok(text) if !text.trim().is_empty() => {
                let trimmed = text.trim_end();
                let tail = match trimmed.char_indices().nth_back(MAX_STDERR_TAIL - 1) {
                    Some((start, _)) => &trimmed[start..],
                    None => trimmed,
                };
                message.push_str("\n  last stderr from the sidecar:\n");
                for line in tail.lines() {
                    message.push_str("    ");
                    message.push_str(line);
                    message.push('\n');
                }
            }
            Ok(_) => message.push_str("\n  (its stderr log is empty)"),
            Err(error) => message.push_str(&format!("\n  (its stderr log is unreadable: {error})")),
        }
        message
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
            return Err(perr(self.missing_reply_message()));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a throwaway python script and return its path.
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(body.as_bytes()).unwrap();
        path
    }

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sidecar-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A sidecar that dies at startup must report WHY, not just that no reply
    /// came. Before this, the operator saw only "reply missing or oversized"
    /// while the cause sat unread in a log file this process had created.
    #[test]
    fn a_sidecar_that_exits_at_startup_reports_its_stderr_and_log_path() {
        let dir = tempdir("exits");
        let body = "import sys\n\
                    sys.stderr.write('sidecar: required dataset is missing\\n')\n\
                    sys.stderr.write('  fix: deploy/syntriass/setup_env.sh\\n')\n\
                    raise SystemExit(3)\n";
        let path = script(&dir, "dies.py", body);
        let log = dir.join("sidecar.log");
        let error = Sidecar::start(Path::new("python3"), &path, &log)
            .err()
            .expect("a sidecar that exits must not start successfully");
        let text = error.to_string();
        assert!(
            text.contains("required dataset is missing"),
            "the sidecar's own diagnosis must reach the caller: {text}"
        );
        assert!(
            text.contains("setup_env.sh"),
            "the remedy must survive to the caller: {text}"
        );
        assert!(
            text.contains(log.to_str().unwrap()),
            "the log path must be named so the full output can be read: {text}"
        );
        assert!(
            text.contains("exited"),
            "the exit status must be reported: {text}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Alive-but-silent and died-at-startup have different causes, so the
    /// message must not conflate them.
    #[test]
    fn a_sidecar_that_stays_alive_but_answers_nothing_is_reported_differently() {
        let dir = tempdir("silent");
        // Closes stdout, then blocks, so no reply arrives and the child lives.
        let body = "import os, sys, time\n\
                    sys.stderr.write('deliberately silent\\n'); sys.stderr.flush()\n\
                    os.close(1)\n\
                    time.sleep(30)\n";
        let path = script(&dir, "silent.py", body);
        let log = dir.join("sidecar.log");
        let error = Sidecar::start(Path::new("python3"), &path, &log)
            .err()
            .expect("a silent sidecar must not start successfully");
        let text = error.to_string();
        assert!(
            text.contains("still running"),
            "a live-but-silent sidecar must be distinguished from one that exited: {text}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An empty log must say so rather than claim the output is unreadable.
    #[test]
    fn an_empty_stderr_log_is_reported_as_empty() {
        let dir = tempdir("quiet");
        let path = script(&dir, "quiet.py", "raise SystemExit(1)\n");
        let log = dir.join("sidecar.log");
        let error = Sidecar::start(Path::new("python3"), &path, &log)
            .err()
            .expect("must not start");
        assert!(
            error.to_string().contains("stderr log is empty"),
            "an empty log needs its own wording: {}",
            error
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The tail is bounded: a large log must not be pasted whole into an error.
    #[test]
    fn a_large_stderr_log_is_truncated_to_a_bounded_tail() {
        let dir = tempdir("large");
        let body = format!(
            "import sys\nsys.stderr.write('x' * {})\nraise SystemExit(1)\n",
            MAX_STDERR_TAIL * 8
        );
        let path = script(&dir, "loud.py", &body);
        let log = dir.join("sidecar.log");
        let error = Sidecar::start(Path::new("python3"), &path, &log)
            .err()
            .expect("must not start");
        let text = error.to_string();
        assert!(
            text.len() < MAX_STDERR_TAIL * 3,
            "the message must stay bounded, got {} bytes",
            text.len()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A healthy sidecar must still start, so these diagnostics cannot be
    /// mistaken for the cause of a failure they only describe.
    #[test]
    fn a_healthy_sidecar_still_starts_and_returns_its_health_reply() {
        let dir = tempdir("ok");
        let body = "import json, sys\n\
                    for line in sys.stdin:\n\
                    \x20   sys.stdout.write(json.dumps({'ok': True, 'train_rows': 7}) + '\\n')\n\
                    \x20   sys.stdout.flush()\n";
        let path = script(&dir, "ok.py", body);
        let log = dir.join("sidecar.log");
        let (sidecar, health) =
            Sidecar::start(Path::new("python3"), &path, &log).expect("must start");
        assert_eq!(health["train_rows"], 7);
        assert!(sidecar.pid() > 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}
