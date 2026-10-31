//! llama-server client with scope-bound slot management.
//!
//! Every generation goes to a slot chosen by [`SlotTable::decide`]. A slot
//! last written by a different [`CacheScope`] is erased (`POST
//! /slots/N?action=erase`) before use; if the erase fails the request is
//! refused rather than sent under another scope's state. This client never
//! calls `save` or `restore` (KV checkpoints are not in the production path).
//!
//! HTTP is the same minimal loopback-only client as the Sovereign adapter
//! (re-implemented here because that request function is private); response
//! parsing reuses `vanian_sovereign::adapters::llama_http`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use vanian_sovereign::adapters::llama_http::{
    chat_request_body, extract_content, parse_http_response,
};
use vanian_sovereign::policy::egress::LoopbackEndpoint;
use vanian_sovereign::ports::{ChatMessage, GenerationParams, PortError, PortErrorKind};

use crate::domain::scope::{CacheScope, SlotTable};
use crate::ports::{GenStats, ScopedGenerator};

const MAX_RESPONSE_BYTES: u64 = 4 << 20;

/// Scoped client for one server.
pub struct ScopedLlama {
    endpoint: LoopbackEndpoint,
    timeout: Duration,
    slots: Mutex<SlotTable>,
    model_sha256: String,
}

fn inf(m: impl Into<String>) -> PortError {
    PortError::new(PortErrorKind::Inference, m)
}

impl ScopedLlama {
    /// `n_slots` must equal the server's `--parallel`.
    pub fn new(
        endpoint: LoopbackEndpoint,
        n_slots: usize,
        model_sha256: &str,
        timeout: Duration,
    ) -> Result<Self, PortError> {
        let slots = SlotTable::new(n_slots)
            .map_err(|e| PortError::new(PortErrorKind::InvalidInput, format!("{e:?}")))?;
        Ok(Self {
            endpoint,
            timeout,
            slots: Mutex::new(slots),
            model_sha256: model_sha256.into(),
        })
    }

    /// Raw request (loopback IP literal only; `Connection: close`; bounded).
    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), PortError> {
        let io = |e: std::io::Error| inf(e.to_string());
        let mut s = TcpStream::connect_timeout(&self.endpoint.addr(), self.timeout).map_err(io)?;
        s.set_read_timeout(Some(self.timeout)).map_err(io)?;
        s.set_write_timeout(Some(self.timeout)).map_err(io)?;
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.endpoint.addr(),
            body.len()
        );
        s.write_all(head.as_bytes()).map_err(io)?;
        s.write_all(body).map_err(io)?;
        let mut raw = Vec::new();
        s.take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(io)?;
        if raw.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(inf("response exceeds size limit"));
        }
        parse_http_response(&raw)
    }

    /// `GET /health` == 200.
    pub fn healthy(&self) -> bool {
        matches!(self.request("GET", "/health", b""), Ok((200, _)))
    }

    /// Drop every slot's ownership (call after a server restart).
    pub fn reset_slots(&self) {
        if let Ok(mut t) = self.slots.lock() {
            let _ = t.invalidate(|_| true);
        }
    }

    /// Erase every slot owned by a scope that no longer holds (e.g. after a
    /// knowledge-snapshot or policy change).
    pub fn invalidate(&self, stale: impl Fn(&str) -> bool) -> Result<(), PortError> {
        let slots = self
            .slots
            .lock()
            .map_err(|_| inf("slot table poisoned"))?
            .invalidate(stale);
        for s in slots {
            self.erase(s)?;
        }
        Ok(())
    }

    fn erase(&self, slot: usize) -> Result<(), PortError> {
        match self.request("POST", &format!("/slots/{slot}?action=erase"), b"{}") {
            Ok((200, _)) => Ok(()),
            Ok((code, b)) => Err(inf(format!(
                "slot {slot} erase refused: HTTP {code} {}",
                String::from_utf8_lossy(&b)
                    .chars()
                    .take(120)
                    .collect::<String>()
            ))),
            Err(e) => Err(e),
        }
    }
}

/// Build the scoped request body: Sovereign's deterministic chat body plus
/// slot pinning and prompt caching. Pure; unit-tested.
pub fn scoped_body(
    messages: &[ChatMessage],
    params: &GenerationParams,
    slot: usize,
) -> Result<Vec<u8>, PortError> {
    let mut v: Value = serde_json::from_slice(&chat_request_body(messages, params))
        .map_err(|e| inf(e.to_string()))?;
    v["id_slot"] = Value::from(slot as u64);
    v["cache_prompt"] = Value::Bool(true);
    Ok(v.to_string().into_bytes())
}

/// Token accounting from an OpenAI-shaped llama-server reply.
pub fn stats_from(body: &[u8]) -> GenStats {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let u = |p: &str| v.pointer(p).and_then(Value::as_u64).unwrap_or(0);
    let prompt = u("/usage/prompt_tokens");
    let evaluated = v
        .pointer("/timings/prompt_n")
        .and_then(Value::as_u64)
        .unwrap_or(prompt);
    GenStats {
        prompt_tokens: prompt,
        completion_tokens: u("/usage/completion_tokens"),
        cached_tokens: v
            .pointer("/timings/cache_n")
            .and_then(Value::as_u64)
            .unwrap_or(prompt.saturating_sub(evaluated)),
        ..Default::default()
    }
}

impl ScopedGenerator for ScopedLlama {
    fn generate(
        &self,
        scope: &CacheScope,
        messages: &[ChatMessage],
        params: &GenerationParams,
    ) -> Result<(String, GenStats), PortError> {
        let t0 = Instant::now();
        let d = self
            .slots
            .lock()
            .map_err(|_| inf("slot table poisoned"))?
            .decide(scope);
        if d.erase_first {
            if let Err(e) = self.erase(d.slot) {
                // Ownership already moved to `scope`; mark empty so a later
                // request retries the erase instead of trusting the slot.
                if let Ok(mut t) = self.slots.lock() {
                    t.forget(d.slot);
                }
                return Err(e);
            }
        }
        let (status, resp) = self.request(
            "POST",
            "/v1/chat/completions",
            &scoped_body(messages, params, d.slot)?,
        )?;
        if status != 200 {
            return Err(inf(format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(&resp)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )));
        }
        let mut st = stats_from(&resp);
        st.wall_ms = t0.elapsed().as_secs_f64() * 1000.0;
        st.slot = d.slot;
        st.slot_erased = d.erase_first;
        Ok((extract_content(&resp)?, st))
    }

    fn model_sha256(&self) -> String {
        self.model_sha256.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_pins_slot_and_caches_prompt() {
        let m = [ChatMessage {
            role: "user",
            content: "x".into(),
        }];
        let v: Value =
            serde_json::from_slice(&scoped_body(&m, &GenerationParams::default(), 3).unwrap())
                .unwrap();
        assert_eq!(v["id_slot"], 3);
        assert_eq!(v["cache_prompt"], true);
        assert_eq!(v["top_k"], 1, "greedy preserved from the Sovereign body");
    }

    #[test]
    fn stats_parse_usage_and_cache() {
        let b = br#"{"usage":{"prompt_tokens":100,"completion_tokens":7},"timings":{"prompt_n":12,"cache_n":88}}"#;
        let s = stats_from(b);
        assert_eq!(
            (s.prompt_tokens, s.completion_tokens, s.cached_tokens),
            (100, 7, 88)
        );
        let s = stats_from(
            br#"{"usage":{"prompt_tokens":50,"completion_tokens":1},"timings":{"prompt_n":10}}"#,
        );
        assert_eq!(s.cached_tokens, 40);
        assert_eq!(stats_from(b"garbage"), GenStats::default());
    }
}
