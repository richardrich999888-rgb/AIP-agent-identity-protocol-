//! Inference adapter for a llama.cpp `llama-server` on loopback.
//!
//! Uses a minimal HTTP/1.1 client over `std::net::TcpStream` instead of an
//! HTTP library. Rationale: the only reachable destination is a validated
//! [`LoopbackEndpoint`] (an IP literal), so there is no DNS path, no proxy
//! environment variable handling, no redirect following and no TLS stack in
//! the trust base. Each request opens one connection with `Connection: close`
//! and reads a bounded response.
//!
//! Endpoint: `POST /v1/chat/completions` (OpenAI-compatible shape served by
//! llama-server, which applies the model's own chat template).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{json, Value};

use crate::policy::egress::LoopbackEndpoint;
use crate::ports::{ChatMessage, GenerationParams, InferencePort, PortError, PortErrorKind};

/// Ceiling on bytes read from the server; a compromised or buggy server
/// cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 4 << 20;

/// llama-server client bound to one loopback endpoint.
pub struct LlamaHttp {
    endpoint: LoopbackEndpoint,
    timeout: Duration,
}

impl LlamaHttp {
    /// Bind to a validated endpoint. `timeout` bounds connect, each read and
    /// each write.
    pub fn new(endpoint: LoopbackEndpoint, timeout: Duration) -> Self {
        Self { endpoint, timeout }
    }

    /// `GET /health` — true only on HTTP 200.
    pub fn healthy(&self) -> bool {
        matches!(self.request("GET", "/health", None), Ok((200, _)))
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), PortError> {
        let io = |e: std::io::Error| PortError::new(PortErrorKind::Inference, e.to_string());
        let mut s = TcpStream::connect_timeout(&self.endpoint.addr(), self.timeout).map_err(io)?;
        s.set_read_timeout(Some(self.timeout)).map_err(io)?;
        s.set_write_timeout(Some(self.timeout)).map_err(io)?;
        let body = body.unwrap_or(&[]);
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.endpoint.addr(),
            body.len()
        );
        s.write_all(head.as_bytes()).map_err(io)?;
        s.write_all(body).map_err(io)?;
        let mut raw = Vec::new();
        s.take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(io)?;
        if raw.len() > MAX_RESPONSE_BYTES {
            return Err(PortError::new(
                PortErrorKind::Inference,
                "response exceeds size limit",
            ));
        }
        parse_http_response(&raw)
    }
}

/// Parse a complete HTTP/1.1 response read until EOF. Handles identity and
/// `chunked` transfer encoding.
pub fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), PortError> {
    let bad = |m: &str| {
        PortError::new(
            PortErrorKind::Inference,
            format!("malformed HTTP response: {m}"),
        )
    };
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("no header terminator"))?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| bad("non-UTF-8 header"))?;
    let body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| bad("empty"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| bad("status"))?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = if chunked {
        dechunk(body).ok_or_else(|| bad("chunk framing"))?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

/// Decode `Transfer-Encoding: chunked`. Returns `None` on malformed framing.
fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let size_hex = std::str::from_utf8(&b[..eol])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        if b.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

/// Build the request JSON. Pure; unit-tested for determinism.
pub fn chat_request_body(messages: &[ChatMessage], p: &GenerationParams) -> Vec<u8> {
    let msgs: Vec<Value> = messages
        .iter()
        .map(|m| json!({"role": m.role, "content": m.content}))
        .collect();
    json!({
        "messages": msgs,
        "max_tokens": p.max_tokens,
        "temperature": p.temperature,
        // Greedy + fixed seed: same weights and prompt give the same output.
        "top_k": 1,
        "seed": p.seed,
        "stream": false
    })
    .to_string()
    .into_bytes()
}

/// Extract `choices[0].message.content` from a response body.
pub fn extract_content(body: &[u8]) -> Result<String, PortError> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|e| PortError::new(PortErrorKind::Inference, format!("invalid JSON: {e}")))?;
    v.pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            PortError::new(
                PortErrorKind::Inference,
                "missing choices[0].message.content",
            )
        })
}

impl InferencePort for LlamaHttp {
    fn chat(
        &self,
        messages: &[ChatMessage],
        params: &GenerationParams,
    ) -> Result<String, PortError> {
        let body = chat_request_body(messages, params);
        let (status, resp) = self.request("POST", "/v1/chat/completions", Some(&body))?;
        if status != 200 {
            let snippet: String = String::from_utf8_lossy(&resp).chars().take(200).collect();
            return Err(PortError::new(
                PortErrorKind::Inference,
                format!("HTTP {status}: {snippet}"),
            ));
        }
        extract_content(&resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parses_identity_and_chunked_bodies() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        assert_eq!(parse_http_response(r).unwrap(), (200, b"hi".to_vec()));
        let c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(c).unwrap(), (200, b"abcde".to_vec()));
    }

    #[test]
    fn malformed_responses_are_errors_not_panics() {
        for r in [
            &b""[..],
            b"garbage",
            b"HTTP/1.1 xx\r\n\r\n",
            b"HTTP/1.1 200\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        ] {
            assert!(
                parse_http_response(r).is_err(),
                "{:?}",
                String::from_utf8_lossy(r)
            );
        }
    }

    #[test]
    fn request_body_is_deterministic_and_greedy() {
        let m = [ChatMessage {
            role: "user",
            content: "x".into(),
        }];
        let a = chat_request_body(&m, &GenerationParams::default());
        assert_eq!(a, chat_request_body(&m, &GenerationParams::default()));
        let v: Value = serde_json::from_slice(&a).unwrap();
        assert_eq!(v["temperature"], 0.0);
        assert_eq!(v["top_k"], 1);
        assert_eq!(v["stream"], false);
    }

    #[test]
    fn content_extraction_requires_expected_shape() {
        assert_eq!(
            extract_content(br#"{"choices":[{"message":{"content":"ok"}}]}"#).unwrap(),
            "ok"
        );
        assert!(extract_content(br#"{"choices":[]}"#).is_err());
        assert!(extract_content(b"not json").is_err());
    }

    #[test]
    fn end_to_end_against_a_local_fake_server() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf).unwrap();
            let body = br#"{"choices":[{"message":{"content":"answer [S1]"}}]}"#;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            s.write_all(resp.as_bytes()).unwrap();
            s.write_all(body).unwrap();
        });
        let c = LlamaHttp::new(
            LoopbackEndpoint::parse(&addr.to_string()).unwrap(),
            Duration::from_secs(5),
        );
        let out = c
            .chat(
                &[ChatMessage {
                    role: "user",
                    content: "q".into(),
                }],
                &GenerationParams::default(),
            )
            .unwrap();
        assert_eq!(out, "answer [S1]");
        h.join().unwrap();
    }

    #[test]
    fn unreachable_endpoint_fails_closed() {
        // Bind then drop to obtain a port with nothing listening.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let c = LlamaHttp::new(
            LoopbackEndpoint::parse(&format!("127.0.0.1:{port}")).unwrap(),
            Duration::from_millis(500),
        );
        let e = c.chat(&[], &GenerationParams::default()).unwrap_err();
        assert_eq!(e.kind, PortErrorKind::Inference);
        assert!(!c.healthy());
    }
}
