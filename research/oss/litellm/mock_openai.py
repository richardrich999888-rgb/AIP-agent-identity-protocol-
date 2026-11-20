"""Deterministic OpenAI-compatible mock model. Every reply is TEST DATA.

Serves `POST /v1/chat/completions` on loopback. The reply text and the
`usage` counts are pure functions of the request, so a test can predict them:

- prompt_tokens = number of whitespace-separated words across all message
  `content` strings;
- the reply is the fixed prefix plus the first 12 hex digits of SHA-256 over
  the canonical JSON of `messages`;
- completion_tokens = number of whitespace-separated words in the reply.

These are not real tokenizer counts. They are labelled TEST DATA so they are
never mistaken for one.

Model names select behaviour, for failure-mode tests:

- `mock-no-usage`: omit `usage` entirely (the provider reported nothing);
- `mock-error`: return HTTP 500.

    python3 mock_openai.py PORT
"""

from __future__ import annotations

import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPLY_PREFIX = "TEST DATA: mock reply"
DIGEST_HEX_CHARS = 12
MAX_BODY_BYTES = 1 << 20  # refuse larger requests rather than buffer them
MODEL_NO_USAGE = "mock-no-usage"
MODEL_ERROR = "mock-error"
FIXED_CREATED = 0  # deterministic timestamp; a real server would use now


class BadRequest(ValueError):
    """The request body is not a chat completion request."""


def words(text: str) -> int:
    """Whitespace-separated word count (the mock's stand-in for tokens)."""
    return len(text.split())


def parse(body: bytes) -> tuple[str, list[dict]]:
    """Validate a request body; return (model, messages) or raise BadRequest."""
    try:
        req = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BadRequest(f"body is not JSON: {e}") from None
    if not isinstance(req, dict):
        raise BadRequest("body must be a JSON object")
    model, messages = req.get("model"), req.get("messages")
    if not isinstance(model, str) or not model:
        raise BadRequest("model must be a non-empty string")
    if not isinstance(messages, list) or not messages:
        raise BadRequest("messages must be a non-empty list")
    for m in messages:
        if not isinstance(m, dict) or not isinstance(m.get("role"), str) or not isinstance(m.get("content"), str):
            raise BadRequest("each message needs string role and content")
    return model, messages


def complete(model: str, messages: list[dict]) -> dict:
    """The deterministic completion for a validated request."""
    canon = json.dumps(messages, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canon).hexdigest()[:DIGEST_HEX_CHARS]
    text = f"{REPLY_PREFIX} {digest}"
    out = {
        "id": f"mock-{digest}",
        "object": "chat.completion",
        "created": FIXED_CREATED,
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
    }
    if model != MODEL_NO_USAGE:
        p = sum(words(m["content"]) for m in messages)
        c = words(text)
        out["usage"] = {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}
    return out


class Handler(BaseHTTPRequestHandler):
    """HTTP adapter: all logic is in parse() and complete()."""

    def _send(self, code: int, obj: dict) -> None:
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        if self.path.rstrip("/") not in ("/v1/chat/completions", "/chat/completions"):
            self._send(404, {"error": {"message": "not found"}})
            return
        n = int(self.headers.get("content-length") or 0)
        if n <= 0 or n > MAX_BODY_BYTES:
            self._send(400, {"error": {"message": "missing or oversized body"}})
            return
        try:
            model, messages = parse(self.rfile.read(n))
        except BadRequest as e:
            self._send(400, {"error": {"message": str(e)}})
            return
        if model == MODEL_ERROR:
            self._send(500, {"error": {"message": "TEST DATA: injected failure"}})
            return
        self._send(200, complete(model, messages))

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("mock: " + fmt % args + "\n")


def serve(port: int) -> ThreadingHTTPServer:
    """Bind on loopback only."""
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    serve(int(sys.argv[1])).serve_forever()
