#!/usr/bin/env python3
"""The "cloud-API app" side of the Pull-the-plug demo (W1.1). Stdlib only.

It is the contrast, not the product: an ordinary assistant that sends each
question to a remote chat-completions endpoint. With the cable in and an
endpoint configured, it answers; with the cable out, it fails — and it must
fail *cleanly*, with a plain reason, never with a made-up answer.

Nothing is embedded. There is no default endpoint and no key in this file or
anywhere in the repository. At demo time the operator supplies:

  CLOUD_API_URL    full URL of an OpenAI-compatible POST /v1/chat/completions
  CLOUD_API_KEY    optional bearer key (read from the environment only; it is
                   never printed, logged or written to a result file)
  CLOUD_MODEL      model name the endpoint expects (default: "default")
  CLOUD_TIMEOUT_S  per-request timeout, seconds (default: 10)

With no CLOUD_API_URL the app reports "not configured — requires internet and
a cloud endpoint" and makes no network call at all.

CLI:  cloud_app.py ask "question"     → one JSON result on stdout, exit 0 if
                                        answered, 1 otherwise
"""
from __future__ import annotations

import errno
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ANSWERED, FAILED, NOT_CONFIGURED = "answered", "failed", "not_configured"


def _classify(exc: BaseException) -> str:
    """A short, honest reason for the audience: what actually went wrong."""
    reason = getattr(exc, "reason", exc)
    if isinstance(exc, urllib.error.HTTPError):
        return f"http_{exc.code}"
    if isinstance(reason, socket.timeout) or isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(reason, socket.gaierror):
        return "dns_unavailable"
    if isinstance(reason, OSError):
        if reason.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return "no_route"
        if reason.errno == errno.ECONNREFUSED:
            return "connection_refused"
        return f"network_error_{reason.errno}" if reason.errno else "network_error"
    return type(exc).__name__


def ask(question: str, env: dict | None = None) -> dict:
    """Send one question. Always returns a result dict; never raises and never
    returns an answer the endpoint did not send."""
    env = os.environ if env is None else env
    url = env.get("CLOUD_API_URL", "").strip()
    result = {"side": "cloud-api", "question": question, "endpoint_configured": bool(url)}
    if not url:
        return {**result, "status": NOT_CONFIGURED,
                "message": "not configured — this app requires internet and a cloud endpoint"}
    body = json.dumps({"model": env.get("CLOUD_MODEL", "default"),
                       "messages": [{"role": "user", "content": question}]}).encode()
    headers = {"Content-Type": "application/json"}
    key = env.get("CLOUD_API_KEY", "")
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    # Say whether the request went via a proxy: offline, a local proxy refuses
    # the connection, and "refused" must not be mistaken for "the cloud said no".
    proxy = urllib.request.getproxies().get(urllib.parse.urlsplit(url).scheme)
    if proxy and urllib.request.proxy_bypass(urllib.parse.urlsplit(url).hostname or ""):
        proxy = None
    if proxy:
        result["via_proxy"] = urllib.parse.urlsplit(proxy).netloc
    timeout = float(env.get("CLOUD_TIMEOUT_S", "10"))
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(1 << 20)
        ms = round((time.monotonic() - t0) * 1000, 1)
        try:
            answer = json.loads(raw)["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            return {**result, "status": FAILED, "reason": "malformed_response", "ms": ms,
                    "request_bytes": len(body), "response_bytes": len(raw)}
        return {**result, "status": ANSWERED, "answer": answer, "ms": ms,
                "request_bytes": len(body), "response_bytes": len(raw)}
    except Exception as exc:  # noqa: BLE001 — every failure is reported, none is raised
        return {**result, "status": FAILED, "reason": _classify(exc),
                "ms": round((time.monotonic() - t0) * 1000, 1), "request_bytes": len(body)}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "ask":
        print(__doc__, file=sys.stderr)
        return 2
    r = ask(argv[1])
    print(json.dumps(r))
    return 0 if r["status"] == ANSWERED else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
