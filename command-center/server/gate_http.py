"""HTTP adapter for the gate, plus the upstream forwarder (native, not P0-059).

POST /call with a signed envelope → Gate.handle. HTTP status: 200 ALLOW, 202 PENDING_APPROVAL,
403 DENY, 400 unparseable body. No logic here beyond transport; loopback only.
"""

from __future__ import annotations

import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gate import Gate

MAX_BODY = 1 << 20
UPSTREAM_TIMEOUT_S = 5.0
STATUS = {"ALLOW": 200, "PENDING_APPROVAL": 202, "DENY": 403}


def http_forwarder(base_url: str):
    """Forward(server, tool, args) → upstream JSON, via POST {base_url}/tools/<server>/<tool>."""
    def forward(server: str, tool: str, args: dict) -> object:
        r = urllib.request.Request(f"{base_url}/tools/{server}/{tool}", data=json.dumps(args).encode(),
                                   headers={"content-type": "application/json"})
        with urllib.request.urlopen(r, timeout=UPSTREAM_TIMEOUT_S) as resp:
            return json.load(resp)
    return forward


def serve(gate: Gate, port: int) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        def _send(self, code: int, obj: dict) -> None:
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("content-length") or 0)
            if self.path != "/call" or n <= 0 or n > MAX_BODY:
                return self._send(400, {"error": "POST /call with a JSON body"})
            try:
                env = json.loads(self.rfile.read(n))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._send(400, {"error": "body is not JSON"})
            r = gate.handle(env)
            self._send(STATUS[r.outcome], r.to_json())

        def log_message(self, *a):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), H)
