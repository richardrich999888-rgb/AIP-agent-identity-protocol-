"""Lab tool server behind the gate. Every reply is TEST DATA. Counts the calls it receives.

POST /tools/<server>/<tool> → {"label": "TEST DATA", "server", "tool", "args"}; GET /hits → {"hits": [...]}.
The hit list is the evidence that a refused call never reached the tool.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def serve(port: int) -> tuple[ThreadingHTTPServer, list]:
    hits: list = []
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):  # noqa: N802
            parts = self.path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "tools":
                return self._send(404, {"error": "not found"})
            args = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
            with lock:
                hits.append((parts[1], parts[2]))
            self._send(200, {"label": "TEST DATA", "server": parts[1], "tool": parts[2], "args": args})

        def do_GET(self):  # noqa: N802
            with lock:
                self._send(200, {"hits": list(hits)})

        def log_message(self, *a):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), H), hits
