#!/usr/bin/env python3
"""A stand-in for the institution's API, for the live gateway run.

It is deliberately dumb: it echoes what it was given. The point of the run is
not what the upstream computes — it is that the gateway's receipt commits to
exactly the request the upstream received, which is checkable only if the
upstream reports that request back verbatim.

Standard library only, no dependencies, one thread.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


class Echo(BaseHTTPRequestHandler):
    def _respond(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = {"_unparsed": raw.decode("utf-8", "replace")}
        payload = {
            "received": {
                "method": self.command,
                "path": parsed.path,
                "query": parsed.query,
                "body": body,
            },
            "status": "ok",
        }
        out = json.dumps(payload, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    HTTPServer(("127.0.0.1", port), Echo).serve_forever()
