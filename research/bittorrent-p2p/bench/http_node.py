"""Central-distribution baselines.

server: python3 http_node.py serve DIR PORT [--no-range]
  Threaded HTTP/1.1 server using os.sendfile (zero-copy). With --no-range it
  ignores Range headers (baseline 1: plain central server); otherwise it
  serves byte ranges (baseline 2: resumable central server).

client: python3 http_node.py get URL OUT_PATH REPORT_JSON
  Resumes from an existing partial file with a Range request when the server
  supports it; verifies nothing itself (verification is done by the bench
  against the published SHA-256, identically for every method).
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import sys
import time
import urllib.request

CHUNK = 1 << 20


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    root = "."
    ranges = True

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        path = os.path.join(self.root, os.path.basename(self.path))
        try:
            size = os.path.getsize(path)
        except OSError:
            self.send_error(404)
            return
        start = 0
        rng = self.headers.get("Range")
        if self.ranges and rng and rng.startswith("bytes="):
            start = int(rng[6:].split("-")[0])
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{size - 1}/{size}")
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(size - start))
        self.send_header("Accept-Ranges", "bytes" if self.ranges else "none")
        self.end_headers()
        with open(path, "rb") as f:
            off = start
            while off < size:
                n = os.sendfile(self.connection.fileno(), f.fileno(), off, min(CHUNK * 8, size - off))
                if n == 0:
                    break
                off += n


def serve(root: str, port: int, ranges: bool) -> None:
    Handler.root = root
    Handler.ranges = ranges
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    srv.serve_forever()


def get(url: str, out: str, report: str) -> None:
    t0 = time.monotonic()
    have = os.path.getsize(out) if os.path.exists(out) else 0
    req = urllib.request.Request(url, headers={"Range": f"bytes={have}-"} if have else {})
    got = 0
    with urllib.request.urlopen(req, timeout=600) as r:
        mode = "ab" if (have and r.status == 206) else "wb"
        if mode == "wb":
            have = 0
        with open(out, mode) as f:
            while True:
                b = r.read(CHUNK)
                if not b:
                    break
                f.write(b)
                got += len(b)
    json.dump({"seconds": time.monotonic() - t0, "bytes_received": got, "resumed_from": have,
               "host": socket.gethostname()}, open(report, "w"))


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2], int(sys.argv[3]), "--no-range" not in sys.argv)
    else:
        get(sys.argv[2], sys.argv[3], sys.argv[4])
