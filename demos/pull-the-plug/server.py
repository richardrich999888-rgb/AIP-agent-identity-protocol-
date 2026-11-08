#!/usr/bin/env python3
"""Side-by-side page for the Pull-the-plug demo (W1.3). Stdlib only.

Serves one self-contained page on 127.0.0.1 — no CDN, no remote font, script
or style — showing the cloud-API app and AIRON Native answering the same
question, the live meter for each, and a network indicator driven by the
harness's route check. Every answer is written to a result file and the page
shows that file's path.

Config (environment):
  DEMO_LOCAL_CMD     JSON list: the runtime command reading one request line
                     on stdin, e.g.
                     ["target/release/syntriass","serve","--eval","--config","CFG"]
  DEMO_PRINCIPAL     JSON principal for the local request,
                     e.g. {"tenant":"koravi-process","clearance":"restricted"}
  DEMO_RESULTS_DIR   where result files go (default demos/pull-the-plug/results)
  CLOUD_*, METER_*   as for cloud_app.py and meter.py

Usage: server.py [PORT]   (default 8765; 0 picks a free port)
"""
from __future__ import annotations

import http.server
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
import harness  # noqa: E402
import meter  # noqa: E402

MAX_BODY = 16 * 1024
PAGE = (HERE / "page.html").read_bytes()


def config(env: dict) -> dict:
    cmd = json.loads(env["DEMO_LOCAL_CMD"]) if env.get("DEMO_LOCAL_CMD") else None
    principal = json.loads(env["DEMO_PRINCIPAL"]) if env.get("DEMO_PRINCIPAL") else None
    return {"local_cmd": cmd, "principal": principal,
            "results": Path(env.get("DEMO_RESULTS_DIR", HERE / "results"))}


def ask_both(question: str, cfg: dict, env: dict) -> dict:
    started = harness.now_utc()

    def local():
        if not cfg["local_cmd"] or cfg["principal"] is None:
            return {"side": "airon-native", "status": "not_configured",
                    "message": "set DEMO_LOCAL_CMD and DEMO_PRINCIPAL"}
        line = json.dumps({"id": "q", "principal": cfg["principal"], "text": question})
        return meter.measure_local(cfg["local_cmd"], line, env=env)

    with ThreadPoolExecutor(2) as pool:
        lf, cf = pool.submit(local), pool.submit(meter.measure_cloud, question, env)
        local_r, cloud_r = lf.result(), cf.result()
    steps = [harness.label("live", "cloud-API side answered" if cloud_r["status"] == "answered"
                           else f"cloud-API side: {cloud_r['status']}"),
             harness.label("live", "AIRON Native side answered" if local_r["status"] == "answered"
                           else f"AIRON Native side: {local_r['status']}")]
    path = harness.write_result(cfg["results"], "pull-the-plug", steps,
                                {"question": question, "cloud": cloud_r, "local": local_r}, started)
    return {"cloud": cloud_r, "local": local_r, "result_file": str(path)}


def status(cfg: dict, env: dict) -> dict:
    s = harness.offline_status()
    return {**s, "hardware": harness.hardware_report()["label"],
            "local_configured": bool(cfg["local_cmd"]) and cfg["principal"] is not None,
            "cloud_configured": bool(env.get("CLOUD_API_URL", "").strip())}


def make_handler(cfg: dict, env: dict, port_ref: list):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "pull-the-plug"

        def _host_ok(self) -> bool:
            # DNS-rebinding guard: only this loopback origin may talk to the page.
            host = (self.headers.get("Host") or "").lower()
            return host in {f"127.0.0.1:{port_ref[0]}", f"localhost:{port_ref[0]}"}

        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                             "style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; "
                             "frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj):
            self._send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self):
            if not self._host_ok():
                return self._json(403, {"error": "host not allowed"})
            if self.path == "/":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            if self.path == "/api/status":
                return self._json(200, status(cfg, env))
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok():
                return self._json(403, {"error": "host not allowed"})
            if self.path != "/api/ask":
                return self._json(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                return self._json(413 if n > MAX_BODY else 400, {"error": "body required, at most 16 KiB"})
            try:
                q = json.loads(self.rfile.read(n))["question"]
                if not isinstance(q, str) or not q.strip():
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                return self._json(400, {"error": "expected {\"question\": \"...\"}"})
            self._json(200, ask_both(q.strip(), cfg, env))

        def log_message(self, *a):
            pass

    return H


def serve(port: int, env: dict | None = None) -> http.server.ThreadingHTTPServer:
    env = dict(os.environ if env is None else env)
    cfg = config(env)
    port_ref = [port]
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), make_handler(cfg, env, port_ref))
    port_ref[0] = srv.server_port
    return srv


if __name__ == "__main__":
    srv = serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8765)
    print(f"Pull the plug: http://127.0.0.1:{srv.server_port}/", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
