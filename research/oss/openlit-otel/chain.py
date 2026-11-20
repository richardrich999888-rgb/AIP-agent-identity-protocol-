"""Item 1.4: OpenLIT SDK → OTLP → pinned OTel Collector → JSON sink, offline.

    unshare -n sh -c 'python3 command-center/server/netns_lo_up.py && \
        OPENLIT_VENV/bin/python research/oss/openlit-otel/chain.py OTELCORECOL OUT.json'

1. A stdlib HTTP sink on loopback records the OTLP/JSON bodies it receives.
2. The pinned `otelcorecol` runs an OTLP/HTTP receiver and an `otlphttp`
   exporter (`encoding: json`) pointed at the sink.
3. The deterministic mock model from research/oss/litellm serves the calls.
   Its usage is TEST DATA: prompt 3, completion 5.
4. `openlit.init` instruments the `openai` client, which makes one chat call.
5. Checks:
   - the spans reached the sink through the collector;
   - one span carries the GenAI semantic-convention token counts equal to
     the mock's (3 and 5).

   It also records, without asserting, whatever cost attribute OpenLIT
   reports while offline.

Exit 0 only if every check passes. All output is TEST DATA.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "litellm"))
import mock_openai  # noqa: E402

WAIT_S = 20.0
MSGS = [{"role": "user", "content": "hello there agent"}]
EXPECT_IN, EXPECT_OUT = 3, 5  # mock_openai word counts for MSGS and its reply


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


received: list[tuple[str, dict]] = []


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        try:
            received.append((self.path, json.loads(body)))
        except json.JSONDecodeError:
            received.append((self.path, {"_non_json_bytes": len(body)}))
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def attrs(span: dict) -> dict:
    out = {}
    for a in span.get("attributes", []):
        v = a.get("value", {})
        out[a["key"]] = next(iter(v.values())) if v else None
    return out


def spans(bodies) -> list[dict]:
    out = []
    for path, b in bodies:
        if not path.endswith("/v1/traces"):
            continue
        for rs in b.get("resourceSpans", []):
            for ss in rs.get("scopeSpans", []):
                out += ss.get("spans", [])
    return out


def main(otelcol: str, out_path: str) -> int:
    sink_port, recv_port = free_port(), free_port()
    sink = ThreadingHTTPServer(("127.0.0.1", sink_port), Sink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    mock = mock_openai.serve(0)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    cfg = Path(tempfile.mkdtemp()) / "otelcol.yaml"
    cfg.write_text(f"""receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:{recv_port}
exporters:
  otlphttp:
    endpoint: http://127.0.0.1:{sink_port}
    encoding: json
    compression: none
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp]
""")
    col = subprocess.Popen([otelcol, "--config", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    result: dict = {"label": "TEST DATA", "checks": {}}
    try:
        deadline = time.monotonic() + WAIT_S
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", recv_port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        import openai
        import openlit
        from opentelemetry import trace

        t0 = time.monotonic()
        openlit.init(otlp_endpoint=f"http://127.0.0.1:{recv_port}", application_name="vanian-lab",
                     environment="TEST", disable_metrics=True)
        result["openlit_init_s"] = round(time.monotonic() - t0, 3)
        client = openai.OpenAI(base_url=f"http://127.0.0.1:{mock.server_address[1]}/v1", api_key="sk-test-not-a-secret")
        r = client.chat.completions.create(model="mock-1", messages=MSGS)
        result["response_usage"] = r.usage.model_dump() if r.usage else None
        trace.get_tracer_provider().force_flush()
        deadline = time.monotonic() + WAIT_S
        while time.monotonic() < deadline and not spans(received):
            time.sleep(0.2)
        sp = spans(received)
        gen = [attrs(s) for s in sp if any(k.startswith("gen_ai.") for k in attrs(s))]
        result["spans_received"] = len(sp)
        result["genai_span_attrs"] = gen[:1]
        a = gen[0] if gen else {}
        result["checks"] = {
            "spans reached the sink through the collector": len(sp) > 0,
            "gen_ai.usage.input_tokens == mock prompt tokens": str(a.get("gen_ai.usage.input_tokens")) == str(EXPECT_IN),
            "gen_ai.usage.output_tokens == mock completion tokens": str(a.get("gen_ai.usage.output_tokens")) == str(EXPECT_OUT),
        }
        result["cost_attributes_reported"] = {k: v for k, v in a.items() if "cost" in k}
    finally:
        col.terminate()
        try:
            out, _ = col.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            col.kill()
            out, _ = col.communicate()
        result["collector_log_tail"] = out.decode(errors="replace").splitlines()[-8:]
        sink.shutdown()
        mock.shutdown()
    Path(out_path).write_text(json.dumps(result, indent=1, default=str) + "\n")
    for k, v in result["checks"].items():
        print(f"{'ok  ' if v else 'FAIL'} {k}")
    failed = [k for k, v in result["checks"].items() if not v]
    print(f"checks: {len(result['checks']) - len(failed)} passed, {len(failed)} failed")
    return 0 if result["checks"] and not failed else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
