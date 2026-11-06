#!/usr/bin/env python3
"""Tests for the Pull-the-plug live meter (W1.2).

Run: python3 -m unittest discover -s demos/pull-the-plug -p 'test_*.py'
The local side is exercised with a stand-in runtime that prints a Response in
the runtime's own JSON shape and burns real CPU; a drift guard ties the field
names to sovereign/syntriass-runtime/src/app.rs.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
import meter  # noqa: E402
from test_harness import NETNS_SKIP  # noqa: E402

FAKE_RUNTIME = r'''
import json, sys, time, socket
req = json.loads(sys.stdin.readline())
t = time.process_time()
while time.process_time() - t < 0.3:      # real CPU, so the meter has something to measure
    pass
if req.get("try_network"):
    s = socket.socket(); s.settimeout(1)
    try: s.connect(("198.51.100.7", 443))
    except OSError: pass
# The real `serve --eval` envelope: {"id": ..., "response": Response}.
print(json.dumps({"id": req.get("id"), "response": {
  "strategy": {"kind": "retrieve_and_cite"},
  "outcome": {"kind": "answer", "text": "Refunds within 30 days [doc-7]", "sources": ["doc-7"]},
  "cost": {"wall_ms": 301.5, "cpu_s": {"runtime": 0.3}, "rss_mib": {"runtime": 20.0},
           "model_calls": 1, "prompt_tokens": 120, "completion_tokens": 18, "cached_tokens": 0,
           "model_load_ms": 0.0, "interpreter_calls": 0, "escalations": 0},
  "capability_hash": None, "audit_hash": "ab"}}))
'''


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.fake = Path(cls.tmp.name) / "fake_runtime.py"
        cls.fake.write_text(FAKE_RUNTIME)
        cls.cmd = [sys.executable, "-I", str(cls.fake)]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()


class Local(Fixture):
    def test_reads_the_runtime_report_and_measures_independently(self):
        r = meter.measure_local(self.cmd, json.dumps({"q": "refund policy?"}), env={})
        self.assertEqual(r["status"], "answered")
        self.assertEqual(r["answer"], "Refunds within 30 days [doc-7]")
        rt = r["runtime"]
        self.assertEqual(rt["source"], "runtime-reported")
        self.assertEqual((rt["model_calls"], rt["sources"], rt["strategy"]),
                         (1, ["doc-7"], {"kind": "retrieve_and_cite"}))
        o = r["outer"]
        self.assertEqual(o["source"], "measured by meter")
        self.assertGreaterEqual(o["cpu_s_child"], 0.25)   # the 0.3 s busy loop, measured from outside
        self.assertGreaterEqual(o["wall_ms"], 250)
        self.assertIn("namespace", o["bytes_out_scope"])

    def test_missing_fields_stay_null_never_invented(self):
        f = Path(self.tmp.name) / "sparse.py"
        f.write_text('import json,sys; sys.stdin.readline(); print(json.dumps({"outcome":{"kind":"answer","text":"x"}}))')
        r = meter.measure_local([sys.executable, "-I", str(f)], "{}", env={})
        for k in ("strategy", "model_calls", "prompt_tokens", "cpu_s_total", "sources"):
            self.assertIsNone(r["runtime"][k], k)

    def test_a_runtime_error_envelope_is_a_failure_carrying_the_runtimes_message(self):
        f = Path(self.tmp.name) / "err.py"
        f.write_text('import json,sys; sys.stdin.readline(); print(json.dumps({"error": "principal: unknown tenant"}))')
        r = meter.measure_local([sys.executable, "-I", str(f)], "{}", env={})
        self.assertEqual((r["status"], r["reason"]), ("failed", "runtime_error"))
        self.assertEqual(r["runtime_error"], "principal: unknown tenant")
        self.assertNotIn("answer", r)

    def test_the_bare_response_of_ask_is_also_read(self):
        f = Path(self.tmp.name) / "bare.py"
        f.write_text('import json,sys; sys.stdin.readline(); print(json.dumps({"strategy":"s","outcome":'
                     '{"kind":"answer","text":"t","sources":["d"]},"cost":{"model_calls":0}}))')
        r = meter.measure_local([sys.executable, "-I", str(f)], "{}", env={})
        self.assertEqual((r["status"], r["runtime"]["model_calls"], r["runtime"]["strategy"]), ("answered", 0, "s"))

    def test_no_response_is_a_failure_with_no_runtime_figures(self):
        f = Path(self.tmp.name) / "silent.py"
        f.write_text("import sys; sys.stdin.readline(); print('not json')")
        r = meter.measure_local([sys.executable, "-I", str(f)], "{}", env={})
        self.assertEqual((r["status"], r["reason"]), ("failed", "no_runtime_response"))
        self.assertNotIn("runtime", r)
        self.assertNotIn("answer", r)

    @unittest.skipIf(NETNS_SKIP is not None, f"SKIPPED, not passed: {NETNS_SKIP}")
    def test_offline_bytes_out_is_zero_even_when_the_runtime_tries_the_network(self):
        code = ("import sys,json; sys.path.insert(0,%r); import meter; "
                "print(json.dumps(meter.measure_local(%r, json.dumps({'try_network': True}), env={})))"
                % (str(HERE), self.cmd))
        p = subprocess.run([sys.executable, "-I", str(HERE.parent / "common" / "harness.py"), "run-offline",
                            "--", sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual(r["status"], "answered")
        self.assertEqual(r["outer"]["bytes_out_non_loopback"], 0)


class Rupees(unittest.TestCase):
    def test_no_rate_no_figure(self):
        r = meter.inr_local(0.5, {})
        self.assertIsNone(r["inr"])
        self.assertIn("rate not set", r["note"])
        self.assertIsNone(meter.inr_cloud(500, {})["inr"])

    def test_figures_come_from_the_configured_rate_with_the_formula_shown(self):
        r = meter.inr_local(36.0, {"METER_INR_PER_CPU_HOUR": "10"})
        self.assertAlmostEqual(r["inr"], 0.1)
        self.assertEqual((r["rate"], r["cpu_s"]), (10.0, 36.0))
        self.assertIn("METER_INR_PER_CPU_HOUR", r["formula"])
        c = meter.inr_cloud(2000, {"METER_INR_PER_1K_TOKENS": "0.5"})
        self.assertAlmostEqual(c["inr"], 1.0)

    def test_unreported_tokens_give_no_figure_even_with_a_rate(self):
        r = meter.inr_cloud(None, {"METER_INR_PER_1K_TOKENS": "0.5"})
        self.assertIsNone(r["inr"])
        self.assertIn("no token usage", r["note"])

    def test_negative_rate_refused(self):
        with self.assertRaises(ValueError):
            meter.inr_local(1.0, {"METER_INR_PER_CPU_HOUR": "-1"})


class SchemaDrift(unittest.TestCase):
    def test_every_runtime_field_the_meter_reads_exists_in_the_runtime(self):
        src = (REPO / "sovereign/syntriass-runtime/src/app.rs").read_text()
        for field in ("wall_ms", "cpu_s", "model_calls", "prompt_tokens", "completion_tokens", "escalations",
                      "strategy", "outcome", "cost"):
            self.assertRegex(src, rf"pub {field}:", field)
        self.assertIn("Answer { text: String, sources: Vec<String> }", src)
        # The serve --eval envelope the meter unwraps (regression: W1.2 first read it as the Response).
        bin_src = (REPO / "sovereign/syntriass-runtime/src/bin/syntriass.rs").read_text()
        self.assertIn('json!({"id": v["id"], "response": r})', bin_src)
        self.assertIn('json!({"error": e})', bin_src)
        self.assertRegex(src, r'#\[serde\(tag = "kind", rename_all = "snake_case"\)\]\s*pub enum Outcome')


class CloudTokens(unittest.TestCase):
    def test_cloud_side_rupees_only_from_reported_usage(self):
        import http.server, os, threading  # noqa: E401

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                out = json.dumps({"choices": [{"message": {"content": "ok"}}],
                                  "usage": {"total_tokens": 2000}}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1"
        try:
            r = meter.measure_cloud("q", {"CLOUD_API_URL": f"http://127.0.0.1:{srv.server_port}/v1/chat/completions",
                                          "METER_INR_PER_1K_TOKENS": "0.5"})
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual((r["status"], r["tokens"]), ("answered", 2000))
        self.assertAlmostEqual(r["inr"]["inr"], 1.0)
        self.assertEqual(r["outer"]["source"], "measured by meter")


if __name__ == "__main__":
    unittest.main()
