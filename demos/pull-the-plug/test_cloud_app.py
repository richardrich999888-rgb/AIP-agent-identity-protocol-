#!/usr/bin/env python3
"""Tests for the cloud-API comparison app (W1.1).

Run: python3 -m unittest discover -s demos/pull-the-plug -p 'test_*.py'
Every endpoint here is a local mock on 127.0.0.1; no test contacts a real API.
"""
import http.server
import json
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
import cloud_app  # noqa: E402
from test_harness import NETNS_SKIP  # noqa: E402

KEY = "test-key-never-printed-0123456789"


class Mock(http.server.BaseHTTPRequestHandler):
    mode = "ok"
    seen: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Mock.seen.append({"auth": self.headers.get("Authorization"), "body": json.loads(body)})
        if Mock.mode == "slow":
            time.sleep(2)
        if Mock.mode == "401":
            self.send_response(401)
            self.end_headers()
            return
        out = b"not json" if Mock.mode == "malformed" else json.dumps(
            {"choices": [{"message": {"content": "answer from the mock endpoint"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class CloudApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mock)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/v1/chat/completions"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        Mock.mode, Mock.seen = "ok", []

    def env(self, **kw):
        # NO_PROXY so the mock is reached directly, not through the sandbox proxy.
        return {"CLOUD_API_URL": self.url, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1", **kw}

    def test_not_configured_makes_no_call_and_says_why(self):
        r = cloud_app.ask("q", {})
        self.assertEqual(r["status"], "not_configured")
        self.assertIn("requires internet", r["message"])
        self.assertEqual(Mock.seen, [])

    def test_answers_with_exactly_what_the_endpoint_sent(self):
        import os
        old = {k: os.environ.get(k) for k in ("NO_PROXY", "no_proxy")}
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1"
        try:
            r = cloud_app.ask("what is the policy?", self.env())
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        self.assertEqual(r["status"], "answered", r)
        self.assertEqual(r["answer"], "answer from the mock endpoint")
        self.assertEqual(Mock.seen[0]["body"]["messages"][0]["content"], "what is the policy?")
        self.assertGreater(r["request_bytes"], 0)
        self.assertGreater(r["response_bytes"], 0)

    def _ask(self, **kw):
        import os
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1"
        return cloud_app.ask("q", self.env(**kw))

    def test_key_is_sent_as_bearer_and_never_returned(self):
        r = self._ask(CLOUD_API_KEY=KEY)
        self.assertEqual(Mock.seen[0]["auth"], "Bearer " + KEY)
        self.assertNotIn(KEY, json.dumps(r))

    def test_no_key_sends_no_authorization_header(self):
        self._ask()
        self.assertIsNone(Mock.seen[0]["auth"])

    def test_http_error_is_a_clean_failure(self):
        Mock.mode = "401"
        r = self._ask()
        self.assertEqual((r["status"], r["reason"]), ("failed", "http_401"))
        self.assertNotIn("answer", r)

    def test_malformed_response_is_not_turned_into_an_answer(self):
        Mock.mode = "malformed"
        r = self._ask()
        self.assertEqual((r["status"], r["reason"]), ("failed", "malformed_response"))
        self.assertNotIn("answer", r)

    def test_timeout_is_a_clean_failure(self):
        Mock.mode = "slow"
        r = self._ask(CLOUD_TIMEOUT_S="0.5")
        self.assertEqual((r["status"], r["reason"]), ("failed", "timeout"))

    def test_refused_endpoint_is_a_clean_failure(self):
        import os
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1"
        r = cloud_app.ask("q", {"CLOUD_API_URL": "http://127.0.0.1:9/v1/chat/completions"})
        self.assertEqual((r["status"], r["reason"]), ("failed", "connection_refused"))

    def test_cli_exit_code_and_single_json_line(self):
        p = subprocess.run([sys.executable, "-I", str(HERE / "cloud_app.py"), "ask", "q"],
                           capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(p.returncode, 1)
        self.assertEqual(json.loads(p.stdout)["status"], "not_configured")

    def _offline_ask(self, env: dict) -> dict:
        code = ("import sys,json; sys.path.insert(0,%r); import cloud_app; "
                "print(json.dumps(cloud_app.ask('q', {'CLOUD_API_URL':'https://198.51.100.7/v1/chat/completions',"
                "'CLOUD_TIMEOUT_S':'3'})))" % str(HERE))
        p = subprocess.run([sys.executable, "-I", str(HERE.parent / "common" / "harness.py"), "run-offline",
                            "--", sys.executable, "-I", "-c", code], capture_output=True, text=True,
                           timeout=60, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual(r["status"], "failed")
        self.assertNotIn("answer", r)
        return r

    @unittest.skipIf(NETNS_SKIP is not None, f"SKIPPED, not passed: {NETNS_SKIP}")
    def test_with_the_plug_pulled_and_no_proxy_the_reason_is_no_route(self):
        r = self._offline_ask({"PATH": "/usr/bin:/bin"})
        self.assertEqual(r["reason"], "no_route")
        self.assertNotIn("via_proxy", r)

    @unittest.skipIf(NETNS_SKIP is not None, f"SKIPPED, not passed: {NETNS_SKIP}")
    def test_with_the_plug_pulled_behind_a_proxy_the_result_names_the_proxy(self):
        r = self._offline_ask({"PATH": "/usr/bin:/bin", "HTTPS_PROXY": "http://127.0.0.1:3128"})
        self.assertEqual(r["via_proxy"], "127.0.0.1:3128")
        self.assertEqual(r["reason"], "connection_refused")

if __name__ == "__main__":
    unittest.main()
