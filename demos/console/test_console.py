"""The console stays local and serves only what it should. Runs without models."""
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server  # noqa: E402


class Console(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.srv.server_port
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def get(self, path, host=None, data=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data,
                                     headers={"Host": host or f"127.0.0.1:{self.port}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def test_page_has_csp_and_no_external_references(self):
        code, body, h = self.get("/")
        self.assertEqual(code, 200)
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertNotRegex(body.decode(), r'(src|href)="https?://')
        self.assertNotRegex(body.decode(), r"\.innerHTML\s*=|insertAdjacentHTML|document\.write")

    def test_foreign_host_is_refused(self):
        self.assertEqual(self.get("/api/status", host="evil.example")[0], 403)
        self.assertEqual(self.get("/api/run", host="evil.example", data=b"{}")[0], 403)

    def test_only_listed_assets_are_served(self):
        self.assertEqual(self.get("/assets/syntriass-mark.png")[0], 200)
        for p in ("/assets/../server.py", "/assets/server.py", "/demos/console/server.py", "/api/report/zzzz"):
            self.assertEqual(self.get(p)[0], 404, p)

    def test_unknown_mode_and_bad_question_are_rejected(self):
        _, b, _ = self.get("/api/run", data=json.dumps({"mode": "rm -rf"}).encode())
        self.assertIn("unknown mode", json.loads(b)["error"])
        _, b, _ = self.get("/api/ask", data=json.dumps({"question": "", "model": "qwen2.5-1.5b-q4"}).encode())
        self.assertIn("error", json.loads(b))
        _, b, _ = self.get("/api/ask", data=json.dumps({"question": "x", "model": "gpt-4"}).encode())
        self.assertEqual(json.loads(b)["error"], "unknown model")

    def test_oversized_body_is_refused(self):
        self.assertEqual(self.get("/api/ask", data=b"{" + b" " * 20000 + b"}")[0], 413)


if __name__ == "__main__":
    unittest.main()
