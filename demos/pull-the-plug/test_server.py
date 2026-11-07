#!/usr/bin/env python3
"""Tests for the side-by-side page (W1.3).

Run: python3 -m unittest discover -s demos/pull-the-plug -p 'test_*.py'
The local side uses the stand-in runtime from test_meter (real serve --eval
envelope); the cloud side is unconfigured or pointed at an unreachable address.
"""
import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
import server  # noqa: E402
from test_harness import NETNS_SKIP  # noqa: E402
from test_meter import FAKE_RUNTIME  # noqa: E402

PRINCIPAL = {"tenant": "koravi-process", "clearance": "restricted"}


class Page(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        fake = Path(cls.tmp.name) / "fake_runtime.py"
        fake.write_text(FAKE_RUNTIME)
        cls.results = Path(cls.tmp.name) / "results"
        env = {"DEMO_LOCAL_CMD": json.dumps([sys.executable, "-I", str(fake)]),
               "DEMO_PRINCIPAL": json.dumps(PRINCIPAL), "DEMO_RESULTS_DIR": str(cls.results)}
        cls.srv = server.serve(0, env)
        cls.port = cls.srv.server_port
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def test_page_loads_nothing_from_outside(self):
        r, html = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        text = html.decode()
        self.assertNotRegex(text, r"""(src|href)\s*=\s*["']?\s*(https?:)?//""")
        self.assertNotRegex(text, r"@import|url\(\s*['\"]?https?:")
        # No HTML sink: answers are inserted as text only.
        self.assertNotRegex(text, r"\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write")
        self.assertIn("default-src 'self'", r.getheader("Content-Security-Policy"))

    def test_status_reports_the_route_check(self):
        r, data = self.req("GET", "/api/status")
        s = json.loads(data)
        self.assertIn("offline", s)
        self.assertTrue(s["local_configured"])
        self.assertFalse(s["cloud_configured"])
        self.assertIn("vCPU", s["hardware"])

    def test_ask_runs_both_sides_and_writes_the_result_file_shown(self):
        r, data = self.req("POST", "/api/ask", json.dumps({"question": "refund policy?"}))
        self.assertEqual(r.status, 200, data)
        out = json.loads(data)
        self.assertEqual(out["local"]["status"], "answered")
        self.assertEqual(out["local"]["runtime"]["sources"], ["doc-7"])
        self.assertEqual(out["cloud"]["status"], "not_configured")
        f = Path(out["result_file"])
        self.assertTrue(f.is_relative_to(self.results))
        rec = json.loads(f.read_text())
        self.assertEqual(rec["measurements"]["local"]["answer"], out["local"]["answer"])
        self.assertTrue(all(s["kind"] == "live" for s in rec["steps"]))

    def test_foreign_host_header_is_refused(self):
        for path, method in (("/", "GET"), ("/api/status", "GET")):
            r, _ = self.req(method, path, host="evil.example:80")
            self.assertEqual(r.status, 403, path)
        r, _ = self.req("POST", "/api/ask", json.dumps({"question": "q"}), host="evil.example")
        self.assertEqual(r.status, 403)

    def test_bad_requests(self):
        self.assertEqual(self.req("POST", "/api/ask", "{}")[0].status, 400)
        self.assertEqual(self.req("POST", "/api/ask", json.dumps({"question": "  "}))[0].status, 400)
        self.assertEqual(self.req("POST", "/api/ask", "x" * (17 * 1024))[0].status, 413)
        self.assertEqual(self.req("GET", "/etc/passwd")[0].status, 404)

    def test_binds_loopback_only(self):
        self.assertEqual(self.srv.server_address[0], "127.0.0.1")

    def test_page_works_in_a_real_browser_and_requests_nothing_external(self):
        if BROWSER_SKIP:
            self.skipTest(f"SKIPPED, not passed: {BROWSER_SKIP}")
        import shutil
        root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
        shot = Path(self.tmp.name) / "page.png"
        p = subprocess.run([shutil.which("node"), str(HERE / "browser_check.js"), f"http://127.0.0.1:{self.port}/",
                            str(shot)], capture_output=True, text=True, timeout=90,
                           env={**os.environ, "NODE_PATH": root})
        out = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertNotIn("fatal", out, out)
        self.assertEqual(out["errors"], [])
        self.assertEqual(out["external"], [])
        self.assertEqual((out["local"], out["cloud"]), ("answered", "not_configured"))
        self.assertIn("result file", out["foot"])
        self.assertTrue(shot.exists())



def _browser_unavailable() -> str | None:
    import shutil
    node = shutil.which("node")
    if not node:
        return "node is not installed"
    root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
    r = subprocess.run([node, "-e", "require('playwright')"], capture_output=True, text=True,
                       env={"NODE_PATH": root, "PATH": "/usr/bin:/bin:/usr/local/bin"})
    return None if r.returncode == 0 else "playwright is not available to node"


BROWSER_SKIP = _browser_unavailable()


class Offline(unittest.TestCase):
    @unittest.skipIf(NETNS_SKIP is not None, f"SKIPPED, not passed: {NETNS_SKIP}")
    def test_pulled_plug_end_to_end(self):
        """Server inside the offline namespace, page queried over loopback."""
        with tempfile.TemporaryDirectory() as t:
            fake = Path(t) / "fake_runtime.py"
            fake.write_text(FAKE_RUNTIME)
            driver = f'''
import json, sys, threading, http.client
sys.path.insert(0, {str(HERE)!r})
import server
env = {{"DEMO_LOCAL_CMD": json.dumps([sys.executable, "-I", {str(fake)!r}]),
        "DEMO_PRINCIPAL": json.dumps({PRINCIPAL!r}), "DEMO_RESULTS_DIR": {str(Path(t) / "r")!r},
        "CLOUD_API_URL": "https://198.51.100.7/v1/chat/completions", "CLOUD_TIMEOUT_S": "3"}}
srv = server.serve(0, env); p = srv.server_port
threading.Thread(target=srv.serve_forever, daemon=True).start()
def go(m, path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", p, timeout=30)
    c.request(m, path, body=body, headers={{"Host": f"127.0.0.1:{{p}}", "Content-Type": "application/json"}})
    return json.loads(c.getresponse().read())
print(json.dumps({{"status": go("GET", "/api/status"),
                  "ask": go("POST", "/api/ask", json.dumps({{"question": "refund policy?"}}))}}))
srv.shutdown(); srv.server_close()
'''
            p = subprocess.run([sys.executable, "-I", str(HERE.parent / "common" / "harness.py"), "run-offline",
                                "--", sys.executable, "-I", "-c", driver], capture_output=True, text=True, timeout=90)
            self.assertEqual(p.returncode, 0, p.stderr)
            out = json.loads(p.stdout)
            self.assertTrue(out["status"]["offline"])
            self.assertTrue(out["status"]["cloud_configured"])
            local, cloud = out["ask"]["local"], out["ask"]["cloud"]
            self.assertEqual(local["status"], "answered")
            self.assertEqual(local["outer"]["bytes_out_non_loopback"], 0)
            self.assertEqual((cloud["status"], cloud["reason"]), ("failed", "no_route"))
            self.assertNotIn("via_proxy", cloud)   # the server's env has no proxy, so none is used
            self.assertNotIn("answer", cloud)


if __name__ == "__main__":
    unittest.main()
