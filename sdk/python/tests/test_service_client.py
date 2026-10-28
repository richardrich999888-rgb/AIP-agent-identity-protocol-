"""Client transport negative tests; real service interoperability is separate."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from vanian import ApiError, Page, VanianClient


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            calls = []

            def log_message(self, *_args):
                pass

            def do_GET(self):
                type(self).calls.append((self.path, self.headers.get("Authorization")))
                if self.path == "/v1/access":
                    self.send_response(302)
                    self.send_header("Location", "/secret-target")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"items": [], "limit": 50, "offset": 0, "next_offset": None}).encode())

            def do_POST(self):
                type(self).calls.append((self.path, self.headers.get("Authorization")))
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"unavailable"}')

        cls.handler = Handler
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_https_and_origin_validation(self):
        for url in ["http://bank.internal", "https://user:password@bank.internal", "https://bank.internal?q=secret", "https://bank.internal/path", "ftp://bank.internal"]:
            with self.assertRaises(ValueError):
                VanianClient(url, lambda: "credential")
        with self.assertRaises(ValueError):
            VanianClient("http://bank.internal", lambda: "credential", allow_loopback_http=True)

    def test_redirect_refused_without_sending_token_to_target(self):
        client = VanianClient(self.base, lambda: "secret", allow_loopback_http=True)
        self.handler.calls.clear()
        with self.assertRaises(ApiError) as caught:
            client.access()
        self.assertEqual(caught.exception.status, 302)
        self.assertNotIn("secret", str(caught.exception))
        self.assertEqual(self.handler.calls, [("/v1/access", "Bearer secret")])

    def test_credentials_rotate_and_pagination_is_typed(self):
        tokens = iter(["first", "second"])
        client = VanianClient(self.base, lambda: next(tokens), allow_loopback_http=True)
        self.handler.calls.clear()
        self.assertIsNone(client.list_agents().next_offset)
        self.assertEqual(client.list_agents().items, [])
        self.assertEqual([x[1] for x in self.handler.calls], ["Bearer first", "Bearer second"])

    def test_response_limit(self):
        client = VanianClient(self.base, lambda: "secret", allow_loopback_http=True, max_response_bytes=8)
        with self.assertRaises(ApiError) as caught:
            client.list_agents()
        self.assertEqual(caught.exception.code, "response_too_large")

    def test_input_bounds(self):
        client = VanianClient("https://bank.internal", lambda: "credential")
        for args in [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"offset": 100001}, {"limit": True}]:
            with self.assertRaises(ValueError):
                client.list_agents(**args)
        for value in ["", "..", "x\nheader", "x" * 257]:
            with self.assertRaises(ValueError):
                client.get_agent(value)

    def test_registration_is_not_automatically_retried(self):
        client = VanianClient(self.base, lambda: "admin-secret", allow_loopback_http=True, retries=3)
        self.handler.calls.clear()
        with self.assertRaises(ApiError) as caught:
            client.register_deployment({"schema_version": "vanian.deployment.v1"})
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(self.handler.calls, [("/v1/deployments", "Bearer admin-secret")])
        self.assertNotIn("admin-secret", str(caught.exception))
        with self.assertRaises(ValueError):
            client.register_deployment({"large": "x" * 24576})
        with self.assertRaises(ValueError):
            client.register_deployment({"number": float("nan")})

    def test_deployment_read_methods_reuse_safe_pagination(self):
        client = VanianClient(self.base, lambda: "reader-secret", allow_loopback_http=True)
        self.assertEqual(client.list_deployments().items, [])
        with self.assertRaises(ValueError):
            client.list_deployments(limit=101)

    def test_invalid_page_is_a_structured_error(self):
        for page in [{}, {"items": [], "limit": 1, "offset": 0, "next_offset": 0}]:
            with self.assertRaises(ApiError) as caught:
                Page.parse(page)
            self.assertEqual(caught.exception.code, "invalid_page")


if __name__ == "__main__":
    unittest.main()
