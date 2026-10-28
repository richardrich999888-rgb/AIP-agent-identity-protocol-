#!/usr/bin/env python3
"""Transport and MCP-boundary regressions, not a Linux observation test.

Requires the pinned MCP SDK in integrations/evidence-mcp/requirements.txt.
The real service/official-client integration runs in client_smoke.py.
"""

import importlib.util
import io
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import anyio
from jsonschema import ValidationError
from mcp import types
from vanian import ApiError, Page, VanianClient

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("vanian_mcp_boundaries", ROOT / "integrations/evidence-mcp/server.py")
MCP = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MCP
SPEC.loader.exec_module(MCP)


class TransportBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            calls = {}

            def log_message(self, *_args):
                pass

            def do_GET(self):
                count = type(self).calls.get(self.path, 0) + 1
                type(self).calls[self.path] = count
                if self.path.startswith("/v1/health") and ("retry" not in self.path or count == 1):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    # Declares 0x40 bytes then closes mid-chunk. This raises
                    # http.client.IncompleteRead, not URLError or OSError.
                    self.wfile.write(b'40\r\n{"sensitive-fixture":"partial"}\r\n')
                    self.close_connection = True
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ready"}')

        cls.handler = Handler
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.httpd.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def test_truncated_chunk_is_a_redacted_structured_transport_error(self):
        self.handler.calls.clear()
        client = VanianClient(self.base, lambda: "fixture-credential", retries=0, allow_loopback_http=True)
        with self.assertRaises(ApiError) as caught:
            client.get_health()
        self.assertEqual(caught.exception.code, "transport_failed")
        self.assertNotIn("sensitive-fixture", str(caught.exception))
        self.assertNotIn("fixture-credential", str(caught.exception))
        self.assertEqual(self.handler.calls["/v1/health"], 1)

    def test_truncated_chunk_get_retry_is_bounded_and_recovers(self):
        self.handler.calls.clear()
        client = VanianClient(self.base, lambda: "fixture-credential", retries=1, allow_loopback_http=True)
        # Exercise the actual GET transport helper, with a distinct response
        # path whose first request is malformed and second request is valid.
        result = client._get("/v1/health?retry=1")
        self.assertEqual(result, {"status": "ready"})
        self.assertEqual(self.handler.calls["/v1/health?retry=1"], 2)

    def test_invalid_pagination_never_leaks_keyerror_or_accepts_an_invalid_cursor(self):
        valid = {"items": [], "limit": 1, "offset": 0, "next_offset": None}
        for document in ({}, {"items": []}, None, {**valid, "limit": True},
                         {**valid, "limit": 0}, {**valid, "offset": -1},
                         {**valid, "items": [{}, {}]}, {**valid, "next_offset": 0},
                         {**valid, "next_offset": 100001}):
            with self.subTest(document=document), self.assertRaises(ApiError) as caught:
                Page.parse(document)
            self.assertEqual(caught.exception.code, "invalid_page")
        self.assertIsNone(Page.parse(valid).next_offset)


class FakeBackend:
    """A controlled service boundary; does not generate evidence or verdicts."""

    def __init__(self):
        self.scope = {"role": "reader", "tenant_id": "tenant-a"}
        self.payload = {"status": "unavailable", "reason": "fixture backend"}
        self.reads = 0

    def access(self):
        return dict(self.scope)

    def get_health(self):
        self.reads += 1
        return self.payload


class McpBoundaries(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.tools = MCP.EvidenceTools(self.backend)

    def call(self):
        return self.tools.call("vanian_get_observer_health", {})

    def callback(self):
        # Capture the real handler supplied to the official SDK's Server.
        # This isolates response serialization, not protocol interoperability.
        with mock.patch.object(MCP, "Server", side_effect=lambda *args, **kwargs: kwargs):
            return MCP.make_server(self.tools)["on_call_tool"]

    async def invoke(self):
        return await self.callback()(None, types.CallToolRequestParams(
            name="vanian_get_observer_health", arguments={}))

    def test_startup_requires_tenant_bound_reader_and_scope_changes_refuse_before_read(self):
        for scope in ({"role": "machine", "tenant_id": "tenant-a"}, {"role": "reader"},
                      {"role": "admin", "tenant_id": "tenant-a"}):
            self.backend.scope = scope
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                MCP.EvidenceTools(self.backend)
        for scope in ({"role": "reader", "tenant_id": "tenant-b"},
                      {"role": "admin", "tenant_id": "tenant-a"}):
            self.backend.scope = scope
            with self.subTest(scope=scope), self.assertRaises(ApiError) as caught:
                self.call()
            self.assertEqual(caught.exception.code, "credential_scope_changed")
        self.assertEqual(self.backend.reads, 0)

    def test_rate_limit_resets_after_window_and_never_reads_after_limit(self):
        self.tools.calls = 120
        with self.assertRaises(ApiError) as caught:
            self.call()
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(self.backend.reads, 0)
        self.tools.window_start -= 61
        self.assertEqual(self.call(), self.backend.payload)
        self.assertEqual(self.tools.calls, 1)

    def test_unsupported_tools_and_extra_tenant_arguments_are_refused(self):
        for name in ("shell", "vanian_export", "vanian_get_signing_key"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.tools.call(name, {})
        with self.assertRaises(ValidationError):
            self.tools.call("vanian_get_observer_health", {"tenant_id": "tenant-b"})
        with self.assertRaises(ValidationError):
            self.tools.call("vanian_list_agents", {"limit": 26})
        self.assertEqual(self.backend.reads, 0)

    def test_large_structured_payload_is_not_duplicated_in_text(self):
        self.backend.payload = {"fixture": "x" * 200_000}
        response = anyio.run(self.invoke)
        self.assertFalse(response.is_error)
        self.assertEqual(response.structured_content, self.backend.payload)
        self.assertLess(len(response.content[0].text), 256)
        self.assertLessEqual(len(response.model_dump_json(by_alias=True).encode()), MCP.MAX_OUTPUT - 4096)

    def test_serialization_envelope_and_upstream_payload_limits_are_enforced(self):
        # The raw result fits MAX_OUTPUT, but not the complete allowed MCP
        # envelope. The handler must refuse it without returning the payload.
        self.backend.payload = {"fixture": "x" * (MCP.MAX_OUTPUT - 2000)}
        self.assertLess(len(json.dumps(self.backend.payload).encode()), MCP.MAX_OUTPUT)
        response = anyio.run(self.invoke)
        self.assertTrue(response.is_error)
        self.assertIsNone(response.structured_content)
        self.assertLess(len(response.model_dump_json(by_alias=True).encode()), 1024)
        self.backend.payload = {"fixture": "x" * MCP.MAX_OUTPUT}
        with self.assertRaises(ApiError) as caught:
            self.call()
        self.assertEqual(caught.exception.code, "output_limit")

    def test_bounded_input_refuses_oversized_or_invalid_utf8_frames(self):
        async def next_frame():
            return await anext(MCP.BoundedInput())
        for payload, exception in ((b"x" * (MCP.MAX_INPUT + 1), ValueError),
                                   (b"\xff\n", UnicodeDecodeError)):
            with self.subTest(exception=exception), mock.patch.object(MCP.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload))):
                with self.assertRaises(exception):
                    anyio.run(next_frame)
        with mock.patch.object(MCP.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b'{"jsonrpc":"2.0"}\n'))):
            self.assertEqual(anyio.run(next_frame), '{"jsonrpc":"2.0"}\n')


if __name__ == "__main__":
    unittest.main(verbosity=2)
