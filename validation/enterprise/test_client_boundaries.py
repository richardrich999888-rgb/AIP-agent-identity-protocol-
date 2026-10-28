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
from openapi_contract import OpenAPIContract, RUN_OPERATIONS

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


class OpenAPIContracts(unittest.TestCase):
    def test_all_same_run_routes_are_documented_and_match_actual_rust_handlers(self):
        contract = OpenAPIContract()
        contract.assert_route_alignment()
        self.assertEqual(len(RUN_OPERATIONS), 6)
        source = (ROOT / "aip-service/src/lib.rs").read_text()
        with self.assertRaises(AssertionError):
            contract.assert_route_alignment(source.replace('"/v1/runs/:id/evaluation"',
                                                          '"/v1/undocumented-evaluation"'))
        # Omitting a new read cannot silently remove it from coverage.
        del contract.operations[("GET", "/v1/runs/{run_artifact_id}/metadata")]
        with self.assertRaises(AssertionError):
            contract.assert_route_alignment()

    def test_same_run_wire_schema_refuses_caller_trust_and_preserves_limitations(self):
        contract = OpenAPIContract()
        bundle = {"run_id":"schema-fixture","agent_id":"schema-agent", "expectation":None,
                  "signed_receipt":None,"signed_reconciliation":None,
                  "batches_jsonl":"schema-only\n","health_jsonl":"schema-only\n","verification_time_ms":1}
        contract.validate_request("POST", "/v1/runs", bundle)
        with self.assertRaises(AssertionError):
            contract.validate_request("POST", "/v1/runs", {**bundle,"trust":{"approved":True}})
        evaluation = {"run_id":"schema-fixture","agent_id":"schema-agent",
            "archive_integrity_verified":False,"checkpoint_verified":False,
            "authorization_verified":False,"gateway_receipt_verified":False,
            "signed_reconciliation_verified":False,"receipt_within_authorization":None,
            "gateway_disposition":None,"reconciliation":None,"tool_boundary":None,
            "limitations":["Schema-only values do not establish signature validity or workload execution."]}
        metadata = {"run_artifact_id":"a"*64,"run_id":"schema-fixture","agent_id":"schema-agent",
                    "bundle_sha256":"b"*64,"batches_sha256":"c"*64,"health_sha256":"d"*64,
                    "verification_scope":"same_run_evaluation","evaluation":evaluation}
        path = "/v1/runs/" + metadata["run_artifact_id"] + "/metadata"
        contract.validate_response("GET", path, 200, metadata)
        for altered in ({**metadata,"verification_scope":"verified_execution"},
                        {**metadata,"bundle_sha256":"not-a-digest"},
                        {**metadata,"evaluation":{key:value for key,value in evaluation.items() if key != "limitations"}}):
            with self.subTest(keys=altered.keys()), self.assertRaises(AssertionError):
                contract.validate_response("GET", path, 200, altered)


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

    def get_run_metadata(self, run_artifact_id):
        self.reads += 1
        return {"run_artifact_id":run_artifact_id,"evaluation":self.payload}

    def evaluate_run(self, run_artifact_id):
        self.reads += 1
        return self.payload

    def get_run_verdict(self, run_artifact_id):
        self.reads += 1
        return {"reconciliation":self.payload,"attestation":{"fixture":True}}


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

    def test_same_run_tools_preserve_uncertainty_and_reject_scope_injection(self):
        self.assertEqual(len(MCP.TOOLS), 8)
        self.backend.payload = {"reconciliation":{"execution":"CannotProve"},
                                "limitations":["fixture missing independent attribution"]}
        metadata = self.tools.call("vanian_get_evidence_metadata", {"evidence_id":"run-1","kind":"run_bundle"})
        evaluation = self.tools.call("vanian_verify_stored_evidence", {"evidence_id":"run-1","kind":"run_bundle"})
        verdict = self.tools.call("vanian_get_execution_verdict", {"verdict_id":"run-1","kind":"run_bundle"})
        self.assertEqual(metadata["evaluation"], self.backend.payload)
        self.assertEqual(evaluation, self.backend.payload)
        self.assertEqual(verdict["reconciliation"], self.backend.payload)
        calls = self.backend.reads
        for tool, args in [
            ("vanian_get_evidence_metadata", {"evidence_id":"run-1","kind":"run_bundle","trust":{}}),
            ("vanian_get_execution_verdict", {"verdict_id":"run-1","kind":"run_bundle","tenant_id":"b"}),
        ]:
            with self.assertRaises(ValidationError):
                self.tools.call(tool, args)
        self.backend.scope["tenant_id"] = "tenant-b"
        with self.assertRaises(ApiError):
            self.tools.call("vanian_verify_stored_evidence", {"evidence_id":"run-1","kind":"run_bundle"})
        self.assertEqual(self.backend.reads, calls)

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
