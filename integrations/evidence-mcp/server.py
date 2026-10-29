"""Optional stdio evidence facade. No sensor, signer, administration or shell.

One OS-owned process per authenticated institutional client. Each process uses
its own tenant-bound Reader service credential. No HTTP listener is exposed.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import asdict
from typing import Any

import anyio
from jsonschema import ValidationError, validate
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from vanian import ApiError, VanianClient

LOG = logging.getLogger("vanian.evidence_mcp")
MAX_INPUT = 65_536
MAX_OUTPUT = 262_144
IDENTIFIER = {"type": "string", "minLength": 1, "maxLength": 256}
EVIDENCE_QUERY = {"evidence_id": IDENTIFIER, "kind": {"type": "string", "enum": ["packet", "observation_archive", "run_bundle"], "default": "packet"}}
PAGE = {
    "limit": {"type": "integer", "minimum": 1, "maximum": 25, "default": 25},
    "offset": {"type": "integer", "minimum": 0, "maximum": 100000, "default": 0},
}


def _schema(properties=None, required=()):
    return {"type": "object", "properties": properties or {},
            "required": list(required), "additionalProperties": False}


TOOLS = {
    "vanian_list_agents": ("List agent identities asserted by stored packets; not independently observed identity.", _schema(PAGE)),
    "vanian_get_agent_identity": ("Read stored agent metadata and its explicit trust level.", _schema({"agent_id": IDENTIFIER}, ("agent_id",))),
    "vanian_get_agent_activity": ("Read packet-derived activity, not kernel evidence.", _schema({"agent_id": IDENTIFIER, **PAGE}, ("agent_id",))),
    "vanian_get_execution_verdict": ("Retrieve a signed reconciler document without changing its verdict or evidence grade.", _schema({"verdict_id": IDENTIFIER, "kind": {"type":"string", "enum":["verdict","run_bundle"], "default":"verdict"}}, ("verdict_id",))),
    "vanian_get_observation_coverage": ("Return real service coverage availability, including not-connected states.", _schema()),
    "vanian_get_evidence_metadata": ("Retrieve scoped packet, collector-archive or same-run metadata only; raw evidence and export are not available.", _schema(EVIDENCE_QUERY, ("evidence_id",))),
    "vanian_get_observer_health": ("Return service health and explicit unavailable probe/collector health.", _schema()),
    "vanian_verify_stored_evidence": ("Reevaluate the stored record with the existing Rust verifiers. Same-run records use configured anchors and retained checkpoints; preserve the engine verdict, tool-boundary result and stated limitations.", _schema(EVIDENCE_QUERY, ("evidence_id",))),
}


class EvidenceTools:
    def __init__(self, client: VanianClient):
        self.client = client
        access = client.access()
        if access.get("role") != "reader" or not access.get("tenant_id"):
            raise ValueError("MCP requires a tenant-bound Reader credential")
        self.tenant_id = access["tenant_id"]
        self.window_start, self.calls = time.monotonic(), 0

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name not in TOOLS:
            raise ValueError("unsupported tool")
        validate(args, TOOLS[name][1])
        now = time.monotonic()
        if now - self.window_start >= 60:
            self.window_start, self.calls = now, 0
        self.calls += 1
        if self.calls > 120:
            raise ApiError(429, "rate_limited")
        access = self.client.access()
        if access.get("role") != "reader" or access.get("tenant_id") != self.tenant_id:
            raise ApiError(403, "credential_scope_changed")
        if name == "vanian_list_agents":
            result = asdict(self.client.list_agents(**{"limit": 25, **args}))
        elif name == "vanian_get_agent_identity":
            result = self.client.get_agent(**args)
        elif name == "vanian_get_agent_activity":
            result = asdict(self.client.get_agent_activity(**{"limit": 25, **args}))
        elif name == "vanian_get_execution_verdict":
            result = (self.client.get_run_verdict(args["verdict_id"]) if args.get("kind") == "run_bundle"
                      else self.client.get_verdict(args["verdict_id"]))
        elif name == "vanian_get_observation_coverage":
            result = self.client.get_coverage()
        elif name == "vanian_get_evidence_metadata":
            if args.get("kind") == "run_bundle":
                result = self.client.get_run_metadata(args["evidence_id"])
            elif args.get("kind") == "observation_archive":
                result = self.client.get_observation_metadata(args["evidence_id"])
            else:
                result = self.client.get_evidence_metadata(args["evidence_id"])
        elif name == "vanian_get_observer_health":
            result = self.client.get_health()
        else:
            if args.get("kind") == "run_bundle":
                result = self.client.evaluate_run(args["evidence_id"])
            elif args.get("kind") == "observation_archive":
                result = self.client.verify_observation(args["evidence_id"])
            else:
                result = self.client.verify_evidence(args["evidence_id"])
        if len(json.dumps(result, ensure_ascii=True).encode()) > MAX_OUTPUT:
            raise ApiError(0, "output_limit")
        return result


class BoundedInput:
    """Refuse an oversize frame before JSON parsing; close the stdio session."""

    def __aiter__(self):
        return self

    async def __anext__(self):
        line = await anyio.to_thread.run_sync(lambda: sys.stdin.buffer.readline(MAX_INPUT + 1))
        if not line:
            raise StopAsyncIteration
        if len(line) > MAX_INPUT:
            raise ValueError("MCP input frame exceeds limit")
        return line.decode("utf-8", errors="strict")


def make_server(tools: EvidenceTools) -> Server:
    async def list_tools(ctx: ServerRequestContext, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[
            types.Tool(name=name, description=description, input_schema=schema,
                       annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False))
            for name, (description, schema) in TOOLS.items()
        ])

    # Serialize outbound service calls: bounded concurrency and no mutable
    # process-global credential changes during a request.
    lock = anyio.Lock()

    async def call_tool(ctx: ServerRequestContext, params: types.CallToolRequestParams) -> types.CallToolResult:
        try:
            async with lock:
                result = await anyio.to_thread.run_sync(lambda: tools.call(params.name, params.arguments or {}))
            response = types.CallToolResult(
                content=[types.TextContent(type="text", text="Evidence response; use structuredContent and its stated limitations.")],
                structured_content=result,
            )
            if len(response.model_dump_json(by_alias=True).encode()) > MAX_OUTPUT - 4096:
                raise ApiError(0, "output_limit")
            LOG.info("read tool=%s outcome=ok", params.name)
            return response
        except (ApiError, ValueError, ValidationError):
            # Never render an upstream body, credential, or input to the model.
            LOG.info("read outcome=refused")
            return types.CallToolResult(is_error=True, content=[
                types.TextContent(type="text", text="Evidence request refused or unavailable")
            ])

    return Server("vanian-evidence-mcp", version="0.1.0", on_list_tools=list_tools, on_call_tool=call_tool)


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    client = VanianClient(
        os.environ["VANIAN_BASE_URL"], lambda: os.environ["VANIAN_API_TOKEN"],
        max_response_bytes=MAX_OUTPUT, retries=0,
        ca_file=os.environ.get("VANIAN_CA_FILE"),
        allow_loopback_http=os.environ.get("VANIAN_ALLOW_LOOPBACK_HTTP") == "1",
    )
    server = make_server(EvidenceTools(client))

    async def run():
        async with stdio_server(stdin=BoundedInput()) as (reader, writer):
            await server.run(reader, writer, server.create_initialization_options())

    anyio.run(run)


if __name__ == "__main__":
    main()
