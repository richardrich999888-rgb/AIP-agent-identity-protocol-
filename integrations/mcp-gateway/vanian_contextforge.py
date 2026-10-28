"""Signed tool receipts at ContextForge's actual dispatch boundary.

API: IBM/mcp-context-forge ff6a566a + cpex 0.1.4. Cryptography and JSON
canonicalization remain in aip-mcp-gateway's Rust receipt-only executable.
No Forwarded receipt exists until ContextForge invokes the real post hook.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

from cpex.framework import HttpHeaderPayload, Plugin, PluginConfig, PluginContext, PluginViolation
from cpex.framework.hooks.tools import (
    ToolPostInvokePayload,
    ToolPostInvokeResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DECISION = re.compile(r"[0-9a-fA-F]{32}\Z")
_STATE = "vanian.receipt.call"


class ReceiptUnavailable(RuntimeError):
    """The gateway cannot establish/persist its receipt; payloads stay private."""


class VanianToolReceiptPlugin(Plugin):
    """Least-scope receipt plugin, with durable single-use decision reservations.

    Configure as the final pre-invoke plugin, with no argument/name-changing
    hooks after it, and disable automatic retry/cache plugins for these tools.
    A missing post hook leaves a durable pending row, never a success receipt.
    """

    def __init__(self, config: PluginConfig):
        super().__init__(config)
        options = config.config or {}
        self.binary = str(options.get("signer_binary", ""))
        self.database = str(options.get("replay_database", ""))
        self.tools = frozenset(options.get("tools", []))
        self.principals = dict(options.get("agent_principals", {}))
        self.timeout = float(options.get("signer_timeout_seconds", 5))
        self.max_requests = int(options.get("max_requests", 100_000))
        self.max_bytes = int(options.get("max_request_bytes", 524_288))
        if not Path(self.binary).is_absolute() or not Path(self.database).is_absolute():
            raise ValueError("signer_binary and replay_database must be absolute paths")
        if not self.tools or not self.principals or not (0 < self.timeout <= 30):
            raise ValueError("explicit tools, agent_principals and a bounded timeout are required")
        if not (1 <= self.max_requests <= 10_000_000 and 1024 <= self.max_bytes <= 524_288):
            raise ValueError("invalid request bounds")
        if any(not isinstance(agent, str) or not _IDENTIFIER.fullmatch(agent) for agent in self.principals.values()):
            raise ValueError("invalid principal-to-agent binding")
        # A gateway administrator supplies all signing configuration. Never
        # accept executable paths, sink paths or keys from request headers.
        names = ("AIP_GATEWAY_KEY_FILE", "AIP_GATEWAY_PUBLIC_KEY", "AIP_GATEWAY_ID",
                 "AIP_GATEWAY_KEY_VERSION", "AIP_GATEWAY_RECEIPTS")
        self.signer_env = {name: os.environ[name] for name in names}
        self.signer_env["PATH"] = os.defpath
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_database(self) -> None:
        # Parent directory must be owned by the gateway administrator.
        if Path(self.database).is_symlink():
            raise ValueError("replay database must not be a symbolic link")
        descriptor = os.open(self.database, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise ValueError("replay database must be a regular owner-only file")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ValueError("replay database must be owned by the gateway service user")
        finally:
            os.close(descriptor)
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS requests (
                agent_id TEXT NOT NULL, decision_id TEXT NOT NULL,
                request_id TEXT NOT NULL, received_at_ms INTEGER NOT NULL,
                commitment TEXT NOT NULL, state TEXT NOT NULL,
                PRIMARY KEY (agent_id, decision_id), UNIQUE (agent_id, request_id)
            )""")

    def _reserve(self, call: dict[str, Any], commitment: list[int]) -> str | None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM requests WHERE agent_id=? AND (decision_id=? OR request_id=?)",
                                  (call["agent_id"], call["decision_id"], call["tool_call_id"])).fetchone():
                return "REPLAY_REFUSED"
            if connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0] >= self.max_requests:
                return "RECEIPT_JOURNAL_FULL"
            connection.execute("INSERT INTO requests VALUES (?, ?, ?, ?, ?, 'pending')",
                               (call["agent_id"], call["decision_id"], call["tool_call_id"],
                                call["received_at_ms"], bytes(commitment).hex()))
        return None

    def _finish(self, call: dict[str, Any], state: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE requests SET state=? WHERE agent_id=? AND decision_id=?",
                               (state, call["agent_id"], call["decision_id"]))

    async def _signer(self, operation: str, call: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(call, allow_nan=False, separators=(",", ":")).encode()
        if len(encoded) > 1_048_576:
            raise ReceiptUnavailable("receipt input limit exceeded")
        process = await asyncio.create_subprocess_exec(
            self.binary, operation, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=self.signer_env,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(process.communicate(encoded), timeout=self.timeout)
        except BaseException:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        if process.returncode != 0 or len(stdout) > 131_072:
            raise ReceiptUnavailable("Rust signer failed; no verified receipt is available")
        try:
            return json.loads(stdout)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReceiptUnavailable("invalid signer response") from error

    @staticmethod
    def _violation(code: str) -> ToolPreInvokeResult:
        return ToolPreInvokeResult(continue_processing=False, violation=PluginViolation(
            reason=code, description="Tool request refused by gateway receipt policy", code=code,
        ))

    async def _refuse(self, call: dict[str, Any], code: str) -> ToolPreInvokeResult:
        try:
            await self._signer("issue", {**call, "disposition": "Refused"})
        except Exception:
            return self._violation("RECEIPT_UNAVAILABLE")
        return self._violation(code)

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        context.set_state(_STATE, None)
        try:
            headers: dict[str, str] = {}
            for name, value in (payload.headers.root.items() if payload.headers else []):
                normalized = name.lower()
                if normalized in headers or not isinstance(value, str):
                    return self._violation("INVALID_RECEIPT_HEADERS")
                headers[normalized] = value
            agent = headers.get("x-aip-agent-id", "")
            decision = headers.get("x-aip-decision-id", "")
            request_id = headers.get("x-aip-request-id", "")
            if not _IDENTIFIER.fullmatch(agent) or not _DECISION.fullmatch(decision) or not _IDENTIFIER.fullmatch(request_id):
                return self._violation("MISSING_OR_INVALID_RECEIPT_IDENTITY")
            if self.principals.get(context.user_email) != agent:
                return self._violation("AGENT_PRINCIPAL_MISMATCH")
            if not isinstance(payload.args, dict):
                return self._violation("INVALID_TOOL_ARGUMENTS")
            call = {
                "method": "tools/call", "tool_name": payload.name, "arguments": payload.args,
                "agent_id": agent, "decision_id": decision.lower(), "tool_call_id": request_id,
                "headers": {name: headers[name] for name in ("mcp-method", "mcp-name") if name in headers},
                "received_at_ms": time.time_ns() // 1_000_000,
            }
            if len(json.dumps(call, allow_nan=False).encode()) > self.max_bytes:
                return self._violation("TOOL_REQUEST_TOO_LARGE")
            if payload.name not in self.tools:
                return await self._refuse(call, "UNSUPPORTED_TOOL")
            if headers.get("mcp-method", "tools/call") != "tools/call" or headers.get("mcp-name", payload.name) != payload.name:
                return await self._refuse(call, "HEADER_BODY_DISAGREEMENT")
            checked = await self._signer("check", call)
            if checked.get("ready") is not True:
                raise ReceiptUnavailable("signer readiness not established")
            refusal = await asyncio.to_thread(self._reserve, call, checked["parameter_commitment"])
            if refusal:
                return await self._refuse(call, refusal)
            context.set_state(_STATE, call)
            # These headers belong to this gateway's receipt boundary. In
            # particular, its namespaced Mcp-Name is not the upstream name.
            # The gateway's MCP client supplies upstream protocol headers.
            remaining = {name: value for name, value in (payload.headers.root.items() if payload.headers else [])
                         if name.lower() not in {"x-aip-agent-id", "x-aip-decision-id", "x-aip-request-id", "mcp-method", "mcp-name"}}
            modified = payload.model_copy(update={"headers": HttpHeaderPayload(root=remaining)})
            return ToolPreInvokeResult(continue_processing=True, modified_payload=modified)
        except Exception:
            return self._violation("RECEIPT_UNAVAILABLE")

    async def tool_post_invoke(self, payload: ToolPostInvokePayload, context: PluginContext) -> ToolPostInvokeResult:
        call = context.get_state(_STATE)
        if call is None:
            # ContextForge invokes post hooks for pre-hook refusals as well.
            return ToolPostInvokeResult(continue_processing=True)
        # Clear before I/O: ContextForge may invoke error post hooks again when
        # a later plugin fails. Never turn that second callback into success.
        context.set_state(_STATE, None)
        result = payload.result
        if not isinstance(result, dict):
            result = {"isError": True, "content": []}
        disposition = "Failed" if result.get("isError", result.get("is_error", False)) else "Forwarded"
        try:
            signed = await self._signer("issue", {**call, "disposition": disposition, "response": result})
            await asyncio.to_thread(self._finish, call, disposition)
            metadata = dict(result.get("_meta") or {})
            metadata["vanian"] = {"receipt_persisted": True, "signed_receipt": signed["signed_receipt"]}
            result = {**result, "_meta": metadata}
        except Exception:
            try:
                await asyncio.to_thread(self._finish, call, "receipt_error")
            except Exception:
                # A simultaneous journal outage must not mask uncertainty.
                # The previously committed pending record remains a gap.
                pass
            # The underlying effect may already have occurred. Tell the caller
            # precisely that receipt coverage is unavailable; never retry it.
            result = {"isError": True, "content": [{"type": "text", "text":
                      "Gateway receipt unavailable. The tool may have executed; do not automatically retry."}],
                      "_meta": {"vanian": {"receipt_persisted": False, "coverage": "CANNOT_PROVE"}}}
        return ToolPostInvokeResult(continue_processing=True, modified_payload=payload.model_copy(update={"result": result}))
