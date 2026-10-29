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
        self.require_authorization = options.get("require_authorization", False)
        if type(self.require_authorization) is not bool:
            raise ValueError("require_authorization must be an explicit boolean")
        self.authorization_binary = str(options.get(
            "authorization_binary", str(Path(self.binary).with_name("aip-execution-assurance"))))
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
        self.authorization_directory: Path | None = None
        self.authorization_env: dict[str, str] = {"PATH": os.defpath}
        if self.require_authorization:
            self.authorization_directory = Path(os.environ["AIP_AUTHORIZATION_DIR"])
            trust_file = Path(os.environ["AIP_RUN_TRUST_FILE"])
            if (not self.authorization_directory.is_absolute() or not trust_file.is_absolute()
                    or not Path(self.authorization_binary).is_absolute()):
                raise ValueError("authorization paths must be administrator-configured absolute paths")
            self._check_admin_path(self.authorization_directory, directory=True)
            self._check_admin_path(trust_file)
            self._check_admin_path(Path(self.authorization_binary))
            self.authorization_env["AIP_RUN_TRUST_FILE"] = str(trust_file)
        self._initialize_database()

    @staticmethod
    def _check_admin_path(path: Path, *, directory: bool = False) -> None:
        metadata = path.lstat()
        correct_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
        if (not correct_type or metadata.st_mode & 0o022
                or (hasattr(os, "getuid") and metadata.st_uid not in (0, os.getuid()))):
            raise ValueError("authorization files and directories must be controlled by the gateway administrator")

    async def _check_authorization(self, call: dict[str, Any]) -> bool:
        """Lookup a signed decision from gateway-owned storage, never a path
        or trust anchor supplied by the monitored client. A reference alone
        grants nothing; Rust verifies the actual received call before dispatch.
        """
        assert self.authorization_directory is not None
        decision_path = self.authorization_directory / (call["decision_id"] + ".json")
        try:
            self._check_admin_path(decision_path)
            descriptor = os.open(decision_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65_536
                        or metadata.st_mode & 0o022
                        or (hasattr(os, "getuid") and metadata.st_uid not in (0, os.getuid()))):
                    return False
                raw = stream.read(65_537)
            if len(raw) > 65_536:
                return False
            expectation = json.loads(raw)
            # Avoid aliasing a decision reference to another signed record.
            if bytes(expectation["decision_id"]).hex() != call["decision_id"]:
                return False
            request = {"expectation": expectation, "agent_id": call["agent_id"],
                       "tool_id": call["tool_name"], "arguments": call["arguments"],
                       "received_at_ms": call["received_at_ms"]}
            process = await asyncio.create_subprocess_exec(
                self.authorization_binary, "check-authorization", stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=self.authorization_env,
            )
            try:
                stdout, _stderr = await asyncio.wait_for(process.communicate(
                    json.dumps(request, allow_nan=False, separators=(",", ":")).encode()), timeout=self.timeout)
            except BaseException:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                raise
            return (process.returncode == 0 and len(stdout) <= 1024
                    and json.loads(stdout).get("authorized") is True)
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            return False

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

    def _claim_post(self, call: dict[str, Any]) -> bool:
        # A copied request context or repeated callback cannot issue twice.
        # The committed pending reservation is the only eligible transition.
        with self._connect() as connection:
            updated = connection.execute(
                "UPDATE requests SET state='receipting' WHERE agent_id=? AND decision_id=? "
                "AND request_id=? AND state='pending'",
                (call["agent_id"], call["decision_id"], call["tool_call_id"]))
            return updated.rowcount == 1

    def _finish(self, call: dict[str, Any], state: str) -> None:
        with self._connect() as connection:
            updated = connection.execute(
                "UPDATE requests SET state=? WHERE agent_id=? AND decision_id=? "
                "AND request_id=? AND state='receipting'",
                (state, call["agent_id"], call["decision_id"], call["tool_call_id"]))
            if updated.rowcount != 1:
                raise ReceiptUnavailable("receipt reservation transition unavailable")

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
        # CPEX PluginRef UUIDs change when ContextForge replaces a cached
        # manager. Its public request-global state survives that replacement;
        # plugin-local contexts keyed by the old UUID do not. This namespaced
        # value is written only by trusted hooks, never from request payloads.
        invocation_request_id = context.global_context.request_id
        context.global_context.state[_STATE] = {"request_id": invocation_request_id, "pre_refused": True}
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
            if self.require_authorization and not await self._check_authorization(call):
                return await self._refuse(call, "AUTHORIZATION_REFUSED")
            checked = await self._signer("check", call)
            if checked.get("ready") is not True:
                raise ReceiptUnavailable("signer readiness not established")
            refusal = await asyncio.to_thread(self._reserve, call, checked["parameter_commitment"])
            if refusal:
                return await self._refuse(call, refusal)
            context.global_context.state[_STATE] = {"request_id": invocation_request_id, "call": call}
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
        handoff = context.global_context.state.get(_STATE)
        # Assign a sentinel before I/O. CPEX merges state with dict.update, so
        # deleting the key would not propagate consumption to the request.
        context.global_context.state[_STATE] = None
        if not isinstance(handoff, dict) or handoff.get("request_id") != context.global_context.request_id:
            return self._unavailable_post(payload)
        if handoff.get("pre_refused") is True:
            # ContextForge invokes error post hooks for pre-hook refusals too.
            # Preserve an existing denial; never allow an unannotated success.
            result = payload.result
            if isinstance(result, dict) and result.get("isError", result.get("is_error", False)):
                return ToolPostInvokeResult(continue_processing=True)
            return self._unavailable_post(payload)
        call = handoff.get("call")
        if not isinstance(call, dict):
            return self._unavailable_post(payload)
        result = payload.result
        if not isinstance(result, dict):
            result = {"isError": True, "content": []}
        disposition = "Failed" if result.get("isError", result.get("is_error", False)) else "Forwarded"
        claimed = False
        try:
            claimed = await asyncio.to_thread(self._claim_post, call)
            if not claimed:
                return self._unavailable_post(payload)
            signed = await self._signer("issue", {**call, "disposition": disposition, "response": result})
            await asyncio.to_thread(self._finish, call, disposition)
            metadata = dict(result.get("_meta") or {})
            metadata["vanian"] = {"receipt_persisted": True, "signed_receipt": signed["signed_receipt"]}
            result = {**result, "_meta": metadata}
        except Exception:
            if claimed:
                try:
                    await asyncio.to_thread(self._finish, call, "receipt_error")
                except Exception:
                    # A simultaneous journal outage must not mask uncertainty.
                    # The committed reservation remains an unresolved gap.
                    pass
            # The underlying effect may already have occurred. Tell the caller
            # precisely that receipt coverage is unavailable; never retry it.
            return self._unavailable_post(payload)
        return ToolPostInvokeResult(continue_processing=True, modified_payload=payload.model_copy(update={"result": result}))

    @staticmethod
    def _unavailable_post(payload: ToolPostInvokePayload) -> ToolPostInvokeResult:
        result = {"isError": True, "content": [{"type": "text", "text":
                  "Gateway receipt unavailable. The tool may have executed; do not automatically retry."}],
                  "_meta": {"vanian": {"receipt_persisted": False, "coverage": "CANNOT_PROVE"}}}
        return ToolPostInvokeResult(continue_processing=True, modified_payload=payload.model_copy(update={"result": result}))
