"""Read-only ADK BasePlugin hooks. No observer key or tool payload is handled."""
from __future__ import annotations

import time
import uuid
import logging

from google.adk.plugins.base_plugin import BasePlugin

from .records import GovernanceEvent, SourceAuthenticity, commitment, json_bytes


class VanianAdkPlugin(BasePlugin):
    def __init__(self, tenant: str, emit):
        super().__init__(name="vanian-correlation")
        if not tenant:
            raise ValueError("operator-configured tenant required")
        self.tenant, self.emit = tenant, emit
        self.dropped_events = 0

    def _event(self, kind, context, extra, tool_args=None):
        try:
            if tool_args is not None:
                extra = {**extra, "argument_reference_commitment": commitment(tool_args)}
            self._emit_event(kind, context, extra)
        except Exception:
            # Observer-only hook failures never replace a tool result or gate
            # execution. Expose a coverage gap without logging tool secrets.
            self.dropped_events += 1
            logging.getLogger(__name__).error("VANIAN correlation event lost; coverage is incomplete")

    def _emit_event(self, kind, context, extra):
        invocation = getattr(context, "invocation_id", None)
        agent = getattr(context, "agent_name", None)
        metadata = {"invocation_id": invocation, "agent_name": agent, **extra,
                    "attribution": "FRAMEWORK_REPORTED", "logical_execution_proof": "NOT_ESTABLISHED"}
        self.emit(GovernanceEvent(
            "google-adk", self.tenant, str(uuid.uuid4()), kind, time.time_ns() // 1_000_000,
            json_bytes(metadata).decode(), SourceAuthenticity("IN_PROCESS_HOOK", "ADK workload", None, None),
            agent_id=agent, task_id=invocation))

    async def before_agent_callback(self, *, agent, callback_context):
        self._event("agent.start", callback_context, {"declared_agent": agent.name})
        return None

    async def after_agent_callback(self, *, agent, callback_context):
        self._event("agent.end", callback_context, {"declared_agent": agent.name})
        return None

    async def before_tool_callback(self, *, tool, tool_args, tool_context):
        self._event("tool.request", tool_context, {"tool": tool.name,
            "tool_call_id": tool_context.function_call_id}, tool_args=tool_args)
        return None

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        self._event("tool.response", tool_context, {"tool": tool.name,
            "tool_call_id": tool_context.function_call_id})
        return None

    async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
        self._event("tool.error", tool_context, {"tool": tool.name,
            "tool_call_id": tool_context.function_call_id, "error_type": type(error).__name__})
        # Do not replace a failed tool result with success or include its secrets.
        return None
