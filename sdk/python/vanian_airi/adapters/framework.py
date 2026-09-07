"""Reference agent-framework adapter.

# What an adapter is

A thin translator from a framework's callback vocabulary into AIRI events.
Nothing more. An adapter holds no keys of its own, makes no trust decisions,
and has no privileged status — this one is written against the
callback shape that LangChain and LangGraph both expose (``on_*`` hooks with
a run id and a payload), and the same class works for AutoGen, CrewAI,
LlamaIndex or a bespoke runtime by wiring their hooks to the same methods.

# Why it is deliberately dumb

Every line of judgement inside an adapter is judgement inside the process
under scrutiny. If an adapter decided which calls were "important enough" to
report, a compromised agent would simply mark its interesting calls
unimportant. The adapter therefore reports what it is told, and the
epistemic work happens in ``aip_airi::corroborate``, off this host.

# Registering with a framework

The framework-specific glue is intentionally not in this package: importing
LangChain to satisfy a type signature would make a heavyweight optional
dependency mandatory. Wire it up at the call site::

    from langchain_core.callbacks import BaseCallbackHandler
    from vanian_airi.adapters.framework import FrameworkAdapter

    class VanianHandler(BaseCallbackHandler):
        def __init__(self, adapter): self.a = adapter
        def on_chain_start(self, serialized, inputs, **kw):
            self.a.on_agent_start(role=serialized.get("name"),
                                  run_id=str(kw.get("run_id")))
        def on_tool_start(self, serialized, input_str, **kw):
            self.a.on_tool_start(tool_id=serialized.get("name", "unknown"),
                                 action_kind="tool.invoke",
                                 parameters=input_str,
                                 tool_call_id=str(kw.get("run_id")))
        def on_tool_end(self, output, **kw):
            self.a.on_tool_end(tool_id=self.a.last_tool_id, result=output)
"""

from __future__ import annotations

from typing import Optional

from ..emitter import AiriEmitter
from ..events import ModelProvenance, PropagationBoundary, ReportedOutcome

__all__ = ["FrameworkAdapter"]


class FrameworkAdapter:
    """Translates framework callbacks into AIRI events.

    ``last_tool_id`` is kept so a framework whose "end" callback omits the
    tool name can still pair a report with its request. It is a convenience
    for the caller and carries no security meaning: the *binding* between a
    request and its report is the parameter commitment, which is in the
    signed preimage of both.
    """

    def __init__(self, emitter: AiriEmitter) -> None:
        self._em = emitter
        self.last_tool_id: Optional[str] = None

    # ── agent lifecycle ─────────────────────────────────────────────────

    def on_agent_start(
        self, role: Optional[str] = None, run_id: Optional[str] = None
    ) -> None:
        self._em.agent_started(agent_role=role, framework_run_id=run_id)

    def on_agent_end(self, detail: Optional[str] = None) -> None:
        self._em.completed(detail=detail)

    def on_agent_error(self, detail: Optional[str] = None) -> None:
        self._em.failed(detail=detail)

    def on_agent_refusal(self, detail: Optional[str] = None) -> None:
        """The agent declined to act — a guardrail, a policy stop, a refusal.

        Distinct from an error: a refusal is a claim about a *non*-execution,
        and where independent evidence covers the window it is checkable.
        """
        self._em.denied(detail=detail)

    # ── model ───────────────────────────────────────────────────────────

    def on_model_start(
        self,
        model_id: str,
        runtime: str = "hosted-api",
        *,
        prompt: object = None,
        runtime_version: Optional[str] = None,
        inference_request_id: Optional[str] = None,
        model_digest: Optional[bytes] = None,
        accelerator: Optional[str] = None,
    ) -> None:
        """The agent asked for a model.

        ``prompt`` is committed, never carried. ``model_digest`` should be
        ``None`` for hosted inference: the agent cannot compute a digest of
        weights it never sees, and inventing one would be a lie in evidence.
        """
        from ..commitment import commit_json

        self._em.model_requested(
            ModelProvenance(
                model_id=model_id,
                runtime=runtime,
                model_digest=model_digest,
                runtime_version=runtime_version,
                inference_request_id=inference_request_id,
                prompt_commitment=None if prompt is None else commit_json(prompt),
                accelerator=accelerator,
            )
        )

    def on_model_end(
        self,
        model_id: str,
        runtime: str = "hosted-api",
        *,
        output: object = None,
        inference_request_id: Optional[str] = None,
    ) -> None:
        """The framework reported back about the inference call.

        Emitted as ``MODEL_INVOCATION_OBSERVED``, which the specification
        names "observed" and which is **not** independent observation: the
        observer here is the framework, running inside the process under
        scrutiny.
        """
        from ..commitment import commit_json

        self._em.model_observed(
            ModelProvenance(
                model_id=model_id,
                runtime=runtime,
                inference_request_id=inference_request_id,
                output_commitment=None if output is None else commit_json(output),
            )
        )

    # ── tools ───────────────────────────────────────────────────────────

    def on_tool_start(
        self,
        tool_id: str,
        action_kind: str,
        parameters: object,
        tool_call_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> None:
        """Layer 1: the agent asked a tool to do something."""
        self.last_tool_id = tool_id
        self._em.tool_requested(
            tool_id=tool_id,
            action_kind=action_kind,
            parameters=parameters,
            tool_call_id=tool_call_id,
            target=target,
        )

    def on_tool_end(
        self,
        tool_id: str,
        parameters: object,
        result: object = None,
        transport_status: Optional[int] = None,
    ) -> None:
        """Layer 2 reporting on layer 3.

        ``parameters`` must be the *same* value passed to
        :meth:`on_tool_start`: the commitment is what binds a report to its
        request, and a report committing to different parameters is a
        different statement, correctly.
        """
        self._em.tool_reported(
            tool_id=tool_id,
            parameters=parameters,
            outcome=ReportedOutcome.SUCCESS,
            result=result,
            transport_status=transport_status,
        )

    def on_tool_error(
        self, tool_id: str, parameters: object, detail: Optional[str] = None
    ) -> None:
        self._em.tool_reported(
            tool_id=tool_id,
            parameters=parameters,
            outcome=ReportedOutcome.FAILURE,
            result=None if detail is None else {"error": detail},
        )

    # ── handoff ─────────────────────────────────────────────────────────

    def on_handoff(
        self, boundary: PropagationBoundary, to_execution_id: bytes
    ) -> None:
        """Record that this execution handed context to another.

        Emitted on the parent side. The child emits its own events naming
        this execution as its parent, so a verifier sees both halves and can
        notice a child claiming a parent that never declared it.
        """
        self._em.context_propagated(boundary, to_execution_id)
