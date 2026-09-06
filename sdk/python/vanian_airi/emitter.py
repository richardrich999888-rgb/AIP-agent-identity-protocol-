"""Building, signing and chaining AIRI events from a Python agent.

# The boundary this class sits on

:class:`AiriEmitter` is the agent's mouth, not its judge. It produces signed
statements about what the agent did. It has no method that authorizes, no
method that produces a verdict, and no access to observer keys. The list of
things it deliberately cannot do is in ``docs/architecture/AIRI_THREAT_MODEL.md``
and is enforced by absence: there is no ``prove()``, no ``warrant()``, no
``set_strength()``.

# Sinks

An emitter writes to a :class:`EventSink`. The default sink appends to an
in-memory list, which is what tests use. Production deployments hand events
to a collector over a transport of their choosing; the SDK does not open
sockets, because a transport failure inside an agent's critical path is a
denial-of-service against the agent, and a transport that silently drops
events is worse than one the operator chose knowingly.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, List, Optional, Protocol

from .commitment import commit_bytes, commit_json
from .context import ExecutionContext, current
from .errors import AiriError
from .events import (
    AgentStart,
    AiriEvent,
    AiriEventKind,
    Completion,
    ContextPropagationBody,
    FrameworkIdentity,
    ModelProvenance,
    PropagationBoundary,
    ReportedOutcome,
    RuntimeBinding,
    SubprocessReport,
    ToolInvocation,
    ToolReport,
)
from .identity import AgentIdentity

__all__ = ["AiriEmitter", "EventSink", "ListSink"]

_GENESIS = bytes(32)


class EventSink(Protocol):
    """Where signed events go. Implementations must not mutate the event."""

    def emit(self, event: AiriEvent) -> None: ...


class ListSink:
    """Collects events in memory. For tests and for a caller that batches."""

    def __init__(self) -> None:
        self.events: List[AiriEvent] = []

    def emit(self, event: AiriEvent) -> None:
        self.events.append(event)


class AiriEmitter:
    """Signs and chains one execution's events.

    One emitter per execution. The sequence counter and chain head are
    per-execution state, and sharing an emitter across executions would
    interleave two chains into one broken sequence.

    Thread-safe: ``_lock`` serialises the read-modify-write of the sequence
    counter and chain head. Without it two threads emitting concurrently
    would produce duplicate sequence numbers, which the Rust chain verifier
    correctly reports as a replay — a self-inflicted false positive.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        framework: FrameworkIdentity,
        sink: Optional[EventSink] = None,
        runtime_binding: Optional[RuntimeBinding] = None,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ) -> None:
        self._identity = identity
        self._framework = framework
        self._sink: EventSink = sink if sink is not None else ListSink()
        self._runtime_binding = runtime_binding
        self._clock_ms = clock_ms
        self._sequence = 0
        self._head = _GENESIS
        self._lock = threading.Lock()

    # ── internals ───────────────────────────────────────────────────────

    def _emit(
        self,
        kind: AiriEventKind,
        payload: object,
        ctx: Optional[ExecutionContext] = None,
    ) -> AiriEvent:
        c = ctx if ctx is not None else current()
        if c.agent_id != self._identity.aip_id:
            raise AiriError(
                f"context is for agent {c.agent_id!r} but this emitter signs "
                f"for {self._identity.aip_id!r}; an agent signs only for itself"
            )
        with self._lock:
            event = AiriEvent(
                kind=kind,
                agent_id=self._identity.aip_id,
                execution_id=c.execution_id,
                parent_execution_id=c.parent_execution_id,
                decision_id=c.decision_id,
                sequence=self._sequence,
                prev_event_hash=self._head,
                emitted_at_ms=self._clock_ms(),
                framework=self._framework,
                runtime_binding=self._runtime_binding,
                payload=payload,  # type: ignore[arg-type]
            )
            preimage = event.signing_preimage()
            event.signature = self._identity.sign(preimage)
            self._sequence += 1
            self._head = event.event_hash()
        self._sink.emit(event)
        return event

    # ── the nine event kinds ────────────────────────────────────────────

    def agent_started(
        self, agent_role: Optional[str] = None, framework_run_id: Optional[str] = None
    ) -> AiriEvent:
        return self._emit(
            AiriEventKind.AGENT_EXECUTION_STARTED,
            AgentStart(agent_role=agent_role, framework_run_id=framework_run_id),
        )

    def model_requested(self, provenance: ModelProvenance) -> AiriEvent:
        """The agent asked for a model. Not proof the provider served it."""
        return self._emit(AiriEventKind.MODEL_INVOCATION_REQUESTED, provenance)

    def model_observed(self, provenance: ModelProvenance) -> AiriEvent:
        """The framework reported back about an inference call.

        Named "observed" by the specification; the observer is the framework,
        inside this process. No more authoritative than any other self-report.
        """
        return self._emit(AiriEventKind.MODEL_INVOCATION_OBSERVED, provenance)

    def tool_requested(
        self,
        tool_id: str,
        action_kind: str,
        parameters: object,
        tool_call_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> AiriEvent:
        """Layer 1: the agent asked a tool to do something.

        ``parameters`` is committed, never carried — see
        :func:`~vanian_airi.commitment.commit_json`.
        """
        return self._emit(
            AiriEventKind.TOOL_INVOCATION_REQUESTED,
            ToolInvocation(
                tool_id=tool_id,
                action_kind=action_kind,
                parameter_commitment=commit_json(parameters),
                tool_call_id=tool_call_id,
                target=target,
            ),
        )

    def tool_reported(
        self,
        tool_id: str,
        parameters: object,
        outcome: ReportedOutcome,
        result: object = None,
        transport_status: Optional[int] = None,
    ) -> AiriEvent:
        """Layer 2 reporting on layer 3, which it cannot see across.

        A success here means bytes resembling a success reached this process.
        It is not evidence that the external effect occurred, and no
        combination of arguments to this method can make it one.
        """
        return self._emit(
            AiriEventKind.TOOL_EXECUTION_REPORTED,
            ToolReport(
                tool_id=tool_id,
                parameter_commitment=commit_json(parameters),
                outcome=outcome,
                result_commitment=None if result is None else commit_json(result),
                transport_status=transport_status,
            ),
        )

    def subprocess_spawned(
        self, program: str, argv: list[str], reported_pid: Optional[int] = None
    ) -> AiriEvent:
        """A subprocess the agent says it started.

        ``argv`` is committed rather than carried: argument vectors routinely
        contain credentials, and evidence is immutable.
        """
        return self._emit(
            AiriEventKind.SUBPROCESS_EXECUTION,
            SubprocessReport(
                program=program,
                argv_commitment=commit_json(argv),
                reported_pid=reported_pid,
            ),
        )

    def context_propagated(
        self, boundary: PropagationBoundary, to_execution_id: bytes
    ) -> AiriEvent:
        return self._emit(
            AiriEventKind.EXECUTION_CONTEXT_PROPAGATED,
            ContextPropagationBody(boundary=boundary, to_execution_id=to_execution_id),
        )

    def completed(self, detail: Optional[str] = None) -> AiriEvent:
        return self._emit(
            AiriEventKind.EXECUTION_COMPLETED,
            Completion(outcome=ReportedOutcome.SUCCESS, detail=detail),
        )

    def failed(self, detail: Optional[str] = None) -> AiriEvent:
        return self._emit(
            AiriEventKind.EXECUTION_FAILED,
            Completion(outcome=ReportedOutcome.FAILURE, detail=detail),
        )

    def denied(self, detail: Optional[str] = None) -> AiriEvent:
        """The agent declined to act.

        Worth its own call: a refusal is a claim about a *non*-execution, and
        where independent evidence supports it, that is a verifiable property
        rather than an absence.
        """
        return self._emit(
            AiriEventKind.EXECUTION_FAILED,
            Completion(outcome=ReportedOutcome.DENIED, detail=detail),
        )

    # ── deliberately absent ─────────────────────────────────────────────
    #
    # There is no prove(), no set_evidence_strength(), no issue_warrant(),
    # no authorize(), and no load_observer_key(). Each absence is a security
    # property, not an omission; adding any of them would let the party under
    # scrutiny author the evidence used to judge it.

    @property
    def sequence(self) -> int:
        """Next sequence number. Exposed for tests and for a caller resuming
        a chain; setting it is deliberately not supported."""
        return self._sequence

    @property
    def head(self) -> bytes:
        """Current chain head."""
        return self._head
