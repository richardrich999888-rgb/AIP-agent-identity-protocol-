"""Reference tool / API / effect adapter.

# The three layers this adapter refuses to collapse

::

    1. Requested invocation   the agent asked for something
    2. Runtime execution      a client library ran and returned
    3. External effect        the far side actually did it

An HTTP 200 is evidence of layer 2. It is routinely mistaken for evidence of
layer 3, and that mistake is the single most common way an accountability
system ends up certifying things that never happened. A proxy, a stub, a
recorded cassette, a compromised client library, a load balancer that
acknowledged and dropped, a database that returned success and then rolled
back — all produce a 200.

:class:`ToolAdapter` therefore emits two events, not one:

* ``TOOL_INVOCATION_REQUESTED`` when the call is about to be made;
* ``TOOL_EXECUTION_REPORTED`` when the client returns.

Both are self-reports. Neither asserts the external effect, and there is no
third method that does, because this process has no way to know.

# What can raise the answer

Only independent observation, joined in ``aip_airi::corroborate``: a
collector-signed kernel socket transition bound to this process instance,
inside the authorized window. Even then the ceiling is what the reconciler
allows — ``Attested``, never ``Proven``, because the content of an
observation is procfs-derived and root-forgeable.

# Gateways are not trust anchors

An MCP gateway or an API gateway that sits between the agent and the world is
a better vantage point than the agent, and it is still not authoritative
until its key lifecycle, transport and independent verification are defined
and tested. Until then a gateway's report is another self-report, from a
different self.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Optional

from ..emitter import AiriEmitter
from ..commitment import commit_json
from ..errors import AiriError
from ..events import ReportedOutcome

__all__ = ["ToolAdapter", "ToolCall"]


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation in flight.

    Returned by :meth:`ToolAdapter.request` and passed back to
    :meth:`ToolAdapter.report`, so the report necessarily commits to the same
    parameters as the request. Making the caller re-supply the parameters by
    hand invites a mismatch that a verifier would correctly read as a
    parameter substitution.
    """

    tool_id: str
    action_kind: str
    parameters: Any
    tool_call_id: Optional[str] = None
    target: Optional[str] = None
    _parameter_commitment: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Client libraries may mutate the caller's arguments while executing.
        # Keep the request's snapshot, including nested lists and dictionaries.
        parameters = deepcopy(self.parameters)
        object.__setattr__(self, "parameters", parameters)
        object.__setattr__(self, "_parameter_commitment", commit_json(parameters))


class ToolAdapter:
    """Emits the request and the report as two distinct statements."""

    def __init__(self, emitter: AiriEmitter) -> None:
        self._em = emitter

    def request(
        self,
        tool_id: str,
        action_kind: str,
        parameters: Any,
        *,
        tool_call_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> ToolCall:
        """Layer 1. Call this **before** the tool runs.

        Emitting before the call is what makes a missing report meaningful:
        a request with no matching report is a run that died mid-call, and a
        request the observer never corroborates is the phantom-claim shape.
        Emitting only after success would erase both.
        """
        call = ToolCall(
            tool_id=tool_id,
            action_kind=action_kind,
            parameters=parameters,
            tool_call_id=tool_call_id,
            target=target,
        )
        self._em.tool_requested(
            tool_id=call.tool_id,
            action_kind=call.action_kind,
            parameters=call.parameters,
            tool_call_id=call.tool_call_id,
            target=call.target,
        )
        return call

    def report(
        self,
        call: ToolCall,
        outcome: ReportedOutcome,
        *,
        result: Any = None,
        transport_status: Optional[int] = None,
    ) -> None:
        """Layer 2. What the client library returned to this process.

        Not evidence of layer 3. There is no argument to this method, and no
        other method on this class, that asserts the external effect occurred.
        """
        # A frozen dataclass does not freeze nested dictionaries or lists.
        # Refuse a changed handle rather than sign a contradictory report.
        parameters = deepcopy(call.parameters)
        if commit_json(parameters) != call._parameter_commitment:
            raise AiriError("tool parameters changed after the request")
        self._em.tool_reported(
            tool_id=call.tool_id,
            parameters=parameters,
            outcome=outcome,
            result=result,
            transport_status=transport_status,
        )

    def subprocess(
        self, program: str, argv: list[str], reported_pid: Optional[int] = None
    ) -> None:
        """A subprocess the agent says it spawned.

        ``argv`` is committed rather than carried — argument vectors routinely
        contain credentials and evidence is immutable. ``program`` is a path,
        not a measurement: a same-path different binary is a different
        program and this field cannot tell the difference. The observer's
        ``exe_content_sha256`` can.
        """
        self._em.subprocess_spawned(program, argv, reported_pid)

    # ── deliberately absent ─────────────────────────────────────────────
    #
    # There is no `confirm_effect()`, no `mark_applied()`, and no
    # `external_effect_verified()`. The process that made the call cannot
    # establish that the call landed, and an API shaped like it could would
    # be used as though it did.
