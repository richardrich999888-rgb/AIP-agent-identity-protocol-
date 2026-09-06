"""Vanian AIRI — the Python boundary for AI-stack accountability.

An agent uses this SDK to make *signed statements* about what it did. It does
not use it to prove anything: proof requires independent observation, which
by construction happens somewhere this process cannot reach.

Minimal example::

    from vanian_airi import (
        load_agent_identity, new_execution, bind,
        AiriEmitter, FrameworkIdentity, ReportedOutcome,
    )

    identity = load_agent_identity("aip1abc...", "/run/secrets/agent.key")
    emitter = AiriEmitter(
        identity,
        FrameworkIdentity("langgraph", "0.2.0", "vanian-airi-adapter/1"),
    )

    with bind(new_execution(identity.aip_id, decision_id=expectation_id)):
        emitter.agent_started(agent_role="researcher")
        emitter.tool_requested("http.post", "http.post", {"url": url})
        # ... the actual call happens here ...
        emitter.tool_reported("http.post", {"url": url},
                              ReportedOutcome.SUCCESS, transport_status=200)
        emitter.completed()

What the resulting events establish: that this agent said these things, in
this order, about this execution, under this authorization. What they do not
establish: that any of it happened. That question is settled by
``aip_airi::corroborate`` against collector-signed observation, and its
default answer is "cannot prove".

Dependencies: the Python standard library, plus ``cryptography`` for Ed25519.
"""

from .commitment import AIRI_PARAM_DOMAIN, commit_bytes, commit_json
from .context import (
    ENV_KEY,
    ExecutionContext,
    bind,
    child_execution,
    current,
    current_or_none,
    from_env,
    new_execution,
)
from .emitter import AiriEmitter, EventSink, ListSink
from .errors import (
    AiriError,
    CommitmentError,
    ContextMalformed,
    ContextUnavailable,
    IdentityUnavailable,
)
from .events import (
    AIRI_EVENT_DOMAIN,
    AIRI_EVENT_VERSION,
    AgentStart,
    AiriEvent,
    AiriEventKind,
    Completion,
    ContextPropagationBody,
    FrameworkIdentity,
    ModelProvenance,
    ProcessInstance,
    PropagationBoundary,
    ReportedOutcome,
    RuntimeBinding,
    SubprocessReport,
    ToolInvocation,
    ToolReport,
)
from .identity import AgentIdentity, load_agent_identity

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # identity
    "AgentIdentity",
    "load_agent_identity",
    # context
    "ExecutionContext",
    "bind",
    "current",
    "current_or_none",
    "new_execution",
    "child_execution",
    "from_env",
    "ENV_KEY",
    # emission
    "AiriEmitter",
    "EventSink",
    "ListSink",
    # events
    "AiriEvent",
    "AiriEventKind",
    "FrameworkIdentity",
    "ProcessInstance",
    "RuntimeBinding",
    "ModelProvenance",
    "ToolInvocation",
    "ToolReport",
    "SubprocessReport",
    "AgentStart",
    "Completion",
    "ContextPropagationBody",
    "PropagationBoundary",
    "ReportedOutcome",
    "AIRI_EVENT_DOMAIN",
    "AIRI_EVENT_VERSION",
    # commitments
    "commit_bytes",
    "commit_json",
    "AIRI_PARAM_DOMAIN",
    # errors
    "AiriError",
    "IdentityUnavailable",
    "ContextUnavailable",
    "ContextMalformed",
    "CommitmentError",
]
