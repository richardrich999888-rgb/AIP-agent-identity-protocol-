"""Execution context and its propagation across Python's concurrency edges.

# What a context is

An :class:`ExecutionContext` names *which* agent run an event belongs to: the
agent id, the AIRI execution id, the parent execution, and the
``ExpectedExecution`` the run claims authorization from. Without it an event
cannot be attributed, and an event attributed to the wrong execution is worse
than no event at all — which is why every lookup here fails closed rather
than inventing a context.

# Why ``contextvars`` and not a global

``contextvars.ContextVar`` is the only mechanism in Python that survives an
``await`` without leaking between concurrently running tasks. A module-level
global would be shared by every task on the event loop, so two agent runs
interleaving on one loop would overwrite each other's context and file their
events under whichever ran last. That is a silent misattribution bug, and in
this system misattribution is the failure we exist to prevent.

# The four edges

======================  ======================================================
Edge                    Mechanism
======================  ======================================================
``await`` / task        ``contextvars`` copies the context into the new task
Thread                  explicit: :func:`bind` inside the thread, from a
                        context captured with :func:`current`
Process (fork/spawn)    explicit: serialize with :meth:`ExecutionContext.to_env`,
                        restore with :func:`from_env` in the child
Subprocess              same as process — the child gets the context in its
                        environment and emits its own events under it
======================  ======================================================

Threads and processes are deliberately explicit. ``contextvars`` does not
cross a thread boundary, and a convenience wrapper that copied the context
automatically would attribute a worker's actions to whichever run happened to
spawn it. Making the handoff visible in the code is the point: a handoff is a
lineage event and it should be written down.

# What the environment carries, and what it does not

:meth:`ExecutionContext.to_env` carries identifiers only. It never carries
the signing key. A child process that needs to sign its own events loads its
own identity through :func:`~vanian_airi.identity.load_agent_identity`; the
parent does not hand it a key through the environment, where it would appear
in ``/proc/<pid>/environ`` for every process on the host.
"""

from __future__ import annotations

import contextvars
import os
import secrets
from dataclasses import dataclass, replace
from typing import Iterator, Mapping, Optional

from .errors import ContextMalformed, ContextUnavailable

__all__ = [
    "ExecutionContext",
    "bind",
    "current",
    "current_or_none",
    "new_execution",
    "child_execution",
    "from_env",
    "ENV_KEY",
]

#: Environment variable carrying a serialized context across a process edge.
ENV_KEY = "VANIAN_AIRI_CONTEXT"

_CTX: contextvars.ContextVar["ExecutionContext"] = contextvars.ContextVar(
    "vanian_airi_execution_context"
)


@dataclass(frozen=True)
class ExecutionContext:
    """Which agent run the next event belongs to.

    Frozen: a context is replaced, never mutated. Mutating a context that a
    concurrent task already captured would retroactively change where that
    task's events are filed.
    """

    agent_id: str
    execution_id: bytes
    parent_execution_id: Optional[bytes] = None
    decision_id: Optional[bytes] = None

    def __post_init__(self) -> None:
        if not self.agent_id:
            raise ContextMalformed("agent_id must not be empty")
        for name in ("execution_id", "parent_execution_id", "decision_id"):
            v = getattr(self, name)
            if v is not None and len(v) != 16:
                raise ContextMalformed(f"{name} must be 16 bytes, got {len(v)}")
        if self.execution_id is None:
            raise ContextMalformed("execution_id is required")

    def to_env(self) -> dict[str, str]:
        """Serialize identifiers for a child process.

        Format: ``v1:<agent_id>:<execution_hex>:<parent_hex|->:<decision_hex|->``.
        Version-tagged so a future change is a parse failure in an old child
        rather than a silent misread.
        """
        def h(b: Optional[bytes]) -> str:
            return b.hex() if b else "-"

        if ":" in self.agent_id:
            raise ContextMalformed("agent_id must not contain ':'")
        value = ":".join(
            [
                "v1",
                self.agent_id,
                self.execution_id.hex(),
                h(self.parent_execution_id),
                h(self.decision_id),
            ]
        )
        return {ENV_KEY: value}

    def with_decision(self, decision_id: Optional[bytes]) -> "ExecutionContext":
        """Attach (or clear) the ExpectedExecution this run claims."""
        return replace(self, decision_id=decision_id)


def _parse(value: str) -> ExecutionContext:
    parts = value.split(":")
    if len(parts) != 5 or parts[0] != "v1":
        raise ContextMalformed(f"unrecognised context encoding: {value!r}")
    _, agent_id, exec_hex, parent_hex, decision_hex = parts

    def unhex(s: str, name: str) -> Optional[bytes]:
        if s == "-":
            return None
        try:
            b = bytes.fromhex(s)
        except ValueError as exc:
            raise ContextMalformed(f"{name} is not hex: {s!r}") from exc
        if len(b) != 16:
            raise ContextMalformed(f"{name} must be 16 bytes, got {len(b)}")
        return b

    exec_id = unhex(exec_hex, "execution_id")
    if exec_id is None:
        raise ContextMalformed("execution_id must be present")
    return ExecutionContext(
        agent_id=agent_id,
        execution_id=exec_id,
        parent_execution_id=unhex(parent_hex, "parent_execution_id"),
        decision_id=unhex(decision_hex, "decision_id"),
    )


def from_env(env: Optional[Mapping[str, str]] = None) -> ExecutionContext:
    """Restore a context a parent process placed in the environment.

    :raises ContextUnavailable: if no context is present.
    :raises ContextMalformed: if one is present but unparseable. A malformed
        context is never repaired or ignored — the child would then emit
        events under an identity nobody chose.
    """
    src = os.environ if env is None else env
    raw = src.get(ENV_KEY)
    if raw is None:
        raise ContextUnavailable(
            f"{ENV_KEY} is not set; this process was not handed an execution context"
        )
    return _parse(raw)


def new_execution(agent_id: str, decision_id: Optional[bytes] = None) -> ExecutionContext:
    """Start a fresh root execution with a random 128-bit id.

    ``secrets.token_bytes`` is used rather than ``random``: execution ids are
    join keys in evidence, and a predictable id lets an attacker pre-compute
    events for a run that has not started.
    """
    return ExecutionContext(
        agent_id=agent_id,
        execution_id=secrets.token_bytes(16),
        parent_execution_id=None,
        decision_id=decision_id,
    )


def child_execution(parent: ExecutionContext) -> ExecutionContext:
    """Derive a child execution for a worker, thread, or subprocess.

    The child gets a fresh id and names its parent. It inherits the parent's
    ``decision_id`` and **no more**: being spawned by a run confers no
    additional authority, and nothing here widens scope.
    """
    return ExecutionContext(
        agent_id=parent.agent_id,
        execution_id=secrets.token_bytes(16),
        parent_execution_id=parent.execution_id,
        decision_id=parent.decision_id,
    )


class _Binding:
    """Context manager returned by :func:`bind`."""

    __slots__ = ("_token", "_ctx")

    def __init__(self, ctx: ExecutionContext) -> None:
        self._ctx = ctx
        self._token: Optional[contextvars.Token] = None

    def __enter__(self) -> ExecutionContext:
        self._token = _CTX.set(self._ctx)
        return self._ctx

    def __exit__(self, *exc: object) -> None:
        if self._token is not None:
            _CTX.reset(self._token)
            self._token = None


def bind(ctx: ExecutionContext) -> _Binding:
    """Make ``ctx`` the active execution for the duration of the block.

    Reentrant and exception-safe: the previous context is restored on exit,
    including when the block raises. Works across ``await`` because it is
    backed by ``contextvars``.

    >>> with bind(new_execution("aip1abc")) as ctx:   # doctest: +SKIP
    ...     emitter.tool_requested(...)
    """
    return _Binding(ctx)


def current() -> ExecutionContext:
    """The active execution context.

    :raises ContextUnavailable: if none is bound. This is a hard error rather
        than a default, because the alternative is filing an event against a
        guessed execution.
    """
    try:
        return _CTX.get()
    except LookupError as exc:
        raise ContextUnavailable(
            "no execution context is bound; wrap the work in `with bind(...)`"
        ) from exc


def current_or_none() -> Optional[ExecutionContext]:
    """The active context, or ``None``. For callers that legitimately have
    no context yet — an adapter deciding whether to start one."""
    return _CTX.get(None)
