"""AIRI event construction and canonical encoding, matching ``aip-airi``.

The preimage layout is defined once, in Rust, at
``aip-standalone/aip-airi/src/event.rs``. This module reproduces it exactly;
``tests/test_canonical_parity.py`` proves the two agree on generated vectors.

Nothing here decides anything. An event is a statement, and every statement
this module builds is a self-report by the agent that signs it.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Union

from .canonical import (
    put_bytes,
    put_domain,
    put_opt_digest,
    put_opt_str,
    put_str,
    put_u8,
    put_u16,
    put_u64,
)

AIRI_EVENT_DOMAIN = "SYNTRIASS/AIRI/EVENT/v1"
AIRI_EVENT_VERSION = 1

#: Mirrors ``MAX_FIELD_LEN`` in the Rust verifier. Exceeding it here would
#: produce an event the Rust side refuses, so the SDK refuses it first.
MAX_FIELD_LEN = 4096

__all__ = [
    "AIRI_EVENT_DOMAIN",
    "AIRI_EVENT_VERSION",
    "AiriEventKind",
    "FrameworkIdentity",
    "ProcessInstance",
    "RuntimeBinding",
    "EXECUTION_IDENTITY_DOMAIN",
    "EXECUTION_BINDING_VERSION",
    "ModelProvenance",
    "ToolInvocation",
    "ToolReport",
    "SubprocessReport",
    "AgentStart",
    "Completion",
    "ContextPropagationBody",
    "PropagationBoundary",
    "ReportedOutcome",
    "AiriEvent",
]


class AiriEventKind(enum.IntEnum):
    """Event discriminants. Part of the signed preimage."""

    AGENT_EXECUTION_STARTED = 0x01
    MODEL_INVOCATION_REQUESTED = 0x02
    #: Named "Observed" by the AIRI specification. **Not** independent
    #: observation — the observer is the framework, inside the process under
    #: scrutiny. Carries no more weight than any other self-report.
    MODEL_INVOCATION_OBSERVED = 0x03
    TOOL_INVOCATION_REQUESTED = 0x04
    TOOL_EXECUTION_REPORTED = 0x05
    SUBPROCESS_EXECUTION = 0x06
    EXECUTION_COMPLETED = 0x07
    EXECUTION_FAILED = 0x08
    EXECUTION_CONTEXT_PROPAGATED = 0x09


class ReportedOutcome(enum.IntEnum):
    SUCCESS = 0x01
    FAILURE = 0x02
    #: The agent declined to act — a refusal, a guardrail, a policy stop.
    DENIED = 0x03
    INDETERMINATE = 0x04


class PropagationBoundary(enum.IntEnum):
    ASYNC_TASK = 0x01
    THREAD = 0x02
    PROCESS = 0x03
    SUBPROCESS = 0x04
    WORKER_QUEUE = 0x05


@dataclass(frozen=True)
class FrameworkIdentity:
    """Which framework produced the event and which adapter translated it.

    Recorded for provenance. Never a trust input: nothing in AIRI grants
    anything on the strength of a framework's name.
    """

    name: str
    version: str
    adapter_version: str

    def encode(self, buf: bytearray) -> None:
        put_str(buf, self.name)
        put_str(buf, self.version)
        put_str(buf, self.adapter_version)


#: Domain tag of the execution-identity encoding, from
#: ``aip_types::EXECUTION_IDENTITY_DOMAIN``.
EXECUTION_IDENTITY_DOMAIN = "GHOST/ExecutionIdentity/v1"

#: From ``aip_types::EXECUTION_BINDING_VERSION``.
EXECUTION_BINDING_VERSION = 1


@dataclass(frozen=True)
class ProcessInstance:
    """pid + start ticks + boot id — the tuple that survives pid reuse."""

    pid: int
    pid_start_time_ticks: int
    boot_id: bytes

    def encode(self, buf: bytearray) -> None:
        """Raw fixed-width, matching ``ExecutionBinding::identity_bytes``.

        Note these fields are *not* length-prefixed: they are fixed width, so
        prefixing them would add bytes the Rust encoder does not write. The
        parity vectors caught exactly that mistake once already.
        """
        buf.extend(self.pid.to_bytes(4, "little"))
        buf.extend(self.pid_start_time_ticks.to_bytes(8, "little"))
        if len(self.boot_id) != 16:
            raise ValueError("boot_id must be 16 bytes")
        buf.extend(self.boot_id)


@dataclass(frozen=True)
class RuntimeBinding:
    """The process the agent *believes* it is in.

    Self-reported. The authoritative binding is the observer's. This exists
    so a verifier can compare the two and notice a disagreement; a match
    proves nothing on its own, because a compromised process can tell the
    truth about its pid while lying about everything else.
    """

    agent_id: str
    process: ProcessInstance
    exe_content_sha256: bytes
    version: int = EXECUTION_BINDING_VERSION

    def identity_bytes(self) -> bytes:
        """Matches ``ExecutionBinding::identity_bytes`` in aip-types exactly.

        ``exe_path`` and ``bound_at_ms`` are excluded: two spellings of the
        same binary are one identity, and a same-path different binary is not.

        ``exe_content_sha256`` is appended raw, not length-prefixed — it is a
        fixed-width field. The cross-language parity vectors enforce this.
        """
        buf = bytearray()
        put_domain(buf, EXECUTION_IDENTITY_DOMAIN)
        put_u16(buf, self.version)
        put_str(buf, self.agent_id)
        self.process.encode(buf)
        if len(self.exe_content_sha256) != 32:
            raise ValueError("exe_content_sha256 must be 32 bytes")
        buf.extend(self.exe_content_sha256)
        return bytes(buf)


@dataclass(frozen=True)
class AgentStart:
    agent_role: Optional[str] = None
    framework_run_id: Optional[str] = None

    def encode(self, buf: bytearray) -> None:
        put_opt_str(buf, self.agent_role)
        put_opt_str(buf, self.framework_run_id)


@dataclass(frozen=True)
class ModelProvenance:
    """What the agent says about a model invocation.

    Establishes that the runtime *asked* for ``model_id``. It does not
    establish that the provider served it, that an accelerator ran anything,
    or that ``model_digest`` describes the weights actually loaded. For
    hosted models ``model_digest`` is ``None``, and that absence is the
    honest answer rather than a gap to be filled.
    """

    model_id: str
    runtime: str
    model_digest: Optional[bytes] = None
    runtime_version: Optional[str] = None
    inference_request_id: Optional[str] = None
    prompt_commitment: Optional[bytes] = None
    output_commitment: Optional[bytes] = None
    #: Self-reported accelerator description. Never proof a GPU ran anything.
    accelerator: Optional[str] = None

    def encode(self, buf: bytearray) -> None:
        put_str(buf, self.model_id)
        put_opt_digest(buf, self.model_digest)
        put_str(buf, self.runtime)
        put_opt_str(buf, self.runtime_version)
        put_opt_str(buf, self.inference_request_id)
        put_opt_digest(buf, self.prompt_commitment)
        put_opt_digest(buf, self.output_commitment)
        put_opt_str(buf, self.accelerator)


@dataclass(frozen=True)
class ToolInvocation:
    """Layer 1 of three: the *requested* invocation. Not execution, not effect."""

    tool_id: str
    action_kind: str
    parameter_commitment: bytes
    tool_call_id: Optional[str] = None
    target: Optional[str] = None

    def encode(self, buf: bytearray) -> None:
        put_str(buf, self.tool_id)
        put_str(buf, self.action_kind)
        put_bytes(buf, self.parameter_commitment)
        put_opt_str(buf, self.tool_call_id)
        put_opt_str(buf, self.target)


@dataclass(frozen=True)
class ToolReport:
    """What came back to the process. Not proof the external effect occurred.

    A 200 means bytes resembling a success reached this process. A proxy, a
    stub, a replayed cassette, or a service that acknowledged and then failed
    all produce the same value.
    """

    tool_id: str
    parameter_commitment: bytes
    outcome: ReportedOutcome
    result_commitment: Optional[bytes] = None
    transport_status: Optional[int] = None

    def encode(self, buf: bytearray) -> None:
        put_str(buf, self.tool_id)
        put_bytes(buf, self.parameter_commitment)
        put_u8(buf, int(self.outcome))
        put_opt_digest(buf, self.result_commitment)
        if self.transport_status is None:
            put_u8(buf, 0)
        else:
            put_u8(buf, 1)
            put_u64(buf, self.transport_status)


@dataclass(frozen=True)
class SubprocessReport:
    program: str
    argv_commitment: bytes
    reported_pid: Optional[int] = None

    def encode(self, buf: bytearray) -> None:
        put_str(buf, self.program)
        put_bytes(buf, self.argv_commitment)
        if self.reported_pid is None:
            put_u8(buf, 0)
        else:
            put_u8(buf, 1)
            put_u64(buf, self.reported_pid)


@dataclass(frozen=True)
class Completion:
    outcome: ReportedOutcome
    detail: Optional[str] = None

    def encode(self, buf: bytearray) -> None:
        put_u8(buf, int(self.outcome))
        put_opt_str(buf, self.detail)


@dataclass(frozen=True)
class ContextPropagationBody:
    boundary: PropagationBoundary
    to_execution_id: bytes

    def encode(self, buf: bytearray) -> None:
        put_u8(buf, int(self.boundary))
        put_bytes(buf, self.to_execution_id)


Payload = Union[
    AgentStart,
    ModelProvenance,
    ToolInvocation,
    ToolReport,
    SubprocessReport,
    Completion,
    ContextPropagationBody,
]


@dataclass
class AiriEvent:
    """One self-authored statement, ready to sign.

    ``signature`` is filled by the emitter. An event without one is a draft
    and must never leave the process.
    """

    kind: AiriEventKind
    agent_id: str
    execution_id: bytes
    sequence: int
    prev_event_hash: bytes
    emitted_at_ms: int
    framework: FrameworkIdentity
    payload: Payload
    parent_execution_id: Optional[bytes] = None
    decision_id: Optional[bytes] = None
    runtime_binding: Optional[RuntimeBinding] = None
    version: int = AIRI_EVENT_VERSION
    signature: Optional[bytes] = field(default=None, compare=False)

    def signing_preimage(self) -> bytes:
        """The exact bytes the agent signs. Mirrors ``AiriEvent::signing_preimage``."""
        self._check_bounds()
        buf = bytearray()
        put_domain(buf, AIRI_EVENT_DOMAIN)
        put_u16(buf, self.version)
        put_str(buf, self.agent_id)
        put_bytes(buf, self.execution_id)
        _put_opt_id(buf, self.parent_execution_id)
        _put_opt_id(buf, self.decision_id)
        put_u64(buf, self.sequence)
        put_bytes(buf, self.prev_event_hash)
        put_u64(buf, self.emitted_at_ms)
        self.framework.encode(buf)
        if self.runtime_binding is None:
            put_u8(buf, 0)
        else:
            put_u8(buf, 1)
            put_bytes(buf, self.runtime_binding.identity_bytes())
        put_u8(buf, int(self.kind))
        self.payload.encode(buf)
        return bytes(buf)

    def event_hash(self) -> bytes:
        """What the next event in this chain carries as ``prev_event_hash``."""
        return hashlib.sha256(self.signing_preimage()).digest()

    def _check_bounds(self) -> None:
        for name, s in (
            ("agent_id", self.agent_id),
            ("framework.name", self.framework.name),
            ("framework.version", self.framework.version),
            ("framework.adapter_version", self.framework.adapter_version),
        ):
            if len(s.encode("utf-8")) > MAX_FIELD_LEN:
                raise ValueError(
                    f"{name} exceeds {MAX_FIELD_LEN} bytes; the Rust verifier "
                    "would refuse this event"
                )
        if not self.agent_id:
            raise ValueError("agent_id must not be empty")
        if not self.framework.name:
            raise ValueError("framework.name must not be empty")
        if len(self.execution_id) != 16:
            raise ValueError("execution_id must be 16 bytes")
        if len(self.prev_event_hash) != 32:
            raise ValueError("prev_event_hash must be 32 bytes")


def _put_opt_id(buf: bytearray, v: Optional[bytes]) -> None:
    if v is None:
        put_u8(buf, 0)
    else:
        if len(v) != 16:
            raise ValueError("identifier must be 16 bytes")
        put_u8(buf, 1)
        put_bytes(buf, v)
