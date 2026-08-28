"""otgovern — the ASC SENTINEL governance SDK for Python agents.

An agent imports this package, seals its own NEXORA lifecycle anchors and
AIP evidence packets locally, and (optionally) streams them to a governance
hub. The chains it produces are byte-identical to the Rust core's: the
canonical form is compact JSON with recursively sorted keys, which is what
``json.dumps(separators=(",", ":"), sort_keys=True, ensure_ascii=False)``
emits and what serde_json's BTree-backed maps emit — making this the fourth
implementation (Rust native, browser WASM, TypeScript, Python) of one byte
contract, provable with ``ot-verifier`` against any chain built here.

The Rust core enforces the lifecycle law at compile time (typestates);
Python cannot, so this SDK enforces it at runtime with unambiguous
exceptions: executing before delegation raises, anything after a terminal
revocation raises, and a blocked execution records post-state == pre-state
by construction.

No dependencies outside the standard library — the point of an SDK is to
be adoptable, and ``urllib`` is everywhere.

Quick start::

    from otgovern import GovernedAgent, HubClient, governed

    agent = GovernedAgent.born(
        did="did:syntriass:agent:AGT-PY-001",
        supervisor_did="did:syntriass:officer:OFFICER-1",
        model_digest="0" * 64,
    ).delegate(scope=["search_flights"], clearance_level="SECRET")

    # Optional: stream every sealed record to a governance hub. The hub's
    # receipt must echo the locally computed tail hash — a live proof that
    # the server verified byte-identical chains.
    agent.attach(HubClient("http://localhost:8080", token="fleet-token-1"))

    @governed(agent, "search_flights", state_fn=lambda: {"screen": "search"})
    def search_flights(query: str):
        ...

Wrapping an MCP tool handler works the same way — decorate the handler the
server registers, and every MCP tool call becomes a governed, sealed,
hub-attested execution.
"""

from __future__ import annotations

import functools
import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

__all__ = [
    "GENESIS_HASH",
    "GovernanceError",
    "GovernedAgent",
    "HubClient",
    "HubRejection",
    "LifecycleError",
    "canonical_json",
    "governed",
    "seal_hash",
    "sha256_hex",
]

GENESIS_HASH = "0" * 64

_ANCHOR_CHAIN_FIELDS = ("previousAnchorHash", "anchorHash")
_PACKET_CHAIN_FIELDS = ("previousPacketHash", "packetHash")


class GovernanceError(Exception):
    """Base class for SDK errors."""


class LifecycleError(GovernanceError):
    """The runtime lifecycle law refused a transition — the Python analogue
    of the Rust typestate machine's compile errors."""


class HubRejection(GovernanceError):
    """The governance hub refused a record; carries the hub's exact reason."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def canonical_json(value: Any) -> str:
    """Canonical JSON bytes: compact, keys recursively sorted — identical to
    the Rust core's ``canonical_json`` and the console's serializer."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(text: str) -> str:
    """Lowercase-hex SHA-256 of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def seal_hash(previous_hash: str, payload_bytes: str) -> str:
    """The chain link: ``SHA-256(previous_hash + payload_bytes)``."""
    return sha256_hex(previous_hash + payload_bytes)


def _chain_payload(record: Dict[str, Any], chain_fields) -> str:
    return canonical_json({k: v for k, v in record.items() if k not in chain_fields})


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class GovernedAgent:
    """A governed agent's local chain state.

    States mirror the Rust typestates — ``genesis`` → ``delegated`` →
    (executions) → ``revoked`` — enforced at runtime: ``execute`` before
    ``delegate`` raises :class:`LifecycleError`, and nothing seals after
    ``revoke``.
    """

    did: str
    supervisor_did: str
    model_digest: str
    anchors: List[Dict[str, Any]] = field(default_factory=list)
    packets: List[Dict[str, Any]] = field(default_factory=list)
    _anchor_tail: str = GENESIS_HASH
    _packet_tail: str = GENESIS_HASH
    _state: str = "genesis"
    _scope: List[str] = field(default_factory=list)
    _hub: Optional["HubClient"] = None
    _clock: Callable[[], str] = field(default=_now_utc)

    # ── Construction / transitions ──────────────────────────────────────

    @classmethod
    def born(
        cls,
        did: str,
        supervisor_did: str,
        model_digest: str,
        clock: Callable[[], str] = _now_utc,
    ) -> "GovernedAgent":
        """Births the agent: seals the AGENT_GENESIS anchor binding the
        model digest."""
        if not did.startswith("did:syntriass:agent:"):
            raise GovernanceError(f"{did!r} is not a did:syntriass:agent identifier")
        agent = cls(
            did=did,
            supervisor_did=supervisor_did,
            model_digest=model_digest,
            _clock=clock,
        )
        agent._append_anchor(
            "AGENT_GENESIS", supervisor_did, {"modelDigest": model_digest}
        )
        return agent

    def delegate(self, scope: List[str], clearance_level: str) -> "GovernedAgent":
        """Confers authority: seals SUPERVISOR_DELEGATION and enables
        execution. Returns self for chaining."""
        self._require_state("genesis", "delegate")
        self._append_anchor(
            "SUPERVISOR_DELEGATION",
            self.supervisor_did,
            {"scope": list(scope), "clearanceLevel": clearance_level},
        )
        self._scope = list(scope)
        self._state = "delegated"
        return self

    def revoke(self, reason: str) -> None:
        """Terminal revocation: seals the closing anchor; every later
        transition raises."""
        if self._state == "revoked":
            raise LifecycleError(f"{self.did} is already terminally revoked")
        self._append_anchor(
            "AUTHORITY_REVOCATION",
            self.supervisor_did,
            {"terminal": True, "reason": reason},
        )
        self._state = "revoked"

    def attach(self, hub: "HubClient") -> "GovernedAgent":
        """Streams every already-sealed and future record to a hub. Each
        receipt's tail hash must equal the locally computed tail — a live
        cross-language verification on every submission."""
        self._hub = hub
        for anchor in self.anchors:
            hub.submit_anchor(anchor)
        for packet in self.packets:
            hub.submit_packet(packet)
        return self

    # ── Execution ───────────────────────────────────────────────────────

    def execute(
        self,
        tool_name: str,
        fn: Callable[[], Any],
        params: Optional[Dict[str, Any]] = None,
        raw_prompt: str = "",
        pre_state: Optional[Dict[str, Any]] = None,
        post_state: Callable[[], Dict[str, Any]] = lambda: {},
    ) -> Any:
        """Runs ``fn`` under governance: seals an AIP evidence packet (with
        pre/post state hashes) and its ACTION_EXECUTION_SEAL anchor, whether
        the call succeeds, raises, or is refused by scope. Returns ``fn``'s
        result; re-raises its exception after sealing the FAILED evidence.
        """
        if self._state == "genesis":
            raise LifecycleError(
                f"{self.did} holds no delegated authority; call delegate() first"
            )
        if self._state == "revoked":
            raise LifecycleError(
                f"{self.did} is terminally revoked; nothing executes after the kill-switch"
            )
        pre = pre_state if pre_state is not None else {}
        pre_hash = sha256_hex(canonical_json(pre))

        if tool_name not in self._scope:
            self._seal_packet(
                tool_name,
                params or {},
                raw_prompt,
                "BLOCKED_BY_POLICY",
                pre_hash,
                pre_hash,  # nothing ran: post == pre, by construction
            )
            raise LifecycleError(
                f"tool {tool_name!r} is outside the delegated scope {self._scope}"
            )
        try:
            result = fn()
        except Exception:
            self._seal_packet(
                tool_name,
                params or {},
                raw_prompt,
                "FAILED",
                pre_hash,
                sha256_hex(canonical_json(post_state())),
            )
            raise
        self._seal_packet(
            tool_name,
            params or {},
            raw_prompt,
            "SUCCESS",
            pre_hash,
            sha256_hex(canonical_json(post_state())),
        )
        return result

    # ── Chain internals ─────────────────────────────────────────────────

    def _require_state(self, expected: str, action: str) -> None:
        if self._state != expected:
            raise LifecycleError(
                f"cannot {action} while {self.did} is in state {self._state!r}"
            )

    def _append_anchor(self, anchor_type: str, actor_did: str, payload: Dict) -> None:
        sequence = len(self.anchors) + 1
        anchor: Dict[str, Any] = {
            "anchorId": f"{self.did}#anchor-{sequence}",
            "sequenceNumber": sequence,
            "anchorType": anchor_type,
            "agentDid": self.did,
            "actorDid": actor_did,
            "timestampUtc": self._clock(),
            "payload": payload,
        }
        digest = seal_hash(self._anchor_tail, _chain_payload(anchor, _ANCHOR_CHAIN_FIELDS))
        anchor["previousAnchorHash"] = self._anchor_tail
        anchor["anchorHash"] = digest
        self.anchors.append(anchor)
        self._anchor_tail = digest
        if self._hub is not None:
            self._hub.submit_anchor(anchor)

    def _seal_packet(
        self,
        tool_name: str,
        params: Dict[str, Any],
        raw_prompt: str,
        status: str,
        pre_hash: str,
        post_hash: str,
    ) -> None:
        sequence = len(self.packets) + 1
        packet: Dict[str, Any] = {
            "id": f"{self.did}#packet-{sequence}",
            "sequenceNumber": sequence,
            "timestampUtc": self._clock(),
            "agentDid": self.did,
            "anchorHash": self._anchor_tail,
            "delegationPath": [self.supervisor_did, self.did],
            "edgeId": f"{self.did}#edge-1",
            "modelDigest": self.model_digest,
            "rawPrompt": raw_prompt,
            "toolExecuted": {
                "name": tool_name,
                "inputParams": params,
                "status": status,
            },
            "preStateHash": pre_hash,
            "postStateHash": post_hash,
        }
        digest = seal_hash(self._packet_tail, _chain_payload(packet, _PACKET_CHAIN_FIELDS))
        packet["previousPacketHash"] = self._packet_tail
        packet["packetHash"] = digest
        self.packets.append(packet)
        self._packet_tail = digest
        # Every executed packet is acknowledged in the lifecycle chain.
        self._append_anchor(
            "ACTION_EXECUTION_SEAL",
            self.did,
            {"packetId": packet["id"], "packetHash": digest, "status": status},
        )

    # ── Export ──────────────────────────────────────────────────────────

    def packets_jsonl(self) -> str:
        """The evidence packets as a byte-faithful forensic stream —
        exactly what ``ot-verifier --dossier chain.jsonl`` verifies."""
        return "".join(json.dumps(p, ensure_ascii=False) + "\n" for p in self.packets)


class HubClient:
    """Minimal governance-hub client over the standard library.

    On every accepted record the hub answers with an ML-DSA-signed
    attestation whose payload carries the verified tail; this client checks
    that tail against the local chain (byte-identical verification, live)
    and — when ``signer_identity`` is pinned — that the envelope claims the
    expected signer. Full ML-DSA signature verification is `ot-verifier
    --attestation`'s job; the stdlib has no post-quantum crypto, and this
    client says so rather than pretending.
    """

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        signer_identity: Optional[str] = None,
        timeout_s: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.signer_identity = signer_identity
        self.timeout_s = timeout_s

    def _post(self, path: str, record: Dict[str, Any]) -> Dict[str, Any]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(record).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", "replace")
            try:
                doc = json.loads(body)
            except ValueError:
                raise HubRejection(str(err.code), body) from err
            raise HubRejection(
                doc.get("code", str(err.code)), doc.get("detail", doc.get("error", body))
            ) from err

    def _checked(self, envelope: Dict[str, Any], local_tail: str) -> Dict[str, Any]:
        payload = envelope.get("payload", {})
        if payload.get("tailHash") != local_tail:
            raise GovernanceError(
                "hub receipt tail does not match the locally sealed tail — "
                "the server and this SDK disagree about the chain bytes"
            )
        claimed = envelope.get("attestation", {}).get("signerIdentity")
        if self.signer_identity is not None and claimed != self.signer_identity:
            raise GovernanceError(
                f"receipt signed by {claimed!r}, expected pinned {self.signer_identity!r}"
            )
        return envelope

    def submit_anchor(self, anchor: Dict[str, Any]) -> Dict[str, Any]:
        """Submits one anchor; returns the signed receipt envelope."""
        return self._checked(
            self._post("/governance/anchors", anchor), anchor["anchorHash"]
        )

    def submit_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Submits one evidence packet; returns the signed receipt envelope."""
        return self._checked(
            self._post("/governance/packets", packet), packet["packetHash"]
        )


def governed(
    agent: GovernedAgent,
    tool_name: str,
    state_fn: Callable[[], Dict[str, Any]] = lambda: {},
):
    """Decorator: every call to the wrapped function becomes a governed,
    sealed execution. Keyword arguments become the evidence packet's
    ``inputParams`` (they must be JSON-serializable); the wrapped call's
    exceptions seal FAILED evidence and re-raise. Wrap an MCP server's tool
    handler with this and the MCP surface is governed without touching the
    protocol.
    """

    def wrap(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            return agent.execute(
                tool_name,
                lambda: fn(*args, **kwargs),
                params=kwargs,
                raw_prompt=f"[python] {tool_name}",
                pre_state=state_fn(),
                post_state=state_fn,
            )

        return inner

    return wrap
