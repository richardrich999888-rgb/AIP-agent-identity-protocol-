"""Versioned correlation records outside the privileged observer.

These JSON commitments are NOT AIP ActionParameters or AIRI commitments.
Only the existing Rust verifiers can establish AIP authorization, receipts,
observation integrity and reconciliation results.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
import hashlib
import json
import math
from typing import Any


class ClaimStatus(StrEnum):
    DECLARED = "DECLARED"
    DISCOVERED = "DISCOVERED"
    AUTHENTICATED = "AUTHENTICATED"
    INDEPENDENTLY_OBSERVED = "INDEPENDENTLY_OBSERVED"
    VERIFIED = "VERIFIED"
    UNKNOWN = "UNKNOWN"


def _validate_json(value: Any) -> None:
    if value is None or isinstance(value, str) or type(value) in (bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return
    if type(value) is list:
        for item in value:
            _validate_json(item)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _validate_json(item)
        return
    raise ValueError("expected an ordinary JSON value with string keys")


def json_bytes(value: Any) -> bytes:
    _validate_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def commitment(value: Any) -> str:
    """Local v1 correlation encoding, deliberately distinct from AIP/JCS."""
    return hashlib.sha256(b"VANIAN/interop-reference-json/v1\0" + json_bytes(value)).hexdigest()


def strict_json(raw: str | bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("non-finite JSON number")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    _validate_json(value)
    return value


@dataclass(frozen=True)
class EvidenceReference:
    source: str
    sha256: str
    media_type: str
    trust_anchor: str | None = None
    signature_status: str = "NOT_VERIFIED"

    def __post_init__(self):
        if len(self.sha256) != 64 or any(c not in "0123456789abcdef" for c in self.sha256):
            raise ValueError("evidence reference requires lowercase SHA-256")
        if not self.source or not self.media_type:
            raise ValueError("source and media type required")


@dataclass(frozen=True)
class SourceAuthenticity:
    mechanism: str
    authority: str
    trust_anchor: str | None
    authenticated_at_ms: int | None
    signature_status: str = "NOT_PRESENT"
    boundary: str = "APPLICATION"


@dataclass(frozen=True)
class IdentityReference:
    scheme: str
    issuer: str
    subject: str
    tenant: str
    credential_type: str
    verified_at_ms: int
    expires_at_ms: int
    trust_anchor: str
    credential_sha256: str
    workload_identity: str | None = None
    logical_agent_id: str | None = None
    agent_binding_evidence: tuple[EvidenceReference, ...] = ()
    revocation_status: str = "UNKNOWN"
    possession: str = "BEARER"
    status: ClaimStatus = ClaimStatus.AUTHENTICATED


@dataclass(frozen=True)
class IdentityMapping:
    aip_agent_id: str
    tenant: str
    claims: tuple[IdentityReference, ...]
    status: str
    gaps: tuple[str, ...]


def retain_identity_claims(aip_agent_id: str, tenant: str,
                           claims: tuple[IdentityReference, ...]) -> IdentityMapping:
    """Retain issuer-qualified claims. This function never asserts equivalence."""
    if not aip_agent_id or not tenant or any(c.tenant != tenant for c in claims):
        raise ValueError("missing identity or cross-tenant identity mapping")
    return IdentityMapping(aip_agent_id, tenant, claims, "UNRESOLVED", (
        "External credential authentication does not bind a logical AIP agent.",
        "Institution-authorized agent-to-workload mapping evidence is required.",
    ))


@dataclass(frozen=True)
class DecisionReference:
    engine: str
    engine_version: str
    policy_version: str | None
    principal: str
    tenant: str
    resource: str
    action: str
    request_id: str
    execution_context_ref: str | None
    input_commitment: str
    native_result_json: str
    decision: str
    evaluated_at_ms: int
    source: SourceAuthenticity
    evidence: tuple[EvidenceReference, ...] = ()
    conditions: tuple[str, ...] = ()
    authorization_status: str = "REFERENCE_ONLY"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class GovernanceEvent:
    source: str
    tenant: str
    event_id: str
    event_kind: str
    occurred_at_ms: int
    native_json: str
    authenticity: SourceAuthenticity
    agent_id: str | None = None
    workload_id: str | None = None
    task_id: str | None = None
    parent_task_id: str | None = None
    policy_version: str | None = None
    status: ClaimStatus = ClaimStatus.DECLARED
    observation_coverage: str = "NOT_ESTABLISHED"


def reference_assessment(*, has_authorization: bool, has_gateway_receipt: bool,
                         has_bound_observation: bool, remote_observer_available: bool) -> dict:
    """Coverage checklist only. Presence never implies cryptographic verification."""
    return {"reconciliation": "CANNOT_PROVE", "authority": "REQUIRES_CORE_VERIFICATION",
            "authorization_present": has_authorization, "receipt_present": has_gateway_receipt,
            "observation_present": has_bound_observation,
            "remote_kernel": "REQUIRES_CORE_VERIFICATION" if remote_observer_available else "UNOBSERVED",
            "reason": "Use aip-reconcile and pinned anchors; adapter presence is not verification."}
