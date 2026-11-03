"""Lossless reference bridges for upstream decisions. No policy re-evaluation."""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib

from .records import ClaimStatus, GovernanceEvent, SourceAuthenticity, commitment, json_bytes, strict_json


UNAUTHENTICATED = SourceAuthenticity("UNVERIFIED_IMPORT", "unknown", None, None)


def openshell_event(raw: bytes, *, tenant: str) -> GovernanceEvent:
    """Consume native OCSF JSONL from OpenShell; file content is not authenticated.

Supervisor/gateway controls may run outside the workload. This parser makes
no inference about the operator's deployment or the producer's signing key.
"""
    if len(raw) > 1_048_576:
        raise ValueError("oversized OCSF event")
    value = strict_json(raw)
    metadata = value.get("metadata", {})
    producer = metadata.get("product", {}).get("name")
    if producer not in ("OpenShell Sandbox Supervisor", "OpenShell Gateway"):
        raise ValueError("unsupported producer declaration")
    if type(value.get("class_uid")) is not int or type(value.get("time")) is not int:
        raise ValueError("OCSF class_uid and millisecond timestamp required")
    uid = metadata.get("uid")
    if not isinstance(uid, str) or not uid:
        raise ValueError("native event UID required")
    # The native record retains status/action/disposition separately. A network
    # denial is not evidence of absence of all execution, nor a kernel record.
    return GovernanceEvent("nvidia-openshell-ocsf", tenant, uid,
        str(value["class_uid"]), value["time"], json_bytes(value).decode(),
        UNAUTHENTICATED, workload_id=value.get("container", {}).get("uid"),
        status=ClaimStatus.DISCOVERED)


def microsoft_result(result, *, tenant: str, request_id: str, evaluated_at_ms: int,
                     policy_version: str, agent_id: str) -> GovernanceEvent:
    """Accept the actual ACS InterventionPointResult dataclass or its JSON form.

input_identity, enforced_identity, transformations, approvals, warnings and
evidence pointers remain distinct. Pointers are not fetched or verified.
"""
    native = asdict(result) if is_dataclass(result) else result
    # The native Python SDK uses tuples for labels/warnings. Normalize only
    # JSON container representation, without dropping or interpreting fields.
    def containers(value):
        if isinstance(value, (tuple, list)):
            return [containers(item) for item in value]
        if isinstance(value, dict):
            return {key: containers(item) for key, item in value.items()}
        return value
    native = containers(native)
    native = strict_json(json_bytes(native))
    verdict = native.get("verdict")
    if not isinstance(verdict, dict) or verdict.get("decision") not in ("allow", "deny", "transform", "warn", "escalate"):
        raise ValueError("unsupported ACS verdict; retain as unknown outside this adapter")
    return GovernanceEvent("microsoft-agent-control-specification", tenant, request_id,
        "policy." + verdict["decision"], evaluated_at_ms, json_bytes(native).decode(),
        SourceAuthenticity("IN_PROCESS_HOOK", "ACS caller", None, None),
        agent_id=agent_id, policy_version=policy_version)


def correlate_decision_request(event: GovernanceEvent, *, request_tenant: str,
                               evaluated_input_identity: str, received_input_identity: str) -> dict:
    if event.tenant != request_tenant:
        raise ValueError("cross-tenant correlation refused")
    native = strict_json(event.native_json)
    if event.source != "microsoft-agent-control-specification":
        raise ValueError("unsupported native identity semantics")
    original, enforced = native.get("input_identity"), native.get("enforced_identity")
    if not original or not enforced:
        return {"comparison": "INSUFFICIENT_EVIDENCE", "execution": "CANNOT_PROVE"}
    matches = original == evaluated_input_identity and enforced == received_input_identity
    return {"comparison": "AGREEMENT" if matches else "DIVERGENCE",
            "scope": "native ACS identity strings only; authenticity NOT_ESTABLISHED",
            "execution": "CANNOT_PROVE"}
