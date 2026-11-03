"""ACS pre-tool decision content joined to a signed native gateway receipt.

Only the pinned, untransformed tool_args profile is supported. Native identity
hashes establish content consistency, never the authenticity of ACS's source.
"""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .receipts import ReceiptVerifier
from .records import GovernanceEvent, json_bytes, strict_json


def compare_microsoft_receipt(event: GovernanceEvent, *, verifier: ReceiptVerifier,
                              signed_receipt: dict, expected_request_id: str,
                              expected_decision_id: str, expected_gateway_agent: str,
                              expected_framework_agent: str, expected_policy_version: str,
                              tool_aliases: dict[str, str]) -> dict:
    """Compare content under operator-selected context, without issuing authority.

    The alias map is explicit configuration, not authenticated tool equivalence.
    IDs in ACS snapshots and receipts are correlation claims. This function
    never promotes the framework agent to a verified workload identity.
    """
    if event.tenant != verifier.tenant:
        raise ValueError("cross-tenant governance/receipt comparison refused")
    if not all((expected_request_id, expected_decision_id, expected_gateway_agent,
                expected_framework_agent, expected_policy_version)):
        raise ValueError("explicit comparison context required")
    result = {"schema": "vanian.interop.microsoft-receipt-reference.v1",
        "comparison": "INSUFFICIENT_EVIDENCE", "tenant": event.tenant,
        "request_id": expected_request_id, "policy_version": event.policy_version,
        "governance_source_authenticity": "NOT_ESTABLISHED",
        "policy_version_authenticity": "NOT_ESTABLISHED",
        "logical_agent_mapping": "NOT_ESTABLISHED",
        "authorization": "NOT_ESTABLISHED", "kernel_execution": "CANNOT_PROVE",
        "gateway": None, "native_input_consistency": "NOT_VERIFIED"}
    def stop(reason, *, divergent=False):
        return {**result, "comparison": "DIVERGENCE" if divergent else "INSUFFICIENT_EVIDENCE",
                "reason": reason}
    if event.source != "microsoft-agent-control-specification":
        return stop("unsupported governance source")
    if event.policy_version != expected_policy_version:
        return stop("policy version differs from configured context")
    if event.agent_id != expected_framework_agent or event.event_id != expected_request_id:
        return stop("framework agent or request reference differs", divergent=True)
    if len(event.native_json.encode()) > 1_048_576:
        raise ValueError("oversized governance record")
    native = strict_json(event.native_json)
    if not isinstance(native, dict):
        return stop("native result must be an object")
    verdict = native.get("verdict", {})
    if not isinstance(verdict, dict):
        return stop("native verdict unavailable")
    if (verdict.get("decision") not in ("allow", "deny")
            or verdict.get("transform") is not None
            or verdict.get("approval") is not None
            or native.get("transformed_policy_target_applied") is not False
            or native.get("transformed_policy_target") is not None):
        return stop("transforms, approvals and other verdict profiles require native-specific handling")
    policy_input = native.get("policy_input")
    if not isinstance(policy_input, dict) or policy_input.get("intervention_point") != "pre_tool_call":
        return stop("pre_tool_call policy input unavailable")
    # Import the upstream implementation only for this optional integration.
    try:
        sdk_version = version("agent-control-specification")
    except PackageNotFoundError:
        return stop("optional ACS SDK unavailable")
    if sdk_version != "0.4.0b0":
        return stop("unsupported ACS SDK version")
    from agent_control_specification import action_identity
    identity = action_identity(policy_input)
    if not native.get("input_identity") or not native.get("enforced_identity"):
        return stop("native input/enforced identity missing")
    if identity != native["input_identity"] or identity != native["enforced_identity"]:
        return stop("native policy-input commitment differs", divergent=True)
    target = policy_input.get("policy_target", {})
    snapshot = policy_input.get("snapshot", {})
    tool = policy_input.get("tool", {})
    if not all(isinstance(item, dict) for item in (target, snapshot, tool)):
        return stop("unsupported native policy-input shape")
    call, agent = snapshot.get("tool_call", {}), snapshot.get("agent", {})
    if not isinstance(call, dict) or not isinstance(agent, dict) or not isinstance(call.get("name"), str):
        return stop("native tool/agent context unavailable")
    if target.get("kind") != "tool_args" or target.get("path") != "$.tool_call.args":
        return stop("unsupported policy target profile")
    arguments = target.get("value")
    if not isinstance(arguments, dict) or "args" not in call:
        return stop("explicit object tool arguments unavailable")
    if json_bytes(arguments) != json_bytes(call["args"]):
        return stop("policy target differs from snapshot arguments", divergent=True)
    if (agent.get("id") != expected_framework_agent
            or call.get("id") != expected_request_id
            or tool.get("name") != call.get("name")):
        return stop("native agent, tool or request reference differs", divergent=True)
    gateway_tool = tool_aliases.get(call.get("name"))
    if not gateway_tool:
        return stop("no operator-configured tool alias")
    # This profile uses integers only: Python and Rust retain their native
    # encodings. Do not silently reinterpret floating point or large integers.
    def supported(value):
        if type(value) is float or type(value) is int and abs(value) > 2**53 - 1:
            return False
        if isinstance(value, dict):
            return all(supported(item) for item in value.values())
        if isinstance(value, list):
            return all(supported(item) for item in value)
        return True
    if not supported(arguments):
        return stop("tool arguments outside the integer JSON comparison profile")
    request = {"method": "tools/call", "tool_name": gateway_tool,
        "arguments": arguments, "agent_id": expected_gateway_agent,
        "decision_id": expected_decision_id, "tool_call_id": expected_request_id}
    gateway = verifier.compare(tenant=event.tenant, request=request, signed_receipt=signed_receipt)
    comparison = gateway["request_comparison"]
    result.update(gateway=gateway, native_input_consistency="VERIFIED_CONTENT_ONLY",
                  input_identity=native["input_identity"], enforced_identity=native["enforced_identity"],
                  tool_alias={call["name"]: gateway_tool}, tool_alias_authenticity="OPERATOR_CONFIGURED")
    if comparison["agreement"] != "Matches":
        return stop("signed gateway request differs from reported policy input/context", divergent=True)
    if verdict["decision"] == "deny" and comparison["gateway_disposition"] != "Refused":
        return stop("reported denial accompanied by a gateway forwarding disposition", divergent=True)
    return {**result, "comparison": "AGREEMENT",
        "reason": "reported untransformed ACS input matches the signed gateway request; source authority remains unverified"}
