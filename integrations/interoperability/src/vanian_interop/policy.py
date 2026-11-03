"""OPA native decision references. An allow result never issues AIP authority."""
from __future__ import annotations

import time

from .records import DecisionReference, IdentityReference, SourceAuthenticity, commitment, json_bytes, strict_json
from .transport import PinnedHttps, endpoint_origin


class OpaAdapter:
    def __init__(self, endpoint: str, transport: PinnedHttps, *, engine_version: str,
                 policy_version: str, authority: str):
        if endpoint_origin(endpoint) != transport.origin or not policy_version or not authority:
            raise ValueError("explicit policy authority/version and same-origin transport required")
        self.endpoint, self.transport = endpoint, transport
        self.engine_version, self.policy_version, self.authority = engine_version, policy_version, authority

    def evaluate(self, identity: IdentityReference, *, resource: str, action: str,
                 request_id: str, execution_context_ref: str | None, arguments: dict) -> DecisionReference:
        now = time.time_ns() // 1_000_000
        if identity.expires_at_ms <= now or identity.revocation_status == "REVOKED":
            raise ValueError("expired or revoked identity")
        if not resource or not action or not request_id:
            raise ValueError("resource, action and request_id required")
        value = {"principal": {"issuer": identity.issuer, "subject": identity.subject,
                               "tenant": identity.tenant}, "resource": resource, "action": action,
                 "request_id": request_id, "execution_context_ref": execution_context_ref,
                 "arguments": arguments}
        # Detach from caller-owned mutable arguments before dispatch/commitment.
        value = strict_json(json_bytes(value))
        raw = self.transport.request("POST", self.endpoint, body={"input": value})
        response = strict_json(raw)
        if not isinstance(response, dict):
            raise ValueError("OPA response must be an object")
        result = response.get("result")
        decision = "INDETERMINATE"
        version = None
        conditions = ["External decision reference; signed ExpectedExecution is still required.",
                      "Credential revocation is not established by offline JWT verification."]
        if isinstance(result, dict):
            version = result.get("policy_version")
            if version == self.policy_version and type(result.get("allow")) is bool:
                decision = "ALLOW" if result["allow"] else "DENY"
            else:
                conditions.append("Policy version mismatch or unsupported decision shape.")
        else:
            conditions.append("Undefined or unsupported OPA result; no authorization conclusion.")
        return DecisionReference(
            engine="OPA", engine_version=self.engine_version, policy_version=version,
            principal=identity.subject, tenant=identity.tenant, resource=resource, action=action,
            request_id=request_id, execution_context_ref=execution_context_ref,
            input_commitment=commitment(value), native_result_json=json_bytes(response).decode(),
            decision=decision, evaluated_at_ms=now,
            source=SourceAuthenticity("HTTPS", self.authority, "ca-file-sha256:" + self.transport.ca_sha256, now,
                                      boundary="EXTERNAL_POLICY_SERVICE"),
            conditions=tuple(conditions))
