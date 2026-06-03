from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from .models import CapabilityScope, Delegation, VerifyResult

JsonDict = Dict[str, Any]
Transport = Callable[[str, str, Optional[JsonDict], float], Tuple[int, JsonDict]]


class AipClientError(RuntimeError):
    """Raised when the AIP service returns an error or cannot be reached."""


def _urllib_transport(method: str, url: str, body: Optional[JsonDict], timeout: float) -> Tuple[int, JsonDict]:
    data = None
    headers = {"accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["content-type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        status = int(exc.code)
    except urllib.error.URLError as exc:
        raise AipClientError(f"AIP service request failed: {exc}") from exc

    if not payload:
        return status, {}
    try:
        return status, json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise AipClientError(f"AIP service returned non-JSON response from {url}") from exc


@dataclass(frozen=True)
class AipClient:
    """HTTP client for the AIP service."""

    base_url: str = "http://127.0.0.1:8081"
    timeout: float = 5.0
    transport: Transport = _urllib_transport

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, body: Optional[JsonDict] = None) -> JsonDict:
        status, payload = self.transport(method, self._url(path), body, self.timeout)
        if status < 200 or status >= 300:
            error = payload.get("error") if isinstance(payload, dict) else None
            raise AipClientError(f"AIP {method} {path} failed with HTTP {status}: {error or payload}")
        return payload

    def health(self) -> JsonDict:
        return self._request("GET", "/health")

    def public_key(self) -> JsonDict:
        return self._request("GET", "/v1/identity/public-key")

    def issue(
        self,
        *,
        agent_id: str,
        agent_type: str = "ai_model",
        metadata: Optional[JsonDict] = None,
        ttl_seconds: int = 3600,
    ) -> JsonDict:
        return self._request(
            "POST",
            "/v1/identity/issue",
            {
                "agent_id": agent_id,
                "agent_type": agent_type,
                "metadata": metadata,
                "ttl_seconds": ttl_seconds,
            },
        )

    def verify(self, token: str) -> VerifyResult:
        payload = self._request("POST", "/v1/identity/verify", {"token": token})
        return VerifyResult.from_json(payload)

    def delegate(
        self,
        *,
        parent_token: str,
        delegatee_id: str,
        scope: CapabilityScope,
        ttl_seconds: int = 3600,
    ) -> Delegation:
        payload = self._request(
            "POST",
            "/v1/identity/delegate",
            {
                "parent_token": parent_token,
                "delegatee_id": delegatee_id,
                "scope": scope.to_json(),
                "ttl_seconds": ttl_seconds,
            },
        )
        return Delegation.from_json(payload["delegation"])

    def verify_chain(self, *, root_token: str, delegation_ids: list[str]) -> JsonDict:
        return self._request(
            "POST",
            "/v1/identity/verify-chain",
            {"root_token": root_token, "delegation_ids": delegation_ids},
        )

    def revoke(self, *, jti: str, revoked_by: str, reason: str, cascade: bool = False) -> JsonDict:
        return self._request(
            "POST",
            "/v1/identity/revoke",
            {
                "jti": jti,
                "revoked_by": revoked_by,
                "reason": reason,
                "cascade": cascade,
            },
        )

    def revocation_status(self, jti: str) -> JsonDict:
        return self._request("GET", f"/v1/identity/revocation-status/{jti}")
