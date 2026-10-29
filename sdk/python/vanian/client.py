"""Customer retrieval interface. Cryptography stays in the existing Rust verifier.

Routes and response fields are specified in docs/enterprise/openapi.yaml.
This library neither issues authorization nor asserts execution coverage.
Admin configuration registration is distinct from the evidence read methods.
"""

from __future__ import annotations

import ipaddress
import json
import math
import ssl
import time
from http.client import HTTPException
from dataclasses import dataclass
from typing import Any, Callable, Generic, Iterator, TypeVar, TypedDict
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class Agent(TypedDict):
    agent_id: str
    evidence_count: int
    latest_created_at_ms: int
    identity_source: str
    independent_identity_verified: bool


class Activity(TypedDict):
    evidence_id: str
    created_at_ms: int
    decision_id: str
    action_count: int
    evidence_source: str
    independent_execution_verified: bool


class EvidenceMetadata(Activity):
    agent_id: str


class DeploymentSummary(TypedDict):
    deployment_name: str
    workload_count: int
    registered_at_ms: int
    provenance: str
    configuration_status: str
    observer_active: str
    execution_reconciled: str
    identity_binding: str


class Deployment(TypedDict):
    tenant_id: str
    definition: dict[str, Any]
    registered_at_ms: int
    registered_by_key_id: str
    provenance: str
    configuration_status: str
    installed: str
    observer_active: str
    signed_evidence_available: str
    authorization_verified: str
    execution_reconciled: str
    pilot_accepted: str
    identity_binding: str
    trust_anchors_modified: bool
    retention_enforced: bool


T = TypeVar("T")


@dataclass(frozen=True)
class Page(Generic[T]):
    items: list[T]
    limit: int
    offset: int
    next_offset: int | None

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Page:
        try:
            items, limit, offset, next_offset = (
                data["items"], data["limit"], data["offset"], data["next_offset"]
            )
        except (KeyError, TypeError):
            raise ApiError(0, "invalid_page") from None
        if (not isinstance(items, list) or type(limit) is not int or not 1 <= limit <= 100
                or type(offset) is not int or not 0 <= offset <= 100_000 or len(items) > limit):
            raise ApiError(0, "invalid_page")
        if next_offset is not None and (type(next_offset) is not int or not offset < next_offset <= 100_000):
            raise ApiError(0, "invalid_page")
        return cls(items, limit, offset, next_offset)


class ApiError(Exception):
    """A bounded, redacted error: no URL, token, response body, or bank payload."""

    def __init__(self, status: int, code: str):
        self.status, self.code = status, code
        super().__init__(f"VANIAN API {code} (HTTP {status})")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise ValueError("identifier must contain 1..256 characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or value in (".", ".."):
        raise ValueError("invalid identifier")
    return quote(value, safe="")


class VanianClient:
    """Authenticated synchronous client with TLS, bounded reads and GET retries.

    Supply a fresh credential through the callback to support rotation. No
    credential is accepted in the URL. Redirects are refused, including those
    within the same host. Plain HTTP requires explicit loopback-only opt-in.
    """

    def __init__(
        self,
        base_url: str,
        credential_provider: Callable[[], str],
        *,
        timeout: float = 10.0,
        retries: int = 1,
        max_response_bytes: int = 1_048_576,
        ca_file: str | None = None,
        allow_loopback_http: bool = False,
    ):
        parsed = urlsplit(base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain credentials, query or fragment")
        if not parsed.hostname or parsed.path not in ("", "/"):
            raise ValueError("base_url must be a service origin")
        if parsed.scheme != "https":
            try:
                loopback = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = parsed.hostname == "localhost"
            if parsed.scheme != "http" or not allow_loopback_http or not loopback:
                raise ValueError("HTTPS required (HTTP allowed only on explicit loopback)")
        if not math.isfinite(timeout) or not 0 < timeout <= 120:
            raise ValueError("timeout must be finite and in (0,120]")
        if type(retries) is not int or not 0 <= retries <= 3:
            raise ValueError("retries must be 0..3")
        if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 16_777_216:
            raise ValueError("max_response_bytes must be 1..16777216")
        if not callable(credential_provider):
            raise ValueError("credential_provider must be callable")
        self.base_url, self.credential_provider = base_url.rstrip("/"), credential_provider
        self.timeout, self.retries, self.max_response_bytes = timeout, retries, max_response_bytes
        self._opener = build_opener(
            _NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca_file))
        )

    def _get(self, path: str) -> dict[str, Any]:
        return self._request(path)

    def _request(self, path: str, data: bytes | None = None) -> dict[str, Any]:
        retries = self.retries if data is None else 0
        for attempt in range(retries + 1):
            token = self.credential_provider()
            if not isinstance(token, str) or not token or any(c.isspace() for c in token):
                raise ValueError("credential provider must return a nonempty bearer credential")
            req = Request(self.base_url + path, data=data, headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
                "User-Agent": "vanian-python/0.1.0",
                **({"Content-Type": "application/json"} if data is not None else {}),
            })
            try:
                with self._opener.open(req, timeout=self.timeout) as response:
                    raw = response.read(self.max_response_bytes + 1)
                    if len(raw) > self.max_response_bytes:
                        raise ApiError(response.status, "response_too_large")
                    if response.headers.get_content_type() != "application/json":
                        raise ApiError(response.status, "invalid_content_type")
                    try:
                        value = json.loads(raw)
                    except (ValueError, UnicodeError):
                        raise ApiError(response.status, "invalid_json") from None
                    if not isinstance(value, dict):
                        raise ApiError(response.status, "invalid_response")
                    return value
            except HTTPError as exc:
                status = exc.code
                exc.close()
                if status not in (429, 502, 503, 504) or attempt == retries:
                    raise ApiError(status, "request_refused") from None
            except (URLError, TimeoutError, OSError, HTTPException):
                if attempt == retries:
                    raise ApiError(0, "transport_failed") from None
            time.sleep(0.1 * (2 ** attempt))
        raise AssertionError("unreachable")

    @staticmethod
    def _page_query(limit: int, offset: int) -> str:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        if type(offset) is not int or not 0 <= offset <= 100_000:
            raise ValueError("offset must be 0..100000")
        return "?" + urlencode({"limit": limit, "offset": offset})

    def access(self) -> dict[str, Any]:
        return self._get("/v1/access")

    def list_agents(self, *, limit: int = 50, offset: int = 0) -> Page[Agent]:
        return Page.parse(self._get("/v1/agents" + self._page_query(limit, offset)))

    def list_deployments(self, *, limit: int = 50, offset: int = 0) -> Page[DeploymentSummary]:
        return Page.parse(self._get("/v1/deployments" + self._page_query(limit, offset)))

    def get_deployment(self, deployment_name: str) -> Deployment:
        return self._get("/v1/deployments/" + _identifier(deployment_name))

    def register_deployment(self, definition: dict[str, Any]) -> Deployment:
        """Admin-only configuration registration. Never retried automatically."""
        if not isinstance(definition, dict):
            raise ValueError("deployment definition must be an object")
        data = json.dumps(definition, allow_nan=False, separators=(",", ":")).encode()
        if len(data) > 24 * 1024:
            raise ValueError("deployment definition exceeds 24 KiB")
        return self._request("/v1/deployments", data)

    def iter_agents(self, *, limit: int = 50, max_pages: int = 100) -> Iterator[Agent]:
        if type(max_pages) is not int or not 1 <= max_pages <= 10_000:
            raise ValueError("max_pages must be 1..10000")
        offset = 0
        for _ in range(max_pages):
            page = self.list_agents(limit=limit, offset=offset)
            yield from page.items
            if page.next_offset is None:
                return
            offset = page.next_offset
        raise ApiError(0, "pagination_limit")

    def get_agent(self, agent_id: str) -> Agent:
        return self._get("/v1/agents/" + _identifier(agent_id))

    def get_agent_activity(self, agent_id: str, *, limit: int = 50, offset: int = 0) -> Page[Activity]:
        return Page.parse(self._get(
            "/v1/agents/" + _identifier(agent_id) + "/activity" + self._page_query(limit, offset)
        ))

    def get_verdict(self, verdict_id: str) -> dict[str, Any]:
        """Return the stored signed reconciler document; does not regrade it."""
        return self._get("/v1/verdicts/" + _identifier(verdict_id))

    def get_evidence_metadata(self, evidence_id: str) -> EvidenceMetadata:
        return self._get("/v1/evidence/" + _identifier(evidence_id) + "/metadata")

    def verify_evidence(self, evidence_id: str) -> dict[str, Any]:
        """Run service integrity verification; independent authority is not implied."""
        return self._get("/v1/evidence/" + _identifier(evidence_id) + "/verification")

    def get_coverage(self) -> dict[str, Any]:
        return self._get("/v1/coverage")

    def get_observation_metadata(self, observation_id: str) -> dict[str, Any]:
        return self._get("/v1/observations/" + _identifier(observation_id) + "/metadata")

    def verify_observation(self, observation_id: str) -> dict[str, Any]:
        """Verify the admitted historical archive, not current host coverage."""
        return self._get("/v1/observations/" + _identifier(observation_id) + "/verification")

    def get_run_metadata(self, run_artifact_id: str) -> dict[str, Any]:
        """Read server-reevaluated same-run metadata, including all limitations."""
        return self._get("/v1/runs/" + _identifier(run_artifact_id) + "/metadata")

    def get_run_verdict(self, run_artifact_id: str) -> dict[str, Any]:
        """Retrieve the original signed verdict, checked against run recomputation."""
        return self._get("/v1/runs/" + _identifier(run_artifact_id) + "/verdict")

    def evaluate_run(self, run_artifact_id: str) -> dict[str, Any]:
        """Reevaluate immutable inputs using configured public anchors/checkpoints."""
        return self._get("/v1/runs/" + _identifier(run_artifact_id) + "/evaluation")

    def get_agent_runs(self, agent_id: str, *, limit: int = 25, offset: int = 0) -> Page[dict[str, Any]]:
        return Page.parse(self._get("/v1/agents/" + _identifier(agent_id) + "/runs"
                                    + self._page_query(limit, offset)))

    def get_health(self) -> dict[str, Any]:
        return self._get("/v1/health")
