"""Validate the implemented OpenAPI subset against source and real responses.

Uses PyYAML/jsonschema versions pinned in the evidence MCP environment lock.
This checks wire contracts, not signature validity or execution assurance.
Failures name the route/schema location without printing evidence payloads.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request

import yaml
from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[2]
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _normalized(path: str) -> str:
    return re.sub(r"\{[^/{}]+\}|:[^/]+", "{}", path)


class OpenAPIContract:
    def __init__(self, specification: Path | None = None):
        self.specification = specification or ROOT / "docs/enterprise/openapi.yaml"
        self.document = yaml.safe_load(self.specification.read_text())
        assert self.document["openapi"] == "3.1.0", "expected OpenAPI 3.1 JSON Schema semantics"
        self.operations = {}
        for path, entry in self.document["paths"].items():
            for method, operation in entry.items():
                if method in METHODS:
                    key = (method.upper(), path)
                    assert key not in self.operations, "duplicate OpenAPI operation"
                    self.operations[key] = operation
        self._check_local_references(self.document)
        for schema in self.document["components"]["schemas"].values():
            Draft202012Validator.check_schema(schema)

    @staticmethod
    def _check_local_references(node):
        if isinstance(node, dict):
            if "$ref" in node:
                assert node["$ref"].startswith("#/"), "remote schema references are not allowed"
            for value in node.values():
                OpenAPIContract._check_local_references(value)
        elif isinstance(node, list):
            for value in node:
                OpenAPIContract._check_local_references(value)

    def _dereference(self, node):
        while "$ref" in node:
            current = self.document
            for component in node["$ref"][2:].split("/"):
                current = current[component.replace("~1", "/").replace("~0", "~")]
            node = current
        return node

    def assert_route_alignment(self, source: str | None = None):
        source = source if source is not None else (ROOT / "aip-service/src/lib.rs").read_text()
        # The documented subset uses direct get/post handlers. The old
        # conditional managed-signing route is deliberately outside it.
        matches = re.findall(
            r'\.route\(\s*"([^"\n]+)"\s*,\s*(get|post|put|patch|delete|head|options)\(\s*([\w:]+)',
            source,
        )
        implemented = {(method.upper(), _normalized(path)) for path, method, _ in matches}
        # A MethodRouter may add a second operation with get(...).post(...).
        for match in re.finditer(r'\.route\(\s*"([^"\n]+)"\s*,\s*(?:get|post)\(\s*[\w:]+', source):
            chained = re.match(r'\)\s*\.(get|post|put|patch|delete|head|options)\(\s*[\w:]+\s*\)', source[match.end():])
            if chained:
                implemented.add((chained.group(1).upper(), _normalized(match.group(1))))
        documented = {(method, _normalized(path)) for method, path in self.operations}
        missing = documented - implemented
        assert not missing, "OpenAPI documents routes/methods absent from the Rust router: " + repr(sorted(missing))
        new_service_reads = {
            (method.upper(), _normalized(path)) for path, method, handler in matches
            if method == "get" and handler.startswith(("enterprise::", "observations::", "deployments::"))
        }
        assert not new_service_reads - documented, "enterprise read route is missing from OpenAPI"
        identifiers = [operation["operationId"] for operation in self.operations.values()]
        assert len(set(identifiers)) == len(identifiers), "OpenAPI operationId values must be unique"

    def operation(self, method: str, request_path: str):
        path = urlsplit(request_path).path
        for (candidate_method, template), operation in self.operations.items():
            pattern = re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(template))
            if candidate_method == method.upper() and re.fullmatch(pattern, path):
                return template, operation
        raise AssertionError("request has no documented method/route")

    def validate_response(self, method: str, path: str, status: int, payload, content_type="application/json"):
        template, operation = self.operation(method, path)
        response = operation["responses"].get(str(status))
        assert response is not None, f"undocumented HTTP status for {method} {template}: {status}"
        response = self._dereference(response)
        content = response.get("content", {})
        assert content_type in content, f"undocumented response content type for {method} {template}"
        schema = content[content_type]["schema"]
        # Keep local references rooted in the complete components tree.
        validator = Draft202012Validator({**schema, "components": self.document["components"]})
        try:
            validator.validate(payload)
        except ValidationError as exc:
            location = "/".join(str(part) for part in exc.absolute_schema_path)
            raise AssertionError(f"OpenAPI response mismatch for {method} {template} at schema {location}") from None


def _get(client, path: str, *, authenticated=True):
    headers = {"Accept": "application/json"}
    if authenticated:
        headers["Authorization"] = "Bearer " + client.credential_provider()
    request = Request(client.base_url + path, headers=headers)
    try:
        response = client._opener.open(request, timeout=client.timeout)
    except HTTPError as exc:
        response = exc
    with response:
        raw = response.read(client.max_response_bytes + 1)
        assert len(raw) <= client.max_response_bytes, "contract response exceeds the client read limit"
        content_type = response.headers.get_content_type()
        payload = json.loads(raw) if content_type == "application/json" else raw.decode("utf-8")
        return response.status, payload, content_type


def validate_live_reads(reader, other_tenant_reader, writer, *, evidence_id, agent_id, verdict_id, observation_id):
    contract = OpenAPIContract()
    contract.assert_route_alignment()
    cases = [
        (reader, "/v1/access"),
        (reader, "/v1/agents?limit=1&offset=0"),
        (reader, f"/v1/agents/{agent_id}"),
        (reader, f"/v1/agents/{agent_id}/activity?limit=1&offset=0"),
        (reader, f"/v1/evidence/{evidence_id}/metadata"),
        (reader, f"/v1/evidence/{evidence_id}/verification"),
        (reader, f"/v1/verdicts/{verdict_id}"),
        (reader, "/v1/coverage"),
        (reader, "/v1/health"),
        (writer, f"/v1/observations/{observation_id}"),
        (reader, f"/v1/observations/{observation_id}/metadata"),
        (reader, f"/v1/observations/{observation_id}/verification"),
    ]
    covered = set()
    for caller, path in cases:
        status, payload, content_type = _get(caller, path)
        assert status == 200, "authorized contract request failed"
        contract.validate_response("GET", path, status, payload, content_type)
        covered.add(("GET", contract.operation("GET", path)[0]))
        status, payload, content_type = _get(caller, path, authenticated=False)
        assert status == 401, "unauthenticated contract request was not refused"
        contract.validate_response("GET", path, status, payload, content_type)
    # This fixture deliberately uses the default router: configuration
    # registration is disabled and must not silently fall back to RAM. The
    # registry-specific HTTP fixture separately exercises enabled success.
    for path in ("/v1/deployments", "/v1/deployments/not-configured"):
        status, payload, content_type = _get(reader, path)
        assert status == 503, "registry unexpectedly enabled by the default router"
        contract.validate_response("GET", path, status, payload, content_type)
        covered.add(("GET", contract.operation("GET", path)[0]))
        status, payload, content_type = _get(reader, path, authenticated=False)
        assert status == 401, "unauthenticated registry read was not refused"
        contract.validate_response("GET", path, status, payload, content_type)
    documented_gets = {key for key in contract.operations if key[0] == "GET"}
    assert covered == documented_gets, "a documented read operation has no live contract case"
    for _, path in cases:
        if any(marker in path for marker in (agent_id, evidence_id, verdict_id, observation_id)):
            # Reader cannot retrieve raw archives under any tenant. Its
            # explicit 403 has no JSON contract, so the main smoke checks it.
            if path == f"/v1/observations/{observation_id}":
                continue
            status, payload, content_type = _get(other_tenant_reader, path)
            assert status == 404, "cross-tenant identifier did not return the missing-record response"
            contract.validate_response("GET", path, status, payload, content_type)
