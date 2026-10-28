"""Real HTTP SDK/OpenAPI contract test. Configuration fixtures, no observations."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys

from vanian import VanianClient, ApiError
from openapi_contract import OpenAPIContract

ROOT = Path(__file__).resolve().parents[2]
BASE = os.environ["VANIAN_REGISTRY_URL"]
contract = OpenAPIContract()
contract.assert_route_alignment()


def client(variable):
    return VanianClient(BASE, lambda: os.environ[variable], allow_loopback_http=True, retries=0)


def refused(operation, status):
    try:
        operation()
    except ApiError as error:
        assert error.status == status, error
    else:
        raise AssertionError("unauthorized operation succeeded")


def main():
    admin, reader, other, machine = [client("VANIAN_REGISTRY_" + key) for key in ("ADMIN", "READER", "OTHER", "MACHINE")]
    definition = {"schema_version": "vanian.deployment.v1", "deployment_name": "research",
        "workloads": [{"host_id": "host-one", "admin_group": "platform", "probe_id": "probe-one",
                       "transport_public_key_hex": "ab"*32, "logical_agent_ids": ["agent:research"]}],
        "collector": {"host_id": "collector-one", "admin_group": "audit", "observer_id": "observer-one", "noise_public_key_hex": "cd"*32},
        "retention_days_requested": 90, "contextforge": True, "evidence_mcp": True}
    record = admin.register_deployment(definition)
    contract.validate_response("POST", "/v1/deployments", 201, record)
    assert record["tenant_id"] == "tenant-a" and record["registered_by_key_id"] == "admin-a"
    assert record["trust_anchors_modified"] is False and record["retention_enforced"] is False
    for field in ("installed", "observer_active", "signed_evidence_available", "authorization_verified", "execution_reconciled", "pilot_accepted"):
        assert record[field] == "NOT_ASSESSED"
    assert admin.register_deployment(definition) == record
    # Simultaneous resubmissions after an uncertain client outcome must retain
    # one immutable registration and its original operator/time attribution.
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(value == record for value in pool.map(lambda _: admin.register_deployment(definition), range(8)))
    assert reader.get_deployment("research") == record
    contract.validate_response("GET", "/v1/deployments/research", 200, record)
    page = reader.list_deployments(limit=1)
    assert page.items[0]["deployment_name"] == "research"
    assert "definition" not in page.items[0]
    contract.validate_response("GET", "/v1/deployments?limit=1", 200, {"items":page.items,"limit":page.limit,"offset":page.offset,"next_offset":page.next_offset})
    assert other.list_deployments().items == []
    refused(lambda: other.get_deployment("research"), 404)
    refused(lambda: reader.register_deployment(definition), 403)
    refused(lambda: machine.register_deployment(definition), 403)
    wrong = copy.deepcopy(definition); wrong["retention_days_requested"] = 91
    refused(lambda: admin.register_deployment(wrong), 409)
    assert reader.get_coverage()["status"] == "unavailable"
    # Read-only console uses actual backend data and explicit qualification.
    for route in ("/console", "/console/app.js"):
        import urllib.request
        with urllib.request.urlopen(BASE + route) as response:
            content = response.read(262145).decode()
            assert len(content.encode()) <= 262144
            assert "deployment" in content
    subprocess.run(["node", str(ROOT / "validation/enterprise/registry_smoke.ts")], check=True)
    print(json.dumps({"registry_http": "PASS", "python_sdk": "PASS", "typescript_sdk": "PASS",
        "openapi": "PASS", "tenant_and_role_negatives": "PASS", "configuration_only": True,
        "concurrent_idempotent_resubmissions": 8,
        "kernel_observation": "NOT_EXECUTED", "browser_interaction": "NOT_EXECUTED"}))


if __name__ == "__main__":
    main()
