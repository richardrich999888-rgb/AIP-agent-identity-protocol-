"""Opt-in real service + real official MCP client integration.

Called by airon-aip's enterprise client smoke fixture. All records are test
fixtures signed by the existing Rust engine; no observation is fabricated.
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters
from vanian import ApiError, VanianClient
from openapi_contract import validate_live_reads

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "integrations/service_delivery"))
from posture_report import collect as collect_posture
BASE = os.environ["VANIAN_TEST_BASE_URL"]
EVIDENCE = os.environ["VANIAN_TEST_EVIDENCE_ID"]
AGENT = os.environ["VANIAN_TEST_AGENT_ID"]
VERDICT = os.environ["VANIAN_TEST_VERDICT_ID"]
OBSERVATION = os.environ["VANIAN_TEST_OBSERVATION_ID"]


def client(key):
    return VanianClient(BASE, lambda: os.environ[key], retries=0, allow_loopback_http=True)


def server_env(key):
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(ROOT / "sdk/python"),
        "VANIAN_BASE_URL": BASE,
        "VANIAN_API_TOKEN": os.environ[key],
        "VANIAN_ALLOW_LOOPBACK_HTTP": "1",
    }


def refused(operation, status=404):
    try:
        operation()
    except ApiError as exc:
        assert exc.status == status, exc
    else:
        raise AssertionError("unauthorized operation succeeded")


async def check_mcp():
    async def session(key):
        return StdioServerParameters(command=sys.executable,
            args=[str(ROOT / "integrations/evidence-mcp/server.py")], env=server_env(key))

    async with Client(await session("VANIAN_TEST_READER_A")) as a:
        tools = await a.list_tools()
        names = {t.name for t in tools.tools}
        assert len(names) == 8
        assert not any("export" in name or "shell" in name or "sign" in name for name in names)
        good = await a.call_tool("vanian_get_execution_verdict", {"verdict_id": VERDICT})
        assert not good.is_error and good.structured_content
        metadata = await a.call_tool("vanian_get_evidence_metadata", {"evidence_id": EVIDENCE})
        assert not metadata.is_error and metadata.structured_content["evidence_id"] == EVIDENCE
        verified = await a.call_tool("vanian_verify_stored_evidence", {"evidence_id": EVIDENCE})
        assert not verified.is_error
        assert verified.structured_content["verification_scope"] == "integrity_only"
        # Each invocation uses its own verification clock. Compare findings,
        # not timestamps or time-dependent diagnostic wording.
        direct = client("VANIAN_TEST_READER_A").verify_evidence(EVIDENCE)["report"]
        through_mcp = verified.structured_content["report"]
        for field in ("packet_id", "valid", "tampered", "trust_floor", "authority_chain_verified"):
            assert through_mcp[field] == direct[field]
        stable_checks = lambda report: [(c["rule"], c["pass"], c["evaluated"]) for c in report["checks"]]
        assert stable_checks(through_mcp) == stable_checks(direct)
        archive = await a.call_tool("vanian_get_evidence_metadata", {"evidence_id": OBSERVATION, "kind": "observation_archive"})
        assert not archive.is_error and archive.structured_content["current_coverage_established"] is False
        archived_verification = await a.call_tool("vanian_verify_stored_evidence", {"evidence_id": OBSERVATION, "kind": "observation_archive"})
        assert not archived_verification.is_error and archived_verification.structured_content["verified"] is True
        malformed = await a.call_tool("vanian_get_evidence_metadata", {"evidence_id": EVIDENCE, "tenant_id": "other"})
        assert malformed.is_error
        concurrent = await asyncio.gather(*[
            a.call_tool("vanian_get_evidence_metadata", {"evidence_id": EVIDENCE}) for _ in range(8)
        ])
        assert all(not x.is_error for x in concurrent)

    async with Client(await session("VANIAN_TEST_READER_B")) as b:
        for name, args in [
            ("vanian_get_execution_verdict", {"verdict_id": VERDICT}),
            ("vanian_get_evidence_metadata", {"evidence_id": EVIDENCE}),
            ("vanian_verify_stored_evidence", {"evidence_id": EVIDENCE}),
            ("vanian_get_evidence_metadata", {"evidence_id": OBSERVATION, "kind": "observation_archive"}),
            ("vanian_verify_stored_evidence", {"evidence_id": OBSERVATION, "kind": "observation_archive"}),
        ]:
            result = await b.call_tool(name, args)
            assert result.is_error


def main():
    a, b = client("VANIAN_TEST_READER_A"), client("VANIAN_TEST_READER_B")
    validate_live_reads(a, b, client("VANIAN_TEST_WRITER_A"), evidence_id=EVIDENCE,
        agent_id=AGENT, verdict_id=VERDICT, observation_id=OBSERVATION)
    assert a.access()["role"] == "reader"
    posture = collect_posture(a)
    assert posture["tenant_id"] == "tenant-a"
    assert posture["coverage"]["independently_verified_execution"] is False
    assert posture["audit_qualification"] == "NOT_ESTABLISHED"
    assert collect_posture(b)["agent_inventory"]["items"] == []
    assert a.get_agent(AGENT)["independent_identity_verified"] is False
    assert a.get_evidence_metadata(EVIDENCE)["independent_execution_verified"] is False
    assert any(item["evidence_id"] == EVIDENCE for item in a.get_agent_activity(AGENT, limit=100).items)
    assert any(x["agent_id"] == AGENT for x in a.iter_agents(limit=1))
    assert a.get_verdict(VERDICT)
    assert a.verify_evidence(EVIDENCE)["verification_scope"] == "integrity_only"
    assert a.get_coverage()["status"] == "unavailable"
    assert a.get_observation_metadata(OBSERVATION)["offhost_separation_established"] is False
    assert a.verify_observation(OBSERVATION)["verified"] is True
    refused(lambda: b.get_agent(AGENT))
    refused(lambda: b.get_verdict(VERDICT))
    refused(lambda: b.get_evidence_metadata(EVIDENCE))
    refused(lambda: b.verify_evidence(EVIDENCE))
    refused(lambda: b.get_observation_metadata(OBSERVATION))
    refused(lambda: b.verify_observation(OBSERVATION))
    refused(lambda: a._get("/v1/observations/" + OBSERVATION), 403)
    refused(lambda: a._get("/v1/evidence/" + EVIDENCE), 403)
    refused(lambda: a._get("/v1/evidence/" + EVIDENCE + "/export"), 403)
    asyncio.run(check_mcp())
    # The MCP process refuses privilege-bearing credentials before accepting
    # protocol messages. Reader role is verified at the real service boundary.
    writer = subprocess.run([sys.executable, str(ROOT / "integrations/evidence-mcp/server.py")],
        env=server_env("VANIAN_TEST_WRITER_A"), input=b"", capture_output=True, timeout=15)
    assert writer.returncode != 0
    oversize = subprocess.run([sys.executable, str(ROOT / "integrations/evidence-mcp/server.py")],
        env=server_env("VANIAN_TEST_READER_A"), input=b"x" * 65_538 + b"\n", capture_output=True, timeout=15)
    assert oversize.returncode != 0
    subprocess.run(["node", str(ROOT / "validation/enterprise/typescript_smoke.ts")], check=True, timeout=30)
    print(json.dumps({"sdk": "PASS", "real_mcp_client": "PASS", "cross_tenant": "PASS",
        "openapi_contract": "PASS", "service_delivery_posture": "PASS",
        "mcp_privilege_refusal": "PASS", "input_limit": "PASS", "kernel_observation": "NOT_EXERCISED"}))


if __name__ == "__main__":
    main()
