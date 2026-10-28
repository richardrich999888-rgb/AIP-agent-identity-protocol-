#!/usr/bin/env python3
"""Import and retrieve the caller's exact run bundle through real interfaces.

This script creates no observation/authorization/receipt and does not infer
that a fixture or supplied record was produced by an autonomous workload.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request

from mcp import Client, StdioServerParameters
from vanian import ApiError, VanianClient

ROOT = Path(__file__).resolve().parents[2]


def refused(operation, status):
    try:
        operation()
    except ApiError as error:
        assert error.status == status
    else:
        raise AssertionError("restricted read succeeded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--writer-key-file", type=Path, required=True)
    parser.add_argument("--reader-key-file", type=Path, required=True)
    parser.add_argument("--other-key-file", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--browser", action="store_true", help="requires installed Playwright Chromium")
    parser.add_argument("--screenshot", type=Path)
    args = parser.parse_args()
    writer_key, reader_key, other_key = [path.read_text().strip() for path in
        (args.writer_key_file, args.reader_key_file, args.other_key_file)]
    writer, reader, other = [VanianClient(args.url, lambda key=key: key,
        retries=0, allow_loopback_http=True) for key in (writer_key, reader_key, other_key)]
    assert writer.access()["role"] in ("machine", "admin")
    assert reader.access()["role"] == other.access()["role"] == "reader"
    assert reader.access()["tenant_id"] != other.access()["tenant_id"]
    raw = args.bundle.read_bytes()
    assert len(raw) <= 16 * 1024 * 1024
    bundle = json.loads(raw)

    def post(key, body):
        request = Request(args.url.rstrip("/") + "/v1/runs", data=body, method="POST",
            headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        with writer._opener.open(request, timeout=10) as response:
            value = response.read(262145)
            assert len(value) <= 262144
            return json.loads(value)

    admitted = post(writer_key, raw)
    artifact_id = admitted["run_artifact_id"]
    assert admitted["run_id"] == bundle["run_id"]
    assert admitted["bundle_sha256"] == hashlib.sha256(raw).hexdigest()
    assert post(writer_key, raw) == admitted
    assert reader.get_run_metadata(artifact_id) == admitted
    assert reader.evaluate_run(artifact_id) == admitted["evaluation"]
    if bundle.get("signed_reconciliation") is not None:
        assert reader.get_run_verdict(artifact_id) == bundle["signed_reconciliation"]
        assert admitted["evaluation"]["signed_reconciliation_verified"] is True
    assert any(row["run_artifact_id"] == artifact_id
               for row in reader.get_agent_runs(bundle["agent_id"], limit=100).items)
    refused(lambda: other.get_run_metadata(artifact_id), 404)
    refused(lambda: other.evaluate_run(artifact_id), 404)
    refused(lambda: reader._get("/v1/runs/" + artifact_id), 403)
    for key, status in [(reader_key, 403)]:
        try:
            post(key, raw)
        except HTTPError as error:
            assert error.code == status
            error.close()
        else:
            raise AssertionError("Reader filed a run")
    request = Request(args.url.rstrip("/") + "/v1/runs/" + artifact_id,
        headers={"Authorization":"Bearer " + writer_key})
    with writer._opener.open(request, timeout=10) as response:
        assert response.read(16 * 1024 * 1024 + 1) == raw

    async def mcp_checks():
        def parameters(key):
            return StdioServerParameters(command=sys.executable,
                args=[str(ROOT / "integrations/evidence-mcp/server.py")], env={
                    "PATH":os.environ.get("PATH","/usr/bin:/bin"), "PYTHONPATH":str(ROOT / "sdk/python"),
                    "VANIAN_BASE_URL":args.url,"VANIAN_API_TOKEN":key,"VANIAN_ALLOW_LOOPBACK_HTTP":"1"})
        async with Client(parameters(reader_key)) as client:
            tools = await client.list_tools()
            assert len(tools.tools) == 8
            metadata = await client.call_tool("vanian_get_evidence_metadata",
                {"evidence_id":artifact_id,"kind":"run_bundle"})
            evaluated = await client.call_tool("vanian_verify_stored_evidence",
                {"evidence_id":artifact_id,"kind":"run_bundle"})
            assert not metadata.is_error and metadata.structured_content == admitted
            assert not evaluated.is_error and evaluated.structured_content == admitted["evaluation"]
            if bundle.get("signed_reconciliation") is not None:
                verdict = await client.call_tool("vanian_get_execution_verdict",
                    {"verdict_id":artifact_id,"kind":"run_bundle"})
                assert not verdict.is_error and verdict.structured_content == bundle["signed_reconciliation"]
            injected = await client.call_tool("vanian_get_evidence_metadata",
                {"evidence_id":artifact_id,"kind":"run_bundle","tenant_id":other.access()["tenant_id"]})
            assert injected.is_error
        async with Client(parameters(other_key)) as client:
            for name in ("vanian_get_evidence_metadata","vanian_verify_stored_evidence"):
                result = await client.call_tool(name,{"evidence_id":artifact_id,"kind":"run_bundle"})
                assert result.is_error
    asyncio.run(mcp_checks())
    env = dict(os.environ, VANIAN_RUN_BASE_URL=args.url, VANIAN_RUN_ARTIFACT_ID=artifact_id,
        VANIAN_RUN_READER=reader_key, VANIAN_RUN_OTHER_READER=other_key,
        VANIAN_RUN_EXPECTED=json.dumps(admitted, separators=(",", ":")),
        VANIAN_RUN_SIGNED_VERDICT=json.dumps(bundle.get("signed_reconciliation")))
    subprocess.run(["node", str(ROOT / "validation/enterprise/run_typescript_smoke.ts")],
        env=env, check=True, timeout=30)

    console = "NOT_EXERCISED"
    if args.browser:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as browser_runtime:
            browser = browser_runtime.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(args.url.rstrip("/") + "/console")
            page.locator("#credential").fill(reader_key)
            page.locator("#connect button").first.click()
            page.wait_for_function("document.querySelector('#status').textContent.startsWith('Connected')")
            assert page.locator("#credential").input_value() == ""
            page.locator("#run-id").fill(artifact_id)
            page.locator("#run-form button").click()
            page.wait_for_function("document.querySelector('#run').textContent.includes(" + json.dumps(artifact_id) + ")")
            displayed = json.loads(page.locator("#run").inner_text())
            assert displayed == {"metadata":admitted,"evaluation":admitted["evaluation"],
                                 "signed_verdict":bundle.get("signed_reconciliation")}
            if args.screenshot:
                page.screenshot(path=str(args.screenshot), full_page=True)
            page.locator("#disconnect").click()
            assert page.locator("#run").inner_text() == "Disconnected"
            browser.close()
        console = "PASS"
    report = {"run_id":bundle["run_id"],"run_artifact_id":artifact_id,
        "source_bundle_sha256":hashlib.sha256(raw).hexdigest(),
        "api_admission":"PASS","exact_bundle_retrieval":"PASS","python_sdk":"PASS",
        "typescript_sdk":"PASS","official_mcp_client":"PASS","cross_tenant_refusal":"PASS",
        "reader_write_and_raw_refusal":"PASS","console_browser":console,
        "signed_runtime_verdict_retrieval":"PASS" if bundle.get("signed_reconciliation") else "NOT_SUPPLIED",
        "evaluation":admitted["evaluation"],
        "scope":"Retrieval of this exact caller-provided run; workload provenance requires independent run evidence."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key != "evaluation"}))


if __name__ == "__main__":
    main()
