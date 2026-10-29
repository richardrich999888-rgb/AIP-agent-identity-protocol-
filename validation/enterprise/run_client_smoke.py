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
from openapi_contract import validate_run_reads

ROOT = Path(__file__).resolve().parents[2]

# Which stage is executing. Updated by `mark` and read only by the failure
# writer, so a refusal names where it happened without any caller passing
# state around.
_STAGE = {"name": "startup"}

# Exception type -> fixed classification. The exception MESSAGE is never
# retained: this script is invoked with three API key files and compares full
# run bundles, so an upstream message can carry key material or evidence
# bytes. Same discipline as `safe_error` in same_run_validation.py.
_CLASSES = {
    "AssertionError": "assurance_predicate_failed",
    "ApiError": "service_rejected_request",
    "HTTPError": "unexpected_http_status",
    "URLError": "service_unreachable",
    "JSONDecodeError": "malformed_service_response",
    "TimeoutExpired": "subordinate_client_timeout",
    "CalledProcessError": "subordinate_client_exited_nonzero",
    "FileNotFoundError": "required_runtime_missing",
    "ModuleNotFoundError": "required_client_dependency_missing",
    # Playwright raises this one class for a missing browser executable, a
    # sandbox refusal, a launch crash and a navigation failure alike, so the
    # class is a category and not a cause. `browser_facts` below is what
    # separates them.
    "Error": "browser_launch_or_navigation_error",
    "TimeoutError": "browser_wait_timed_out",
}

# Self-computed facts about the browser runtime, attached to a failure record
# only for the console stage. Every value here is something this script
# observes directly -- a uid, a path, whether a path exists, directory NAMES
# under a path we were told to use. None of it is upstream text, so the rule
# that no exception message is ever retained still holds.
def browser_facts():
    facts = {"euid": os.geteuid(),
             "browsers_path_env": os.environ.get("PLAYWRIGHT_BROWSERS_PATH")}
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as runtime:
            executable = runtime.chromium.executable_path
        facts["chromium_executable_path"] = executable
        facts["chromium_executable_exists"] = Path(executable).is_file()
    except Exception as error:
        facts["chromium_executable_path"] = None
        facts["chromium_executable_exists"] = None
        facts["executable_path_lookup_error_type"] = type(error).__name__
    root = facts["browsers_path_env"]
    if root and Path(root).is_dir():
        # Names only. These are Playwright's own version directories.
        facts["browsers_path_entries"] = sorted(
            entry.name for entry in Path(root).iterdir())[:20]
    else:
        facts["browsers_path_entries"] = None
    return facts


# DOM observations captured at the console failure site. Only code holding a
# live page can see these, so they are recorded there and merged by the
# failure writer. Counts, a URL this script constructed, and a length --
# never page text, which a server controls.
_CONSOLE_DOM = {}

#: The element ids the console flow drives. Listed once so the facts and the
#: flow cannot drift apart.
CONSOLE_SELECTORS = ("#credential", "#connect button", "#status", "#run-id",
                     "#run-form button", "#run", "#disconnect")


def mark(name):
    """Record the stage about to run. Costs nothing and makes exit 1 legible."""
    _STAGE["name"] = name


def record_console_dom(page, response_status=None):
    """Count the expected elements. Says which the page is missing, not why.

    CI run 40834240488 narrowed the failure to console_browser_assert with
    the chromium executable present and navigation complete, which leaves
    the DOM as the thing nobody could see. A selector count is the smallest
    fact that distinguishes "the console did not render" from "the console
    rendered and an assertion about its contents failed".
    """
    _CONSOLE_DOM["goto_http_status"] = response_status
    try:
        _CONSOLE_DOM["page_url"] = page.url
        _CONSOLE_DOM["content_length"] = len(page.content())
    except Exception as error:
        _CONSOLE_DOM["page_probe_error_type"] = type(error).__name__
    counts = {}
    for selector in CONSOLE_SELECTORS:
        try:
            counts[selector] = page.locator(selector).count()
        except Exception as error:
            counts[selector] = "probe_error:" + type(error).__name__
    _CONSOLE_DOM["selector_counts"] = counts


def write_failure(output, error):
    """Retain stage + classified type only. Never the message, never values.

    The controller discards this child's stderr on purpose, so without this
    record a failed readback reports only "python exited 1". Writing the
    record here keeps the diagnostics inside the process that knows the stage
    and outside the stream that may contain credentials.
    """
    name = type(error).__name__
    stage = _STAGE["name"]
    record = {
        "source_authority": "enterprise_client_readback_self_report",
        "stage": stage,
        "error_type": name,
        "error_class": _CLASSES.get(name, "unclassified_client_error"),
        "scope": "Stage, error class and self-observed runtime facts only; "
                 "no message, no key material, no bundle bytes.",
    }
    if stage.startswith("console_browser"):
        try:
            record["browser_facts"] = browser_facts()
        except Exception as probe_error:
            record["browser_facts"] = {"probe_failed": type(probe_error).__name__}
        if _CONSOLE_DOM:
            record["console_dom"] = dict(_CONSOLE_DOM)
    try:
        path = Path(output).parent / "client-smoke-failure.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2) + "\n")
    except OSError:
        # A diagnostics write must never mask the original refusal.
        pass
    return record


def refused(operation, status):
    try:
        operation()
    except ApiError as error:
        assert error.status == status
    else:
        raise AssertionError("restricted read succeeded")




def console_flow(page, reader_key, artifact_id, admitted, bundle, args):
    """The console interaction, unchanged. Extracted only so a failure
    inside it can be observed before it unwinds."""
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
    page.locator("#disconnect").click()
    assert page.locator("#run").inner_text() == "Disconnected"


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
    mark("load_disposable_credentials")
    writer_key, reader_key, other_key = [path.read_text().strip() for path in
        (args.writer_key_file, args.reader_key_file, args.other_key_file)]
    writer, reader, other = [VanianClient(args.url, lambda key=key: key,
        retries=0, allow_loopback_http=True, max_response_bytes=16 * 1024 * 1024)
        for key in (writer_key, reader_key, other_key)]
    mark("role_and_tenant_separation")
    assert writer.access()["role"] in ("machine", "admin")
    assert reader.access()["role"] == other.access()["role"] == "reader"
    assert reader.access()["tenant_id"] != other.access()["tenant_id"]
    mark("read_caller_bundle")
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

    mark("api_admission")
    admitted = post(writer_key, raw)
    artifact_id = admitted["run_artifact_id"]
    mark("openapi_contract")
    validate_run_reads(reader, other, writer, bundle=bundle, admitted=admitted)
    mark("python_sdk_readback")
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
    mark("cross_tenant_and_write_refusal")
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
    mark("exact_bundle_retrieval")
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
    mark("official_mcp_client")
    asyncio.run(mcp_checks())
    env = dict(os.environ, VANIAN_RUN_BASE_URL=args.url, VANIAN_RUN_ARTIFACT_ID=artifact_id,
        VANIAN_RUN_READER=reader_key, VANIAN_RUN_OTHER_READER=other_key,
        VANIAN_RUN_EXPECTED=json.dumps(admitted, separators=(",", ":")),
        VANIAN_RUN_SIGNED_VERDICT=json.dumps(bundle.get("signed_reconciliation")))
    mark("typescript_sdk")
    subprocess.run(["node", str(ROOT / "validation/enterprise/run_typescript_smoke.ts")],
        env=env, check=True, timeout=30)

    mark("console_browser_import")
    console = "NOT_EXERCISED"
    if args.browser:
        from playwright.sync_api import sync_playwright
        mark("console_browser_launch")
        with sync_playwright() as browser_runtime:
            browser = browser_runtime.chromium.launch(headless=True)
            mark("console_browser_navigate")
            page = browser.new_page()
            navigation = page.goto(args.url.rstrip("/") + "/console")
            mark("console_browser_assert")
            try:
                console_flow(page, reader_key, artifact_id, admitted, bundle, args)
            except BaseException:
                # Observe the page before unwinding; the exception is
                # re-raised untouched so the refusal is unchanged.
                try:
                    record_console_dom(page, getattr(navigation, "status", None))
                except Exception:
                    pass
                raise
            if args.screenshot:
                page.screenshot(path=str(args.screenshot), full_page=True)
            browser.close()
        console = "PASS"

    mark("write_report")
    report = {"run_id":bundle["run_id"],"run_artifact_id":artifact_id,
        "source_bundle_sha256":hashlib.sha256(raw).hexdigest(),
        "api_admission":"PASS","exact_bundle_retrieval":"PASS","openapi_contract":"PASS","python_sdk":"PASS",
        "typescript_sdk":"PASS","official_mcp_client":"PASS","cross_tenant_refusal":"PASS",
        "reader_write_and_raw_refusal":"PASS","console_browser":console,
        "signed_runtime_verdict_retrieval":"PASS" if bundle.get("signed_reconciliation") else "NOT_SUPPLIED",
        "evaluation":admitted["evaluation"],
        "scope":"Retrieval of this exact caller-provided run; workload provenance requires independent run evidence."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key != "evaluation"}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # The output path is positional in argv; recover it without re-parsing
        # so a diagnostics write cannot itself fail on a parse error.
        argv = sys.argv
        destination = argv[argv.index("--output") + 1] if "--output" in argv else "."
        record = write_failure(destination, error)
        print(json.dumps({"client_smoke_failure": record}), file=sys.stderr)
        raise
