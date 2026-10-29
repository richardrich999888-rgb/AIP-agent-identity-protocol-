"""Run actual pinned ContextForge, real MCP upstream and HTTP JSON-RPC client.

No kernel-observation or business-completion claim is made by this harness.
Generated keys/tokens stay in a temporary directory and never enter results.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
from concurrent.futures import ThreadPoolExecutor
import json
import os
import platform
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import yaml
import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from cpex.framework import PluginConfig
from vanian_contextforge import VanianToolReceiptPlugin

HERE = Path(__file__).resolve().parent
PIN = json.loads((HERE / "contextforge.lock.json").read_text())
AGENT = "agent.bank-evaluation"
PRINCIPAL = "vanian-validator@example.com"
HEADERS = ["X-AIP-Agent-Id", "X-AIP-Decision-Id", "X-AIP-Request-Id", "Mcp-Method", "Mcp-Name"]


def port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http(base: str, path: str, *, token: str | None = None, body=None, headers=None, raw: bytes | None = None):
    outgoing = {"Content-Type": "application/json", **(headers or {})}
    if token:
        outgoing["Authorization"] = "Bearer " + token
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    request = Request(base + path, data=data, headers=outgoing)
    try:
        with urlopen(request, timeout=25) as response:
            value = response.read()
            return response.status, json.loads(value) if value else None
    except HTTPError as error:
        value = error.read()
        try:
            return error.code, json.loads(value)
        except ValueError:
            return error.code, {"unparsed_error": True}


def wait_ready(base: str, process: subprocess.Popen, path: str = "/health") -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("service exited before readiness; inspect captured log")
        try:
            status, _ = http(base, path)
            if status < 500:
                return
        except (OSError, URLError, ValueError):
            pass
        time.sleep(0.2)
    raise RuntimeError("service did not become ready within 90 seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contextforge-source", type=Path, required=True)
    parser.add_argument("--signer-binary", type=Path, required=True)
    parser.add_argument("--fixture-binary", type=Path, help="Rust contextforge_fixture example (test authorization only)")
    parser.add_argument("--agent-script", type=Path, help="Optional real model workload")
    parser.add_argument("--agent-python", type=Path)
    parser.add_argument("--agent-kind", choices=("langgraph", "adk-a2a"), default="langgraph")
    parser.add_argument("--agent-model-directory", type=Path, help="Pre-downloaded model directory for the ADK lab")
    parser.add_argument("--agent-governance-manifest", type=Path, help="Optional native Microsoft ACS manifest")
    parser.add_argument("--agent-opa-binary", type=Path, help="OPA executable for the native ACS dispatcher")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, binary, output = args.contextforge_source.resolve(), args.signer_binary.resolve(), args.output.resolve()
    fixture_binary = args.fixture_binary.resolve() if args.fixture_binary else binary.parent / "examples/contextforge_fixture"
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != PIN["revision"]:
        raise RuntimeError("ContextForge source does not match contextforge.lock.json")
    if hashlib.sha256((source / "uv.lock").read_bytes()).hexdigest() != PIN["uv_lock_sha256"]:
        raise RuntimeError("ContextForge dependency lock does not match the pinned hash")
    for package, expected in [("cpex", PIN["cpex"]), ("mcp", PIN["mcp"]), ("mcp-types", PIN["mcp_types"])]:
        if importlib.metadata.version(package) != expected:
            raise RuntimeError("Run this harness with the pinned ContextForge virtual environment")
    python = source / ".venv/bin/python"
    if not python.is_file() or not binary.is_file() or not fixture_binary.is_file():
        raise RuntimeError("prepare the pinned virtual environment and build aip-tool-receipt plus the contextforge_fixture example first")
    output.mkdir(parents=True, exist_ok=False)
    repository = HERE.parent.parent
    manifest_paths = ["integrations/mcp-gateway/vanian_contextforge.py", "integrations/mcp-gateway/validate_contextforge.py",
                      "integrations/mcp-gateway/test_upstream.py", "integrations/mcp-gateway/contextforge.lock.json",
                      "aip-standalone/aip-mcp-gateway/src/bin/aip-tool-receipt.rs", "aip-standalone/aip-mcp-gateway/src/lib.rs",
                      "aip-standalone/aip-mcp-gateway/src/canonical.rs", "aip-standalone/aip-airi/src/receipt.rs",
                      "aip-standalone/aip-airi/src/boundary.rs", "aip-standalone/aip-mcp-gateway/examples/contextforge_fixture.rs"]
    if args.agent_script:
        manifest_paths.append(str(args.agent_script.resolve().relative_to(repository)))
    source_manifest = {path:hashlib.sha256((repository/path).read_bytes()).hexdigest() for path in manifest_paths}
    source_manifest["built_signer_binary"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    source_manifest["built_authorization_fixture_binary"] = hashlib.sha256(fixture_binary.read_bytes()).hexdigest()
    (output / "source-manifest.json").write_text(json.dumps(source_manifest, indent=2) + "\n")
    checks = []
    processes = []
    log_handles = []
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def check(name: str, condition: bool, detail: str = "") -> None:
        checks.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})
        print(json.dumps(checks[-1]), flush=True)
        if not condition:
            raise AssertionError(name + ": " + detail)

    with tempfile.TemporaryDirectory(prefix="vanian-contextforge-") as temporary:
        run = Path(temporary)
        gateway_port, upstream_port = port(), port()
        base = f"http://127.0.0.1:{gateway_port}"
        upstream = f"http://127.0.0.1:{upstream_port}"
        key = Ed25519PrivateKey.generate()
        keyfile = run / "gateway.key"
        keyfile.write_text(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
        keyfile.chmod(0o600)
        public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        jwt_secret = secrets.token_hex(32)
        journal, receipts, events = run / "requests.sqlite3", run / "receipts.jsonl", run / "upstream.jsonl"
        bank_database = run / "synthetic-bank.sqlite3"
        with sqlite3.connect(bank_database) as connection:
            connection.execute("CREATE TABLE loan_documents (loan_id INTEGER PRIMARY KEY, document_status TEXT NOT NULL)")
            connection.executemany("INSERT INTO loan_documents VALUES (?, ?)",
                                   [(loan_id, "synthetic-documents-require-human-review") for loan_id in [*range(1, 201), 500]])
        tools = {name: "receipt-test-" + name.replace("_", "-")
                 for name in ["loan_read", "loan_fail", "loan_slow", "loan_pause", "loan_unapproved"]}
        config = {
            "plugin_dirs": [str(HERE)],
            "plugin_settings": {"parallel_execution_within_band": False, "plugin_timeout": 15,
                                "fail_on_plugin_error": True, "include_user_info": True},
            "plugins": [{"name": "VanianToolReceipt", "kind": "vanian_contextforge.VanianToolReceiptPlugin",
                         "hooks": ["tool_pre_invoke", "tool_post_invoke"], "mode": "sequential", "on_error": "fail",
                         "priority": 2147483647, "config": {"signer_binary": str(binary), "replay_database": str(journal),
                         "tools": [tools[name] for name in ["loan_read", "loan_fail", "loan_slow", "loan_pause"]],
                         "agent_principals": {PRINCIPAL: AGENT}, "signer_timeout_seconds": 3}}],
        }
        configuration = run / "plugins.yaml"
        configuration.write_text(yaml.safe_dump(config))
        env = dict(os.environ)
        # This harness dispatches only to its own loopback servers. Ambient
        # developer proxy settings must not route those credentials elsewhere.
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env.pop(name, None)
        env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
        env.update({
            "PYTHONPATH": os.pathsep.join([str(source), str(HERE)]), "PYTHONUNBUFFERED": "1",
            "DATABASE_URL": "sqlite:///" + str(run / "contextforge.sqlite3"),
            "JWT_SECRET_KEY": jwt_secret, "AUTH_ENCRYPTION_SECRET": secrets.token_hex(32),
            "PLATFORM_ADMIN_EMAIL": PRINCIPAL, "PLATFORM_ADMIN_PASSWORD": secrets.token_urlsafe(32),
            "DEFAULT_USER_PASSWORD": secrets.token_urlsafe(32), "BASIC_AUTH_PASSWORD": secrets.token_urlsafe(32),
            "AUTH_REQUIRED": "true", "MCP_REQUIRE_AUTH": "true", "EMAIL_AUTH_ENABLED": "true",
            "MCP_ALLOWED_ORIGINS": json.dumps([base]),
            "SECURE_COOKIES": "false", "ENVIRONMENT": "development",
            "EMBED_ENVIRONMENT_IN_TOKENS": "false", "VALIDATE_TOKEN_ENVIRONMENT": "false",
            "PLUGINS_ENABLED": "true", "PLUGINS_CONFIG_FILE": str(configuration),
            "ENABLE_HEADER_PASSTHROUGH": "true",
            "PASSTHROUGH_HEADERS_SOURCE": "env", "DEFAULT_PASSTHROUGH_HEADERS": json.dumps(HEADERS),
            "SSRF_ALLOW_LOCALHOST": "true", "SSRF_ALLOW_PRIVATE_NETWORKS": "false",
            "TOOL_TIMEOUT": "1", "MAX_TOOL_RETRIES": "0", "GATEWAY_TOOL_NAME_SEPARATOR": "-",
            "MCPGATEWAY_UI_ENABLED": "false", "MCPGATEWAY_ADMIN_API_ENABLED": "true",
            "AIP_GATEWAY_KEY_FILE": str(keyfile), "AIP_GATEWAY_PUBLIC_KEY": public_key,
            "AIP_GATEWAY_ID": "gateway.contextforge.validation", "AIP_GATEWAY_KEY_VERSION": "1",
            "AIP_GATEWAY_RECEIPTS": str(receipts), "VANIAN_TEST_UPSTREAM_EVENTS": str(events),
            "VANIAN_TEST_BANK_DB": str(bank_database),
            "VANIAN_TEST_RELEASE_FILE": str(run / "release-test-barrier"),
        })
        token = jwt.encode({"sub": PRINCIPAL, "user": {"email": PRINCIPAL, "is_admin": True},
                            "is_admin": True, "teams": None, "token_use": "api", "jti": secrets.token_hex(16),
                            "aud": "mcpgateway-api", "iss": "mcpgateway", "iat": int(time.time()),
                            "exp": int(time.time()) + 3600}, jwt_secret, algorithm="HS256")

        # Configuration-negative tests use the real plugin constructor and
        # filesystem, separately from the live gateway cases below.
        signer_names = [name for name in env if name.startswith("AIP_GATEWAY_")]
        original_environment = {name:os.environ.get(name) for name in signer_names}
        try:
            os.environ.update({name:env[name] for name in signer_names})
            target, link = run / "must-not-be-created", run / "replay-link.sqlite3"
            link.symlink_to(target)
            for path, name in [(link, "replay_journal_symlink_refused_without_creating_target"),
                               (run / "nonprivate.sqlite3", "nonprivate_replay_journal_refused")]:
                if path != link:
                    path.touch(mode=0o600)
                    path.chmod(0o644)
                rejected = False
                try:
                    entry = {**config["plugins"][0], "config":{**config["plugins"][0]["config"], "replay_database":str(path)}}
                    VanianToolReceiptPlugin(PluginConfig.model_validate(entry))
                except (OSError, ValueError):
                    rejected = True
                check(name, rejected and not target.exists())
        finally:
            for name, value in original_environment.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        def launch(name: str, command: list[str]):
            logfile = (output / (name + ".log")).open("wb")
            log_handles.append(logfile)
            process = subprocess.Popen(command, cwd=run, env=env, stdout=logfile, stderr=subprocess.STDOUT)
            processes.append(process)
            return process

        def gateway_start():
            process = launch("contextforge", [str(python), "-m", "uvicorn", "mcpgateway.main:app",
                            "--host", "127.0.0.1", "--port", str(gateway_port), "--no-access-log"])
            wait_ready(base, process)
            return process

        def invocation(name="loan_read", loan_id=1, amount=500, decision=None, request_id=None, extra=None):
            decision, request_id = decision or secrets.token_hex(16), request_id or secrets.token_hex(16)
            headers = {"X-AIP-Agent-Id": AGENT, "X-AIP-Decision-Id": decision, "X-AIP-Request-Id": request_id}
            if extra:
                for header, value in extra.items():
                    if value is None:
                        headers.pop(header, None)
                    else:
                        headers[header] = value
            body = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                    "params": {"name": tools[name], "arguments": {"loan_id": loan_id, "amount": amount}}}
            return http(base, "/rpc", token=token, body=body, headers=headers), decision, request_id

        def event_count():
            return len(events.read_text().splitlines()) if events.exists() else 0

        def receipt_list():
            return [json.loads(line) for line in receipts.read_text().splitlines()] if receipts.exists() else []

        def succeeded(reply):
            status, value = reply
            return status == 200 and "result" in value and not value["result"].get("isError", False)

        def authorization(decision: str, loan_id: int, amount: int, label: str):
            fixture = json.loads(subprocess.check_output([str(fixture_binary)], input=json.dumps({
                "agent_id":AGENT, "decision_id":decision, "tool_id":tools["loan_read"],
                "arguments":{"loan_id":loan_id, "amount":amount},
            }).encode(), env=env))
            (output / (label + "-authorization.json")).write_text(json.dumps(fixture, indent=2) + "\n")
            return fixture

        def compare(fixture, signed, label: str):
            verify_env = {key:value for key,value in env.items() if key not in ("AIP_GATEWAY_KEY_FILE", "AIP_GATEWAY_RECEIPTS")}
            verify_env.update({"AIP_DECISION_POINT_ID":fixture["decision_point_id"], "AIP_DECISION_POINT_PUBLIC_KEY":fixture["public_key"]})
            result = json.loads(subprocess.check_output([str(binary), "compare"], input=json.dumps({
                "signed_receipt":signed, "expectation":fixture["expectation"],
            }).encode(), env=verify_env))
            (output / (label + "-comparison.json")).write_text(json.dumps(result, indent=2) + "\n")
            return result["tool_boundary"]

        try:
            upstream_process = launch("upstream", [str(python), str(HERE / "test_upstream.py"), "--port", str(upstream_port)])
            wait_ready(upstream, upstream_process, "/mcp")
            gateway = gateway_start()
            status, created = http(base, "/gateways", token=token, body={"name": "receipt-test", "url": upstream + "/mcp",
                "transport": "STREAMABLEHTTP", "passthrough_headers": HEADERS, "visibility": "public"})
            check("actual_contextforge_registers_real_mcp_upstream", status in (200, 201), str(status) + ": " + str(created)[:400])
            first_decision = secrets.token_hex(16)
            honest_authorization = authorization(first_decision, 1, 500, "honest")
            reply, first_decision, first_id = invocation(decision=first_decision)
            check("valid_tool_invocation_reaches_upstream_and_has_signed_receipt", succeeded(reply) and event_count() == 1
                  and receipt_list()[-1]["receipt"]["disposition"] == "Forwarded", "200; signed receipt and one real upstream invocation" if succeeded(reply) else str(reply)[:500])
            check("live_receipt_agrees_with_preissued_signed_authorization_via_real_comparator",
                  "Agrees" in compare(honest_authorization, receipt_list()[-1], "honest"))
            before = event_count()
            replay, _, _ = invocation(decision=first_decision, request_id=first_id)
            check("duplicate_request_refused_without_second_dispatch", not succeeded(replay) and event_count() == before)
            replay, _, _ = invocation(decision=first_decision)
            check("decision_replay_with_new_request_id_refused", not succeeded(replay) and event_count() == before)
            missing, _, _ = invocation(extra={"X-AIP-Decision-Id": None})
            check("missing_decision_refused_without_dispatch", not succeeded(missing) and event_count() == before)
            wrong_agent, _, _ = invocation(extra={"X-AIP-Agent-Id": "agent.impostor"})
            check("principal_agent_mismatch_refused", not succeeded(wrong_agent) and event_count() == before)
            mismatch, _, _ = invocation(extra={"Mcp-Name": "another-tool"})
            check("header_body_disagreement_refused", not succeeded(mismatch) and event_count() == before)
            mismatch, _, _ = invocation(extra={"Mcp-Method": "tools/list"})
            check("method_header_body_disagreement_refused", not succeeded(mismatch) and event_count() == before)
            unapproved, _, _ = invocation(name="loan_unapproved")
            check("unsupported_tool_refused_before_dispatch", not succeeded(unapproved) and event_count() == before)
            malformed_status, malformed = http(base, "/rpc", token=token, raw=b"{broken")
            check("malformed_json_rpc_cannot_dispatch", malformed_status >= 400 or "error" in malformed)
            status, unauthorized = http(base, "/rpc", body={"jsonrpc":"2.0", "id":1,"method":"tools/list"})
            check("unauthenticated_client_rejected", status in (401, 403), str(status))
            status, _ = http(base, "/mcp", token=token, body={"jsonrpc":"2.0", "id":1, "method":"tools/list"},
                             headers={"Origin":"http://untrusted.invalid", "MCP-Protocol-Version":"2026-07-28", "Mcp-Method":"tools/list"})
            check("mcp_ingress_rejects_unapproved_origin", status == 403, str(status))
            async def official_client():
                headers = {"Authorization":"Bearer " + token, "X-AIP-Agent-Id":AGENT,
                           "X-AIP-Decision-Id":secrets.token_hex(16), "X-AIP-Request-Id":secrets.token_hex(16)}
                async with httpx2.AsyncClient(headers=headers, timeout=20, trust_env=False) as http_client:
                    async with Client(streamable_http_client(base + "/mcp", http_client=http_client),
                                      mode="2026-07-28", cache=None) as client:
                        await client.list_tools()
                        result = await client.call_tool(tools["loan_read"], {"loan_id":2, "amount":0})
                        return client.protocol_version, result.model_dump(by_alias=True)
            before, before_mcp_receipts = event_count(), len(receipt_list())
            version, mcp_result = asyncio.run(official_client())
            (output / "mcp-client-result.json").write_text(json.dumps({"protocol_version":version, "result":mcp_result}, indent=2) + "\n")
            check("official_mcp_2_3_client_uses_2026_07_28_transport_and_signed_receipt",
                  version == "2026-07-28" and not mcp_result.get("isError", False) and event_count() == before + 1
                  and len(receipt_list()) == before_mcp_receipts + 1 and receipt_list()[-1]["receipt"]["disposition"] == "Forwarded",
                  json.dumps({"protocol_version":version,"isError":mcp_result.get("isError"),"actual_dispatches":event_count()-before,
                              "receipt_persisted":len(receipt_list()) == before_mcp_receipts + 1,
                              "upstream_compatibility":"Pinned ContextForge strips successful top-level result metadata on /mcp; receipt remains in gateway sink."}))
            failed, _, _ = invocation(name="loan_fail")
            check("real_upstream_error_has_failed_receipt", not succeeded(failed) and receipt_list()[-1]["receipt"]["disposition"] == "Failed")
            slow, _, _ = invocation(name="loan_slow")
            check("gateway_timeout_has_no_success_receipt", not succeeded(slow) and receipt_list()[-1]["receipt"]["disposition"] == "Failed")
            before = event_count()
            with ThreadPoolExecutor(max_workers=8) as executor:
                replies = list(executor.map(lambda index: invocation(loan_id=100 + index)[0], range(8)))
            check("concurrent_calls_have_distinct_signed_receipts", all(succeeded(reply) for reply in replies) and event_count() == before + 8)
            before = event_count()
            race_decision, race_request = secrets.token_hex(16), secrets.token_hex(16)
            with ThreadPoolExecutor(max_workers=8) as executor:
                racing = list(executor.map(lambda _: invocation(decision=race_decision, request_id=race_request)[0], range(8)))
            check("concurrent_duplicate_calls_dispatch_exactly_once", sum(succeeded(reply) for reply in racing) == 1 and event_count() == before + 1)
            mismatched_decision = secrets.token_hex(16)
            mismatch_authorization = authorization(mismatched_decision, 500, 500, "mismatch")
            mismatch, _, _ = invocation(loan_id=500, amount=5_000_000, decision=mismatched_decision)
            mismatch_boundary = compare(mismatch_authorization, receipt_list()[-1], "mismatch")
            check("live_parameter_mismatch_diverges_via_real_rust_comparator_without_agent_claim", succeeded(mismatch)
                  and "ReceiptDoesNotMatchAuthorization" in mismatch_boundary.get("Diverges", {}).get("divergence", {}))
            gateway.terminate()
            gateway.wait(timeout=20)
            gateway = gateway_start()
            before = event_count()
            replay, _, _ = invocation(decision=first_decision, request_id=first_id)
            check("gateway_restart_preserves_replay_protection", not succeeded(replay) and event_count() == before)
            # Corrupt the key after startup: pre-dispatch anchor checking must fail.
            original_key = keyfile.read_text()
            keyfile.write_text(secrets.token_hex(32))
            bad_key, _, _ = invocation()
            check("wrong_signing_key_refused_before_dispatch", not succeeded(bad_key) and event_count() == before)
            keyfile.write_text(original_key)
            receipts.rename(run / "receipts.saved.jsonl")
            receipts.mkdir()
            sink_failure, _, _ = invocation()
            check("receipt_sink_failure_refused_before_dispatch", not succeeded(sink_failure) and event_count() == before)
            receipts.rmdir()
            (run / "receipts.saved.jsonl").rename(receipts)
            before, before_receipts = event_count(), len(receipt_list())
            with ThreadPoolExecutor(max_workers=1) as executor:
                paused = executor.submit(invocation, name="loan_pause")
                deadline = time.monotonic() + 5
                while event_count() == before and time.monotonic() < deadline:
                    time.sleep(0.01)
                if event_count() != before + 1:
                    raise AssertionError("upstream barrier tool did not start")
                keyfile.write_text(secrets.token_hex(32))
                (run / "release-test-barrier").touch()
                signing_outage, _, _ = paused.result(timeout=10)
                keyfile.write_text(original_key)
            failed_result = signing_outage[1].get("result", {})
            check("post_dispatch_signing_failure_reports_cannot_prove_without_success_receipt",
                  not succeeded(signing_outage) and len(receipt_list()) == before_receipts
                  and failed_result.get("_meta", {}).get("vanian", {}).get("coverage") == "CANNOT_PROVE")
            (run / "release-test-barrier").unlink()
            before, before_receipts = event_count(), len(receipt_list())
            with ThreadPoolExecutor(max_workers=1) as executor:
                paused = executor.submit(invocation, name="loan_pause")
                deadline = time.monotonic() + 5
                while event_count() == before and time.monotonic() < deadline:
                    time.sleep(0.01)
                if event_count() != before + 1:
                    raise AssertionError("upstream barrier tool did not start")
                keyfile.write_text(secrets.token_hex(32))
                journal.rename(run / "requests.saved.sqlite3")
                journal.mkdir()
                (run / "release-test-barrier").touch()
                combined_outage, _, _ = paused.result(timeout=10)
                keyfile.write_text(original_key)
                journal.rmdir()
                (run / "requests.saved.sqlite3").rename(journal)
            failed_result = combined_outage[1].get("result", {})
            check("journal_failure_cannot_mask_post_dispatch_receipt_uncertainty",
                  not succeeded(combined_outage) and len(receipt_list()) == before_receipts
                  and failed_result.get("_meta", {}).get("vanian", {}).get("coverage") == "CANNOT_PROVE")
            if args.agent_script:
                if not args.agent_python:
                    raise ValueError("--agent-script requires --agent-python")
                before_events, before_receipts = event_count(), len(receipt_list())
                # The monitored workload gets only its gateway credential and
                # model selection. No signer/authority/collector configuration.
                agent_env = {"PATH":os.defpath, "PYTHONUNBUFFERED":"1",
                             "VANIAN_BANK_GATEWAY_BASE_URL":base, "VANIAN_BANK_GATEWAY_TOKEN":token,
                             "VANIAN_BANK_TOOL_NAME":tools["loan_read"], "VANIAN_BANK_MODEL":"llama3.2:1b"}
                if args.agent_kind == "adk-a2a":
                    if not args.agent_model_directory or not args.agent_model_directory.is_dir():
                        raise ValueError("ADK workload requires a pre-downloaded model directory")
                    agent_env["VANIAN_LOCAL_MODEL_DIR"] = str(args.agent_model_directory.resolve())
                    agent_env["VANIAN_INTEROP_RESULTS"] = str(output / "adk-a2a")
                    if args.agent_governance_manifest:
                        if not args.agent_opa_binary:
                            raise ValueError("native governance requires --agent-opa-binary")
                        agent_env["VANIAN_MICROSOFT_MANIFEST"] = str(args.agent_governance_manifest.resolve())
                        agent_env["ACS_OPA_PATH"] = str(args.agent_opa_binary.resolve())
                        (output / "governance-comparison-context.json").write_text(json.dumps({
                            "tenant": "synthetic-provider", "expected_gateway_agent": AGENT,
                            "expected_framework_agent": "provider_research",
                            "expected_policy_version": "vanian-synthetic-research-v2",
                            "tool_aliases": {"read_loan": tools["loan_read"]},
                        }, indent=2) + "\n")
                # Preserve the venv executable path: resolving its symlink
                # would launch the base interpreter without the framework.
                agent = subprocess.run([str(args.agent_python.absolute()), str(args.agent_script.resolve())],
                                       env=agent_env, cwd=run, capture_output=True, timeout=240)
                (output / f"{args.agent_kind}-agent.log").write_bytes(agent.stdout + agent.stderr)
                check(f"real_{args.agent_kind}_model_chooses_gateway_tool_with_independent_receipt",
                      agent.returncode == 0 and event_count() == before_events + 1 and len(receipt_list()) == before_receipts + 1
                      and receipt_list()[-1]["receipt"]["disposition"] == "Forwarded",
                      "No kernel observation or signed execution verdict is claimed.")
            for signed in receipt_list():
                verify_env = {key: value for key, value in env.items() if key not in ("AIP_GATEWAY_KEY_FILE", "AIP_GATEWAY_RECEIPTS")}
                verification = subprocess.run([str(binary), "verify"], input=json.dumps(signed).encode(), env=verify_env,
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if verification.returncode:
                    raise AssertionError("independent Rust receipt verification failed")
            check("every_exported_receipt_verifies_offline_with_public_anchor_only", bool(receipt_list()))
            shutil.copyfile(receipts, output / "receipts.jsonl")
            shutil.copyfile(events, output / "upstream-events.jsonl")
            with sqlite3.connect(journal) as connection:
                journal_states = dict(connection.execute("SELECT state, COUNT(*) FROM requests GROUP BY state"))
            (output / "trust-anchor.json").write_text(json.dumps({"gateway_id":env["AIP_GATEWAY_ID"], "key_version":1, "public_key":public_key}, indent=2) + "\n")
            report = {"started_at":started_at, "finished_at":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "contextforge":PIN, "checks":checks, "journal_states":journal_states,
                      "host":{"os":platform.system(),"architecture":platform.machine(),"python":sys.version.split()[0]},
                      "scope":"Actual ContextForge + real MCP upstream + HTTP JSON-RPC client. No kernel observation, no banking outcome proof.",
                      "receipt_count":len(receipt_list()), "upstream_invocation_count":event_count()}
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({"result":"PASS", "checks":len(checks), "output":str(output)}), flush=True)
            return 0
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            for handle in log_handles:
                handle.close()
            if not (output / "report.json").exists():
                (output / "report.json").write_text(json.dumps({"result":"FAIL", "contextforge":PIN, "checks":checks,
                    "started_at":started_at, "detail":"Run failed; inspect captured logs. Secrets remained in deleted temporary directory."}, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
