#!/usr/bin/env python3
"""Retain exact commands, exit statuses, source hashes and honest local scope."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    started = datetime.now(timezone.utc)
    output = args.output or ROOT / "validation/enterprise/results" / started.strftime("%Y%m%dT%H%M%SZ")
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "sdk/python")
    env["AIP_ENTERPRISE_CLIENT_SMOKE"] = str(ROOT / "validation/enterprise/client_smoke.py")
    env["AIP_ENTERPRISE_PYTHON"] = sys.executable
    commands = [
        ("format", ["cargo", "fmt", "--all", "--", "--check"]),
        ("rust", ["cargo", "test", "--locked", "-p", "airon-aip", "-p", "aip-mcp-gateway", "-p", "aip-airi", "-p", "aip-authorize", "-p", "aip-observe-verify", "-p", "aip-transport", "-p", "aip-collector", "-p", "aip-reconcile", "--no-fail-fast"]),
        ("postgres_compile", ["cargo", "test", "--locked", "-p", "airon-aip", "--features", "postgres", "--no-run"]),
        ("rbi_controls", [sys.executable, "-B", "validation/rbi_demo/test_run.py"]),
        ("packaging", [sys.executable, "-B", "validation/enterprise/test_packaging.py"]),
        ("agent_harness", [sys.executable, "-B", "validation/enterprise/test_agent_harness.py"]),
        ("sql_parity", [sys.executable, "-B", "validation/enterprise/test_sql_provisioning.py"]),
        ("python_sdk", [sys.executable, "-m", "unittest", "discover", "-s", "sdk/python/tests", "-v"]),
        ("mcp_boundaries", [sys.executable, "validation/enterprise/test_client_boundaries.py"]),
        ("typescript_sdk", ["node", "--test", "sdk/typescript/test/client.test.ts"]),
        ("console_syntax", ["node", "--check", "integrations/enterprise-console/app.js"]),
        ("real_api_mcp_clients", ["cargo", "test", "--locked", "-p", "airon-aip", "--test", "enterprise_api", "real_http_clients_use_the_service_boundary", "--", "--ignored", "--nocapture"]),
        ("offline_build", ["cargo", "build", "--locked", "-p", "aip-observe-verify", "-p", "aip-reconcile", "--bin", "aip-lineage", "--bin", "aip-observe-verify"]),
        ("historical_offline", [sys.executable, "integrations/real_agents/tests/offline_archive_check.py", "--repo", str(ROOT), "--tools", str(ROOT / "target/debug")]),
        ("shell_syntax", ["bash", "-n", "integrations/agents/run.sh"]),
        ("whitespace", ["git", "diff", "--check"]),
    ]
    report = {"started_at": started.isoformat(), "host": platform.platform(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_status": subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True).splitlines(),
        "checks": [], "limitations": ["Local Darwin checks do not exercise Linux kernel sensors, clean Linux installation, two-host separation, PostgreSQL runtime, or institutional performance.",
            "The offline regression uses historical repository fixtures, not a new runtime capture."]}
    # Bind tests to actual source bytes, including new files not committed yet.
    paths = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
    report["source_sha256"] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
        for p in paths if (ROOT / p).is_file() and not p.startswith("validation/enterprise/results/")}
    print("RESULTS " + str(output), flush=True)
    for name, command in commands:
        start = time.monotonic()
        with (output / (name + ".log")).open("wb") as log:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        check = {"name": name, "command": command, "exit_code": result.returncode,
            "status": "PASS" if result.returncode == 0 else "FAIL", "seconds": time.monotonic() - start}
        report["checks"].append(check)
        print(json.dumps(check), flush=True)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return int(any(c["exit_code"] for c in report["checks"]))


if __name__ == "__main__":
    raise SystemExit(main())
