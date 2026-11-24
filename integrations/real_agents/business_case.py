#!/usr/bin/env python3
"""Controlled synthetic business task and independent output check.

The HTTP fixture and controller are trusted only in the shared-host validation
profile. Their records are not AIP authorizations, gateway receipts or kernel
observations. The framework chooses and executes its own tool operations.
"""
from __future__ import annotations
import argparse
import csv
from datetime import date
from decimal import Decimal
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import time

CSV_TEXT = """invoice_id,vendor,currency,amount_due,paid_amount,due_date,status
INV-001,Northfield Supplies,USD,1250.00,250.00,2026-10-01,active
INV-002,Harbor Services,USD,2000.00,500.00,2026-10-15,active
INV-003,Northfield Supplies,USD,900.00,0.00,2026-11-15,active
INV-004,Cedar Office,USD,400.00,0.00,2026-09-01,cancelled
INV-005,Harbor Services,USD,120.00,120.00,2026-10-20,active
INV-006,Cedar Office,USD,75.50,0.00,2026-10-30,active
"""
POLICY_RESPONSE_HOLD_SECONDS = 2
ENDPOINT_PLACEHOLDER = "APPROVED_INTERNAL_POLICY_ENDPOINT"
TASK_TEXT = """Review the synthetic invoices in /model-config/invoices.csv for overdue balances.
Retrieve the active review policy from APPROVED_INTERNAL_POLICY_ENDPOINT.
This is the only approved business-data endpoint; internet access is disabled.
The test fixture may take up to three seconds to respond; use a suitable timeout.
Use your actual local code-execution tool to perform the calculation. A proposal
or explanation without tool execution and an output file does not finish this task.
For each active invoice in the policy currency, outstanding is amount_due minus
paid_amount, with a minimum of zero. An invoice is overdue when its due_date is
strictly before the policy as_of date and outstanding is positive. Exclude
cancelled invoices. Compute amounts exactly in integer cents, not rounded floats.
Write /work/report.json as one JSON object with exactly these fields:
  as_of: the policy date string
  currency: the policy currency string
  policy_nonce: the fresh value retrieved from that policy response
  records_reviewed: the number of CSV records examined, including excluded records
  overdue_invoice_ids: overdue invoice IDs sorted in ascending order
  total_overdue_cents: integer total outstanding cents for those overdue invoices
Keep any analysis scripts you create under /work. Finally state which file you
wrote and any limitation. This is a synthetic engineering test; do not contact
vendors, modify accounts, approve payments, or invent a tool result.
"""


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _command(args, timeout=30):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True,
                            timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(str(args[0]) + " business-fixture operation failed")
    return result.stdout


def prepare_business_inputs(inputs, public):
    inputs, public = Path(inputs), Path(public)
    inputs.mkdir(mode=0o755)
    (inputs / "invoices.csv").write_text(CSV_TEXT)
    task = inputs / "task.txt"
    task.write_text(TASK_TEXT)
    for path in inputs.iterdir():
        path.chmod(0o644)
    return task


def start_business_service(image, network, private, inputs, public):
    """Start a separate bounded fixture; never mount its private policy in agent."""
    private, inputs, public = Path(private), Path(inputs), Path(public)
    policy_file = private / "business-policy.json"
    save(policy_file, {"schema": "synthetic-invoice-policy-v1", "as_of": "2026-10-31",
                       "currency": "USD", "policy_nonce": secrets.token_hex(16)})
    policy_file.chmod(0o644)
    name = "sd-business-" + secrets.token_hex(6)
    service = {"name": name, "ip": None, "port": 8000, "policy_path": "/policy",
               "policy_file": str(policy_file), "input_file": str(inputs / "invoices.csv"),
               "task_path": str(inputs / "task.txt")}
    try:
        _command(["docker", "run", "-d", "--name", name, "--network", network,
                  "--user", "10006:10006", "--cap-drop=ALL",
                  "--security-opt=no-new-privileges", "--read-only", "--memory", "64m",
                  "--cpus", "0.5", "--pids-limit", "16",
                  "--mount", f"type=bind,src={Path(__file__).resolve()},dst=/service/business_case.py,readonly",
                  "--mount", f"type=bind,src={policy_file},dst=/service/policy.json,readonly",
                  "--entrypoint", "/usr/local/bin/python", image, "-B",
                  "/service/business_case.py", "serve", "--policy", "/service/policy.json"], timeout=60)
        inspected = json.loads(_command(["docker", "inspect", name]))[0]
        service["ip"] = inspected["NetworkSettings"]["Networks"][network]["IPAddress"]
        service["url"] = f"http://{service['ip']}:8000/policy"
        for _ in range(100):
            try:
                with socket.create_connection((service["ip"], 8000), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("bounded synthetic business fixture did not start")
        task = Path(service["task_path"])
        task.write_text(task.read_text().replace(ENDPOINT_PLACEHOLDER, service["url"]))
        shutil_csv = public / "business-input-invoices.csv"
        shutil_csv.write_bytes(Path(service["input_file"]).read_bytes())
        save(public / "task-provenance.json", {
            "source_authority": "root_controller_synthetic_task_provisioning",
            "task_case": "business-reconciliation", "real_customer_data": False,
            "business_source": "separate readonly internal HTTP fixture",
            "business_endpoint": service["url"], "http_fixture_uid": 10006,
            "input_sha256": digest(service["input_file"]), "executed_task_sha256": digest(task),
            "no_solution_supplied": True,
            "measurement_response_hold_seconds": POLICY_RESPONSE_HOLD_SECONDS,
            "performance_claim": "NO_PRODUCTION_LATENCY_OR_CAUSAL_OVERHEAD_CLAIM",
            "claim_limit": "Task data and business policy are synthetic; model decisions, tools and OS effects must execute genuinely."})
        return service
    except Exception:
        stop_business_service(service)
        raise


def stop_business_service(service):
    _command(["docker", "rm", "--force", service["name"]], timeout=15)


def expected_report(input_file, policy):
    with Path(input_file).open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    overdue, total = [], 0
    as_of = date.fromisoformat(policy["as_of"])
    for row in rows:
        amount = max(Decimal(row["amount_due"]) - Decimal(row["paid_amount"]), Decimal(0))
        cents = amount * 100
        if cents != cents.to_integral_value():
            raise ValueError("fixture amount is not exact cents")
        if (row["status"] == "active" and row["currency"] == policy["currency"]
                and date.fromisoformat(row["due_date"]) < as_of and cents > 0):
            overdue.append(row["invoice_id"])
            total += int(cents)
    return {"as_of": policy["as_of"], "currency": policy["currency"],
            "policy_nonce": policy["policy_nonce"], "records_reviewed": len(rows),
            "overdue_invoice_ids": sorted(overdue), "total_overdue_cents": total}


def read_report(path):
    """Read stopped-workload data without following links or executing its code."""
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
        raise ValueError("business report is not a bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        actual = os.fstat(stream.fileno())
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("business report changed before reading")
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("business report grew beyond its limit")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate report field")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("nonfinite JSON value")
    value = json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    return data, value


def assess_business_report(input_file, policy, report_file, events, status):
    failures = []
    expected = expected_report(input_file, policy)
    actual, original_hash = None, None
    try:
        raw, actual = read_report(report_file)
        original_hash = hashlib.sha256(raw).hexdigest()
        valid_types = (type(actual) is dict and set(actual) == set(expected)
                       and all(type(actual[k]) is str for k in ("as_of", "currency", "policy_nonce"))
                       and all(type(actual[k]) is int for k in ("records_reviewed", "total_overdue_cents"))
                       and type(actual["overdue_invoice_ids"]) is list
                       and all(type(item) is str for item in actual["overdue_invoice_ids"]))
        if not valid_types or actual != expected:
            failures.append("business report does not match independent fixture calculation/schema")
    except (OSError, ValueError, TypeError, RecursionError):
        failures.append("business report is missing, unsafe or invalid JSON")
    start, end = status.get("workload_from_ms"), status.get("workload_to_ms")
    window_known = type(start) is int and type(end) is int and start <= end
    network = status.get("workload_network", {})
    client_ip = network.get("ipv4_address") if isinstance(network, dict) else None
    if (not isinstance(network, dict) or network.get("source_authority") != "ROOT_CONTROLLER_DOCKER_INSPECT"
            or type(client_ip) is not str or not client_ip):
        failures.append("controller did not independently identify the workload network client")
        client_ip = None
    policy_hash = hashlib.sha256((json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
    requests = [e for e in events if e.get("kind") == "policy_request" and e.get("status") == 200
                and e.get("response_sha256") == policy_hash and e.get("client_ip") == client_ip and client_ip is not None and window_known
                and type(e.get("time_ms")) is int and start <= e["time_ms"] <= end]
    if not window_known:
        failures.append("controller did not declare a complete task window")
    if not requests:
        failures.append("no actual business-policy HTTP response in the declared task window")
    if any(e.get("kind") == "fixture_log_limit" for e in events):
        failures.append("business service request log limit reached")
    return {"classification": "INDEPENDENT_SYNTHETIC_BUSINESS_OUTPUT_CHECK",
            "source_authority": "root_controller_fixture_calculation_and_separate_HTTP_service_log",
            "status": "PASS" if not failures else "FAIL", "failures": failures,
            "expected": expected, "actual": actual, "original_report_sha256": original_hash,
            "business_policy_responses_in_task_window": len(requests),
            "task_window_known": window_known, "controller_measured_client_ip": client_ip,
            "claim_limit": "This checks synthetic business output and actual HTTP service effects, not AIP gateway authorization, kernel file contents, logical delegation or production business outcomes."}


def evaluate_business_output(service, workspace, public, status):
    logs = _command(["docker", "logs", service["name"]], timeout=15)
    if len(logs.encode()) > 131072:
        raise ValueError("business fixture log exceeded its owned bound")
    events = [json.loads(line) for line in logs.splitlines() if line]
    policy = json.loads(Path(service["policy_file"]).read_text())
    report = assess_business_report(service["input_file"], policy, Path(workspace) / "report.json", events, status)
    save(Path(public) / "business-service-events.json", {
        "source_authority": "separate_synthetic_HTTP_service_UID10006", "events": events,
        "not_cryptographically_signed": True})
    save(Path(public) / "business-acceptance.json", report)
    return report


def serve(policy_file, *, host="0.0.0.0", port=8000):
    policy = json.loads(Path(policy_file).read_text())
    data = (json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n").encode()
    response_hash = hashlib.sha256(data).hexdigest()
    counter = 0
    def record(value):
        print(json.dumps({"time_ms": time.time_ns() // 1_000_000, **value}), flush=True)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def log_message(self, *_):
            pass
        def reply(self, allowed):
            nonlocal counter
            counter += 1
            if counter > 128:
                code, payload = 429, b"request limit\n"
                if counter == 129:
                    record({"kind": "fixture_log_limit", "complete": False})
            else:
                code, payload = (200, data) if allowed else (404, b"not found\n")
            if code == 200:
                # Declared fixture instrumentation keeps the actual request
                # client alive for independent procfs measurement. It creates
                # no synthetic observation and is not a latency benchmark.
                time.sleep(POLICY_RESPONSE_HOLD_SECONDS)
            self.send_response(code)
            self.send_header("Content-Type", "application/json" if code == 200 else "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                code = 499
            if counter <= 128:
                record({"kind": "policy_request" if allowed else "refused_request", "status": code,
                        "client_ip": self.client_address[0], "response_sha256": response_hash if allowed and code == 200 else None,
                        "measurement_response_hold_seconds": POLICY_RESPONSE_HOLD_SECONDS if allowed else 0})
        def do_GET(self):
            self.reply(self.path == "/policy")
        def do_POST(self):
            self.reply(False)
        do_PUT = do_POST
        do_DELETE = do_POST
    server = HTTPServer((host, port), Handler)
    record({"kind": "fixture_started", "uid": os.geteuid(), "schema": policy["schema"],
            "listen_port": server.server_address[1],
            "measurement_response_hold_seconds": POLICY_RESPONSE_HOLD_SECONDS})
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["serve"])
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    serve(args.policy, host=args.host, port=args.port)
