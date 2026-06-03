#!/usr/bin/env python3
"""Run a local AIRON pilot smoke and latency evidence pass."""

from __future__ import annotations

import base64
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from generate_airon_latency_histogram import build_report


REPO_ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = REPO_ROOT / "pilot-results"


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_json(cmd: list[str], cwd: Path = REPO_ROOT) -> dict[str, Any]:
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"command produced no JSON output: {' '.join(cmd)}")
    return json.loads(lines[-1])


def request_json(method: str, url: str, body: dict[str, Any] | None = None) -> tuple[dict[str, Any], float]:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=5) as resp:
        payload = resp.read()
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return json.loads(payload.decode("utf-8")), elapsed_ms


def wait_for_health(base_url: str, proc: subprocess.Popen[str]) -> None:
    deadline = time.time() + 30
    last_error: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"AIP service exited early with code {proc.returncode}")
        try:
            request_json("GET", f"{base_url}/health")
            return
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f"AIP service did not become healthy: {last_error}")


def decode_jti(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three segments")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    return str(claims["jti"])


def run_aip_http_smoke() -> dict[str, Any]:
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="airon-aip-pilot-") as tmp:
        env = os.environ.copy()
        env.update(
            {
                "AIP_PORT": str(port),
                "AIP_KEY_PATH": str(Path(tmp) / "signing.key"),
                "AIP_DELEGATION_LOG_PATH": str(Path(tmp) / "delegation.jsonl"),
                "AIP_REVOCATION_LOG_PATH": str(Path(tmp) / "revocation.jsonl"),
                "AIP_ISSUER_URL": base_url,
                "RUST_LOG": "warn",
            }
        )
        proc = subprocess.Popen(
            [
                "cargo",
                "run",
                "--release",
                "--manifest-path",
                "aip-service/Cargo.toml",
                "--bin",
                "airon-aip",
                "--quiet",
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            wait_for_health(base_url, proc)
            timings_ms: dict[str, list[float]] = {}

            def call(name: str, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
                response, elapsed = request_json(method, f"{base_url}{path}", body)
                timings_ms.setdefault(name, []).append(elapsed)
                return response

            health = call("health", "GET", "/health")
            config = call("wellknown_config", "GET", "/.well-known/aip-configuration")
            jwks = call("jwks", "GET", "/.well-known/jwks.json")
            issue = call(
                "issue",
                "POST",
                "/v1/identity/issue",
                {
                    "agent_id": str(uuid.uuid4()),
                    "agent_type": "ai_model",
                    "metadata": {"pilot": "local", "component": "AIP"},
                    "ttl_seconds": 300,
                },
            )
            token = issue["token"]
            jti = decode_jti(token)
            verify_samples = []
            for _ in range(100):
                verified = call("verify", "POST", "/v1/identity/verify", {"token": token})
                verify_samples.append(timings_ms["verify"][-1])
                if not verified["valid"]:
                    raise RuntimeError(f"issued token did not verify: {verified}")

            delegation = call(
                "delegate",
                "POST",
                "/v1/identity/delegate",
                {
                    "parent_token": token,
                    "delegatee_id": str(uuid.uuid4()),
                    "scope": {
                        "allowed": ["evaluate_content", "read_audit_log"],
                        "denied": [],
                    },
                    "ttl_seconds": 300,
                },
            )["delegation"]
            chain = call(
                "verify_chain",
                "POST",
                "/v1/identity/verify-chain",
                {
                    "root_token": token,
                    "delegation_ids": [delegation["delegation_id"]],
                },
            )
            revoke = call(
                "revoke",
                "POST",
                "/v1/identity/revoke",
                {
                    "jti": jti,
                    "revoked_by": "local-pilot",
                    "reason": "pilot cascade revocation check",
                    "cascade": True,
                },
            )
            status = call("revocation_status", "GET", f"/v1/identity/revocation-status/{jti}")
            post_revoke_verify = call("post_revoke_verify", "POST", "/v1/identity/verify", {"token": token})

            if not chain["valid"]:
                raise RuntimeError(f"delegation chain did not verify: {chain}")
            if not status["revoked"]:
                raise RuntimeError(f"revocation status did not mark token revoked: {status}")
            if post_revoke_verify["valid"]:
                raise RuntimeError("revoked token still verifies")

            return {
                "status": "PASS",
                "base_url": base_url,
                "health": health,
                "issuer": config.get("issuer"),
                "jwks_key_count": len(jwks.get("keys", [])),
                "issued_jti": jti,
                "delegation_id": delegation["delegation_id"],
                "cascade_revoked_count": revoke["revoked_count"],
                "verify_http_ms": verify_samples,
                "endpoint_timings_ms": timings_ms,
            }
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def merge_samples(*parts: dict[str, Any]) -> dict[str, list[float]]:
    merged: dict[str, list[float]] = {}
    for part in parts:
        for key, values in part.items():
            if isinstance(values, list):
                merged.setdefault(key, []).extend(float(value) for value in values)
    return merged


def main() -> None:
    RESULT_DIR.mkdir(exist_ok=True)
    samples_arg = os.environ.get("AIRON_PILOT_SAMPLES", "200")
    verify_samples_arg = os.environ.get("AIRON_PILOT_VERIFY_SAMPLES", "2000")

    smoke = run_aip_http_smoke()
    aip_verify = run_json(
        [
            "cargo",
            "run",
            "--release",
            "--manifest-path",
            "aip-service/Cargo.toml",
            "--bin",
            "aip_pilot_latency",
            "--quiet",
            "--",
            "--samples",
            verify_samples_arg,
        ]
    )
    evidence = run_json(
        [
            "cargo",
            "run",
            "--release",
            "--manifest-path",
            "aip-standalone/aip-protocol/Cargo.toml",
            "--example",
            "evidence_packet_latency",
            "--quiet",
            "--",
            "--samples",
            samples_arg,
        ]
    )
    aegis = run_json(
        [
            "cargo",
            "run",
            "--release",
            "--manifest-path",
            "aegis-quantum/benchmarks/Cargo.toml",
            "--example",
            "aegis_pilot_latency",
            "--quiet",
            "--",
            "--samples",
            samples_arg,
        ]
    )

    samples = merge_samples(aip_verify, evidence, aegis)
    raw = {
        "metadata": {
            "pilot": "local_dev_pre_pitch",
            "generated_at": now_utc(),
            "host_os": platform.platform(),
            "python": platform.python_version(),
            "sample_count": {
                "aip_signature_verification": int(verify_samples_arg),
                "aegis_and_evidence": int(samples_arg),
                "aip_http_verify": len(smoke["verify_http_ms"]),
            },
            "caveat": "Local development measurements are screening evidence only; bare-metal XDP/NIC line-rate metrics remain required before banking LOI claims.",
        },
        "measurement_scope": {
            "ml_kem_handshake_ms": "local_dev_user_space",
            "aegis_circuit_breaker_detonation_us": "local_dev_user_space",
            "signature_verification_us": "local_dev_in_process",
            "evidence_packet_assembly_ms": "local_dev_in_process",
            "audit_export_ms": "local_dev_in_memory",
            "storage_overhead_kb": "local_dev_serialized_json",
        },
        "notes": {
            "aegis_circuit_breaker_detonation_us": "Measures local user-space detector trip decision only; excludes real eBPF map update to AQ_BLOCKLIST.",
            "audit_export_ms": "Measures local JSON serialize/deserialize only; excludes network vault query and database/index latency.",
            "ml_kem_handshake_ms": "Measures local Kyber-768 roundtrip in user space.",
            "signature_verification_us": "Measures in-process AIP EdDSA JWT verification without HTTP overhead.",
        },
        "samples": samples,
    }

    samples_path = RESULT_DIR / "local_pilot_samples.json"
    latency_path = RESULT_DIR / "local_pilot_latency_report.json"
    smoke_path = RESULT_DIR / "local_pilot_http_smoke.json"
    summary_path = RESULT_DIR / "local_pilot_summary.json"

    samples_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    latency_report = build_report(raw)
    latency_path.write_text(json.dumps(latency_report, indent=2) + "\n", encoding="utf-8")
    smoke_path.write_text(json.dumps(smoke, indent=2) + "\n", encoding="utf-8")

    failed_metrics = [
        key for key, value in latency_report["metrics"].items() if value["status"] == "FAIL"
    ]
    summary = {
        "status": "FAIL" if failed_metrics or smoke["status"] != "PASS" else "PASS_LOCAL_SCOPE",
        "generated_at": now_utc(),
        "artifacts": {
            "samples": str(samples_path.relative_to(REPO_ROOT)),
            "latency_report": str(latency_path.relative_to(REPO_ROOT)),
            "http_smoke": str(smoke_path.relative_to(REPO_ROOT)),
        },
        "http_smoke_status": smoke["status"],
        "latency_report_status": latency_report["status"],
        "failed_metrics": failed_metrics,
        "not_measured_metrics": [
            key
            for key, value in latency_report["metrics"].items()
            if value["status"] == "NOT_MEASURED"
        ],
        "local_scope_metrics": [
            key
            for key, value in latency_report["metrics"].items()
            if value["status"] == "PASS_LOCAL_SCOPE"
        ],
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))

    if summary["status"] == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()
