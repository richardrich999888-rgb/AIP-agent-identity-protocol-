#!/usr/bin/env python3
"""Exercise the real Linux package in staged filesystems, preserving operator data.

This does not assert a live clean-host installation or separate administration.
The package is built from actual Linux binaries; fixture ELF headers are refused
by executing the installed verifier. No service is started in staging mode.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "deploy/enterprise/linux/package.py"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise RuntimeError("real Linux executables required; no staging result claimed")
    args.archive = args.archive.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    commands = []

    def execute(label, command):
        result = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=60)
        (args.output / (label + ".log")).write_text(result.stdout + result.stderr)
        commands.append({"name": label, "command": [str(x) for x in command], "exit_code": result.returncode})
        if result.returncode:
            raise RuntimeError(label + " failed; see retained log")
        return result.stdout

    report = {"kind": "actual Linux binary package staging lifecycle", "status": "FAILED",
              "live_clean_host_installation": False, "services_started": False,
              "separate_host_acceptance": "INCOMPLETE", "commands": commands}
    try:
        verified = json.loads(execute("package-verify", [sys.executable, INSTALLER, "verify",
            "--archive", args.archive, "--expected-sha256", args.expected_sha256]))
        report["manifest"] = verified["manifest"]
        report["archive_sha256"] = args.expected_sha256
        with tempfile.TemporaryDirectory(prefix="vanian-package-stage-") as work:
            work = Path(work).resolve()
            for role in ("probe", "collector"):
                stage = work / role
                stage.mkdir()
                config = work / (role + ".env")
                if role == "probe":
                    text = "\n".join([
                        "AIP_PROBE_ID=package.lifecycle.probe",
                        "AIP_PROBE_COLLECTOR_ENDPOINT=collector.validation.invalid:8443",
                        "AIP_PROBE_COLLECTOR_NOISE_PUBKEY=" + "ab" * 32,
                        "AIP_PROBE_KEY_PATH=/var/lib/aip-probe/transport.key.json",
                        "AIP_PROBE_SENSORS=sched,connector",
                        "AIP_PROBE_BATCH_INTERVAL_MS=1000", ""])
                else:
                    text = "\n".join([
                        "AIP_COLLECTOR_OBSERVER_ID=package.lifecycle.collector",
                        "AIP_COLLECTOR_KEY_PATH=/var/lib/aip-collector/collector.key.wrapped",
                        "AIP_COLLECTOR_STATE_DIR=/var/lib/aip-collector/state",
                        "AIP_COLLECTOR_LISTEN=0.0.0.0:8443",
                        "AIP_COLLECTOR_PROBES_PATH=/etc/aip/probes.json",
                        "AIP_COLLECTOR_NOISE_KEY_PATH=/var/lib/aip-collector/noise.key.json",
                        "AIP_COLLECTOR_CONTINUITY=strict",
                        "AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=1", ""])
                # Staging configuration is explicit test data; it is never
                # asserted to enroll a real collector or trust anchor.
                config.write_text(text)
                command = [sys.executable, INSTALLER, "install", "--archive", args.archive,
                    "--expected-sha256", args.expected_sha256, "--role", role,
                    "--config", config, "--root", stage]
                execute(role + "-install", command)
                verifier = stage / "opt/vanian/snifferdog/bin/aip-observe-verify"
                version = execute(role + "-installed-verifier", [verifier, "--version"]).strip()
                if not version.startswith("aip-observe-verify "):
                    raise RuntimeError("unexpected installed executable")
                receipt = stage / "etc/aip/vanian-runtime-install.json"
                installation = json.loads(receipt.read_text())
                for name, expected in installation["installed"].items():
                    if digest(stage / name.lstrip("/")) != expected:
                        raise RuntimeError("installed file differs from receipt")
                state = stage / ("var/lib/aip-" + role)
                sentinel = state / "operator-retention-sentinel"
                sentinel.write_text("operator-owned retention test data; not agent evidence\n")
                retained = {str(sentinel.relative_to(stage)): digest(sentinel),
                            "etc/aip/" + role + ".env": digest(stage / ("etc/aip/" + role + ".env"))}
                execute(role + "-uninstall", [sys.executable, INSTALLER, "uninstall", "--root", stage])
                for name, expected in retained.items():
                    if digest(stage / name) != expected:
                        raise RuntimeError("uninstall changed retained operator data")
                if receipt.exists() or verifier.exists():
                    raise RuntimeError("uninstall left recorded software")
                execute(role + "-reinstall", command)
                if digest(sentinel) != retained[str(sentinel.relative_to(stage))]:
                    raise RuntimeError("reinstall changed operator data")
                report.setdefault("roles", {})[role] = {"installed_executable": version,
                    "installed_hashes_checked": True, "uninstall_retained_data": retained,
                    "reinstallation_preserved_data": True}
        report["status"] = "PASS"
    finally:
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "scope": report["kind"],
                      "live_clean_host_installation": False}))


if __name__ == "__main__":
    main()
