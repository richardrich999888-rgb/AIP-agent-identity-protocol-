#!/usr/bin/env python3
"""Bare-metal readiness checks for AEGIS live-fire stress validation.

This script does not execute line-rate traffic. It verifies whether a host is
ready to participate in the two-server validation lab and writes a structured
report for the pilot dossier.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional


SCRIPT_DIR = Path(__file__).resolve().parent
AEGIS_ROOT = SCRIPT_DIR.parent
REPO_ROOT = AEGIS_ROOT.parent
DEFAULT_OUTPUT = REPO_ROOT / "pilot-results" / "live_fire_readiness_report.json"

NATIVE_XDP_DRIVERS = {
    "i40e": "Intel X710/XL710",
    "ice": "Intel E810",
    "ixgbe": "Intel 82599/X520/X540/X550",
    "mlx5_core": "Mellanox/NVIDIA ConnectX-4/5/6",
}


def run_command(args: list[str], timeout_seconds: int = 10) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        return {"status": "MISSING", "command": args, "error": str(exc)}
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "command": args}

    return {
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "command": args,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def which_tool(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    if path:
        return {"status": "PASS", "path": path}
    return {"status": "FAIL", "reason": f"{name} not found in PATH"}


def check_interface(iface: Optional[str]) -> dict[str, Any]:
    if not iface:
        return {
            "status": "SKIP",
            "reason": "No interface supplied. Pass --iface <nic> on the Linux host.",
        }

    sysfs_path = Path("/sys/class/net") / iface
    if not sysfs_path.exists():
        return {
            "status": "FAIL",
            "interface": iface,
            "reason": f"{sysfs_path} does not exist",
        }

    ethtool = shutil.which("ethtool")
    driver = None
    bus_info = None
    if ethtool:
        info = run_command([ethtool, "-i", iface])
        if info["status"] == "PASS":
            for line in info["stdout"].splitlines():
                if line.startswith("driver:"):
                    driver = line.split(":", 1)[1].strip()
                if line.startswith("bus-info:"):
                    bus_info = line.split(":", 1)[1].strip()

    native_profile = NATIVE_XDP_DRIVERS.get(driver or "")
    return {
        "status": "PASS" if native_profile else "WARN",
        "interface": iface,
        "driver": driver,
        "bus_info": bus_info,
        "native_xdp_profile": native_profile,
        "reason": None
        if native_profile
        else "Driver is not in the known native-XDP allowlist; verify with bpftool/netdev before line-rate claims.",
    }


def check_pktgen() -> dict[str, Any]:
    proc_path = Path("/proc/net/pktgen")
    if proc_path.exists():
        return {"status": "PASS", "path": str(proc_path)}
    return {
        "status": "WARN",
        "reason": "pktgen module not loaded. On Linux, run: sudo modprobe pktgen",
    }


def check_trex() -> dict[str, Any]:
    candidates = ["t-rex-64", "trex-console", "trex-console.py"]
    found = [path for name in candidates if (path := shutil.which(name))]
    if found:
        return {"status": "PASS", "paths": found}
    return {
        "status": "WARN",
        "reason": "Cisco TRex was not found in PATH; install it on the traffic-generator server for 10/40 GbE proof.",
    }


def role_checks(role: str, iface: Optional[str]) -> dict[str, Any]:
    checks: dict[str, Any] = {
        "os": {
            "status": "PASS" if platform.system() == "Linux" else "FAIL",
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "root": {
            "status": "PASS" if hasattr(os, "geteuid") and os.geteuid() == 0 else "WARN",
            "reason": "Root is required for live XDP attach, bpftool map inspection, pktgen, and TRex/DPDK device binding.",
        },
        "ip": which_tool("ip"),
        "ethtool": which_tool("ethtool"),
        "interface": check_interface(iface),
    }

    if role == "gateway":
        checks.update(
            {
                "bpftool": which_tool("bpftool"),
                "stress_ng": which_tool("stress-ng"),
                "clang": which_tool("clang"),
                "llvm_objcopy": which_tool("llvm-objcopy"),
            }
        )
    else:
        checks.update(
            {
                "trex": check_trex(),
                "pktgen": check_pktgen(),
                "python3": which_tool("python3"),
            }
        )

    return checks


def summarize(role: str, checks: dict[str, Any]) -> str:
    hard_failures = []
    warnings = []

    required = {"os", "ip", "ethtool", "interface"}
    if role == "gateway":
        required.update({"bpftool", "stress_ng"})
    else:
        required.update({"python3"})

    for name, result in checks.items():
        status = result.get("status")
        if name in required and status == "FAIL":
            hard_failures.append(name)
        elif status in {"WARN", "SKIP"}:
            warnings.append(name)

    if hard_failures:
        return "BLOCKED"
    if warnings:
        return "READY_WITH_WARNINGS"
    return "READY"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check AEGIS live-fire lab readiness.")
    parser.add_argument("--role", choices=["gateway", "traffic-generator"], required=True)
    parser.add_argument("--iface", help="Physical NIC used for the direct DAC link.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--allow-blocked",
        action="store_true",
        help="Return exit code 0 even when readiness is blocked; useful for local report generation on macOS.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks = role_checks(args.role, args.iface)
    status = summarize(args.role, checks)
    report = {
        "metadata": {
            "suite": "aegis-live-fire-readiness",
            "role": args.role,
            "generated_epoch_ns": time.time_ns(),
            "aegis_root": str(AEGIS_ROOT),
        },
        "checks": checks,
        "overall_status": status,
        "claim_boundary": (
            "Readiness only verifies host prerequisites. Throughput, p99 latency, "
            "and XDP drop/pass claims require executing the live-fire traffic plan."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"AEGIS live-fire readiness report written: {args.output}")
    print(f"overall_status={status}")
    return 0 if status in {"READY", "READY_WITH_WARNINGS"} or args.allow_blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
