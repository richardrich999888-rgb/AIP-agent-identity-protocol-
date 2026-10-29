#!/usr/bin/env python3
"""Offline clean installation of built SDK distributions; no registry publish.

Requires Python venv/pip and Node/npm. These checks caught the earlier .ts
node_modules export defect that source-import tests could not detect.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def verify_python_wheel(wheel, directory):
    """Install and inspect the wheel without inheriting source import paths."""
    subprocess.run([sys.executable, "-I", "-m", "venv", str(directory)], check=True, capture_output=True)
    python = str(Path(directory) / "bin/python")
    subprocess.run([python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
                   check=True, capture_output=True)
    subprocess.run([python, "-I", "-c",
        "import sys, pathlib, vanian, importlib.metadata; from vanian import VanianClient; "
        "assert pathlib.Path(vanian.__file__).resolve().is_relative_to(pathlib.Path(sys.prefix).resolve()), 'SDK import escaped the clean environment'; "
        "assert importlib.metadata.version('vanian-sdk') == '0.1.0'; "
        "assert all(callable(getattr(VanianClient, name, None)) for name in ('register_deployment', 'list_deployments', 'get_deployment', 'get_run_metadata', 'get_run_verdict', 'evaluate_run', 'get_agent_runs'))"],
        cwd=directory, check=True, capture_output=True)


def verify(wheel, typescript):
    with tempfile.TemporaryDirectory(prefix="vanian-sdk-install-") as directory:
        verify_python_wheel(wheel, directory)
        subprocess.run(["npm", "install", "--ignore-scripts", "--offline", "--no-audit", "--no-fund",
            "--prefix", directory, str(typescript)], check=True, capture_output=True)
        subprocess.run(["node", "--input-type=module", "-e",
            "import { VanianClient } from '@vanian/evidence-client'; if (typeof VanianClient !== 'function' || !['registerDeployment', 'listDeployments', 'getDeployment', 'getRunMetadata', 'getRunVerdict', 'evaluateRun', 'getAgentRuns'].every(name => typeof VanianClient.prototype[name] === 'function')) process.exit(1);"],
            cwd=directory, check=True, capture_output=True)
    return {"python_wheel": "INSTALLED_AND_IMPORTED", "typescript_tgz": "INSTALLED_AND_IMPORTED",
            "network_calls_to_evidence_service": 0, "kernel_observation": "NOT_EXERCISED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--typescript", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.wheel.resolve(), args.typescript.resolve())))


if __name__ == "__main__":
    main()
