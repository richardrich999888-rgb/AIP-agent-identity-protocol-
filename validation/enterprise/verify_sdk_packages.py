#!/usr/bin/env python3
"""Offline clean installation of built SDK distributions; no registry publish.

Requires Python venv/pip and Node/npm. These checks caught the earlier .ts
node_modules export defect that source-import tests could not detect.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def verify(wheel, typescript):
    with tempfile.TemporaryDirectory(prefix="vanian-sdk-install-") as directory:
        subprocess.run(["python3", "-m", "venv", directory], check=True, capture_output=True)
        subprocess.run([directory + "/bin/python", "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
                       check=True, capture_output=True)
        subprocess.run([directory + "/bin/python", "-c",
            "from vanian import VanianClient; import importlib.metadata; assert importlib.metadata.version('vanian-sdk') == '0.1.0'"],
            cwd=directory, check=True, capture_output=True)
        subprocess.run(["npm", "install", "--ignore-scripts", "--offline", "--no-audit", "--no-fund",
            "--prefix", directory, str(typescript)], check=True, capture_output=True)
        subprocess.run(["node", "--input-type=module", "-e",
            "import { VanianClient } from '@vanian/evidence-client'; if (typeof VanianClient !== 'function') process.exit(1);"],
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
