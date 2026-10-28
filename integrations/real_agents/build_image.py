#!/usr/bin/env python3
"""Build a pinned third-party runtime, separately from the privileged observer."""
import argparse
import json
import re
import subprocess
from pathlib import Path

here = Path(__file__).resolve().parent
pins = json.loads((here / "frameworks.lock.json").read_text())
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("framework", choices=pins)
parser.add_argument("--python-image", required=True, help="Python 3.12 Debian image@sha256:digest")
parser.add_argument("--uv-version", required=True)
parser.add_argument("--tag", required=True)
args = parser.parse_args()
if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}", args.python_image):
    parser.error("base image must have an immutable sha256 digest")
if not re.fullmatch(r"\d+\.\d+\.\d+", args.uv_version):
    parser.error("pin uv to a full release version")
pin = pins[args.framework]
subprocess.run(["docker", "build", "--tag", args.tag,
    "--build-arg", f"FRAMEWORK={args.framework}",
    "--build-arg", f'REPOSITORY={pin["repository"]}',
    "--build-arg", f'COMMIT={pin["commit"]}',
    "--build-arg", f"PYTHON_IMAGE={args.python_image}",
    "--build-arg", f"UV_VERSION={args.uv_version}", str(here)], check=True)
subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", args.tag], check=True)
