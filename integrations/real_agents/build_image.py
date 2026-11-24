#!/usr/bin/env python3
"""Build a pinned third-party runtime, separately from the privileged observer."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def runtime_python(framework):
    if framework not in ("agent_zero", "deerflow", "openhands"):
        raise ValueError("unsupported framework")
    return ("/opt/framework/backend/.venv/bin/python" if framework == "deerflow"
            else "/opt/framework/.venv/bin/python")


def main():
    pins = json.loads((HERE / "frameworks.lock.json").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("framework", choices=pins)
    parser.add_argument("--python-image", required=True, help="Python 3.12 Debian image@sha256:digest")
    parser.add_argument("--uv-version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--metadata-out", type=Path,
                        help="Optional public image/source metadata JSON; contains no environment values")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}", args.python_image):
        parser.error("base image must have an immutable sha256 digest")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.uv_version):
        parser.error("pin uv to a full release version")
    pin = pins[args.framework]
    if not re.fullmatch(r"[0-9a-f]{40}", pin["commit"]):
        parser.error("upstream source must have an immutable full commit")
    subprocess.run(["docker", "build", "--tag", args.tag,
        "--build-arg", f"FRAMEWORK={args.framework}",
        "--build-arg", f'REPOSITORY={pin["repository"]}',
        "--build-arg", f'COMMIT={pin["commit"]}',
        "--build-arg", f"PYTHON_IMAGE={args.python_image}",
        "--build-arg", f"UV_VERSION={args.uv_version}", str(HERE)], check=True)
    inspected = subprocess.run(["docker", "image", "inspect", args.tag],
                               capture_output=True, text=True, check=True)
    image = json.loads(inspected.stdout)[0]
    labels = image.get("Config", {}).get("Labels") or {}
    if (labels.get("org.opencontainers.image.revision") != pin["commit"]
            or labels.get("org.opencontainers.image.source") != pin["repository"]):
        raise ValueError("built image source labels do not match the immutable framework pin")
    if args.metadata_out:
        files = [HERE / "Dockerfile", HERE / "frameworks.lock.json", *sorted((HERE / "adapters").glob("*.py")),
                 HERE / "adapters/entrypoint.sh"]
        metadata = {"classification": "CONTAINER_BUILD_ONLY_NO_AGENT_OR_MODEL_EXECUTION",
            "framework": args.framework, "upstream_repository": pin["repository"],
            "upstream_commit": pin["commit"], "python_base_image": args.python_image,
            "uv_version": args.uv_version, "image_id": image["Id"],
            "image_os": image["Os"], "image_architecture": image["Architecture"],
            "runtime_python": runtime_python(args.framework),
            "source_sha256": {str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
            "model_calls": 0, "autonomous_workload_executed": False,
            "delegation": "UNVALIDATED", "logical_agent_attribution": "CANNOT_PROVE"}
        args.metadata_out.parent.mkdir(parents=True, exist_ok=True)
        args.metadata_out.write_text(json.dumps(metadata, indent=2) + "\n")
    print(image["Id"])


if __name__ == "__main__":
    main()
