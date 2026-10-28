#!/usr/bin/env python3
"""Prepare role-specific OCI build inputs from the existing verified archive.

This does not build/run an image or qualify Docker/Kubernetes/kernel support.
"""
import argparse
import json
from pathlib import Path
import re

import package as runtime


def prepare(args):
    manifest, files = runtime.verified_package(args.archive, args.expected_sha256)
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}", args.base_image):
        raise ValueError("explicit institution-approved base image digest required")
    root = Path(args.output)
    if root.exists():
        raise ValueError("refusing to replace a container build context")
    root.mkdir(parents=True, mode=0o700)
    (root / "bin").mkdir()
    for name in (f"aip-{args.role}", "aip-observe-verify"):
        path = root / "bin" / name
        path.write_bytes(files[f"bin/{name}"][0])
        path.chmod(0o755)
    dockerfile = (f"FROM {args.base_image}\n"
        f"LABEL org.opencontainers.image.revision={manifest['source_commit']}\n"
        "LABEL io.vanian.mode=OBSERVER_ONLY\n"
        f"COPY bin/aip-{args.role} /usr/local/bin/aip-{args.role}\n"
        "COPY bin/aip-observe-verify /usr/local/bin/aip-observe-verify\n"
        f"USER {'0:0' if args.role == 'probe' else '10001:10001'}\n"
        f"ENTRYPOINT [\"/usr/local/bin/aip-{args.role}\"]\n")
    (root / "Dockerfile").write_text(dockerfile)
    (root / ".dockerignore").write_text("*\n!Dockerfile\n!bin/\n!bin/*\n")
    report = {"schema": "vanian.container-build-inputs.v1", "mode": "OBSERVER_ONLY",
        "role": args.role, "base_image": args.base_image, "target": manifest["target"],
        "runtime_archive_sha256": args.expected_sha256.lower(),
        "files": {str(p.relative_to(root)): runtime.digest(p.read_bytes()) for p in root.rglob("*") if p.is_file()},
        "image_built": False, "runtime_validation": "NOT_EXECUTED"}
    (root / "build-inputs.json").write_bytes(runtime.canonical(report))
    print(json.dumps(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--role", choices=("probe", "collector"), required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--output", required=True)
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
