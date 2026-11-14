#!/usr/bin/env python3
"""Read-only, dependency-free inventory of pinned Git trees; not a security scan.

Never imports repository modules, executes workloads, installs dependencies, or
opens the network. Output describes source presence, never runtime acceptance.
Pass a captured revisions.json to reproduce the exact inventory after refs move.
"""

import argparse
import functools
import hashlib
import json
from pathlib import PurePosixPath
import re
import subprocess
import sys
import tomllib


SCOPED_BRANCHES = (
    "main",
    "integration/snifferdog-complete-enterprise-validation",
    "fix/vanian-end-to-end-green",
    "feature/vanian-agent-governance-interoperability",
    "integration/vanian-enterprise-service-delivery",
    "feature/syntriass-runtime-v02",
    "feature/wow-demos",
    "fix/ci-userns-sandbox-tests",
    "fix/chart-probe-seccomp",
    "fix/aip-edge-distinct-corroboration",
)


def git(*args):
    return subprocess.check_output(["git", *args])


@functools.lru_cache(maxsize=None)
def tree(revision):
    rows = []
    for entry in git("ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        rows.append((path.decode(), mode, kind, oid))
    return rows


@functools.lru_cache(maxsize=None)
def blob(oid):
    return git("cat-file", "blob", oid)


def category(path):
    p = PurePosixPath(path)
    name = p.name
    if name == "Cargo.toml":
        return "cargo_manifest"
    if name == "Cargo.lock":
        return "cargo_lock"
    if name == "pyproject.toml" or name.startswith("requirements") or name in {
        "uv.lock", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg"
    }:
        return "python_dependency"
    if name in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        return "javascript_dependency"
    if path.startswith(".github/workflows/"):
        return "workflow"
    if "Dockerfile" in name or name.endswith(".service"):
        return "container_or_service"
    if path.startswith("deploy/"):
        return "deployment"
    if name.endswith(".lock.json"):
        return "upstream_pin"
    if "LICENSE" in name.upper() or name.startswith("COPYING") or name in {
        "deny.toml", ".gitleaks.toml", ".gitleaksignore", "rust-toolchain.toml", "rust-toolchain"
    }:
        return "license_policy"
    return None


def summarize(path, raw, kind):
    text = raw.decode("utf-8", errors="replace")
    if kind == "cargo_manifest":
        data = tomllib.loads(text)
        return {k: data[k] for k in (
            "package", "workspace", "dependencies", "dev-dependencies",
            "build-dependencies", "target", "features"
        ) if k in data}
    if kind == "cargo_lock":
        packages = tomllib.loads(text).get("package", [])
        external = [p for p in packages if "source" in p]
        return {
            "packages": len(packages), "external_packages": len(external),
            "registry_packages_without_checksum": [
                {k: p[k] for k in ("name", "version", "source")}
                for p in external if p["source"].startswith("registry+") and "checksum" not in p
            ],
            "git_sources": sorted({p["source"] for p in external if p["source"].startswith("git+")}),
        }
    if kind == "python_dependency" and path.endswith("pyproject.toml"):
        return tomllib.loads(text)
    if kind == "upstream_pin":
        return json.loads(text)
    if kind in {"workflow", "container_or_service", "deployment", "python_dependency", "license_policy"}:
        patterns = r"uses:|^FROM |image:|pip install|cargo install|apt(-get)? install|\bcurl\b|\bwget\b|sha256|==|@sha256:|^User=|^ExecStart=|^AmbientCapabilities=|^CapabilityBoundingSet=|^PrivateNetwork=|^RestrictAddressFamilies=|ignore|RUSTSEC"
        return {"review_lines": [
            {"line": n, "text": line.strip()}
            for n, line in enumerate(text.splitlines(), 1) if re.search(patterns, line)
        ]}
    return {}


def snapshot(branch, revision):
    rows = tree(revision)
    files = []
    module_counts = {}
    integration_roots = set()
    external_roots = set()
    evidence_count = 0
    for path, mode, kind, oid in rows:
        parts = PurePosixPath(path).parts
        if path.startswith("integrations/") and len(parts) > 2:
            integration_roots.add(parts[1])
        if path.startswith("validation/external/") and len(parts) > 3:
            external_roots.add(parts[2])
        if path.startswith(("aip-standalone/", "aip-service/")) and path.endswith(".rs"):
            root = "/".join(parts[:2]) if parts[0] == "aip-standalone" else parts[0]
            module_counts[root] = module_counts.get(root, 0) + 1
        if "/results/" in path or "/evidence/" in path or path.startswith("validation/traces/"):
            evidence_count += 1
        label = category(path)
        if label and kind == "blob":
            raw = blob(oid)
            files.append({
                "path": path, "mode": mode, "git_blob": oid,
                "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                "category": label, "parsed": summarize(path, raw, label),
            })
    manifest = next((f["parsed"] for f in files if f["path"] == "Cargo.toml"), {})
    return {
        "branch": branch, "revision": revision,
        "tree": git("rev-parse", revision + "^{tree}").decode().strip(),
        "tracked_entries": len(rows), "configuration_files": len(files),
        "root_workspace_members": manifest.get("workspace", {}).get("members", []),
        "native_source_and_test_file_counts": module_counts,
        "integration_directories": sorted(integration_roots),
        "external_evaluation_directories": sorted(external_roots),
        "retained_evidence_file_count": evidence_count,
        "configuration": files,
    }


def capture_refs():
    advertised = []
    for row in git("for-each-ref", "--format=%(refname:short) %(objectname)", "refs/remotes/origin/").decode().splitlines():
        ref, revision = row.split()
        if ref != "origin/HEAD" and ref != "origin":
            advertised.append({"branch": ref.removeprefix("origin/"), "revision": revision})
    return {"schema": "vanian.p0-048.revisions.v1", "refs": advertised}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revisions", help="Previously captured revisions.json")
    parser.add_argument("--refs-only", action="store_true")
    args = parser.parse_args()
    if args.revisions:
        with open(args.revisions, encoding="utf-8") as handle:
            refs = json.load(handle)
    else:
        refs = capture_refs()
    revisions = {}
    for row in refs["refs"]:
        if not re.fullmatch(r"[0-9a-f]{40}", row["revision"]):
            raise ValueError("only full immutable Git SHA-1 revisions are accepted")
        if row["branch"] in revisions:
            raise ValueError("duplicate branch in revisions")
        revisions[row["branch"]] = row["revision"]
    if args.refs_only:
        result = refs
    else:
        missing = sorted(set(SCOPED_BRANCHES) - revisions.keys())
        if missing:
            raise ValueError(f"required branches missing: {missing}")
        result = {
            "schema": "vanian.p0-048.inventory.v1",
            "scope": "Structural source/configuration inventory, not runtime or security acceptance",
            "previous_checkpoint_matches": [
                {"branch": b, "revision": rev, "path": p}
                for b, rev in sorted(revisions.items()) for p, _, _, _ in tree(rev)
                if "p0-048" in p.lower() or "p0_048" in p.lower()
            ],
            "snapshots": [snapshot(b, revisions[b]) for b in SCOPED_BRANCHES],
        }
        # Many branches contain identical configuration blobs. Keep one parsed
        # value per blob/category without implying separate runtime evidence.
        parsed_objects = {}
        for captured in result["snapshots"]:
            for entry in captured["configuration"]:
                key = entry["git_blob"] + ":" + entry["category"]
                parsed_objects[key] = entry.pop("parsed")
                entry["parsed_ref"] = key
        result["configuration_objects"] = parsed_objects
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
