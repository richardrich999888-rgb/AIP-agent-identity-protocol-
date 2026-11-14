#!/usr/bin/env python3
"""Reproduce the P0-057 structural audit from captured immutable refs.

Reuse the P0-048 inventory. This does not execute or qualify any workload.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = "61dd73013d02ea7869de104d953f330098df1c32"
SPEC = importlib.util.spec_from_file_location("p048_inventory", ROOT / "validation/p0_048/inventory.py")
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--refs", type=Path, help="Captured revisions; otherwise capture local remote refs")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    refs = json.loads(args.refs.read_text()) if args.refs else inventory.capture_refs()
    (args.out / "revisions.json").write_text(json.dumps(refs, indent=2) + "\n")
    objects = {}
    snapshots = []
    for row in refs["refs"]:
        snap = inventory.snapshot(row["branch"], row["revision"])
        for entry in snap["configuration"]:
            key = entry["git_blob"] + ":" + entry["category"]
            objects[key] = entry.pop("parsed")
            entry["parsed_ref"] = key
        snapshots.append(snap)
    result = {"schema": "vanian.p0-057.structural-audit.v1", "base": BASE,
              "scope": "All captured remote trees: source counts, dependency/build/deployment/pin/license inventory; not exhaustive security or runtime acceptance",
              "snapshots": snapshots, "configuration_objects": objects}
    raw = json.dumps(result, indent=2, sort_keys=True).encode() + b"\n"
    (args.out / "inventory.json.gz").write_bytes(gzip.compress(raw, mtime=0))
    prs = json.loads((args.out / "provider-snapshot.json").read_text())["open_prs"]
    reconcile = []
    for pr in prs:
        head = pr["head_sha"]
        merge_base = git("merge-base", BASE, head)
        changes = git("diff", "--name-status", merge_base, head).splitlines()
        ours = set(git("diff", "--name-only", merge_base, BASE).splitlines())
        theirs = set(git("diff", "--name-only", merge_base, head).splitlines())
        reconcile.append({"pr": pr["number"], "head": head, "base": BASE, "merge_base": merge_base,
                          "head_is_ancestor": merge_base == head,
                          "base_is_ancestor": merge_base == BASE,
                          "counts_base_only_head_only": git("rev-list", "--left-right", "--count", BASE + "..." + head),
                          "head_changed_paths_from_common_base": changes,
                          "overlapping_changed_paths": sorted(ours & theirs),
                          "overlap_is_not_a_merge_conflict_test": True})
    (args.out / "ancestry.json").write_text(json.dumps(reconcile, indent=2) + "\n")
    summary = {"base": BASE, "default_branch": "main", "default_sha": git("rev-parse", "origin/main"),
               "remote_head_count": len(refs["refs"]), "open_pr_count": len(prs),
               "inventory_uncompressed_sha256": hashlib.sha256(raw).hexdigest(),
               "inventory_bytes": len(raw), "unique_configuration_objects": len(objects),
               "branches": [{k: s[k] for k in ("branch", "revision", "tree", "tracked_entries", "configuration_files")} for s in snapshots]}
    (args.out / "audit-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "branches"}, indent=2))


if __name__ == "__main__":
    main()
