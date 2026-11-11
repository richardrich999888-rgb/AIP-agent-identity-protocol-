#!/usr/bin/env python3
"""Check the audit's source references and archived bytes, not execution verdicts.

Run from the repository root. Writes a JSON report to stdout. No network,
dependency installation, sensor activation or evidence rewriting occurs.
"""

import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


EVIDENCE = Path("validation/p0_048/iteration-001")
BASELINE = "4d0ce1e32c8dedde4e3a930abc2becf1f56b864e"
CANDIDATE = "9ed1662af95ce83bbbee69c9387d5bd638713575"


def git(*args):
    return subprocess.check_output(["git", *args])


def main():
    failures = []
    inventory_bytes = (EVIDENCE / "inventory.json").read_bytes()
    inventory = json.loads(inventory_bytes)
    repeated = subprocess.check_output([
        sys.executable, "validation/p0_048/inventory.py", "--revisions",
        str(EVIDENCE / "revisions.json"),
    ])
    if repeated != inventory_bytes:
        failures.append("inventory is not byte-reproducible from captured revisions")

    checked_files = 0
    blobs = {}
    for snapshot in inventory["snapshots"]:
        revision = snapshot["revision"]
        for entry in snapshot["configuration"]:
            oid = git("rev-parse", revision + ":" + entry["path"]).decode().strip()
            if oid not in blobs:
                blobs[oid] = git("cat-file", "blob", oid)
            raw = blobs[oid]
            if (oid != entry["git_blob"] or len(raw) != entry["bytes"]
                    or hashlib.sha256(raw).hexdigest() != entry["sha256"]):
                failures.append("configuration bytes mismatch: " + entry["path"])
            if entry["parsed_ref"] not in inventory["configuration_objects"]:
                failures.append("missing parsed object: " + entry["path"])
            checked_files += 1

    local_links = 0
    for document in sorted(Path("docs/research").glob("P0-048-*.md")):
        for target in re.findall(r"\]\(([^)]+)\)", document.read_text()):
            if "://" in target:
                continue
            local_links += 1
            if not (document.parent / target.split("#")[0]).exists():
                failures.append(f"missing source link: {document}: {target}")

    # Hash original decompressed bytes against the existing preservation
    # manifest. This is explicitly not a signature or origin verification.
    archive_root = Path("validation/final_acceptance/same-run-qualified/originals")
    archive_entries = json.loads((archive_root / "files.json").read_text())
    for entry in archive_entries:
        path = archive_root / entry["retained"]
        raw = path.read_bytes()
        if entry["compression"] == "gzip-mtime-zero":
            raw = gzip.decompress(raw)
        elif entry["compression"] != "none":
            failures.append("unsupported historical compression: " + str(path))
        if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            failures.append("retained original differs from manifest: " + str(path))

    changed = git("diff", "--name-only", CANDIDATE, BASELINE).decode().splitlines()
    non_documentation = [p for p in changed if not p.startswith((
        "docs/", "validation/final_acceptance/"
    ))]
    if non_documentation:
        failures.append("candidate/publication source delta: " + repr(non_documentation))

    result = {
        "schema": "vanian.p0-048.inventory-check.v1",
        "scope": "Audit reproducibility and byte integrity, not cryptographic execution acceptance",
        "status": "FAIL" if failures else "PASS",
        "snapshots": len(inventory["snapshots"]),
        "configuration_references_checked": checked_files,
        "distinct_configuration_blobs_checked": len(blobs),
        "local_document_links_checked": local_links,
        "historical_original_files_hashed": len(archive_entries),
        "candidate_to_publication_changed_files": len(changed),
        "candidate_to_publication_non_documentation_changes": non_documentation,
        "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "failures": failures,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
