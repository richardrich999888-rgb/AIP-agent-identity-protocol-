#!/usr/bin/env python3
"""Check the imported tree against the SHA-256 manifest that shipped with it.

The import arrived with `MANIFEST.md`, a SHA-256 per file, so a recipient can
prove nothing changed in transit. Wiring the crates into this workspace
required rewriting two Cargo manifests. The RBI branch also applied a
semantics-preserving clippy match-guard refactor in registry.rs. Those three
reviewed deviations are pinned below by FULL current SHA-256, so an additional
change to any of them is a finding, not an unlimited path exemption. Run:

    python3 orbitaltrust-accountability/verify_manifest.py
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Workspace wiring plus the reviewed RBI clippy refactor (22293d0).
# MANIFEST.md remains unchanged as evidence of the original import.
EXPECTED_DEVIATIONS = {
    "rust/ot-accountability-core/Cargo.toml": "cbe6665d88d2c670edcf90c6fbeb08457bd0a9c6b1b9d94e3f3bf36b2f2726fc",
    "rust/ot-sentinel/Cargo.toml": "ee5f354f2920b5fe940e6085ae0d13141bd5a4d10d71bd5275a8414b362f9ba5",
    "rust/ot-sentinel/src/registry.rs": "9765e6507d8aad595801663f0dd75a2b8ca6aa5ab2df27ef52d5f9f750b24da9",
}

# `| `path` | 123 | `abcdef…` |` — the manifest truncates each digest, so the
# comparison is a prefix match against the full hash of the file on disk.
ROW = re.compile(r"^\| `([^`]+)` \| *[\d,]+ \| `([0-9a-f]+)…?` \|", re.M)


def main() -> int:
    manifest = (HERE / "MANIFEST.md").read_text()
    rows = ROW.findall(manifest)
    if not rows:
        print("FAIL: MANIFEST.md parsed to zero rows; the format changed")
        return 2

    unchanged, deviated, missing = 0, [], []
    approved = set()
    for rel, prefix in rows:
        path = HERE / rel
        if not path.exists():
            missing.append(rel)
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest.startswith(prefix.rstrip("…")):
            unchanged += 1
        else:
            deviated.append(rel)
            if EXPECTED_DEVIATIONS.get(rel) == digest:
                approved.add(rel)

    print(f"files in manifest : {len(rows)}")
    print(f"byte-identical    : {unchanged}")
    print(f"deviated          : {len(deviated)}")
    print(f"missing           : {len(missing)}")

    unexpected = sorted(set(deviated) - approved)
    for rel in sorted(deviated):
        note = "reviewed deviation (exact SHA-256)" if rel in approved else "UNEXPECTED"
        print(f"  {note}: {rel}")
    for rel in missing:
        print(f"  MISSING: {rel}")

    if unexpected or missing:
        print("\nFAIL: the import deviates from its manifest beyond the exact reviewed revisions.")
        return 1
    print("\nPASS: original import matches except for the exact reviewed deviations above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
