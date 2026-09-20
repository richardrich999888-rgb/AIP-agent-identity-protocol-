#!/usr/bin/env python3
"""Check the imported tree against the SHA-256 manifest that shipped with it.

The import arrived with `MANIFEST.md`, a SHA-256 per file, so a recipient can
prove nothing changed in transit. Wiring the crates into this workspace
required rewriting two `Cargo.toml` files, which necessarily breaks their
hashes. This script exists so that deviation stays *measured* rather than
asserted: it prints every file whose content no longer matches, and exits
non-zero if any file other than the two known ones has moved.

That is the difference between "we only changed the manifests" as a claim and
as a fact. Run:

    python3 orbitaltrust-accountability/verify_manifest.py
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The two files this repository rewrote to wire the crates into its workspace,
# each carrying a comment saying so. Any *other* deviation is a finding.
EXPECTED_DEVIATIONS = {
    "rust/ot-accountability-core/Cargo.toml",
    "rust/ot-sentinel/Cargo.toml",
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

    print(f"files in manifest : {len(rows)}")
    print(f"byte-identical    : {unchanged}")
    print(f"deviated          : {len(deviated)}")
    print(f"missing           : {len(missing)}")

    unexpected = sorted(set(deviated) - EXPECTED_DEVIATIONS)
    for rel in sorted(deviated):
        note = "expected (workspace wiring)" if rel in EXPECTED_DEVIATIONS else "UNEXPECTED"
        print(f"  {note}: {rel}")
    for rel in missing:
        print(f"  MISSING: {rel}")

    if unexpected or missing:
        print("\nFAIL: the import deviates from its manifest beyond the two wired manifests.")
        return 1
    print("\nPASS: every imported source file is byte-identical to the manifest;")
    print("the only deviations are the two Cargo.toml files rewritten to wire")
    print("the crates into this workspace, each documented in its own header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
