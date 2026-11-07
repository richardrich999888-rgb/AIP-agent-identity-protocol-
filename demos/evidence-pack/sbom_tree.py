#!/usr/bin/env python3
"""CycloneDX 1.6 SBOM + licence list from `cargo tree`, scoped to what ships (W8.2).

`cargo tree -e normal` for the exact packages and features the demo kit's
binaries are built from, so build-only and dev-only crates are excluded and
nothing is listed that is not linked into a shipped binary. Licences are the
crates' own declared SPDX expressions (Cargo.toml `license`), not a legal
review; anything not plainly permissive is flagged for one.

usage: sbom_tree.py NAME REPO OUT_PREFIX -- CARGO_TREE_ARGS...
writes OUT_PREFIX.cdx.json and OUT_PREFIX.licences.json
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0",
              "Unicode-DFS-2016", "0BSD", "CC0-1.0", "Unlicense", "BSL-1.0", "Apache-2.0 WITH LLVM-exception",
              "CDLA-Permissive-2.0"}
LINE = re.compile(r"^(?P<name>\S+) v(?P<ver>\S+)(?: \((?P<src>[^)]*)\))?(?: \(\*\))?\|(?P<lic>.*)$")


def review_needed(expr: str) -> bool:
    """True unless some OR-branch consists only of permissive licences."""
    if not expr:
        return True
    for branch in re.split(r"\s+OR\s+|/", expr):
        parts = [p.strip(" ()") for p in re.split(r"\s+AND\s+", branch)]
        if all(p in PERMISSIVE for p in parts):
            return False
    return True


def main() -> int:
    if "--" not in sys.argv:
        print(__doc__, file=sys.stderr)
        return 2
    i = sys.argv.index("--")
    name, repo, prefix = sys.argv[1:i]
    args = sys.argv[i + 1:]
    cmd = ["cargo", "tree", "--locked", "-e", "normal", "--prefix", "none", "--format", "{p}|{l}", *args]
    out = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, check=True).stdout
    comps: dict[str, dict] = {}
    for line in out.splitlines():
        # cargo tree marks an already-printed subtree by appending " (*)" to the
        # line, i.e. after the licence: strip it before parsing.
        m = LINE.match(re.sub(r" \(\*\)$", "", line.strip()))
        if not m:
            continue
        local = bool(m["src"]) and m["src"].startswith("/")
        purl = f"pkg:cargo/{m['name']}@{m['ver']}"
        lic = m["lic"].strip()
        c = {"type": "library", "name": m["name"], "version": m["ver"], "bom-ref": purl,
             "properties": [{"name": "syntriass:source", "value": "workspace" if local else "crates.io"}]}
        if not local:
            c["purl"] = purl
        if lic:
            c["licenses"] = [{"expression": lic}]
        comps[purl] = c
    ordered = [comps[k] for k in sorted(comps)]
    commit = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    serial = hashlib.sha256(json.dumps(ordered, sort_keys=True).encode()).hexdigest()
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
           "version": 1,
           "metadata": {"component": {"type": "application", "name": name, "version": commit},
                        "properties": [{"name": "syntriass:scope", "value": "cargo tree -e normal " + " ".join(args)},
                                       {"name": "syntriass:note", "value": "declared licences, not a legal review"}]},
           "components": ordered}
    Path(prefix + ".cdx.json").write_text(json.dumps(bom, indent=1) + "\n")
    by_lic: dict[str, list[str]] = {}
    for c in ordered:
        lic = c.get("licenses", [{}])[0].get("expression", "") or "(none declared)"
        by_lic.setdefault(lic, []).append(f"{c['name']}@{c['version']}")
    summary = {"name": name, "commit": commit, "components": len(ordered),
               "licences": {k: len(v) for k, v in sorted(by_lic.items(), key=lambda kv: -len(kv[1]))},
               "review_needed": {k: v for k, v in sorted(by_lic.items()) if review_needed(k if k != "(none declared)" else "")}}
    Path(prefix + ".licences.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(f"{name}: {len(ordered)} components, {len(by_lic)} licence expressions, "
          f"{sum(len(v) for v in summary['review_needed'].values())} components need licence review")
    return 0


if __name__ == "__main__":
    sys.exit(main())
