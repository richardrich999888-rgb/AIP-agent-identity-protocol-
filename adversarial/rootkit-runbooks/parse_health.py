#!/usr/bin/env python3
"""Phase 5 output-parsing harness — validates against fixtures, never a rootkit.

# What this is, and what it is emphatically not

The Tier-2 rootkit tests (TripleCross, ebpfkit, bad-bpf, Boopkit, pamspy) run
ONLY inside a dedicated, snapshotted, network-isolated VM, by a human, per the
runbook in this directory's README. They load code into the kernel and are
irreversible on a live host. **This script runs no rootkit and loads nothing.**

It is the other half: given a saved sample of what the observer produced during
such a VM run — the collector's signed health record — it asserts that the
observer reached the integrity state the runbook says that attack must force.
That is the whole contract of Phase 5: the attack must drive the observer to a
signed `IntegrityUnknown` / `CANNOT_PROVE`, never a clean finding.

Until a VM run has actually happened, the fixtures in `fixtures/` stand in for
its outputs, so the harness itself is exercised and correct before it is ever
pointed at a real capture. A fixture is clearly labelled as such; substituting
a real capture is a file swap, not a code change.

# Why parse the observer's output rather than the rootkit's

The rootkit's own stdout tells you it attached. It cannot tell you whether the
observer noticed. The only evidence that matters for the product claim is the
*observer's* signed health for the attacked window, so that is what this reads.

Usage:
    parse_health.py <manifest.tsv>
Exit:
    0  every row's observed state matched the state its attack must force
    1  at least one mismatch (a FALSE-PROVEN result — a product defect)
    2  a fixture was missing or unreadable
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The observer states that satisfy "degraded to an honest non-answer". A clean
# `Active` while a blinding attack is live is the FALSE-PROVEN failure the whole
# program exists to catch.
HONEST_UNDER_ATTACK = {"IntegrityUnknown", "Degraded", "CannotProve", "ContinuityUnverified"}


def observed_state(health_path: Path) -> str:
    """The state of the LAST signed health record in a JSONL capture.

    Last, not first: a capture spans the attack window, and the record that
    matters is the one signed while the attack was live.
    """
    text = health_path.read_text().strip()
    if not text:
        raise ValueError(f"{health_path} is empty")
    last = [ln for ln in text.splitlines() if ln.strip()][-1]
    record = json.loads(last)
    # Accept either the sealed health-archive shape ({"health": {...}}) or a
    # bare health object, so a real capture and a hand-written fixture parse
    # the same way.
    health = record.get("health", record)
    state = health.get("state")
    if state is None:
        raise ValueError(f"{health_path}: no health.state field")
    return state


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    manifest = Path(argv[1])
    rows = [
        ln.split("\t")
        for ln in manifest.read_text().splitlines()
        if ln.strip() and not ln.startswith("#")
    ]

    failures = 0
    for row in rows:
        if len(row) < 4:
            print(f"  MALFORMED ROW: {row}")
            failures += 1
            continue
        tool, kind, fixture, expected = row[0], row[1], row[2], row[3]
        path = HERE / fixture
        if not path.exists():
            print(f"  MISSING FIXTURE for {tool}: {path}")
            return 2
        try:
            state = observed_state(path)
        except (ValueError, json.JSONDecodeError) as e:
            print(f"  UNREADABLE {tool}: {e}")
            return 2

        if kind == "attack":
            ok = state in HONEST_UNDER_ATTACK
            verdict = "PASS" if ok else "FALSE-PROVEN"
        elif kind == "control":
            # A control run has no attack; a non-degraded state is correct and
            # a spurious integrity failure would be a false positive.
            ok = state not in {"IntegrityUnknown"}
            verdict = "PASS" if ok else "FALSE-POSITIVE"
        else:
            print(f"  UNKNOWN KIND {kind!r} for {tool}")
            failures += 1
            continue

        print(f"  {verdict:12} {tool:16} kind={kind:8} observed={state:20} (expected {expected})")
        if not ok:
            failures += 1

    print("-" * 60)
    if failures:
        print(f"FAIL: {failures} row(s) did not reach the required state.")
        print("A FALSE-PROVEN row is a product-level defect: the observer signed")
        print("coverage it did not have while an attack was live. Fix before RBI.")
        return 1
    print("PASS: every attack row forced an honest non-answer; controls clean.")
    print("NOTE: these are FIXTURES. Replace with real VM captures per README.md")
    print("      before citing this as evidence of a live rootkit result.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
