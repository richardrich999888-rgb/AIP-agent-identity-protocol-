#!/usr/bin/env python3
"""Drive the native offline verifier over retained P0-048 synthetic archives.

The public announcements are explicit test trust inputs, not independent key
custody. Keep mutation files separate from original signed evidence.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--originals", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    checks = []

    def run(label, directory, anchor, expected=0, batches=None, include_health=True):
        cmd = [str(args.verifier), "--observer-id", anchor["observer_id"],
               "--key-version", str(anchor["key_version"]),
               "--pubkey", bytes(anchor["public_key"]).hex(),
               "--batches", str(batches or directory / "batches.jsonl"), "--json"]
        if include_health:
            cmd.extend(["--health", str(directory / "health.jsonl")])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        (args.output / (label + ".stdout.json")).write_text(result.stdout)
        (args.output / (label + ".stderr.txt")).write_text(result.stderr)
        matched = result.returncode == expected
        if expected == 2:
            matched = matched and "cannot read" in result.stderr and "health.jsonl" in result.stderr
        elif expected == 1:
            native = json.loads(result.stdout)
            matched = matched and any(f["kind"] == "SignatureRejected" for f in native["findings"])
        checks.append({"label": label, "command": cmd,
                       "expected_exit": expected, "actual_exit": result.returncode,
                       "coverage_verdict": "NOT_EVALUATED" if include_health else "UNAVAILABLE",
                       "status": "PASS" if matched else "FAIL"})

    directories = sorted(p.parent for p in args.originals.glob("*/observer.json"))
    if len(directories) != 3:
        raise SystemExit("expected exactly the three retained regression runs")
    for directory in directories:
        anchor = json.loads((directory / "observer.json").read_text())
        if directory.name.endswith("-ObserverLost"):
            # An intentionally killed observer never emitted health. Preserve
            # that absence, require its native verification refusal, and only
            # then check the initial batch's signature as a narrower property.
            state = json.loads((directory / "result.json").read_text())
            assert state["scenario"] == "ObserverLost" and state["result"] == "CANNOT_PROVE"
            assert not (directory / "health.jsonl").exists()
            run("outage-missing-health-refused", directory, anchor, expected=2)
            run("outage-initial-batch-signature-only", directory, anchor, include_health=False)
        else:
            run(directory.name, directory, anchor)
    honest = next(p for p in directories if p.name.endswith("-Honest"))
    anchor = json.loads((honest / "observer.json").read_text())
    original = (honest / "batches.jsonl").read_bytes()
    match = re.search(rb'"attested_at_ms"\s*:\s*([0-9])', original)
    if not match:
        raise SystemExit("no signed collector timestamp to mutate")
    pos = match.start(1)
    replacement = b"2" if original[pos:pos + 1] != b"2" else b"3"
    modified = original[:pos] + replacement + original[pos + 1:]
    assert sum(a != b for a, b in zip(original, modified)) == 1
    tampered = args.output / "MUTATED-one-byte-batches.jsonl"
    tampered.write_bytes(modified)
    run("one-byte-tamper", honest, anchor, expected=1, batches=tampered)
    wrong = dict(anchor)
    wrong["public_key"] = list(anchor["public_key"])
    wrong["public_key"][0] ^= 1
    run("wrong-anchor", honest, wrong, expected=1)
    report = {
        "scope": "Offline signature and supplied archive-chain checks; not capture completeness",
        "independent_administration": False,
        "verifier_sha256": hashlib.sha256(args.verifier.read_bytes()).hexdigest(),
        "original_sha256": hashlib.sha256(original).hexdigest(),
        "mutated_sha256": hashlib.sha256(modified).hexdigest(),
        "changed_bytes": 1, "checks": checks,
        "status": "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL",
    }
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": len(checks)}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
