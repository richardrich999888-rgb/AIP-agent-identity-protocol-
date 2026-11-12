#!/usr/bin/env python3
"""Check the labelled synthetic lifecycle archive with the native offline CLI.

Signature acceptance is not an execution verdict or independent administration.
No health/coverage record is invented for this stimulus-based regression.
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
    anchor = json.loads((args.originals / "scope-and-anchor.json").read_text())
    originals = args.originals / "batches.jsonl"
    raw = originals.read_bytes()
    packet = json.loads(raw)
    assert not anchor["live_connector_capture"]
    assert not anchor["independent_administration"]
    assert anchor["coverage"] == "NOT_ESTABLISHED"
    assert [e["bound"] is not None for e in packet["batch"]["kernel_events"]] == anchor["expected_bound"]
    checks = []

    def check(label, batches, key, expected_exit, missing_health=False):
        cmd = [str(args.verifier), "--observer-id", anchor["observer_id"],
               "--key-version", str(anchor["key_version"]), "--pubkey", bytes(key).hex(),
               "--batches", str(batches), "--json"]
        if missing_health:
            assert not (args.originals / "health.jsonl").exists()
            cmd += ["--health", str(args.originals / "health.jsonl")]
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        (args.output / (label + ".stdout.json")).write_text(run.stdout)
        (args.output / (label + ".stderr.txt")).write_text(run.stderr)
        ok = run.returncode == expected_exit
        if expected_exit == 1:
            ok = ok and any(f["kind"] == "SignatureRejected" for f in json.loads(run.stdout)["findings"])
        if missing_health:
            ok = ok and "cannot read" in run.stderr and "health.jsonl" in run.stderr
        checks.append({"label": label, "command": cmd, "exit_code": run.returncode,
                       "expected_exit": expected_exit, "status": "PASS" if ok else "FAIL"})

    check("original-signature-only", originals, anchor["public_key"], 0)
    check("missing-health-refused", originals, anchor["public_key"], 2, missing_health=True)
    match = re.search(rb'"attested_at_ms"\s*:\s*([0-9])', raw)
    assert match, "a signed timestamp must be available for the one-byte attack"
    pos = match.start(1)
    modified = raw[:pos] + (b"2" if raw[pos:pos + 1] != b"2" else b"3") + raw[pos + 1:]
    assert sum(a != b for a, b in zip(raw, modified)) == 1
    mutation = args.output / "MUTATED-one-byte-batches.jsonl"
    mutation.write_bytes(modified)
    check("one-byte-tamper", mutation, anchor["public_key"], 1)
    wrong_key = list(anchor["public_key"])
    wrong_key[0] ^= 1
    check("wrong-anchor", originals, wrong_key, 1)
    result = {
        "scope": anchor["scope"], "execution_verdict": "NOT_EVALUATED",
        "coverage": "NOT_ESTABLISHED", "independent_administration": False,
        "verifier_sha256": hashlib.sha256(args.verifier.read_bytes()).hexdigest(),
        "original_sha256": hashlib.sha256(raw).hexdigest(),
        "mutated_sha256": hashlib.sha256(modified).hexdigest(), "changed_bytes": 1,
        "checks": checks, "status": "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL",
    }
    (args.output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "checks": len(checks)}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
