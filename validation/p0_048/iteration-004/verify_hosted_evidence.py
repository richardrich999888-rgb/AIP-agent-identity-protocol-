#!/usr/bin/env python3
"""Recheck retained hosted originals and deliberately altered copies locally.

This checks signatures, supplied chains and the recorded absence of coverage.
It does not attest the CI host, independently administered custody or task success.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
HOSTED = HERE / "hosted/p0-native-evidence"
SOURCE = "ea5fe9e9ad10da0b490b411afc9f757e01259c73"
ZIP_HASH = "cd0e919510fc5922de8638dacf98d11e22d82e84f6d6e5c1c3a8890ac1cca29c"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def one_byte_modification(raw):
    old = b'"probe_id":"probe-host-1"'
    new = b'"probe_id":"probe-host-2"'
    # Kernel events repeat their batch's probe ID. Mutate only the first
    # occurrence, keeping the copied JSON valid and every original untouched.
    assert old in raw
    changed = raw.replace(old, new, 1)
    assert len(raw) == len(changed) and sum(a != b for a, b in zip(raw, changed)) == 1
    json.loads(changed)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha((HERE / "hosted-artifact.zip").read_bytes()) == ZIP_HASH
    checked = []
    for line in (HOSTED / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        path = (HOSTED / name).resolve()
        assert path.is_relative_to(HOSTED.resolve())
        assert sha(path.read_bytes()) == digest, name
        checked.append(name)
    summary = json.loads((HOSTED / "summary.json").read_text())
    assert summary["source_commit"] == SOURCE and summary["source_changes"] == []
    assert summary["status"] == "PASS" and len(summary["cases"]) == 10
    assert all(c["status"] == "PASS" for c in summary["cases"])
    for name, digest in summary["source_sha256"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name
        original = subprocess.check_output(["git", "show", SOURCE + ":" + name], cwd=ROOT)
        assert sha(original) == digest, name

    anchors = {label: json.loads((HOSTED / "originals" / label / "scope-and-anchor.json").read_text())
               for label in ("t09", "t15")}
    results = []
    for label in ("t09", "t15"):
        source = HOSTED / "originals" / label
        anchor = anchors[label]
        raw = (source / "batches.jsonl").read_bytes()
        changed = one_byte_modification(raw)
        mutation = out / (label + "-one-byte-modified.jsonl")
        mutation.write_bytes(changed)
        key = bytes(anchor["public_key"]).hex()
        wrong_key = bytes(anchors["t15" if label == "t09" else "t09"]["public_key"]).hex()
        assert key != wrong_key
        for name, batch, pubkey, expected in (
            ("original", source / "batches.jsonl", key, 0),
            ("one-byte-modified", mutation, key, 1),
            ("wrong-anchor", source / "batches.jsonl", wrong_key, 1),
        ):
            command = [str(args.verifier.resolve()), "--observer-id", anchor["observer_id"],
                       "--key-version", str(anchor["key_version"]), "--pubkey", pubkey,
                       "--batches", str(batch), "--health", str(source / "health.jsonl"), "--json"]
            start = time.monotonic()
            run = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            (out / (label + "-" + name + ".json")).write_bytes(run.stdout)
            (out / (label + "-" + name + ".stderr")).write_bytes(run.stderr)
            result = json.loads(run.stdout)
            assert run.returncode == expected, (label, name, run.returncode)
            if expected == 0:
                assert result["findings"] == []
                assert result["health"]["with_coverage"] == 0
                assert result["health"]["without_coverage"] == 1
                assert result["health"]["states"] == ["Degraded" if label == "t15" else "ContinuityUnverified"]
            else:
                assert result["findings"], (label, name)
            results.append({"case": label + "-" + name, "command": command,
                            "expected_exit_code": expected, "actual_exit_code": run.returncode,
                            "duration_seconds": time.monotonic() - start, "status": "PASS"})
    loss = json.loads((HOSTED / "originals/t15/batches.jsonl").read_text())
    assert loss["batch"]["dropped_events"] > 0
    report = {"status": "PASS", "source_commit": SOURCE,
              "artifact_sha256": ZIP_HASH, "artifact_manifest_files_checked": len(checked),
              "current_source_files_matching_hosted_source": len(summary["source_sha256"]),
              "verifier_sha256": sha(args.verifier.read_bytes()), "cases": results,
              "lost_event_health": "Degraded", "coverage_asserted": False,
              "independent_administration": False, "execution_verdict": "NOT_EVALUATED"}
    (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "cases": len(results), "manifest_files": len(checked)}))


if __name__ == "__main__":
    main()
