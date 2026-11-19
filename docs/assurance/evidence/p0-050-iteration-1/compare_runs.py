#!/usr/bin/env python3
"""Compare retained applicability runs without importing the teaching harness.

Diagnostics are unsigned: these consistency checks do not authenticate a claimed
verdict. Verify the signed suites separately, then rerun the validator if needed.
"""
import json
from pathlib import Path
import sys


def read(path):
    return json.loads(path.read_text())


def main():
    baseline, *candidates = map(Path, sys.argv[1:])
    if not candidates:
        raise ValueError("usage: compare_runs.py BASELINE CANDIDATE [CANDIDATE...]")
    old = read(baseline / "result.json")
    assert old["result"] == "PARTIAL_B3_ADVERSARIAL_FAILURE"
    summary = []
    for candidate in candidates:
        new = read(candidate / "result.json")
        assert new["result"] == "PASS_BOUNDED_B3" and not new["tree_dirty"]
        assert new["dataset_manifest_sha256"] == old["dataset_manifest_sha256"]
        # Each fresh teaching session has its own identity, covered by its
        # questions digest. Compare the actual cited questions and choices;
        # never require independent sessions to have identical identities.
        questions_a = read(baseline / "questions.json")
        questions_b = read(candidate / "questions.json")
        assert questions_a.pop("session_id") == old["session_id"]
        assert questions_b.pop("session_id") == new["session_id"]
        assert questions_a == questions_b
        assert new["model_calls"] == 0 and new["activation_performed"] is False
        for before, after in zip(old["runs"], new["runs"], strict=True):
            name = after["name"]
            assert name == before["name"] and after["state_unchanged"] is True
            assert (baseline / name / "cases.jsonl").read_bytes() == (candidate / name / "cases.jsonl").read_bytes()
            a, b = read(baseline / name / "capability.json"), read(candidate / name / "capability.json")
            assert a.keys() == b.keys()
            assert [k for k in a if a[k] != b[k]] == ["applicability"]
            if name == "explicit-forms-validation":
                assert after["exit_status"] == 0 and after["expert_passed"] == after["expert_cases"] == 12
            if name == "explicit-forms-attacks":
                assert after["exit_status"] == 0 and after["expert_passed"] == after["expert_cases"] == 26
                report = read(candidate / name / "scoreboard.json")
                probes = [r for r in report["cases"] if r["origin"] == "suite" and r["id"].startswith("fa-")]
                assert len(probes) == 6
                assert all(r["expected"] == r["got"] == "NOT_APPLICABLE" and r["passed"] for r in probes)
        summary.append({"directory": str(candidate), "source": new["commit"],
                        "binary_sha256": new["binary_sha256"], "wall_seconds": new["wall_seconds"],
                        "hardware": new["hardware"], "unchanged_labels": True,
                        "only_artifact_change": "applicability", "holdout": "12/12",
                        "adversarial": "26/26", "frozen_nonactivation_subset": "6/6"})
    print(json.dumps({"status": "CONSISTENT_BOUNDED_RESULTS", "runs": summary}, indent=2))


if __name__ == "__main__":
    main()
