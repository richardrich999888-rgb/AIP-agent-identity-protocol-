#!/usr/bin/env python3
"""Test composition with real gateway receipts and a labeled fixture expectation.

Unused agent/observer anchors are test keys, never sensor or identity evidence.
The accepted signature must still yield CannotProve without observations.
"""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verifier", type=Path, required=True)
    args = parser.parse_args()
    archive = Path(__file__).parent / "results/20261028/combined"
    fixture = json.loads((archive / "honest-authorization.json").read_text())
    gateway = json.loads((archive / "trust-anchor.json").read_text())
    receipts = [json.loads(line) for line in (archive / "receipts.jsonl").read_text().splitlines()]
    receipt = next(r for r in receipts if r["receipt"]["decision_id"] == fixture["expectation"]["decision_id"])
    # These roles are unused because this case has no identity or observer
    # evidence. Their presence must not establish either missing guarantee.
    anchors = {"agent_key": [11] * 32, "decision_point_id": fixture["decision_point_id"],
        "decision_point_key": list(bytes.fromhex(fixture["public_key"])),
        "gateway_id": gateway["gateway_id"], "gateway_version": gateway["key_version"],
        "gateway_key": list(bytes.fromhex(gateway["public_key"])),
        "observer_id": "unused-test-observer", "observer_version": 1, "observer_key": [12] * 32,
        "verification_time_ms": receipt["receipt"]["received_at_ms"],
        "health_max_age_ms": 1000, "window_tolerance_ms": 0}
    bundle = {"expectation": fixture["expectation"], "receipt": receipt, "observation": None}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "anchors.json").write_text(json.dumps(anchors))
        def run(value):
            (root / "bundle.json").write_text(json.dumps(value))
            return subprocess.run([str(args.verifier.resolve()), str(root / "anchors.json"),
                str(root / "bundle.json")], text=True, capture_output=True)
        result = run(bundle)
        if result.returncode:
            raise AssertionError(result.stderr)
        verified = json.loads(result.stdout)
        assert "CannotProve" in json.dumps(verified["runtime_reconciliation"])
        assert verified["authority_chain"] == "NOT_ASSESSED_BY_THIS_COMPOSITION"
        bad_receipt = copy.deepcopy(bundle)
        bad_receipt["receipt"]["receipt"]["parameter_commitment"][0] ^= 1
        assert run(bad_receipt).returncode != 0
        bad_expectation = copy.deepcopy(bundle)
        bad_expectation["expectation"]["agent_id"] = "forged-agent"
        assert run(bad_expectation).returncode != 0
    print(json.dumps({"tests": 3, "status": "PASS", "scope": "native offline composition; no new runtime observation"}))


if __name__ == "__main__":
    main()
