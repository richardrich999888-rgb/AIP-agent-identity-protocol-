#!/usr/bin/env python3
"""Verify retained expert suites with a second Ed25519 implementation.

Requires Python cryptography (tested with 50.0.0); stage it before disconnecting.
Usage: python3 verify_suite_signatures.py EVIDENCE_DIR --trusted-keys KEYS.json
The trusted mapping must come from the evaluator/operator, not an untrusted pack.
This checks suite signatures and their report bindings, not rule correctness,
expert qualifications, approval, diagnostic authenticity or overall readiness.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def verify(folder: Path, trusted: dict) -> list:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    results = []
    paths = sorted(folder.glob("*/suite.json"))
    if not paths:
        raise ValueError("no suites found")
    for path in paths:
        suite = json.loads(path.read_text())
        names = ("suite_id", "tenant", "task", "expert_id", "cases")
        if set(suite) != {*names, "signature_hex"}:
            raise ValueError(f"{path}: unexpected suite fields")
        case_names = ("id", "text", "expected", "counterexample")
        for c in suite["cases"]:
            if set(c) != set(case_names):
                raise ValueError(f"{path}: unexpected case fields")
        body = {k: suite[k] for k in names}
        body["cases"] = [{k: c[k] for k in case_names} for c in suite["cases"]]
        payload = b"syntriass-expert-suite/v1\n" + json.dumps(
            body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted[suite["expert_id"]]))
        key.verify(bytes.fromhex(suite["signature_hex"]), payload)
        sha = hashlib.sha256(payload).hexdigest()
        report = json.loads((path.parent / "scoreboard.json").read_text())
        if report["validation"]["suite_hash"] != sha or report["validation"]["suite_expert"] != suite["expert_id"]:
            raise ValueError(f"{path}: diagnostic refers to another suite")
        results.append({"suite": str(path.relative_to(folder)), "suite_hash": sha,
                        "signature_verified": True, "expert_id": suite["expert_id"]})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--trusted-keys", type=Path, required=True)
    args = parser.parse_args()
    try:
        results = verify(args.folder, json.loads(args.trusted_keys.read_text()))
    except ImportError as error:
        print(f"NOT READY: missing offline verification dependency: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"REFUSED: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"result": "SUITE_SIGNATURES_VERIFIED", "suites": results,
                      "diagnostic_or_release_approved": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
