#!/usr/bin/env python3
"""Offline replay of the frozen teaching applicability acceptance.

Trust is a caller-supplied file, never inferred from a packet's own public key.
OpenSSL verifies the existing Ed25519 suite encoding independently of Rust.
The separately supplied trusted syntriass binary recomputes every outcome;
unsigned scoreboards and result.json are not inputs to the verdict.
This does not approve/activate a capability or establish expert identity/custody.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

# Ordered cases from the unchanged P0-049 acceptance, not regenerated labels.
# The six frozen nonactivation probes are a subset of the 26-case attack suite.
CASES = {
    "explicit-forms-validation": (12, "755e39ca9d2206746391baebf458c87d6cfe058a5aa248e002efd910c0a47967"),
    "explicit-forms-attacks": (26, "e7c446cc4da83a8273f296dc3e98f217143e8eac948854572aca27534386398c"),
}
DOMAIN = b"syntriass-expert-suite/v1\n"
SUITE_FIELDS = ("suite_id", "tenant", "task", "expert_id", "cases")
CASE_FIELDS = ("id", "text", "expected", "counterexample")


class Rejected(ValueError):
    """Supplied material or recomputed outcome does not satisfy acceptance."""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate JSON field: " + key)
        result[key] = value
    return result


def read_json(path):
    return parse_json(path.read_bytes())


def parse_json(raw):
    if len(raw) > 4 * 1024 * 1024:
        raise Rejected("oversized input")
    return json.loads(raw, object_pairs_hook=unique_object)


def checked(condition, message):
    if not condition:
        raise Rejected(message)


def verify(evidence, trust, binary, out, openssl="openssl"):
    """Recompute acceptance using externally selected trust and runtime bytes."""
    out.mkdir(parents=True, exist_ok=False)
    binary = binary.resolve()
    checked(digest(binary.read_bytes()) == trust["binary_sha256"], "runtime hash mismatch")
    public = bytes.fromhex(trust["public_key_hex"])
    checked(len(public) == 32, "Ed25519 public key must be 32 bytes")
    executable = shutil.which(openssl)
    checked(executable is not None, "OpenSSL is required; no signature check was skipped")
    results = []
    for label, (count, expected_cases_hash) in CASES.items():
        source = evidence / label
        cap_file = source / "capability.json"
        cap_raw = cap_file.read_bytes()
        checked(digest(cap_raw) == trust["capability_sha256"], "capability hash mismatch")
        cap = parse_json(cap_raw)
        checked(cap["required"]["tenant"] == trust["tenant"], "capability tenant mismatch")
        checked(cap["intended_task"] == trust["task"], "capability task mismatch")
        suite_raw = (source / "suite.json").read_bytes()
        suite = parse_json(suite_raw)
        checked(set(suite) == {*SUITE_FIELDS, "signature_hex"}, "unexpected suite fields")
        checked(suite["suite_id"] == "p0-049/b3/" + label, "suite ID mismatch")
        for field in ("tenant", "task", "expert_id"):
            checked(suite[field] == trust[field], "suite " + field + " mismatch")
        cases = suite["cases"]
        checked(isinstance(cases, list) and len(cases) == count, "frozen case count changed")
        checked(all(isinstance(c, dict) and set(c) == set(CASE_FIELDS) for c in cases), "unexpected case fields")
        cases = [{f: c[f] for f in CASE_FIELDS} for c in cases]
        checked(digest(canonical(cases)) == expected_cases_hash, "frozen cases changed")
        signature = bytes.fromhex(suite["signature_hex"])
        checked(len(signature) == 64, "invalid Ed25519 signature length")
        unsigned = {f: cases if f == "cases" else suite[f] for f in SUITE_FIELDS}
        with tempfile.TemporaryDirectory(prefix="syntriass-verify-") as scratch:
            temp = Path(scratch)
            # RFC 8410 Ed25519 SubjectPublicKeyInfo (OID 1.3.101.112).
            (temp / "public.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + public)
            (temp / "message").write_bytes(DOMAIN + canonical(unsigned))
            (temp / "signature").write_bytes(signature)
            command = [executable, "pkeyutl", "-verify", "-pubin", "-inkey", str(temp / "public.der"),
                       "-keyform", "DER", "-rawin", "-in", str(temp / "message"), "-sigfile", str(temp / "signature")]
            signed = subprocess.run(command, capture_output=True, timeout=15)
            (out / (label + "-signature.log")).write_bytes(signed.stdout + signed.stderr)
            checked(signed.returncode == 0, "suite signature rejected")
        replay_cases = out / (label + "-cases.jsonl")
        replay_cases.write_text("".join(json.dumps({"id": c["id"], "text": c["text"], "label": c["expected"]}) + "\n" for c in cases))
        # Replay exactly the bytes hashed above, even if the input packet changes
        # afterwards. The evaluator owns the new output directory and runtime.
        snapshot = out / (label + "-capability.json")
        snapshot.write_bytes(cap_raw)
        snapshot.chmod(0o400)
        command = [str(binary), "cap-check", "--file", str(snapshot), "--cases", str(replay_cases)]
        run = subprocess.run(command, capture_output=True, timeout=30)
        (out / (label + "-stdout.jsonl")).write_bytes(run.stdout)
        (out / (label + "-stderr.log")).write_bytes(run.stderr)
        checked(run.returncode == 0, "native replay command failed")
        observed = [json.loads(line, object_pairs_hook=unique_object) for line in run.stdout.splitlines() if line.strip()]
        checked(len(observed) == count, "native replay omitted or duplicated results")
        for case, actual in zip(cases, observed):
            checked(actual.get("id") == case["id"], "native replay changed case identity/order")
            checked(actual.get("expected") == case["expected"], "native replay changed expectation")
            checked(actual.get("got") == case["expected"], "outcome mismatch: " + case["id"])
        results.append({"suite": label, "cases": count, "passed": count, "command": command,
                        "cases_sha256": expected_cases_hash, "suite_sha256": digest(suite_raw),
                        "signature_verification": "PASS", "recomputed_outcomes": "PASS"})
    return {"schema": "syntriass.applicability-replay/v1", "status": "PASS",
            "trust": trust, "suites": results, "frozen_nonactivation_passed": 6,
            "nonactivation_is_subset_of_26": True,
            "openssl": subprocess.check_output([executable, "version"], text=True).strip(),
            "openssl_sha256": digest(Path(executable).read_bytes()),
            "activation_performed": False, "expert_identity_verified": False,
            "independent_administration": False,
            "scope": "Signed frozen cases and recomputed component outcomes; no full teaching/kit/production acceptance"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--trust", type=Path, required=True, help="separately reviewed trust and byte pins")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    # A prior output must never be overwritten, even on an error path.
    if args.out.exists():
        parser.error("output already exists; choose a fresh directory")
    try:
        report = verify(args.evidence.resolve(), read_json(args.trust), args.binary, args.out)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report = {"status": "FAIL", "error": str(error), "activation_performed": False}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
