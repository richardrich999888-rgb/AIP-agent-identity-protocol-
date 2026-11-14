#!/usr/bin/env python3
"""Classify immutable historical findings without filtering the scanner report.

This is a repository hygiene gate, not Kubernetes deployment acceptance. New
findings, changed evidence, scanner errors and missing expected findings fail.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLASSIFICATIONS = Path(__file__).with_name("security_classifications.json")


def verify_inputs(root, policy):
    root = root.resolve()
    if policy["schema"] != "vanian.security-classification.v1":
        raise ValueError("unknown classification schema")
    for item in policy["immutable_files"]:
        path = root / item["path"]
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("historical evidence must be a regular repository file")
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("historical evidence changed: " + item["path"])
    ignored = (root / ".gitleaksignore").read_text().splitlines()
    for fingerprint in policy["gitleaks_fingerprints"]:
        if ignored.count(fingerprint) != 1:
            raise ValueError("missing or duplicate exact checksum fingerprint")


def key(item):
    return (item["rule_id"], item["path"], item["start_line"], item["end_line"])


def classify(root, policy, report, scan_exit):
    verify_inputs(root, policy)
    # 42 is reserved for scanner findings. Operational failures must never be
    # converted into a successful classification of an absent/partial report.
    if scan_exit not in (0, 42):
        raise ValueError("scanner failed operationally: exit " + str(scan_exit))
    if report.get("version") != "2.1.0" or len(report.get("runs", [])) != 1:
        raise ValueError("expected one SARIF 2.1.0 scanner run")
    run = report["runs"][0]
    driver = run["tool"]["driver"]
    if driver["name"] != "Trivy" or driver["version"] != policy["trivy_version"]:
        raise ValueError("unexpected scanner identity/version; review before accepting")
    results = run["results"]
    if not isinstance(results, list) or bool(results) != (scan_exit == 42):
        raise ValueError("scanner exit code and report findings disagree")
    expected = {key(item) for item in policy["archived_misconfigurations"]}
    if len(expected) != 4:
        raise ValueError("expected exactly four individually reviewed archival warnings")
    accepted, blocked = [], []
    seen = set()
    for result in results:
        locations = result.get("locations", [])
        if len(locations) != 1:
            raise ValueError("finding must have exactly one physical location")
        physical = locations[0]["physicalLocation"]
        region = physical.get("region", {})
        item = {
            "rule_id": result["ruleId"],
            "path": physical["artifactLocation"]["uri"],
            "start_line": region.get("startLine"),
            "end_line": region.get("endLine"),
        }
        identity = key(item)
        if identity in expected and identity not in seen and result.get("level") == "error":
            accepted.append(item)
            seen.add(identity)
        else:
            blocked.append(item)
    missing = sorted(expected - seen)
    return {
        "schema": "vanian.security-gate.v1",
        "status": "PASS_WITH_ARCHIVED_FINDINGS" if not blocked and not missing else "FAIL",
        "scanner_exit": scan_exit,
        "raw_findings": len(results),
        "archived_findings": accepted,
        "blocking_findings": blocked,
        "missing_expected_findings": missing,
        "scope": policy["scope"],
        "deployment_qualified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--verify-inputs", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--scan-exit", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        policy = json.loads(CLASSIFICATIONS.read_text())
        if args.verify_inputs:
            verify_inputs(args.root, policy)
            result = {"status": "PASS", "scope": "immutable evidence and exact checksum fingerprints"}
        else:
            if args.report is None or args.scan_exit is None:
                raise ValueError("--report and --scan-exit are required")
            result = classify(args.root, policy, json.loads(args.report.read_text()), args.scan_exit)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {"status": "FAIL", "error": str(error)}
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    if os.environ.get("GITHUB_STEP_SUMMARY") and not args.verify_inputs:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("### Security finding classification\n\n")
            summary.write("Status: **" + result["status"] + "**.\n\n")
            summary.write("The unfiltered SARIF is retained. Four historical HIGH warnings may be classified only at their exact location and original file hash. New findings and scanner failures block. This does not qualify the enabled Kubernetes deployment.\n")
    print(text, end="")
    return 0 if result["status"].startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
