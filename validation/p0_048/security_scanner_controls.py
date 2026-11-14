#!/usr/bin/env python3
"""Exercise real scanners against copied unsafe YAML and a fresh fake secret.

All mutations live in a temporary directory. No real credential, deployed
resource, production key or repository evidence is changed.
"""

import argparse
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

import security_gate as gate


def run(command, cwd, expected, report):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    report.append({"command": command, "exit_code": result.returncode, "expected_exit": expected})
    if result.returncode != expected:
        raise ValueError("unexpected scanner/control exit: " + str(result.returncode))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = []
    summary = {"status": "FAIL", "commands": records, "scope": "synthetic detection controls, no production acceptance"}
    try:
        policy = json.loads(gate.CLASSIFICATIONS.read_text())
        with tempfile.TemporaryDirectory(prefix="p0-048-security-controls-") as directory:
            root = Path(directory)
            for item in policy["immutable_files"]:
                target = root / item["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(gate.ROOT / item["path"], target)
            shutil.copyfile(gate.ROOT / ".gitleaksignore", root / ".gitleaksignore")
            archive = root / policy["immutable_files"][1]["path"]
            duplicate = root / "new-deployment.yaml"
            duplicate.write_bytes(archive.read_bytes())
            # A copy is a new artifact. None of its warnings may inherit the
            # exact historical archive's classification.
            report = root / "trivy.sarif"
            run([args.trivy, "fs", "--scanners", "misconfig", "--severity", "CRITICAL,HIGH",
                 "--ignorefile", "", "--skip-check-update", "--exit-code", "42", "--format", "sarif",
                 "--output", str(report), "."], root, 42, records)
            decision = gate.classify(root, policy, json.loads(report.read_text()), 42)
            if decision["status"] != "FAIL" or len(decision["archived_findings"]) != 4:
                raise ValueError("copied manifest was not distinguished from the original")
            new = decision["blocking_findings"]
            if {r["rule_id"] for r in new if r["path"] == duplicate.name} != {r["rule_id"] for r in policy["archived_misconfigurations"]}:
                raise ValueError("copied manifest did not trigger every required HIGH rule")
            summary["trivy_copy_control"] = {"status": "PASS", "archived_findings": 4, "new_blocking_findings": len(new)}

            # This nested throwaway repository starts a different commit at the
            # exact inventory path/lines. Old commit fingerprints must not hide it.
            work = root / "gitleaks-control"
            work.mkdir()
            for name in (".gitleaks.toml", ".gitleaksignore"):
                shutil.copyfile(gate.ROOT / name, work / name)
            target = work / policy["immutable_files"][0]["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            # Generated locally and never usable with a provider. Do not retain it.
            fake = "ghp_" + secrets.token_hex(18)
            target.write_text("\n" * 7514 + 'tokenizer.json = "' + fake + '"\n')
            for command in (["git", "init", "-q"], ["git", "add", "."],
                            ["git", "-c", "user.name=Security control", "-c", "user.email=control@example.invalid",
                             "-c", "commit.gpgsign=false", "commit", "-qm", "synthetic scanner control"]):
                run(command, work, 0, records)
            output = root / "gitleaks-control.json"
            run([args.gitleaks, "git", "--redact", "--exit-code", "42", "--report-format", "json",
                 "--report-path", str(output), "."], work, 42, records)
            findings = json.loads(output.read_text())
            if not any(f["File"] == policy["immutable_files"][0]["path"] and f["StartLine"] == 7515 for f in findings):
                raise ValueError("new secret at the historical path and line was not detected")
            summary["gitleaks_new_commit_control"] = {"status": "PASS", "findings": len(findings), "values_retained": False}
            # The Trivy job owns secret coverage too. A harmless generated
            # provider-shaped token must still trigger that independent scanner.
            trivy_secret = root / "trivy-secret.json"
            run([args.trivy, "fs", "--scanners", "secret", "--severity", "CRITICAL,HIGH", "--ignorefile", "",
                 "--exit-code", "42", "--format", "json", "--output", str(trivy_secret), str(work)], root, 42, records)
            found = sum(len(r.get("Secrets", [])) for r in json.loads(trivy_secret.read_text()).get("Results", []))
            if not found:
                raise ValueError("Trivy secret scanner did not detect the synthetic token")
            summary["trivy_secret_control"] = {"status": "PASS", "findings": found, "values_retained": False}
            summary["status"] = "PASS"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "commands"}, indent=2))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
