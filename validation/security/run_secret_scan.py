#!/usr/bin/env python3
"""Scan the exact GitHub PR range and checked-out tree without API pagination."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gitleaks", default=os.environ.get("GITLEAKS", "gitleaks"))
    args = parser.parse_args()
    repo = args.repository.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    checkout = git(repo, "rev-parse", "HEAD")
    base = os.environ.get("PR_BASE_SHA", "")
    head = os.environ.get("PR_HEAD_SHA", "")
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (base, head)):
            raise ValueError("PR scan requires exact base and head commit SHAs")
        for value in (base, head):
            if git(repo, "rev-parse", value + "^{commit}") != value:
                raise ValueError("PR range does not resolve to the supplied exact commits")
        history = base + ".." + head
    else:
        # Scheduled/manual runs scan all ancestors of the checked-out commit.
        history = checkout
    scope = {"event": os.environ.get("GITHUB_EVENT_NAME"), "base_sha": base,
             "head_sha": head, "checkout_sha": checkout, "history_range": history,
             "history_commits": int(git(repo, "rev-list", "--count", history)),
             "tree": "entire checked-out working tree", "results": {}}
    print(json.dumps({k: v for k, v in scope.items() if k != "results"}), flush=True)
    common = ["--no-banner", "--redact", "--exit-code", "1",
              "--config", str(repo / ".gitleaks.toml"),
              "--gitleaks-ignore-path", str(repo / ".gitleaksignore"),
              "--report-format", "sarif"]
    for name, command in (
        ("history", ["git", "--log-opts=" + history]),
        ("tree", ["dir"]),
    ):
        report = output / ("gitleaks-" + name + ".sarif")
        result = subprocess.run([args.gitleaks, *command, *common,
                                 "--report-path", str(report), "."], cwd=repo)
        scope["results"][name] = {"exit_code": result.returncode, "report": report.name}
    (output / "scope.json").write_text(json.dumps(scope, indent=2) + "\n")
    # A scanner execution/configuration error is also a failing gate.
    return 1 if any(item["exit_code"] != 0 for item in scope["results"].values()) else 0


if __name__ == "__main__":
    sys.exit(main())
