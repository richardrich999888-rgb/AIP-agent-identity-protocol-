#!/usr/bin/env python3
"""Execute the ten previously blocked native checks; early return is not PASS.

Use built test executables on an authorized disposable Linux host. This does
not install software, change capabilities, mount filesystems or claim a separate
administrative domain. The workflow prepares its own disposable VM explicitly.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ("cgroup_live", "an_exec_sample_carries_the_execing_tasks_cgroup_id"),
    ("fanotify", "fa05_live_a_write_by_this_process_is_bound_through_the_kernels_pidfd"),
    ("fanotify", "fa06_live_a_writer_that_exited_before_the_read_is_unbound"),
    ("gate10_xdp_evaluation", "x10a_this_kernel_loads_and_executes_an_xdp_parser_without_attaching_it"),
    ("gate10_xdp_evaluation", "x10b_the_verifier_is_the_judge_an_unsafe_program_is_refused"),
    ("sniffer_dog", "t09_live_short_lived_process_is_seen_by_the_kernel_connector"),
    ("sniffer_dog", "t10_live_exec_replacement_is_delivered_as_a_kernel_exec_event"),
    ("sniffer_dog", "t15_live_kernel_event_loss_is_signalled_and_degrades_coverage"),
    ("socksend", "sk07_live_a_loopback_send_is_reported_under_the_senders_pid_with_its_count"),
    ("wiretap", "wt10_live_loopback_handshake_is_captured_with_kernel_stamps_and_counted_loss"),
)
BLOCKED = re.compile(
    r"\b(?:SKIP(?:PED)?|UNAVAILABLE|BLOCKED)\b|no private tmpfs|required live capability missing",
    re.IGNORECASE,
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify(name, text, returncode, timed_out=False):
    if timed_out:
        return "FAIL", "test exceeded its deadline"
    if BLOCKED.search(text):
        return "BLOCKED", "required live assertion did not execute under its prerequisites"
    if returncode != 0:
        return "FAIL", "test process failed"
    one = re.findall(r"^running (\d+) tests?$", text, re.MULTILINE)
    # With --nocapture, a test's stderr can appear between this prefix and
    # its final `ok`. Require the name plus the exact completed summary;
    # a zero-match filter or a different named test must still fail.
    selected = re.findall(r"^test (\S+) \.\.\.", text, re.MULTILINE)
    results = re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
        text, re.MULTILINE,
    )
    if one != ["1"] or selected != [name] or results != [("1", "0", "0")]:
        return "FAIL", "expected exactly one named executed assertion, with no ignored tests"
    return "PASS", "the selected native test executed and passed"


def executables(build_log, root=ROOT):
    found = {}
    wanted = {family for family, _ in CASES}
    for line in build_log.splitlines():
        item = json.loads(line)
        if item.get("reason") != "compiler-artifact":
            continue
        target = item.get("target", {})
        family = target.get("name")
        if family not in wanted or target.get("kind") != ["test"]:
            continue
        expected = root / "aip-standalone/aip-observe/tests" / (family + ".rs")
        if Path(target["src_path"]).resolve() != expected.resolve():
            raise ValueError(f"wrong source path for {family}")
        if family in found or not item.get("executable"):
            raise ValueError(f"duplicate or missing executable for {family}")
        found[family] = Path(item["executable"]).resolve()
    if set(found) != wanted:
        raise ValueError("missing required test executables: " + repr(sorted(wanted - set(found))))
    return found


def host_details():
    def read(path):
        try:
            return Path(path).read_text().strip()
        except OSError as error:
            return str(error)

    namespaces = {}
    for label, path in (("self_net", "/proc/self/ns/net"), ("pid1_net", "/proc/1/ns/net")):
        try:
            namespaces[label] = os.readlink(path)
        except OSError as error:
            namespaces[label] = str(error)
    status = read("/proc/self/status")
    return {
        "kernel": platform.release(), "machine": platform.machine(), "euid": os.geteuid(),
        "os_release": read("/etc/os-release"), "namespaces": namespaces,
        "process_security": [s for s in status.splitlines() if s.startswith(("Cap", "Seccomp", "NoNewPrivs"))],
        "platform": {k: os.environ.get(k) for k in (
            "RUNNER_ENVIRONMENT", "RUNNER_ARCH", "ImageOS", "ImageVersion", "GITHUB_RUN_ID",
            "GITHUB_REPOSITORY", "GITHUB_SHA",
        )},
    }


def execute(command, timeout, env):
    start = time.monotonic()
    try:
        run = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=timeout)
        return run.returncode, run.stdout, False, time.monotonic() - start
    except subprocess.TimeoutExpired as error:
        return None, error.stdout or b"", True, time.monotonic() - start


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-log", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--require-github-hosted", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    summary = {
        "schema": "vanian.p0-048.native-qualification.v1", "status": "FAIL",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_changes": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).splitlines(),
        "host": host_details(), "cases": [], "offline_checks": [],
        "scope": "Native component assertions; not full framework, capture-rate or enterprise acceptance",
        "independent_administration": False, "airgap_acceptance": False,
    }
    try:
        if args.require_github_hosted:
            if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.geteuid() != 0:
                raise ValueError("requires the explicitly prepared disposable GitHub-hosted VM")
            ns = summary["host"]["namespaces"]
            if not ns["self_net"].startswith("net:[") or ns["self_net"] != ns["pid1_net"]:
                raise ValueError("process connector must run in the VM PID 1 network namespace")
        binaries = executables(args.build_log.read_text())
        summary["build_log_sha256"] = digest(args.build_log)
        summary["binary_sha256"] = {name: digest(path) for name, path in binaries.items()}
        summary["source_sha256"] = {
            str(p.relative_to(ROOT)): digest(p) for p in [
                ROOT / "Cargo.lock", Path(__file__), ROOT / "aip-standalone/aip-observe/src/probe.rs",
                *(ROOT / "aip-standalone/aip-observe/tests" / (f + ".rs") for f in sorted(binaries)),
            ]
        }
        env = dict(os.environ, AIP_REQUIRE_LIVE="1", P0_048_LIVE_RETAIN_DIR=str(out / "originals"))
        for index, (family, name) in enumerate(CASES, 1):
            command = [str(binaries[family]), name, "--exact", "--nocapture", "--test-threads=1"]
            rc, raw, timeout, duration = execute(command, 45, env)
            logfile = out / f"{index:02}-{family}.log"
            logfile.write_bytes(raw)
            state, reason = classify(name, raw.decode(errors="replace"), rc, timeout)
            result = {"family": family, "test": name, "status": state, "reason": reason,
                      "command": command, "exit_code": rc, "timed_out": timeout,
                      "duration_seconds": duration, "log": logfile.name, "log_sha256": digest(logfile)}
            summary["cases"].append(result)
            print(json.dumps(result), flush=True)
        summary["verifier_sha256"] = digest(args.verifier)
        for label in ("t09", "t15"):
            directory = out / "originals" / label
            if not (directory / "scope-and-anchor.json").is_file():
                summary["offline_checks"].append({"case": label, "status": "BLOCKED", "reason": "live archive absent"})
                continue
            anchor = json.loads((directory / "scope-and-anchor.json").read_text())
            command = [str(args.verifier.resolve()), "--observer-id", anchor["observer_id"],
                       "--key-version", str(anchor["key_version"]), "--pubkey", bytes(anchor["public_key"]).hex(),
                       "--batches", str(directory / "batches.jsonl"), "--health", str(directory / "health.jsonl"), "--json"]
            rc, raw, timeout, duration = execute(command, 30, env)
            (out / f"{label}-offline.json").write_bytes(raw)
            summary["offline_checks"].append({"case": label, "command": command, "exit_code": rc,
                "status": "PASS" if rc == 0 and not timeout else "FAIL", "duration_seconds": duration,
                "scope": "Signature and supplied chain only; no independent administration or execution verdict"})
        if (len(summary["cases"]) == len(CASES) and all(c["status"] == "PASS" for c in summary["cases"])
                and len(summary["offline_checks"]) == 2 and all(c["status"] == "PASS" for c in summary["offline_checks"])):
            summary["status"] = "PASS"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (out / "SHA256SUMS").write_text("".join(
        digest(p) + "  " + str(p.relative_to(out)) + "\n"
        for p in sorted(out.rglob("*")) if p.is_file() and p.name != "SHA256SUMS"
    ))
    print(json.dumps({"status": summary["status"], "cases": len(summary["cases"])}), flush=True)
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
