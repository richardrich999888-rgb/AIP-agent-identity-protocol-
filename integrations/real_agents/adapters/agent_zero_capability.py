#!/usr/bin/env python3
"""Real framework/tool preflight in its own disposable context, never AIP proof."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from agent_zero_runtime import configure, REVIEWED_PROFILE
from launch import DiagnosticJournal, run_logged_task

MAX_TIMEOUT = 240
MAX_RESULT_BYTES = 65536


def read_regular_json(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RESULT_BYTES:
        raise ValueError("capability data must be a bounded regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        actual = os.fstat(stream.fileno())
        if not stat.S_ISREG(actual.st_mode) or (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino):
            raise ValueError("capability data changed before reading")
        raw = stream.read(MAX_RESULT_BYTES + 1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError("capability data exceeds its bound")
    return raw, json.loads(raw)


def assess_result(challenge, result_path, response, log_items):
    raw, result = read_regular_json(result_path)
    expected = {"capability_id": challenge["capability_id"],
                "sum": challenge["left"] + challenge["right"]}
    if (type(result) is not dict or set(result) != set(expected) or
            type(result.get("sum")) is not int or result != expected):
        raise ValueError("actual capability file does not match the independent challenge")
    code_items = [item for item in log_items if item.get("type") == "code_exe"
                  and isinstance(item.get("kvps"), dict)
                  and item["kvps"].get("runtime") in ("python", "terminal", "nodejs")
                  and isinstance(item["kvps"].get("code"), str)
                  and item["kvps"]["code"].strip()]
    if not code_items:
        raise ValueError("framework did not record an actual code-execution tool operation")
    if not isinstance(response, str) or challenge["capability_id"] not in response or str(expected["sum"]) not in response:
        raise ValueError("actual final response does not contain the challenge result")
    return {"status": "PASS", "framework_code_operations": len(code_items),
            "output_sha256": hashlib.sha256(raw).hexdigest(),
            "final_response_matches_challenge": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=MAX_TIMEOUT)
    args = parser.parse_args()
    if not 1 <= args.timeout <= MAX_TIMEOUT:
        raise ValueError("invalid bounded capability timeout")
    config = json.loads(args.config.read_text())
    if config.get("reviewed_profile") != REVIEWED_PROFILE:
        raise ValueError("capability requires the explicit reviewed Tiny Local profile")
    _, challenge = read_regular_json(args.challenge)
    if (set(challenge) != {"capability_id", "left", "right"} or
            type(challenge["capability_id"]) is not str or
            not 1 <= len(challenge["capability_id"]) <= 64 or
            any(type(challenge[k]) is not int for k in ("left", "right"))):
        raise ValueError("invalid public capability challenge")
    report = {"classification": "REAL_FRAMEWORK_CODE_FINAL_RESPONSE_CAPABILITY_ONLY",
              "source_authority": "readonly_launcher_and_framework_application_log",
              "status": "FAIL", "independent_kernel_observation": False,
              "business_task_acceptance": False, "software_patch_acceptance": False,
              "timeout_s": args.timeout, "separate_context_and_container": True}
    for path in (os.environ["HOME"], "/tmp/framework", "/tmp/framework-logs"):
        Path(path).mkdir(parents=True, exist_ok=True)
    configurations = []
    context = None
    # Upstream prints live messages. Retain only this explicitly bounded,
    # non-secret protocol summary, never unrestricted stdout/environment.
    with DiagnosticJournal("/work/capability-adapter.jsonl") as journal:
        journal.emit("capability_configure_started", {})
        def configured(value):
            configurations.append(value)
            journal.emit("configuration_verified", value)
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            try:
                context = configure(config, config["preset"]["chat"]["name"], on_configured=configured)
                journal.emit("capability_configure_ready", {})
                from agent import UserMessage
                prompt = (
                    "Perform this harmless capability check using your available code tool. "
                    "Read the public JSON file " + str(args.challenge) + ". Add its integer left and right values. "
                    "Write /work/capability-result.json with exactly capability_id copied from the input "
                    "and sum as the calculated integer. Do not access any other service or delegate. "
                    "Then provide a final response containing the capability_id and calculated sum. "
                    "This is a preflight test, not the later business task. No result file has been supplied.")
                response = run_logged_task(context, UserMessage(prompt), args.timeout, journal,
                                           os.environ.get("FRAMEWORK_COMMIT", "UNSPECIFIED"))
                # Actual pinned public snapshot, with live/non-atomic semantics.
                items = context.log.output().items
                report.update(assess_result(challenge, "/work/capability-result.json", response, items))
            except Exception as error:
                report["failure_type"] = type(error).__name__
                journal.emit("capability_failed", {"exception_type": type(error).__name__})
            finally:
                if context is not None:
                    context.kill_process()
    report["configuration_checks"] = configurations
    print(json.dumps(report, allow_nan=False))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
