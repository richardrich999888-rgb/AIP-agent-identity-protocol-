#!/usr/bin/env python3
"""Unprivileged control-flow regressions, NOT a demonstration rehearsal.

Run the real run.sh in a temporary tree with an allowlisted PATH. Cargo,
clock/privilege probes, the system run and gateway are fixtures. No repository
binary is built or executed; no service, clock, mount or kernel is touched.
"""

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


RUN_SH = Path(__file__).with_name("run.sh")
BASH = shutil.which("bash")
STUB = r'''
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["FIXTURE_CALLS"], "a") as log:
    log.write(json.dumps([name, args]) + "\n")

if name == "timedatectl":
    if args and args != ["show", "--property=NTPSynchronized", "--value"]:
        raise SystemExit(98)
    value = os.environ["FIXTURE_CLOCK"]
    # Also model the old human-readable query for before/after regression runs.
    print(value if args else "System clock synchronized: " + value, end="\n")
    if os.environ["FIXTURE_CLOCK_RC"] != "0":
        print("fixture clock query failed", file=sys.stderr)
    raise SystemExit(int(os.environ["FIXTURE_CLOCK_RC"]))
elif name == "pgrep":
    # A daemon is always 'running', even for an unsynchronised/unknown clock.
    raise SystemExit(0)
elif name == "cargo":
    if args[0] == "build" and "aip-probe" in args:
        print(os.environ["FIXTURE_BUILD_OUTPUT"], end="", file=sys.stderr)
        raise SystemExit(int(os.environ["FIXTURE_BUILD_RC"]))
    if args[0] == "build" and "aip-mcp-gateway" in args:
        raise SystemExit(int(os.environ["FIXTURE_GATEWAY_BUILD_RC"]))
    if args[0] == "test":
        print("test an_address_the_institution_never_named ... ok")
        print("test a_misparameterised_call_diverges ... ok")
    raise SystemExit(0)
elif name == "timeout":
    if args[0] == "900":
        if os.environ.get("AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK") != "1":
            raise SystemExit("RBI must enable the collector clock policy")
        output = Path(args[-1])
        output.mkdir(parents=True)
        control = os.environ["FIXTURE_CONTROL"]
        if control != "missing":
            (output / "health.A.control.jsonl").write_text(control + "\n")
        state = output / "work/state"
        state.mkdir(parents=True)
        start = 200 if os.environ["FIXTURE_BACKFILL"] == "1" else 400
        health = [
            {"state": "Active", "sequence": 2, "attested_coverage": {"from_ms": 200, "to_ms": 300}},
            {"state": "IntegrityUnknown", "sequence": 3, "attested_coverage": None},
            {"state": "Active", "sequence": 4, "attested_coverage": {"from_ms": start, "to_ms": 500}},
        ]
        (state / "health.archive.jsonl").write_text("".join(json.dumps({"health": h}) + "\n" for h in health))
        (state / "attested.archive.jsonl").write_text(json.dumps({
            "sequence": 3, "batch": {"claimed_from_ms": 300, "claimed_to_ms": 400},
        }) + "\n")
        print("PASS fixture system result -- not a live run")
        raise SystemExit(int(os.environ["FIXTURE_SYSTEM_RC"]))
    if args[0] == "30":
        # Deterministic receipt-shaped fixtures; no signature/crypto is tested.
        with open(os.environ["AIP_GATEWAY_RECEIPTS"], "w") as receipts:
            mode = os.environ["FIXTURE_RECEIPTS"]
            values = (1, 1) if mode == "equal" else (1, 2)
            if mode == "missing":
                values = (1,)
            for value in values:
                receipts.write(json.dumps({"receipt": {
                    "tool_id": "fixture.tool", "gateway_id": "fixture.gateway",
                    "parameter_commitment": [value] * 32,
                }}) + "\n")
            if mode == "malformed":
                receipts.write("not JSON\n")
        sys.stdin.read()
        raise SystemExit(int(os.environ["FIXTURE_GATEWAY_RC"]))
elif name == "python3":
    if args == ["-c", "import secrets;print(secrets.token_hex(32))"]:
        print("01" * 32)
        raise SystemExit(0)
    os.execv(sys.executable, [sys.executable] + args)
elif name == "id":
    print("0")  # Only the script's privilege precondition is simulated.
    raise SystemExit(0)
elif name == "git":
    print("TEST-FIXTURE-ONLY")
    raise SystemExit(0)
elif name == "date":
    print("2000-01-01T00:00:00Z")
    raise SystemExit(0)
elif name == "uname":
    print("fixture host -- not a demonstration machine")
    raise SystemExit(0)
elif name == "cat":
    if args == ["/sys/kernel/tracing/events/sched/sched_process_exec/id"]:
        print("123")
    else:
        os.execv(os.environ["FIXTURE_CAT"], ["cat"] + args)
    raise SystemExit(0)
# Never fall through to a real mount, service or other host command.
print("unexpected fixture command: " + name, file=sys.stderr)
raise SystemExit(99)
'''

# Intercept only the tracefs readability probe so the test does not inspect the
# host's tracing filesystem. All other [ expressions retain Bash semantics.
BASH_ENV = r'''
function [ {
  if [[ "$#" == 3 && "$1" == -r && "$2" == /sys/kernel/tracing/available_events && "$3" == ']' ]]; then
    return 0
  fi
  if [[ "$#" == 4 && "$1" == '!' && "$2" == -r && "$3" == /sys/kernel/tracing/available_events && "$4" == ']' ]]; then
    return 1
  fi
  builtin [ "$@"
}
'''


class RehearsalControlFlowTests(unittest.TestCase):
    def run_fixture(self, *, clock="yes", clock_rc=0, missing_clock=False,
                    build_rc=0, build_output="", skip=False, system_rc=0,
                    bad_build_log=False, gateway_build_rc=0, gateway_rc=0,
                    receipts="valid", control=None, pilot=False, quoted_path=False,
                    backfill=False):
        with tempfile.TemporaryDirectory(prefix="rbi-demo-test-") as tmp:
            root = Path(tmp)
            demo = root / "validation/rbi_demo"
            demo.mkdir(parents=True)
            shutil.copyfile(RUN_SH, demo / "run.sh")
            shutil.copyfile(RUN_SH.with_name("check_control.py"), demo / "check_control.py")
            script = demo / "run.sh"
            if pilot:
                script = root / "validation/pilot_e2e/run.sh"
                script.parent.mkdir()
                shutil.copyfile(RUN_SH.parent.parent / "pilot_e2e/run.sh", script)
            # A stale executable exists: failed builds must not reach any act.
            gateway = root / "target/debug/aip-mcp-gateway"
            gateway.parent.mkdir(parents=True)
            gateway.write_text("#!/bin/sh\nexit 99\n")
            gateway.chmod(0o755)

            commands = root / "bin"
            commands.mkdir()
            for name in ("bash", "dirname", "mkdir", "tee", "grep", "sed",
                         "tail", "head", "wc", "env"):
                executable = shutil.which(name)
                self.assertIsNotNone(executable, name)
                (commands / name).symlink_to(executable)
            dispatcher = commands / "fixture-command"
            dispatcher.write_text("#!" + sys.executable + "\n" + STUB)
            dispatcher.chmod(0o755)
            for name in ("timedatectl", "pgrep", "cargo", "timeout", "python3",
                         "id", "git", "date", "uname", "cat", "mount", "gcc"):
                if not (name == "timedatectl" and missing_clock):
                    (commands / name).symlink_to(dispatcher)
            shell_env = root / "shell-env"
            shell_env.write_text(BASH_ENV)
            calls = root / "calls.jsonl"
            out = root / ("reviewer's output" if quoted_path else "out")
            out.mkdir()
            if bad_build_log:
                (out / "build.log").mkdir()  # Deterministic redirection failure.
            env = {
                "PATH": str(commands), "LC_ALL": "C", "HOME": str(root),
                "BASH_ENV": str(shell_env), "AIP_DEMO_SKIP_SYSTEM": str(int(skip)),
                "FIXTURE_CALLS": str(calls), "FIXTURE_CLOCK": clock,
                "FIXTURE_CLOCK_RC": str(clock_rc),
                "FIXTURE_BUILD_RC": str(build_rc),
                "FIXTURE_BUILD_OUTPUT": build_output,
                "FIXTURE_SYSTEM_RC": str(system_rc),
                "FIXTURE_GATEWAY_BUILD_RC": str(gateway_build_rc),
                "FIXTURE_GATEWAY_RC": str(gateway_rc),
                "FIXTURE_RECEIPTS": receipts,
                "FIXTURE_BACKFILL": str(int(backfill)),
                "FIXTURE_CONTROL": control if control is not None else json.dumps({
                    "health": {"state": "Active", "attested_coverage": {"from_ms": 200, "to_ms": 300}}}),
                "FIXTURE_CAT": shutil.which("cat"),
            }
            result = subprocess.run(
                [BASH, str(script), str(out)], env=env,
                text=True, capture_output=True, timeout=20,
            )
            transcript = re.sub(r"\x1b\[[0-9;]*m", "", (out / "transcript.txt").read_text())
            invoked = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertNotIn("mount", [name for name, _ in invoked])
            build_log = "" if bad_build_log else (out / "build.log").read_text()
            clock_log = (out / "clock.log").read_text() if (out / "clock.log").exists() else ""
            return result.returncode, transcript, invoked, build_log, clock_log

    def assert_not_rehearsed(self, result):
        self.assertNotEqual(result[0], 0, result[1])
        self.assertNotIn("REHEARSED: all five", result[1])

    def test_synchronised_clock_can_pass_with_all_simulated_acts(self):
        result = self.run_fixture()
        self.assertEqual(result[0], 0, result[1])
        self.assertIn("PASS clock: synchronised", result[1])
        self.assertIn("REHEARSED: all five", result[1])
        self.assertIn(["timedatectl", ["show", "--property=NTPSynchronized", "--value"]], result[2])
        self.assertIn("NTPSynchronized=yes", result[4])

    def test_unsynchronised_clock_fails_despite_running_daemon(self):
        result = self.run_fixture(clock="no")
        self.assert_not_rehearsed(result)
        self.assertIn("clock: unsynchronised", result[1])
        self.assertIn("1 check(s) failed; system run: pass", result[1])
        self.assertNotIn("PASS clock:", result[1])

    def test_unknown_clock_values_fail_despite_running_daemon(self):
        for value in ("", "unknown", "maybe", "yes please", "yes\nno"):
            with self.subTest(value=value):
                result = self.run_fixture(clock=value)
                self.assert_not_rehearsed(result)
                self.assertIn("clock: unknown", result[1])
                self.assertNotIn("PASS clock:", result[1])

    def test_missing_clock_query_fails_despite_running_daemon(self):
        result = self.run_fixture(missing_clock=True)
        self.assert_not_rehearsed(result)
        self.assertIn("clock: unknown", result[1])
        self.assertIn("timedatectl is missing", result[1])

    def test_failed_clock_query_cannot_pass_even_if_it_prints_yes(self):
        result = self.run_fixture(clock="yes", clock_rc=1)
        self.assert_not_rehearsed(result)
        self.assertIn("clock: unknown", result[1])
        self.assertIn("fixture clock query failed", result[4])

    def test_failed_build_stops_before_acts_regardless_of_diagnostics(self):
        for output in ("error: simulated compiler failure\n", "linker failed\n",
                       "", "\x1b[31merror:\x1b[0m coloured diagnostic\n"):
            with self.subTest(output=output):
                result = self.run_fixture(build_rc=101, build_output=output)
                self.assert_not_rehearsed(result)
                self.assertIn("FAIL build failed (exit 101)", result[1])
                self.assertNotIn("daemons and offline verifier built", result[1])
                self.assertFalse(any(name == "timeout" for name, _ in result[2]))
                cargo_calls = [args for name, args in result[2] if name == "cargo"]
                self.assertEqual(len(cargo_calls), 1, cargo_calls)
                self.assertEqual(result[3], output)

    def test_successful_build_is_not_rejected_for_error_shaped_log_text(self):
        output = "error: fixture text with a successful command status\n"
        result = self.run_fixture(build_output=output)
        self.assertEqual(result[0], 0, result[1])
        self.assertIn("PASS daemons and offline verifier built", result[1])
        self.assertEqual(result[3], output)

    def test_unwritable_build_log_cannot_report_built(self):
        result = self.run_fixture(bad_build_log=True)
        self.assert_not_rehearsed(result)
        self.assertIn("FAIL build failed", result[1])
        self.assertNotIn("daemons and offline verifier built", result[1])
        self.assertFalse(any(name == "cargo" for name, _ in result[2]))

    def test_explicit_skip_is_never_a_successful_rehearsal(self):
        result = self.run_fixture(skip=True)
        self.assert_not_rehearsed(result)
        self.assertIn("SKIPPED by request (AIP_DEMO_SKIP_SYSTEM=1)", result[1])
        self.assertEqual(result[1].count("skipped (full system)"), 3)
        self.assertIn("0 check(s) failed; system run: skipped", result[1])
        self.assertFalse(any(name == "timeout" and args[0] == "900"
                             for name, args in result[2]))

    def test_failed_system_run_cannot_be_hidden_by_other_passing_checks(self):
        result = self.run_fixture(system_rc=1)
        self.assert_not_rehearsed(result)
        self.assertIn("1 check(s) failed; system run: fail", result[1])
        self.assertEqual(result[1].count("fail (full system)"), 3)

    def test_pilot_build_failure_stops_before_compiling_interferer(self):
        result = self.run_fixture(pilot=True, build_rc=101, build_output="error: compiler failed\n")
        self.assert_not_rehearsed(result)
        self.assertIn("FAIL build failed (exit 101)", result[1])
        self.assertFalse(any(name in ("gcc", "timeout") for name, _ in result[2]))

    def test_gateway_build_failure_never_uses_stale_executable(self):
        result = self.run_fixture(gateway_build_rc=101)
        self.assert_not_rehearsed(result)
        self.assertIn("gateway build failed (exit 101)", result[1])
        self.assertNotIn("PASS Act 4b:", result[1])
        self.assertFalse(any(name == "timeout" and args[0] == "30" for name, args in result[2]))

    def test_gateway_failure_after_writing_receipts_is_not_a_pass(self):
        for rc in (1, 124):
            with self.subTest(rc=rc):
                result = self.run_fixture(gateway_rc=rc)
                self.assert_not_rehearsed(result)
                self.assertNotIn("PASS Act 4b:", result[1])

    def test_bad_gateway_receipts_are_not_a_pass(self):
        for mode in ("equal", "missing", "malformed"):
            with self.subTest(mode=mode):
                result = self.run_fixture(receipts=mode)
                self.assert_not_rehearsed(result)
                self.assertNotIn("PASS Act 4b:", result[1])

    def test_generic_pilot_success_requires_stronger_rbi_control_evidence(self):
        for control in ("missing", "not JSON", "", "[]",
                        json.dumps({"health": {"state": "Degraded", "attested_coverage": {"fixture": True}}}),
                        json.dumps({"health": {"state": "Active", "attested_coverage": None}})):
            with self.subTest(control=control):
                result = self.run_fixture(control=control)
                self.assert_not_rehearsed(result)
                self.assertNotIn("PASS Act 1 honest path:", result[1])

    def test_quoted_output_path_is_not_interpolated_as_python_code(self):
        result = self.run_fixture(quoted_path=True)
        self.assertEqual(result[0], 0, result[1])
        self.assertIn("1 checks passed in the system run", result[1])

    def test_recovery_cannot_backfill_the_blinded_interval(self):
        result = self.run_fixture(backfill=True)
        self.assert_not_rehearsed(result)
        self.assertIn("1 check(s) failed; system run: fail", result[1])
        self.assertNotIn("PASS Act 1 honest path:", result[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
