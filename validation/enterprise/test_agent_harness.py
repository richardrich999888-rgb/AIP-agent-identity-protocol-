#!/usr/bin/env python3
"""Exercise the real harness's build block with controlled Cargo outcomes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "integrations/agents/run.sh").read_text()
BUILD_BLOCK = SCRIPT.split('step "Build the daemons and the offline verifier"', 1)[1].split('W="$OUT/work"', 1)[0]


class AgentHarnessBuild(unittest.TestCase):
    def run_build(self, status, diagnostic, stale=False):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            fake_bin = work / "fake-bin"
            fake_bin.mkdir()
            (work / "target/debug").mkdir(parents=True)
            if stale or status == 0:
                for name in ("aip-probe", "aip-collector", "aip-observe-verify", "aip-lineage"):
                    path = work / "target/debug" / name
                    path.write_text("fixture binary\n")
                    path.chmod(0o755)
            cargo = fake_bin / "cargo"
            cargo.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$REPO/cargo-args\"\n"
                "printf '%s\\n' \"$TEST_DIAGNOSTIC\" >&2\nexit \"$TEST_CARGO_STATUS\"\n")
            cargo.chmod(0o755)
            env = dict(os.environ, REPO=str(work), OUT=str(work),
                TEST_CARGO_STATUS=str(status), TEST_DIAGNOSTIC=diagnostic,
                PATH=str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))
            functions = "set -uo pipefail\nstep() { :; }\nok() { echo \"PASS: $*\"; }\ndie() { echo \"FAIL: $*\"; exit 1; }\n"
            result = subprocess.run([shutil.which("bash"), "-s"], input=functions + BUILD_BLOCK,
                capture_output=True, text=True, env=env, check=False)
            return result, (work / "build.log").read_text(), (work / "cargo-args").read_text().splitlines()

    def test_failed_builds_never_pass_with_stale_binaries_or_unusual_diagnostics(self):
        for diagnostic in ("", "fatal: dependency unavailable", "\x1b[31merror\x1b[0m: dependency failed"):
            with self.subTest(diagnostic=diagnostic):
                result, _, _ = self.run_build(101, diagnostic, stale=True)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("PASS:", result.stdout)

    def test_success_is_decided_by_exit_status_and_selects_all_real_binaries(self):
        result, log, args = self.run_build(0, "error: this is only test text")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS:", result.stdout)
        self.assertIn("error: this is only test text", log)
        self.assertIn("--locked", args)
        for name in ("aip-probe", "aip-collector", "aip-observe-verify", "aip-reconcile"):
            self.assertIn(["-p", name], [args[i:i + 2] for i in range(len(args) - 1)])
        for name in ("aip-probe", "aip-collector", "aip-observe-verify", "aip-lineage"):
            self.assertIn(["--bin", name], [args[i:i + 2] for i in range(len(args) - 1)])

    def test_default_clock_policy_and_writer_shutdown_are_preserved(self):
        self.assertIn("AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=1", SCRIPT)
        self.assertNotIn("AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0", SCRIPT)
        verify_position = SCRIPT.index('step "Verify the archive OFFLINE')
        self.assertLess(SCRIPT.index('wait "$PROBE_PID"'), verify_position)
        self.assertLess(SCRIPT.index('wait "$COLLECTOR_PID"'), verify_position)


if __name__ == "__main__":
    unittest.main(verbosity=2)
