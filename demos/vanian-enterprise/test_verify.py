"""Unit tests for verify.py: a failed or missing check is FAIL, never PARTIAL."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import verify as v

GOOD = {
    "policy": "PASS: 17/17\n",
    "server-suite": "Ran 70 tests in 4.9s\n\nOK\n",
    "litellm-acceptance": "checks: 16 passed, 0 failed\n",
    "revocation-gap": "test result: ok. 3 passed; 0 failed\n",
    "live-sensors": "test result: ok. 6 passed; 0 failed\n",
}


def lab(tmp: Path, logs: dict, kill: dict | None, shadow: dict | None = None) -> Path:
    for name, text in logs.items():
        (tmp / f"test-{name}.log").write_text(text)
    for run, checks in (("live-kill", kill), ("live-shadow", shadow if shadow is not None else kill)):
        if checks is not None:
            (tmp / f"{run}-latest").mkdir()
            (tmp / f"{run}-latest" / "result.json").write_text(json.dumps({"checks": checks}))
    return tmp


def run(runs: Path) -> tuple[int, dict]:
    with contextlib.redirect_stdout(io.StringIO()):
        code = v.main(runs)
    s = json.loads((runs / "verify-summary.json").read_text())
    return code, {c["capability"].split()[0]: c["status"] for c in s["capabilities"]}


class Verify(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_all_good_is_partial_not_verified(self):
        code, st = run(lab(self.tmp, GOOD, {"a": True}))
        self.assertEqual(code, 1)
        self.assertEqual((st["2"], st["6"], st["8"], st["10"], st["1"], st["7"]),
                         ("PARTIAL", "PARTIAL", "PARTIAL", "PARTIAL", "NOT_AVAILABLE", "NOT_IMPLEMENTED"))
        self.assertNotIn("VERIFIED", st.values())

    def test_failed_policy_is_fail(self):
        code, st = run(lab(self.tmp, {**GOOD, "policy": "FAIL: 1/17\n"}, {"a": True}))
        self.assertEqual(st["6"], "FAIL")

    def test_skipped_server_suite_is_fail(self):
        _, st = run(lab(self.tmp, {**GOOD, "server-suite": "OK (skipped=9)\n"}, {"a": True}))
        self.assertEqual((st["6"], st["8"], st["10"], st["12"]), ("FAIL",) * 4)

    def test_failed_kill_check_is_fail(self):
        _, st = run(lab(self.tmp, GOOD, {"a": True, "b": False}))
        self.assertEqual(st["8"], "FAIL")

    def test_failed_shadow_check_is_fail(self):
        _, st = run(lab(self.tmp, GOOD, {"a": True}, shadow={"a": False}))
        self.assertEqual((st["2"], st["8"]), ("FAIL", "PARTIAL"))

    def test_missing_runs_are_fail(self):
        _, st = run(lab(self.tmp, {}, None))
        self.assertEqual((st["2"], st["6"], st["8"], st["10"], st["11"], st["12"]), ("FAIL",) * 6)

    def test_acceptance_count_must_match(self):
        _, st = run(lab(self.tmp, {**GOOD, "litellm-acceptance": "checks: 15 passed, 1 failed\n"}, {"a": True}))
        self.assertEqual(st["10"], "FAIL")


if __name__ == "__main__":
    unittest.main()
