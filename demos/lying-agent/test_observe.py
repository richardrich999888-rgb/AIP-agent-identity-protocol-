#!/usr/bin/env python3
"""Tests for the W2.2 observation, verdict and screen.

Run: python3 -m unittest discover -s demos/lying-agent -p 'test_*.py'
The live test needs root, the release binaries, tracefs and auditd; without
them it is SKIPPED with the reason, never passed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import observe  # noqa: E402
import show  # noqa: E402


def live_unavailable() -> str | None:
    if os.geteuid() != 0:
        return "needs root (kernel sensors, auditctl)"
    for b in ("aip-probe", "aip-collector", "aip-observe-verify"):
        if not (REPO / "target/release" / b).exists():
            return f"target/release/{b} not built"
    if not shutil.which("auditctl"):
        return "auditd not installed"
    st = subprocess.run(["auditctl", "-s"], capture_output=True, text=True).stdout
    if "enabled 1" not in st and "pid 0" in st:
        return "auditd daemon not running"
    return None


LIVE_SKIP = live_unavailable()


class Units(unittest.TestCase):
    def test_self_log_search_reads_text_not_numbers(self):
        log = [{"ts_ms": 1793963039301, "pid": 9, "step": "read input", "file": "/r/invoice.txt"}]
        self.assertFalse(observe.self_log_mentions(log, ["127.0.0.1:39301", ":39301"]))
        self.assertTrue(observe.self_log_mentions(log + [{"step": "x", "note": "sent to 127.0.0.1:39301"}],
                                                  ["127.0.0.1:39301"]))

    def test_tamper_changes_exactly_one_signed_field(self):
        rec = {"sequence": 3, "batch": {"kernel_events": [
            {"kind": {"SocketState": {"remote": {"addr": [127, 0, 0, 1], "port": 41697}, "new_state": 2}}}]}}
        with tempfile.TemporaryDirectory() as t:
            src, dst = Path(t) / "a.jsonl", Path(t) / "b.jsonl"
            src.write_text(json.dumps(rec) + "\n")
            what = observe.tamper_signed_byte(src, dst, 3, 0)
            self.assertEqual(what, "batch 3 event 0: remote port 41697 -> 41698")
            changed = json.loads(dst.read_text())
            rec["batch"]["kernel_events"][0]["kind"]["SocketState"]["remote"]["port"] = 41698
            self.assertEqual(changed, rec)
            with self.assertRaises(ValueError):
                observe.tamper_signed_byte(src, dst, 99, 0)

    def _result(self, detected: bool, verified=True, tampered_verified=False) -> dict:
        return {"hardware": {"label": "4 vCPU, 15 GB RAM, no GPU"}, "measurements": {
            "require_synced_clock": "1",
            "agent": {"pid": 7, "pid_source": "demo harness (process launch)", "self_log_steps": ["start", "done"],
                      "self_log_mentions_undeclared_action": False},
            "sniffer_dog": {"connect_detected": detected, "connect_events": [
                {"remote": "127.0.0.1:5", "bound_pid": 7, "bound_start_ticks": 1, "bound_exe_sha256": "ab" * 32,
                 "batch_sequence": 2, "index": 0, "mechanism": "SockStateTracepoint"}] if detected else [],
                "file_detected": False, "file_events": []},
            "auditd": {"available": True, "connect_seen": detected, "connect_pids": ["7"] if detected else [],
                       "file_seen": False},
            "offline_verification": {"verified": verified,
                                     "tamper": {"performed": detected, "change": "c", "verified": tampered_verified}},
            "ground_truth": {"undeclared_action_happened": detected}}}

    def test_screen_says_only_what_the_result_says(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "r.json"
            p.write_text(json.dumps(self._result(False)))
            s = show.render(p)
            self.assertIn("connect: NOT DETECTED", s)
            self.assertNotIn("CONNECT to", s)
            self.assertIn(str(p), s)
            p.write_text(json.dumps(self._result(True)))
            s = show.render(p)
            self.assertIn("CONNECT to 127.0.0.1:5", s)
            self.assertIn("REJECTED", s)
            p.write_text(json.dumps(self._result(True, tampered_verified=True)))
            self.assertIn("still VERIFIED — PROBLEM", show.render(p))
            self.assertIn("scripted test agent", show.render(p))


@unittest.skipIf(LIVE_SKIP is not None, f"SKIPPED, not passed: {LIVE_SKIP}")
class Live(unittest.TestCase):
    """The real pipeline: probe (no key) → collector (sole key), auditd, agent."""

    def run_mode(self, mode: str, out: Path) -> dict:
        env = dict(os.environ, AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=os.environ.get(
            "AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK", "0"))
        p = subprocess.run([sys.executable, str(HERE / "observe.py"), str(out), "--mode", mode],
                           capture_output=True, text=True, timeout=300, env=env)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        return json.loads(p.stdout)

    def test_lying_run_is_caught_and_honest_run_is_not(self):
        with tempfile.TemporaryDirectory() as t:
            lying = self.run_mode("lying", Path(t) / "a")
            honest = self.run_mode("honest", Path(t) / "b")
        sd = lying["sniffer_dog"]
        self.assertTrue(lying["ground_truth"]["undeclared_action_happened"])
        self.assertFalse(lying["agent"]["self_log_mentions_undeclared_action"])
        self.assertTrue(sd["connect_detected"])
        self.assertTrue(all(c["bound_pid"] == lying["agent"]["pid"] for c in sd["connect_events"]))
        self.assertTrue(lying["auditd"]["connect_seen"])
        self.assertIn(str(lying["agent"]["pid"]), lying["auditd"]["connect_pids"])
        self.assertTrue(lying["offline_verification"]["verified"])
        self.assertTrue(lying["offline_verification"]["tamper"]["performed"])
        self.assertFalse(lying["offline_verification"]["tamper"]["verified"])
        # The negative control: nothing undeclared happened, nothing is reported.
        self.assertFalse(honest["ground_truth"]["undeclared_action_happened"])
        self.assertFalse(honest["sniffer_dog"]["connect_detected"])
        self.assertFalse(honest["sniffer_dog"]["file_detected"])
        self.assertFalse(honest["auditd"]["connect_seen"])
        self.assertTrue(honest["offline_verification"]["verified"])


if __name__ == "__main__":
    unittest.main()
