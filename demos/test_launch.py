"""launch.py: readiness is reported honestly, and rehearsals count only consecutive passes."""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import launch  # noqa: E402


def fake(rcs):
    """A ready mode whose successive runs exit with the given codes."""
    it = iter(rcs)
    return {"title": "fake", "ready": lambda: None, "repos": lambda: [],
            "cmd": lambda out: [sys.executable, "-c", f"import sys; sys.exit({next(it)})"]}


class Readiness(unittest.TestCase):
    def test_every_mode_is_listed_with_a_reason_when_not_ready(self):
        rows = {r["mode"]: r for r in launch.check()}
        self.assertEqual(set(rows), {"security", "pq", "quantum", "investor-3min", "teach", "customer-<sector>"})
        for r in rows.values():
            self.assertTrue(r["ready"] or r["reason"], r)

    def test_teach_and_model_modes_are_not_ready(self):
        for m in ("teach", "investor-3min", "customer-energy"):
            with redirect_stdout(io.StringIO()) as o:
                rc, path = launch.run(m, Path(tempfile.mkdtemp()))
            self.assertEqual((rc, path), (launch.NOT_READY, None), m)
            self.assertIn("NOT READY", o.getvalue())

    def test_unknown_mode_is_an_error_not_a_pass(self):
        self.assertEqual(launch.run("nonsense", Path(tempfile.mkdtemp()))[0], 2)
        self.assertIsNone(launch.mode_spec("customer-"))


class Runs(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "REHEARSAL_LOG.md"

    def go(self, rcs, n):
        with mock.patch.dict(launch.MODES, {"fake": fake(rcs)}), mock.patch.object(launch, "LOG", self.log), \
                redirect_stdout(io.StringIO()):
            return launch.rehearse("fake", n, self.tmp / "out")

    def test_result_file_is_labelled_live_and_records_the_exit(self):
        with mock.patch.dict(launch.MODES, {"fake": fake([1])}), redirect_stdout(io.StringIO()):
            rc, path = launch.run("fake", self.tmp)
        r = json.loads(path.read_text())
        self.assertEqual(rc, 1)
        self.assertEqual(r["steps"][0]["kind"], "live")
        self.assertEqual((r["measurements"]["exit_code"], r["measurements"]["passed"]), (1, False))

    def test_all_passes(self):
        self.assertEqual(self.go([0, 0, 0], 3), 0)
        self.assertIn("| fake | 3/3 consecutive | PASS |", self.log.read_text())

    def test_a_failure_stops_the_rehearsal_and_is_logged(self):
        self.assertEqual(self.go([0, 1, 0], 3), 1)
        self.assertIn("1/3 consecutive | FAIL at run 2", self.log.read_text())
        self.assertFalse((self.tmp / "out/03").exists())


if __name__ == "__main__":
    unittest.main()
