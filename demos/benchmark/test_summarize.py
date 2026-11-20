"""summarize.py recomputes the recorded figures; these pin what the files say.

If a result file under research/capability-learning/results changes, these
fail, so REPRODUCE.md can never silently drift from the evidence.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from summarize import summarize

ROOT = Path(__file__).resolve().parents[2]
EXPECT = {  # system: (correct/40, decision correct/32, paired delta, bootstrap CI)
    "B1": (11, 3, -0.650, [-0.800, -0.500]),
    "B2": (12, 4, -0.625, [-0.800, -0.450]),
    "B3": (13, 5, -0.600, [-0.775, -0.425]),
    "B4": (8, 0, -0.725, [-0.850, -0.575]),
}


class Recorded(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = summarize(ROOT)

    def test_table_figures(self):
        for name, (c, d, delta, ci) in EXPECT.items():
            r = self.s["systems"][name]
            self.assertEqual((r["correct"], r["decision_correct_of_32"]), (c, d), name)
            self.assertAlmostEqual(r["paired_delta_vs_candidate"], delta, places=3)
            self.assertEqual(r["bootstrap_95ci"], ci, name)
        cand = self.s["systems"]["candidate"]
        self.assertEqual((cand["correct"], cand["decision_correct_of_32"], cand["false_activation"]), (37, 29, 0))

    def test_candidate_cpu_is_not_the_capability_path_figure(self):
        # The whole-benchmark figure includes the 8 probes the model answers.
        self.assertEqual(self.s["systems"]["candidate"]["cpu_s_per_task"], 3.05)
        self.assertEqual(self.s["candidate_items_with_zero_model_calls"], 32)

    def test_unpaired_items_are_refused(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            src = ROOT / "research/capability-learning/results"
            dst = tmp / "research/capability-learning/results"
            shutil.copytree(src / "run1", dst / "run1", ignore=shutil.ignore_patterns("evidence"))
            shutil.copytree(src / "baselines_q8", dst / "baselines_q8")
            b1 = dst / "baselines_q8/B1.jsonl"
            rows = [json.loads(l) for l in b1.read_text().splitlines()]
            rows[0]["id"] = "renamed"
            b1.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            with self.assertRaises(SystemExit):
                summarize(tmp)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
