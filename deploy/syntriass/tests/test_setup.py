#!/usr/bin/env python3
"""Tests for the dataset step and the environment installer (X6, X7).

X6: `.gitignore` carries a blanket `*.jsonl`, so the sidecar's seeded training
data is absent on a fresh clone and the failure surfaced several layers away
as "sidecar reply missing or oversized". The fix regenerates and proves the
result byte-identical to the digests pinned in the tracked MANIFEST.json.

X7: the documented requirement was "Python >= 3.10 with numpy", but
methods/extractors.py imports sklearn lazily, so the real requirement only
showed up at sidecar startup. The lock pins the full set with hashes.

The property these tests exist to protect: a dataset that does not match its
pinned digest is REFUSED, not accepted with a warning, because a measurement
taken on a different dataset is not comparable to the published figures.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERIFY = ROOT / "deploy/syntriass/verify_datasets.py"
SETUP = ROOT / "deploy/syntriass/setup_env.sh"
LOCK = ROOT / "deploy/syntriass/requirements.lock"
DATASET = ROOT / "research/system-one/data/maintenance-priority-v2"

EXIT_OK, EXIT_USAGE, EXIT_MISSING, EXIT_MISMATCH = 0, 2, 3, 4


def verify(*args):
    return subprocess.run([sys.executable, "-I", str(VERIFY), *args],
                          capture_output=True, text=True, timeout=900, cwd=ROOT)


class DatasetVerification(unittest.TestCase):
    """Runs against the real dataset. Restores whatever it disturbs."""

    def setUp(self):
        self.saved = {}
        for path in DATASET.glob("*.jsonl"):
            self.saved[path] = path.read_bytes()

    def tearDown(self):
        for path in DATASET.glob("*.jsonl"):
            if path not in self.saved:
                path.unlink()
        for path, data in self.saved.items():
            path.write_bytes(data)

    def test_check_passes_when_every_split_matches(self):
        if not self.saved:
            self.skipTest("dataset not generated; run verify_datasets.py --generate")
        result = verify("--check")
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("splits match their pinned digests", result.stdout)

    def test_an_absent_dataset_exits_missing_and_names_the_remedy(self):
        for path in DATASET.glob("*.jsonl"):
            path.unlink()
        result = verify("--check")
        self.assertEqual(result.returncode, EXIT_MISSING)
        self.assertIn("setup_env.sh", result.stderr)
        self.assertIn("--generate", result.stderr)

    def test_a_corrupted_split_is_refused_not_warned_about(self):
        """The decisive property. One flipped byte must stop the step."""
        if not self.saved:
            self.skipTest("dataset not generated")
        target = DATASET / "train.jsonl"
        target.write_bytes(b'{"id":"tampered"}\n')
        result = verify("--check")
        self.assertEqual(result.returncode, EXIT_MISMATCH)
        self.assertIn("DIFFERENT dataset", result.stderr)
        self.assertNotIn("warning", result.stderr.lower())

    def test_the_failure_message_shows_pinned_and_actual(self):
        if not self.saved:
            self.skipTest("dataset not generated")
        (DATASET / "val.jsonl").write_bytes(b"corrupt\n")
        result = verify("--check")
        self.assertIn("pinned:", result.stderr)
        self.assertIn("actual:", result.stderr)

    def test_generate_repairs_a_corrupted_split_and_then_matches(self):
        if not self.saved:
            self.skipTest("dataset not generated")
        (DATASET / "train.jsonl").write_bytes(b"corrupt\n")
        result = verify("--generate")
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("regenerating", result.stdout)

    def test_regeneration_is_byte_identical_to_the_pinned_digests(self):
        """Why committing the data is unnecessary: the seed reproduces it."""
        for path in DATASET.glob("*.jsonl"):
            path.unlink()
        self.assertEqual(verify("--generate").returncode, EXIT_OK)
        tracked = json.loads(subprocess.run(
            ["git", "show",
             "HEAD:research/system-one/data/maintenance-priority-v2/MANIFEST.json"],
            cwd=ROOT, capture_output=True, text=True, timeout=60).stdout)
        import hashlib
        for split, expected in tracked["files"].items():
            actual = hashlib.sha256((DATASET / f"{split}.jsonl").read_bytes()).hexdigest()
            self.assertEqual(actual, expected, split)

    def test_check_and_generate_are_mutually_exclusive(self):
        self.assertNotEqual(verify("--check", "--generate").returncode, EXIT_OK)


class PinnedDigestsComeFromGitNotTheWorkingTree(unittest.TestCase):
    def test_the_comparison_reads_the_tracked_manifest(self):
        """A regenerated run rewrites MANIFEST.json, so comparing against the
        on-disk copy would compare a file with itself and always pass."""
        source = VERIFY.read_text()
        self.assertIn('"git", "show"', source)
        self.assertIn("HEAD:", source)


class RequirementsLock(unittest.TestCase):
    def test_every_pinned_package_carries_a_sha256(self):
        text = LOCK.read_text()
        pins = re.findall(r"^([A-Za-z0-9_.-]+)==", text, re.M)
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", text)
        self.assertTrue(pins)
        self.assertEqual(len(pins), len(hashes),
                         "every pin needs a hash or --require-hashes refuses the set")

    def test_the_three_direct_requirements_are_pinned(self):
        text = LOCK.read_text()
        for package in ("numpy==", "scikit-learn==", "pytest=="):
            self.assertIn(package, text)

    def test_fastembed_is_excluded_and_the_reason_is_recorded(self):
        """It would fetch a model from Hugging Face at first use, so it cannot
        be part of an offline path."""
        text = LOCK.read_text()
        self.assertNotIn("fastembed==", text)
        self.assertIn("fastembed", text)
        self.assertIn("Hugging Face", text)

    def test_the_platform_assumption_is_stated(self):
        self.assertIn("cp311", LOCK.read_text())


class SetupScript(unittest.TestCase):
    def test_it_is_executable_and_syntactically_valid(self):
        self.assertTrue(os.access(SETUP, os.X_OK))
        self.assertEqual(
            subprocess.run(["bash", "-n", str(SETUP)], capture_output=True).returncode, 0)

    def test_it_requires_hashes(self):
        """Installing without --require-hashes would make the lock decorative."""
        text = SETUP.read_text()
        self.assertIn("--require-hashes", text)
        self.assertEqual(text.count("pip install"), text.count("--require-hashes"))

    def test_it_prefers_the_bundle_wheels_over_pypi(self):
        text = SETUP.read_text()
        self.assertIn("--no-index", text)
        self.assertLess(text.index("--no-index"), text.index("falling back to PyPI"))

    def test_it_installs_into_a_venv_by_default(self):
        """Installing system-wide fails on a distribution-managed package that
        ships no RECORD file; observed with `packaging`."""
        text = SETUP.read_text()
        self.assertIn("-m venv", text)
        self.assertIn("RECORD", text)

    def test_an_unknown_argument_is_refused(self):
        result = subprocess.run(["bash", str(SETUP), "--nonsense"],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 2)

    def test_it_runs_the_dataset_step_unless_told_not_to(self):
        text = SETUP.read_text()
        self.assertIn("verify_datasets.py", text)
        self.assertIn("--skip-data", text)


class DocumentedRequirementMatchesReality(unittest.TestCase):
    def test_the_readme_no_longer_says_only_numpy(self):
        readme = (ROOT / "deploy/syntriass/README.md").read_text()
        row = next(line for line in readme.splitlines()
                   if line.startswith("| Python |"))
        self.assertIn("scikit-learn", row)
        self.assertIn("requirements.lock", row)

    def test_the_readme_documents_the_setup_entry_points(self):
        readme = (ROOT / "deploy/syntriass/README.md").read_text()
        self.assertIn("setup_env.sh", readme)
        self.assertIn("verify_datasets.py", readme)

    def test_the_sidecar_names_the_file_and_the_command(self):
        source = (ROOT / "research/system-one/harness/sidecar.py").read_text()
        self.assertIn("setup_env.sh", source)
        self.assertIn("verify_datasets.py", source)
        self.assertIn("missing file:", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
