#!/usr/bin/env python3
"""Regression tests for enterprise-client-readback diagnostics.

Motivating failure: GitHub Actions run 40825279520 on commit 35f215d failed at
`same_run_validation.py` line 653 with exactly `evidence.Refused: python
exited 1`. The readback executed over forty bare asserts and reported which
one fired nowhere, because `evidence.command` discards the child's stderr on
purpose (the child receives three API key files and compares whole run
bundles, so its stderr may carry key material).

These tests pin the repair and its limits: the stage is retained, the
classification is retained, and the exception MESSAGE never is.
"""
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "validation/enterprise/run_client_smoke.py"


def load_module():
    """Import the script with its external clients stubbed.

    The readback imports `mcp`, `vanian` and `openapi_contract`, which are
    installed only on the validation runner. Stubbing them lets the
    diagnostics contract be tested anywhere, which is the point: a diagnostics
    path that only runs on the machine that already failed is no help.
    """
    for name, attrs in (("mcp", {"Client": object, "StdioServerParameters": object}),
                        ("vanian", {"ApiError": type("ApiError", (Exception,), {}),
                                    "VanianClient": object}),
                        ("openapi_contract", {"validate_run_reads": lambda *a, **k: None})):
        if name not in sys.modules:
            module = types.ModuleType(name)
            for key, value in attrs.items():
                setattr(module, key, value)
            sys.modules[name] = module
    spec = importlib.util.spec_from_file_location("run_client_smoke_under_test", TARGET)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = load_module()
SOURCE = TARGET.read_text()


class StageRecording(unittest.TestCase):
    def test_every_marked_stage_name_is_unique(self):
        """Two stages sharing a name would make a refusal ambiguous."""
        names = [line.split('mark("', 1)[1].split('"', 1)[0]
                 for line in SOURCE.splitlines() if line.strip().startswith('mark("')]
        self.assertGreaterEqual(len(names), 12)
        self.assertEqual(len(names), len(set(names)), "duplicate stage name")

    def test_the_stage_recorded_at_failure_is_the_last_one_marked(self):
        MODULE.mark("api_admission")
        MODULE.mark("python_sdk_readback")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "public" / "enterprise-clients.json"
            record = MODULE.write_failure(output, AssertionError())
        self.assertEqual(record["stage"], "python_sdk_readback")

    def test_the_startup_stage_is_set_before_anything_is_marked(self):
        fresh = load_module()
        self.assertEqual(fresh._STAGE["name"], "startup")


class ClassificationNotEcho(unittest.TestCase):
    def test_known_exception_types_classify(self):
        cases = {AssertionError: "assurance_predicate_failed",
                 TimeoutError: "unclassified_client_error"}
        for error_type, expected in cases.items():
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "public" / "out.json"
                record = MODULE.write_failure(output, error_type())
            self.assertEqual(record["error_class"], expected, error_type.__name__)

    def test_an_unknown_exception_type_is_classified_not_dropped(self):
        with tempfile.TemporaryDirectory() as temporary:
            record = MODULE.write_failure(Path(temporary) / "out.json",
                                          RuntimeError("anything"))
        self.assertEqual(record["error_class"], "unclassified_client_error")
        self.assertEqual(record["error_type"], "RuntimeError")

    def test_the_exception_message_is_never_retained(self):
        """The decisive property. A message can carry a key or bundle bytes."""
        secret = "sk-live-AKIAIOSFODNN7EXAMPLE-do-not-retain"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "public" / "out.json"
            MODULE.write_failure(output, AssertionError(secret))
            written = (output.parent / "client-smoke-failure.json").read_text()
        self.assertNotIn(secret, written)
        self.assertNotIn("sk-live", written)
        for value in json.loads(written).values():
            self.assertNotIn(secret, str(value))

    def test_the_record_carries_no_free_text_field_an_upstream_could_fill(self):
        with tempfile.TemporaryDirectory() as temporary:
            record = MODULE.write_failure(Path(temporary) / "out.json",
                                          AssertionError("x" * 500))
        self.assertEqual(set(record),
                         {"source_authority", "stage", "error_type", "error_class", "scope"})


class RetentionBehaviour(unittest.TestCase):
    def test_the_record_lands_beside_the_output_so_the_controller_retains_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "public" / "enterprise-clients.json"
            MODULE.write_failure(output, AssertionError())
            self.assertTrue((output.parent / "client-smoke-failure.json").is_file())

    def test_a_diagnostics_write_failure_does_not_mask_the_original_refusal(self):
        """A full or read-only disk must not turn a refusal into a crash here."""
        with tempfile.TemporaryDirectory() as temporary:
            blocker = Path(temporary) / "blocked"
            blocker.write_text("not a directory")
            record = MODULE.write_failure(blocker / "nested" / "out.json", AssertionError())
        self.assertEqual(record["error_class"], "assurance_predicate_failed")

    def test_the_script_reraises_so_the_controller_still_sees_a_nonzero_exit(self):
        self.assertIn("raise", SOURCE.rsplit("write_failure(destination, error)", 1)[1])


class NoAssuranceWeakened(unittest.TestCase):
    #: Measured on the pre-repair file (commit 35f215d) with the same counting
    #: rule used below. Not a guess: `git show 35f215d:<file>` counts 25.
    BASELINE_PREDICATES = 25

    @staticmethod
    def count_predicates(source):
        return sum(1 for line in source.splitlines()
                   if line.strip().startswith("assert ") or ".is_error" in line)

    def test_no_assertion_was_removed_or_softened_by_the_repair(self):
        """`mark` is insert-only, so the predicate count must be unchanged."""
        self.assertEqual(self.count_predicates(SOURCE), self.BASELINE_PREDICATES,
                         "predicate count changed; the repair must be insert-only")

    def test_the_baseline_matches_the_committed_pre_repair_file_when_git_is_present(self):
        """Anchors BASELINE_PREDICATES to history instead of to this file."""
        import subprocess
        try:
            before = subprocess.run(
                ["git", "show", "35f215d:validation/enterprise/run_client_smoke.py"],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("git unavailable")
        if before.returncode:
            self.skipTest("pre-repair commit 35f215d not present in this clone")
        self.assertEqual(self.count_predicates(before.stdout), self.BASELINE_PREDICATES)

    def test_no_bare_except_swallows_a_predicate_failure(self):
        self.assertNotIn("except:", SOURCE)
        self.assertNotIn("except Exception:\n        pass", SOURCE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
