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
import re
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
    def setUp(self):
        # Stage is module state. Pin it per test so these cases cannot depend
        # on the order unittest happens to run them in, and so none of them
        # accidentally lands on a console sub-stage.
        MODULE.mark("python_sdk_readback")

    def test_known_exception_types_classify(self):
        cases = {AssertionError: "assurance_predicate_failed",
                 TimeoutError: "browser_wait_timed_out",
                 ValueError: "unclassified_client_error"}
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
        """A non-console failure carries exactly five fixed keys and no more."""
        with tempfile.TemporaryDirectory() as temporary:
            record = MODULE.write_failure(Path(temporary) / "out.json",
                                          AssertionError("x" * 500))
        self.assertEqual(set(record),
                         {"source_authority", "stage", "error_type", "error_class", "scope"})

    def test_a_console_failure_adds_browser_facts_and_nothing_else(self):
        """The one permitted extra key, and it holds observations only."""
        MODULE.mark("console_browser_launch")
        with tempfile.TemporaryDirectory() as temporary:
            record = MODULE.write_failure(Path(temporary) / "out.json",
                                          AssertionError("y" * 500))
        self.assertEqual(set(record),
                         {"source_authority", "stage", "error_type", "error_class",
                          "scope", "browser_facts"})
        self.assertNotIn("y" * 50, json.dumps(record))


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


class BrowserStageFacts(unittest.TestCase):
    """The console stage needs more than a class name to be diagnosable.

    CI run 40833025313 reported stage=console_browser, error_type=Error,
    error_class=unclassified_client_error. That was already a large
    improvement on `python exited 1`, but Playwright raises `Error` for a
    missing executable, a sandbox refusal, a launch crash and a navigation
    failure alike. A local reproduction produced the same class from a
    missing headless-shell binary, and a separate local test DISPROVED the
    root-sandbox theory by launching Chromium headless as uid 0 with no
    args. So the class is a category, not a cause.
    """

    def test_playwright_error_is_classified_rather_than_unclassified(self):
        with tempfile.TemporaryDirectory() as temporary:
            MODULE.mark("console_browser_launch")
            record = MODULE.write_failure(Path(temporary) / "out.json",
                                          type("Error", (Exception,), {})())
        self.assertEqual(record["error_class"], "browser_launch_or_navigation_error")

    def test_a_console_stage_failure_attaches_self_observed_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            MODULE.mark("console_browser_navigate")
            record = MODULE.write_failure(Path(temporary) / "out.json", AssertionError())
        self.assertIn("browser_facts", record)
        facts = record["browser_facts"]
        self.assertIn("euid", facts)
        self.assertIn("chromium_executable_exists", facts)

    def test_a_non_console_stage_does_not_pay_for_the_browser_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            MODULE.mark("api_admission")
            record = MODULE.write_failure(Path(temporary) / "out.json", AssertionError())
        self.assertNotIn("browser_facts", record)

    def test_browser_facts_are_observations_not_upstream_text(self):
        """Every value must be a uid, a path, a bool, or a list of names."""
        facts = MODULE.browser_facts()
        allowed = (int, bool, str, type(None), list)
        for key, value in facts.items():
            self.assertIsInstance(value, allowed, key)
            if isinstance(value, list):
                for entry in value:
                    self.assertIsInstance(entry, str, key)
                    self.assertLess(len(entry), 256, key)

    def test_browser_facts_never_leak_an_exception_message(self):
        secret = "sk-live-must-not-appear"
        with tempfile.TemporaryDirectory() as temporary:
            MODULE.mark("console_browser_launch")
            record = MODULE.write_failure(Path(temporary) / "out.json",
                                          AssertionError(secret))
        self.assertNotIn(secret, json.dumps(record))

    def test_the_console_substages_are_ordered_and_distinct(self):
        names = [line.split('mark("', 1)[1].split('"', 1)[0]
                 for line in SOURCE.splitlines() if line.strip().startswith('mark("')]
        console = [name for name in names if name.startswith("console_browser")]
        self.assertEqual(console, ["console_browser_import", "console_browser_launch",
                                   "console_browser_navigate", "console_browser_assert"])


class ConsoleDomFacts(unittest.TestCase):
    """CI run 40834240488 narrowed the failure to console_browser_assert with
    chromium present and navigation complete, which left the DOM as the only
    thing nobody could see. Selector counts are the smallest fact that
    separates "the console did not render" from "it rendered and an assertion
    about its contents failed".
    """

    class FakePage:
        """Minimal stand-in. Playwright is not installed on every host that
        needs to run these tests, and the contract under test is ours."""

        def __init__(self, counts, url="http://127.0.0.1:19994/console",
                     content="<html>x</html>"):
            self._counts, self.url, self._content = counts, url, content

        def content(self):
            return self._content

        def locator(self, selector):
            counts, page = self._counts, self

            class Located:
                def count(self):
                    value = counts.get(selector, 0)
                    if isinstance(value, Exception):
                        raise value
                    return value

            return Located()

    def setUp(self):
        MODULE._CONSOLE_DOM.clear()

    def tearDown(self):
        MODULE._CONSOLE_DOM.clear()

    def test_every_driven_selector_is_counted(self):
        page = self.FakePage({name: 1 for name in MODULE.CONSOLE_SELECTORS})
        MODULE.record_console_dom(page, 200)
        counts = MODULE._CONSOLE_DOM["selector_counts"]
        self.assertEqual(set(counts), set(MODULE.CONSOLE_SELECTORS))
        self.assertEqual(MODULE._CONSOLE_DOM["goto_http_status"], 200)

    def test_a_missing_element_is_reported_as_zero_not_omitted(self):
        """Zero here is a measurement, which is exactly what is wanted."""
        page = self.FakePage({**{n: 1 for n in MODULE.CONSOLE_SELECTORS}, "#run": 0})
        MODULE.record_console_dom(page, 200)
        self.assertEqual(MODULE._CONSOLE_DOM["selector_counts"]["#run"], 0)

    def test_one_failing_selector_probe_does_not_lose_the_others(self):
        page = self.FakePage({**{n: 2 for n in MODULE.CONSOLE_SELECTORS},
                              "#status": RuntimeError("boom")})
        MODULE.record_console_dom(page, None)
        counts = MODULE._CONSOLE_DOM["selector_counts"]
        self.assertEqual(counts["#status"], "probe_error:RuntimeError")
        self.assertEqual(counts["#credential"], 2)

    def test_page_text_is_never_retained_only_its_length(self):
        secret = "SERVER-CONTROLLED-TEXT-sk-live-nope"
        page = self.FakePage({n: 1 for n in MODULE.CONSOLE_SELECTORS},
                             content="<html>" + secret + "</html>")
        MODULE.record_console_dom(page, 200)
        blob = json.dumps(MODULE._CONSOLE_DOM)
        self.assertNotIn(secret, blob)
        self.assertNotIn("sk-live", blob)
        self.assertIsInstance(MODULE._CONSOLE_DOM["content_length"], int)

    def test_the_facts_reach_the_failure_record(self):
        page = self.FakePage({n: 1 for n in MODULE.CONSOLE_SELECTORS})
        MODULE.record_console_dom(page, 200)
        MODULE.mark("console_browser_assert")
        with tempfile.TemporaryDirectory() as temporary:
            record = MODULE.write_failure(Path(temporary) / "out.json", AssertionError())
        self.assertIn("console_dom", record)
        self.assertIn("selector_counts", record["console_dom"])

    def test_no_console_dom_key_when_nothing_was_observed(self):
        MODULE.mark("console_browser_launch")
        with tempfile.TemporaryDirectory() as temporary:
            record = MODULE.write_failure(Path(temporary) / "out.json", AssertionError())
        self.assertNotIn("console_dom", record)

    def test_the_selector_list_matches_what_console_flow_actually_drives(self):
        """If the flow gains a selector, the facts must gain it too."""
        flow = SOURCE.split("def console_flow(", 1)[1].split("\ndef ", 1)[0]
        driven = set(re.findall(r'locator\("([^"]+)"\)', flow))
        self.assertTrue(driven.issubset(set(MODULE.CONSOLE_SELECTORS)),
                        driven - set(MODULE.CONSOLE_SELECTORS))


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
