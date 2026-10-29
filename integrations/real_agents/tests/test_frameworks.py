#!/usr/bin/env python3
"""Unit tests for the five-framework launcher interface.

These tests never contact a model and never import an upstream framework.
They pin the properties that must hold whether or not a framework is
installed: the contract is declared before the run, an unknown name refuses,
goose refuses rather than degrading, and the aider fixture starts genuinely
failing so a no-op edit cannot satisfy its predicate.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters"))

from frameworks import (ADAPTERS, AdapterRefused, LOCAL_PLACEHOLDER_KEY, RunContext,
                        _seed_aider_repo, adapter, effect_contract)

FIVE = {"smolagents", "aider", "goose", "browser_use", "open_interpreter"}


class Registry(unittest.TestCase):
    def test_exactly_the_five_assigned_frameworks_are_registered(self):
        self.assertEqual(set(ADAPTERS), FIVE)

    def test_each_adapter_name_matches_its_registry_key(self):
        for key, value in ADAPTERS.items():
            self.assertEqual(key, value.name)

    def test_an_unknown_framework_refuses_instead_of_defaulting(self):
        with self.assertRaises(AdapterRefused):
            adapter("autogpt")

    def test_every_adapter_declares_the_model_endpoint_requirement(self):
        for name, value in ADAPTERS.items():
            self.assertIn("model_endpoint", value.requires, name)


class Contracts(unittest.TestCase):
    def test_every_framework_emits_a_complete_pre_run_contract(self):
        work = Path("/work")
        for name in FIVE:
            contract = effect_contract(name, work)
            self.assertEqual(contract["provenance"], "CONTROLLER_DECLARED_BEFORE_RUN", name)
            self.assertTrue(contract["task"].strip(), name)
            effect = contract["effect"]
            self.assertTrue(effect["kind"], name)
            self.assertTrue(effect["detail"], name)
            self.assertTrue(effect["corroborating_source"], name)

    def test_contracts_are_json_serialisable_so_they_can_be_retained(self):
        for name in FIVE:
            json.dumps(effect_contract(name, Path("/work")))

    def test_no_two_frameworks_share_an_effect_detail(self):
        """A shared effect would let one framework's run satisfy another's gate."""
        details = [json.dumps(effect_contract(n, Path("/work"))["effect"]["detail"],
                              sort_keys=True) for n in sorted(FIVE)]
        self.assertEqual(len(set(details)), len(details))

    def test_each_corroborating_source_is_independent_of_the_framework(self):
        """The checker must never be the framework's own report."""
        for name in FIVE:
            source = effect_contract(name, Path("/work"))["effect"]["corroborating_source"]
            self.assertNotIn("self-report", source.lower(), name)
            self.assertNotIn("framework log", source.lower(), name)


class GooseIsRefusedNotDegraded(unittest.TestCase):
    def test_goose_refuses_with_a_stated_reason_rather_than_inventing_an_argv(self):
        context = RunContext(work=Path("/work"), model_id="m", model_base_url="http://127.0.0.1:1",
                             timeout_s=1, emit=lambda *_: None)
        with self.assertRaises(AdapterRefused) as caught:
            ADAPTERS["goose"].run(context)
        message = str(caught.exception)
        self.assertIn("non-interactive", message)
        self.assertIn("goose-ai", message)

    def test_the_goose_effect_still_forbids_mutation(self):
        detail = effect_contract("goose", Path("/work"))["effect"]["detail"]
        self.assertTrue(detail["mutation_forbidden"])


class AiderFixture(unittest.TestCase):
    def test_the_seeded_repository_starts_with_a_genuinely_failing_test(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            _seed_aider_repo(repo)
            self.assertTrue((repo / ".git").is_dir())
            # Run the seeded test with the stdlib only, so the assertion does
            # not depend on pytest being installed in this environment.
            check = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0,'.');"
                 "from calc import add; sys.exit(0 if add(2,3)==5 else 3)"],
                cwd=repo, capture_output=True, timeout=60)
            self.assertEqual(check.returncode, 3,
                             "the fixture must fail before the agent edits it")

    def test_the_seeded_repository_has_exactly_one_baseline_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            _seed_aider_repo(repo)
            log = subprocess.run(["git", "log", "--oneline"], cwd=repo,
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(len(log.stdout.strip().splitlines()), 1)


class NoCredentialLeaks(unittest.TestCase):
    def test_the_local_placeholder_is_not_a_credential_shaped_secret(self):
        self.assertNotIn("sk-", LOCAL_PLACEHOLDER_KEY)
        self.assertIn("no-credential", LOCAL_PLACEHOLDER_KEY)

    def test_the_module_reads_no_cloud_model_credential_from_the_environment(self):
        source = (Path(__file__).resolve().parents[1] / "adapters/frameworks.py").read_text()
        for forbidden in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY\"]", "HF_TOKEN",
                          "GEMINI_API_KEY", "getenv(\"OPENAI_API_KEY"):
            self.assertNotIn(forbidden, source, forbidden)


if __name__ == "__main__":
    unittest.main(verbosity=2)
