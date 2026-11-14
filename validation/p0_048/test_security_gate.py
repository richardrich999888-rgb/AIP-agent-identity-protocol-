#!/usr/bin/env python3
"""Regression controls for the historical-evidence security gate."""

import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import security_gate as gate


class SecurityGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = json.loads(gate.CLASSIFICATIONS.read_text())
        for item in self.policy["immutable_files"]:
            path = self.root / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(gate.ROOT / item["path"], path)
        shutil.copyfile(gate.ROOT / ".gitleaksignore", self.root / ".gitleaksignore")
        self.report = json.loads((gate.ROOT / "validation/p0_048/iteration-004/implementation-trivy.sarif").read_text())

    def result(self, exit_code=42):
        return gate.classify(self.root, self.policy, self.report, exit_code)

    def test_original_findings_remain_visible_and_are_not_deployment_acceptance(self):
        result = self.result()
        self.assertEqual(result["status"], "PASS_WITH_ARCHIVED_FINDINGS")
        self.assertEqual(result["raw_findings"], 4)
        self.assertEqual(len(result["archived_findings"]), 4)
        self.assertFalse(result["deployment_qualified"])

    def test_changed_archival_bytes_fail_even_if_findings_look_the_same(self):
        path = self.root / self.policy["immutable_files"][1]["path"]
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "historical evidence changed"):
            self.result()

    def test_changed_inventory_is_not_accepted_by_its_old_fingerprint(self):
        path = self.root / self.policy["immutable_files"][0]["path"]
        path.write_text("{}\n")
        with self.assertRaises(ValueError):
            self.result()

    def test_symlink_cannot_replace_the_archival_file(self):
        path = self.root / self.policy["immutable_files"][1]["path"]
        data = path.read_bytes()
        path.unlink()
        target = self.root / "elsewhere"
        target.write_bytes(data)
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            self.result()

    def test_absent_evidence_is_an_error(self):
        (self.root / self.policy["immutable_files"][1]["path"]).unlink()
        with self.assertRaises(OSError):
            self.result()

    def test_same_warning_in_a_new_manifest_blocks(self):
        result = copy.deepcopy(self.report["runs"][0]["results"][0])
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "deploy/new.yaml"
        self.report["runs"][0]["results"].append(result)
        result = self.result()
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(len(result["blocking_findings"]), 1)

    def test_new_rule_at_the_same_archival_location_blocks(self):
        result = copy.deepcopy(self.report["runs"][0]["results"][0])
        result["ruleId"] = "generic-api-key"
        self.report["runs"][0]["results"].append(result)
        self.assertEqual(self.result()["status"], "FAIL")

    def test_changed_location_blocks(self):
        self.report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] += 1
        self.assertEqual(self.result()["status"], "FAIL")

    def test_duplicate_result_is_not_silently_collapsed(self):
        self.report["runs"][0]["results"].append(copy.deepcopy(self.report["runs"][0]["results"][0]))
        self.assertEqual(self.result()["status"], "FAIL")

    def test_missing_expected_warning_is_not_a_clean_scan(self):
        self.report["runs"][0]["results"].pop()
        self.assertEqual(self.result()["status"], "FAIL")

    def test_zero_result_scan_does_not_prove_the_archive_was_scanned(self):
        self.report["runs"][0]["results"] = []
        self.assertEqual(self.result(0)["status"], "FAIL")

    def test_scanner_operational_errors_fail_even_with_a_valid_report(self):
        for code in (1, 2, -9, 124):
            with self.subTest(exit_code=code), self.assertRaises(ValueError):
                self.result(code)

    def test_exit_zero_with_findings_is_inconsistent(self):
        with self.assertRaises(ValueError):
            self.result(0)

    def test_unreviewed_scanner_version_fails(self):
        self.report["runs"][0]["tool"]["driver"]["version"] = "0.0.0"
        with self.assertRaises(ValueError):
            self.result()

    def test_multiple_runs_fail(self):
        self.report["runs"].append(copy.deepcopy(self.report["runs"][0]))
        with self.assertRaises(ValueError):
            self.result()

    def test_multiple_locations_fail(self):
        locations = self.report["runs"][0]["results"][0]["locations"]
        locations.append(copy.deepcopy(locations[0]))
        with self.assertRaises(ValueError):
            self.result()

    def test_missing_or_duplicate_fingerprint_fails(self):
        path = self.root / ".gitleaksignore"
        original = path.read_text()
        fingerprint = self.policy["gitleaks_fingerprints"][0]
        for text in (original.replace(fingerprint, ""), original + fingerprint + "\n"):
            path.write_text(text)
            with self.assertRaises(ValueError):
                self.result()


if __name__ == "__main__":
    unittest.main(verbosity=2)
