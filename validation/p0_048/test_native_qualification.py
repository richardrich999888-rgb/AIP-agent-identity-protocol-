"""Negative controls for the qualification gate; these are not kernel evidence."""
import importlib.util
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("native_qualification", Path(__file__).with_name("native_qualification.py"))
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


def output(name="selected", count=1, ignored=0):
    return (f"running {count} test\ntest {name} ... ok\n"
            f"test result: ok. {count} passed; 0 failed; {ignored} ignored; 0 measured; 6 filtered out; finished in 0.01s\n")


class GateTests(unittest.TestCase):
    def test_one_named_executed_test(self):
        self.assertEqual(qualification.classify("selected", output(), 0)[0], "PASS")

    def test_nocapture_diagnostics_between_name_and_ok(self):
        text = output().replace("... ok", "... kernel assertion diagnostics\nok")
        self.assertEqual(qualification.classify("selected", text, 0)[0], "PASS")

    def test_early_returns_cannot_be_passes(self):
        for marker in ("SKIP t09", "SKIPPED", "XDP is UNAVAILABLE", "BLOCKED", "no private tmpfs", "required live capability missing"):
            with self.subTest(marker=marker):
                self.assertEqual(qualification.classify("selected", marker + "\n" + output(), 0)[0], "BLOCKED")

    def test_nonzero_exit_overrides_pass_output(self):
        self.assertEqual(qualification.classify("selected", output(), 101)[0], "FAIL")

    def test_zero_matching_tests_is_failure(self):
        self.assertEqual(qualification.classify("selected", output(count=0), 0)[0], "FAIL")

    def test_wrong_named_test_is_failure(self):
        self.assertEqual(qualification.classify("selected", output("other"), 0)[0], "FAIL")

    def test_ignored_test_is_failure(self):
        self.assertEqual(qualification.classify("selected", output(ignored=1), 0)[0], "FAIL")

    def test_multiple_or_duplicated_results_are_failure(self):
        for text in (output(count=2), output() + output()):
            self.assertEqual(qualification.classify("selected", text, 0)[0], "FAIL")

    def test_missing_result_is_failure(self):
        self.assertEqual(qualification.classify("selected", "test selected ... ok\n", 0)[0], "FAIL")

    def test_timeout_overrides_even_complete_output(self):
        self.assertEqual(qualification.classify("selected", output(), 0, True)[0], "FAIL")

    def test_every_previously_blocked_and_failed_case_is_required(self):
        ledger = json.loads((qualification.ROOT / "validation/p0_048/iteration-003/blocked-tests.json").read_text())
        expected = {(Path(c["path"]).stem, c["test"]) for c in ledger["blocked"] + ledger["failed"]}
        self.assertEqual(set(qualification.CASES), expected)
        self.assertEqual(len(qualification.CASES), 10)

    def test_missing_build_artifacts_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing required"):
            qualification.executables("")

    def test_wrong_source_path_is_rejected(self):
        record = {"reason": "compiler-artifact", "target": {"name": "cgroup_live", "kind": ["test"], "src_path": "/tmp/unrelated.rs"}, "executable": "/tmp/imposter"}
        with self.assertRaisesRegex(ValueError, "wrong source"):
            qualification.executables(json.dumps(record))

    def test_duplicate_artifact_is_rejected(self):
        record = {"reason": "compiler-artifact", "target": {"name": "cgroup_live", "kind": ["test"], "src_path": str(qualification.ROOT / "aip-standalone/aip-observe/tests/cgroup_live.rs")}, "executable": "/tmp/test"}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            qualification.executables(json.dumps(record) + "\n" + json.dumps(record))

    def test_changed_toolchain_bytes_cannot_execute_installer(self):
        spec = importlib.util.spec_from_file_location("install_test_toolchain", Path(__file__).with_name("install_test_toolchain.py"))
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as temp:
            argv = ["installer", "--prefix", str(Path(temp) / "rust"), "--record", str(Path(temp) / "record.json")]
            with mock.patch("sys.argv", argv), mock.patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(b"changed archive")), mock.patch.object(installer.subprocess, "run") as execute:
                with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                    installer.main()
                execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
