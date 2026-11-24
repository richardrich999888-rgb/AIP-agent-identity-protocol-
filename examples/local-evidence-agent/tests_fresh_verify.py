"""Negative package controls, with an explicit stop at the Rust boundary.

These files contain no signed observations and are never called a real capture.
Successful kernel/audit/model verification requires the separate actual runner.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fresh_verify_under_test", HERE / "fresh_verify.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ControlledRustBoundaryReached(RuntimeError):
    pass


class FreshPackageNegativeControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fresh-negative-fixture-")
        self.root = Path(self.temporary.name)
        self.public = self.root / "public"
        self.public.mkdir()
        self.trust = self.root / "separate-operator-trust.json"
        names = ["attested.archive.jsonl", "health.archive.jsonl", "run-manifest.json", "task-manifest.json",
                 "launch.json", "task-output-manifest.json", "source-hashes.json", "model-identity.json",
                 "audit-status.json", "auditd.log", "verification.json", "observation-summary.json",
                 "agent-events.jsonl", *[f"answers/case-{n}.json" for n in range(1, 5)]]
        for name in names:
            path = self.public / name
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps({"classification": "CONTROLLED_NEGATIVE_FIXTURE_NOT_A_CAPTURE", "member": name}) + "\n")
        self.authority = {"schema": "vanian-local-qa-controller-trust-v1", "source_commit": "a" * 40,
            "run_id": "controlled-fixture-not-a-workload",
            "observer_anchor": {"observer_id": "fixture", "key_version": 1, "public_key": "0" * 64},
            "checkpoint": {"sha256": {name: self.sha(self.public / name) for name in verifier.ARCHIVES}},
            "public_files": {str(p.relative_to(self.public)): self.sha(p) for p in self.public.rglob("*") if p.is_file()}}
        self.save_trust()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def save_trust(self):
        self.trust.write_text(json.dumps(self.authority))

    def rejected_before_rust(self, *, trust=None):
        with mock.patch.object(verifier, "verify", side_effect=AssertionError("Rust boundary must not be reached")) as boundary:
            with self.assertRaises(verifier.Refused):
                verifier.verify_fresh(self.public, trust or self.trust, self.root / "unused-tools")
            boundary.assert_not_called()

    def test_complete_pinned_fixture_delegates_to_rust_without_claiming_a_capture(self):
        with mock.patch.object(verifier, "verify", side_effect=ControlledRustBoundaryReached) as boundary:
            with self.assertRaises(ControlledRustBoundaryReached):
                verifier.verify_fresh(self.public, self.trust, self.root / "unused-tools")
            boundary.assert_called_once()

    def test_modified_task_manifest_rejected_before_rust(self):
        (self.public / "task-manifest.json").write_text('{"classification":"TAMPERED_FIXTURE"}')
        self.rejected_before_rust()

    def test_modified_signed_archive_bytes_rejected_before_rust(self):
        with (self.public / "attested.archive.jsonl").open("ab") as stream:
            stream.write(b"tampered-fixture\n")
        self.rejected_before_rust()

    def test_extra_unapproved_file_rejected_before_rust(self):
        (self.public / "unapproved.json").write_text("{}")
        self.rejected_before_rust()

    def test_missing_file_rejected_before_rust(self):
        (self.public / "launch.json").unlink()
        self.rejected_before_rust()

    def test_missing_hash_cannot_hide_public_file(self):
        del self.authority["public_files"]["launch.json"]
        self.save_trust()
        self.rejected_before_rust()

    def test_hash_for_missing_file_is_not_a_complete_inventory(self):
        self.authority["public_files"]["missing.json"] = "f" * 64
        self.save_trust()
        self.rejected_before_rust()

    def test_member_symlink_to_identical_bytes_is_rejected(self):
        original = self.public / "launch.json"
        external = self.root / "identical.json"
        external.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(external)
        self.rejected_before_rust()

    def test_unapproved_symlink_directory_is_rejected(self):
        target = self.root / "other-directory"
        target.mkdir()
        (self.public / "extra-link").symlink_to(target, target_is_directory=True)
        self.rejected_before_rust()

    def test_operator_trust_cannot_be_inside_public_package(self):
        inside = self.public / "self-approved-trust.json"
        inside.write_bytes(self.trust.read_bytes())
        self.rejected_before_rust(trust=inside)

    def test_operator_trust_symlink_is_rejected(self):
        linked = self.root / "operator-link.json"
        linked.symlink_to(self.trust)
        self.rejected_before_rust(trust=linked)

    def test_public_checkpoint_cannot_replace_separate_checkpoint(self):
        self.authority["checkpoint"] = None
        path = self.public / "checkpoint.json"
        path.write_text('{"classification":"UNAPPROVED_PUBLIC_CHECKPOINT"}')
        self.authority["public_files"]["checkpoint.json"] = self.sha(path)
        self.save_trust()
        self.rejected_before_rust()

    def test_public_anchor_cannot_replace_separate_anchor(self):
        self.authority["observer_anchor"] = None
        path = self.public / "observer-anchor.json"
        path.write_text('{"classification":"UNAPPROVED_PUBLIC_ANCHOR"}')
        self.authority["public_files"]["observer-anchor.json"] = self.sha(path)
        self.save_trust()
        self.rejected_before_rust()

    def test_duplicate_trust_field_is_rejected(self):
        text = self.trust.read_text()
        self.trust.write_text(text[:-1] + ',"source_commit":"' + "a" * 40 + '"}')
        self.rejected_before_rust()

    def test_nonfinite_trust_value_is_rejected(self):
        self.authority["fixture_nan"] = float("nan")
        self.save_trust()
        self.rejected_before_rust()

    def test_absolute_or_parent_member_name_is_rejected(self):
        for name in ("../outside.json", "/outside.json", "answers/../launch.json", "answers//case-1.json"):
            with self.subTest(name=name), self.assertRaises(verifier.Refused):
                verifier.checked_file(self.public, name)

    def test_cli_output_symlink_directory_cannot_write_inside_originals(self):
        alias = self.root / "outside-alias"
        alias.symlink_to(self.public, target_is_directory=True)
        output = alias / "not-an-original-result.json"
        argv = [str(HERE / "fresh_verify.py"), "--package", str(self.public), "--trust", str(self.trust),
                "--tools", str(self.root / "unused-tools"), "--output", str(output)]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(verifier, "verify_fresh") as boundary:
            with self.assertRaises(verifier.Refused):
                verifier.main()
            boundary.assert_not_called()
        self.assertFalse((self.public / "not-an-original-result.json").exists())

    def test_cli_dangling_output_symlink_refused_before_verification(self):
        target = self.root / "must-not-be-created.json"
        output = self.root / "dangling-output.json"
        output.symlink_to(target)
        argv = [str(HERE / "fresh_verify.py"), "--package", str(self.public), "--trust", str(self.trust),
                "--tools", str(self.root / "unused-tools"), "--output", str(output)]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(verifier, "verify_fresh") as boundary:
            with self.assertRaises(verifier.Refused):
                verifier.main()
            boundary.assert_not_called()
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
