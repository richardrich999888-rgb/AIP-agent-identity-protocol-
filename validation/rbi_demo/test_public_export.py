#!/usr/bin/env python3
"""Unprivileged export boundary tests; no actual rehearsal is claimed."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from collect_public import collect


class PublicExportTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "source"; source.mkdir()
        state = source / "rbi-rehearsal/system/work/state"; state.mkdir(parents=True)
        archive = state / "attested.archive.jsonl"
        archive.write_bytes(b'{"original":"signed fixture bytes, not real evidence"}\n')
        archive.chmod(0o600)
        log = source / "rbi-rehearsal/system_run.log"; log.write_text("FAIL original diagnostic\n")
        for name in ("collector.key.wrapped", "probe.key.json", "noise.key.json", "pass", ".env"):
            secret = state.parent / name; secret.write_text("DO-NOT-PUBLISH")
            secret.chmod(0o600)
        return source, state, archive

    def test_exact_public_copy_is_readable_without_changing_private_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, state, archive = self.fixture(root)
            destination = root / "public"; report = collect(source, destination)
            name = "rbi-rehearsal/system/work/state/attested.archive.jsonl"
            copied = destination / name
            self.assertEqual(copied.read_bytes(), archive.read_bytes())
            self.assertEqual(report["files"][name]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            self.assertEqual(report["verification_claim"], False)
            self.assertFalse(report["refused"])
            for path in destination.rglob("*"):
                if path.is_file(): self.assertNotIn(b"DO-NOT-PUBLISH", path.read_bytes())
            for private in state.parent.iterdir():
                if private.is_file() and private.name != "system_run.log":
                    self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)

    def test_symlink_to_private_material_is_refused_but_other_diagnostics_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, state, archive = self.fixture(root)
            archive.unlink(); archive.symlink_to(state.parent / "probe.key.json")
            destination = root / "public"; report = collect(source, destination)
            self.assertEqual(report["status"], "PARTIAL_REFUSED")
            self.assertIn("rbi-rehearsal/system/work/state/attested.archive.jsonl", report["refused"])
            self.assertIn("FAIL original diagnostic", (destination / "rbi-rehearsal/system_run.log").read_text())
            self.assertFalse((destination / "rbi-rehearsal/system/work/state/attested.archive.jsonl").exists())

    def test_symlinked_parent_and_hardlinked_public_alias_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, state, archive = self.fixture(root)
            archive.unlink(); os.link(state.parent / "probe.key.json", archive)
            destination = root / "public"; report = collect(source, destination)
            self.assertTrue(report["refused"])
            self.assertFalse((destination / "rbi-rehearsal/system/work/state/attested.archive.jsonl").exists())
            other = root / "other"; other.mkdir()
            (other / "rbi-rehearsal").symlink_to(source / "rbi-rehearsal", target_is_directory=True)
            report = collect(other, root / "other-public")
            self.assertTrue(report["refused"])
            self.assertFalse(report["files"])

    def test_existing_destination_is_refused_without_modifying_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, _, _ = self.fixture(root)
            destination = root / "public"; destination.mkdir()
            secret = destination / "stale-secret"; secret.write_text("retained")
            with self.assertRaises(FileExistsError): collect(source, destination)
            self.assertEqual(secret.read_text(), "retained")

    def test_cli_upload_gate_is_issued_only_for_completed_fresh_exports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, state, archive = self.fixture(root)
            destination = root / "public"; destination.mkdir()
            (destination / "stale-secret").write_text("DO-NOT-PUBLISH")
            output = root / "github-output"; output.touch()
            helper = Path(__file__).with_name("collect_public.py")
            args = [sys.executable, "-B", str(helper), "--source", str(source),
                    "--output", str(destination), "--github-output", str(output)]
            refused = subprocess.run(args, capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(output.read_text(), "")
            # A newly created partial export remains a failed step, but its safe
            # diagnostics and refusal manifest are available for upload.
            archive.unlink(); archive.symlink_to(state.parent / "probe.key.json")
            args[args.index("--output") + 1] = str(root / "fresh-public")
            partial = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(partial.returncode, 1)
            self.assertEqual(output.read_text(), "export_ready=true\n")
            report = json.loads((root / "fresh-public/export-manifest.json").read_text())
            self.assertEqual(report["status"], "PARTIAL_REFUSED")
            self.assertIn("rbi-rehearsal/system_run.log", report["files"])
            workflow = Path(__file__).resolve().parents[2] / ".github/workflows/rbi-rehearsal.yml"
            self.assertIn("if: always() && steps.export_public.outputs.export_ready == 'true'", workflow.read_text())

    def test_missing_failed_stage_is_recorded_without_inventing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "source"; source.mkdir()
            report = collect(source, root / "public")
            self.assertFalse(report["files"])
            self.assertFalse(report["verification_claim"])
            self.assertIn("rbi-rehearsal/control_check.log", report["missing"])
            self.assertEqual(json.loads((root / "public/export-manifest.json").read_text()), report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
