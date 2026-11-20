"""Failure injection for the actual Security workflow's audit/tee command.

No network, Cargo install or third-party Python modules. The temporary cargo
stub supplies a chosen exit status; the workflow's declared shell runs its real
command. Removing `shell: bash` reproduces the old false-green failure.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/security.yml"


def audit_step():
    text = WORKFLOW.read_text()
    section = text.split("      - name: Audit (fail on any vulnerability)\n", 1)[1]
    section = section.split("      - ", 1)[0]
    command = re.search(r"^        run: (.+)$", section, re.MULTILINE)
    if not command or command[1] in ("|", ">"):
        raise ValueError("audit step changed; update its execution test")
    shell = re.search(r"^        shell: (.+)$", section, re.MULTILINE)
    if shell is None:
        prefix = ["bash", "-e"]  # GitHub's unspecified Linux shell.
    elif shell[1] == "bash":
        prefix = ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
    else:
        raise ValueError("unrecognised audit shell; test its actual semantics")
    return prefix, command[1]


class AuditExitTests(unittest.TestCase):
    def run_audit(self, status, unwritable_report=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            cargo.write_text(
                "#!/bin/sh\n"
                "[ \"$*\" = 'audit --ignore RUSTSEC-2026-0097 --json' ] || exit 99\n"
                "printf '%s\\n' '{\"fixture\":true}'\n"
                'exit "$P0049_AUDIT_EXIT"\n'
            )
            cargo.chmod(0o700)
            if unwritable_report:
                (root / "audit.json").mkdir()
            prefix, command = audit_step()
            script = root / "step.sh"
            script.write_text(command + "\n")
            result = subprocess.run(
                [*prefix, str(script)], cwd=root,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                     "P0049_AUDIT_EXIT": str(status)},
                text=True, capture_output=True, timeout=10, check=False,
            )
            if not unwritable_report:
                self.assertEqual(json.loads((root / "audit.json").read_text()), {"fixture": True})
            return result.returncode

    def test_clean_audit_succeeds_and_retains_report(self):
        self.assertEqual(self.run_audit(0), 0)

    def test_vulnerability_refusal_survives_tee(self):
        self.assertEqual(self.run_audit(1), 1)

    def test_operational_failure_survives_tee(self):
        self.assertEqual(self.run_audit(42), 42)

    def test_report_write_failure_is_not_a_pass(self):
        self.assertNotEqual(self.run_audit(0, unwritable_report=True), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
