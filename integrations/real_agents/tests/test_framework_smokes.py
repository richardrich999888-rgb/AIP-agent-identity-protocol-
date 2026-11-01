"""Ordinary controller fixtures, never framework/agent/model validation."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "adapters"))
from build_image import runtime_python
from framework_smokes import _command_for, child_hold_seconds, source_project_metadata, wait_start_gate


class FrameworkSmokeContracts(unittest.TestCase):
    def test_child_command_handles_spaces_quotes_and_literal_shell_syntax(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "quoted ' file $(not-a-command).json"
            parts = shlex.split(_command_for(str(target)))
            self.assertEqual(parts[:2], ["python", "-c"])
            subprocess.run([sys.executable, *parts[1:]], check=True)
            value = json.loads(target.read_text())
            self.assertEqual(value["component"], "actual-upstream-tool")
            self.assertGreater(value["pid"], 0)

    def test_virtual_application_version_is_explicitly_source_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pyproject.toml"
            path.write_text('[project]\nname = "deer-flow"\nversion = "2.2.0-dev"\n')
            self.assertEqual(source_project_metadata(path), {
                "name": "deer-flow", "version": "2.2.0-dev",
                "origin": "SOURCE_PYPROJECT_NOT_INSTALLED_DISTRIBUTION"})
            path.write_text('[project]\nname = "deer-flow"\n')
            with self.assertRaises(ValueError):
                source_project_metadata(path)

    def test_framework_runtime_interpreter_paths_are_distinct_and_explicit(self):
        self.assertEqual(runtime_python("deerflow"), "/opt/framework/backend/.venv/bin/python")
        self.assertEqual(runtime_python("openhands"), "/opt/framework/.venv/bin/python")
        self.assertEqual(runtime_python("agent_zero"), "/opt/framework/.venv/bin/python")
        with self.assertRaises(ValueError):
            runtime_python("unknown")


    def test_component_hold_is_explicit_finite_and_bounded(self):
        with patch.dict("os.environ", {"SNIFFERDOG_SMOKE_CHILD_HOLD_SECONDS": "2"}):
            self.assertEqual(child_hold_seconds(), 2)
        for value in ("nan", "inf", "-1", "3.1"):
            with self.subTest(value=value), patch.dict("os.environ", {"SNIFFERDOG_SMOKE_CHILD_HOLD_SECONDS": value}):
                with self.assertRaises(ValueError):
                    child_hold_seconds()

    def test_component_gate_rejects_arbitrary_workload_selected_path(self):
        with patch.dict("os.environ", {"SNIFFERDOG_SMOKE_START_FILE": "/work/agent-controlled"}):
            with self.assertRaises(ValueError):
                wait_start_gate()


if __name__ == "__main__":
    unittest.main()
