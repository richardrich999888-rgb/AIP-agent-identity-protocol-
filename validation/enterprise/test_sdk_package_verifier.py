#!/usr/bin/env python3
"""Exercise an actual offline wheel install despite source metadata pollution."""
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "verify_sdk_packages", Path(__file__).with_name("verify_sdk_packages.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture_wheel(root):
    """A valid packaging fixture; no service, evidence or SDK behavior is simulated."""
    files = {
        "vanian/__init__.py": b"class VanianClient:\n" + b"".join(
            f"    def {name}(self): pass\n".encode()
            for name in ("register_deployment", "list_deployments", "get_deployment",
                         "get_run_metadata", "get_run_verdict", "evaluate_run", "get_agent_runs")
        ),
        "vanian_sdk-0.1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: vanian-sdk\nVersion: 0.1.0\n",
        "vanian_sdk-0.1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    records = []
    for name, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        records.append(f"{name},sha256={digest},{len(content)}")
    records.append("vanian_sdk-0.1.0.dist-info/RECORD,,")
    files["vanian_sdk-0.1.0.dist-info/RECORD"] = ("\n".join(records) + "\n").encode()
    wheel = root / "vanian_sdk-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return wheel


class CleanWheelInstallationTests(unittest.TestCase):
    def test_relative_pythonpath_and_source_egg_info_cannot_replace_installed_wheel(self):
        with tempfile.TemporaryDirectory(prefix="vanian-wheel-regression-") as directory:
            root = Path(directory)
            source = root / "sdk/python"
            (source / "vanian").mkdir(parents=True)
            (source / "vanian/__init__.py").write_text("raise RuntimeError('source package imported')\n")
            metadata = source / "vanian_sdk.egg-info"
            metadata.mkdir()
            (metadata / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: vanian-sdk\nVersion: 0.1.0\n")
            (metadata / "top_level.txt").write_text("vanian\n")
            wheel = fixture_wheel(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {"PYTHONPATH": "sdk/python"}):
                    MODULE.verify_python_wheel(wheel, root / "clean-venv")
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
