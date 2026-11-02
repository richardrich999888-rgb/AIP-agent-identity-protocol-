"""Bootstrap controls; these tests never start or call a model server.

The retry case uses explicit subprocess/asset fixtures, not inference evidence.
The optional prepared-asset case verifies real local files and metadata only;
set VANIAN_MODEL_TEST_ASSETS to opt in. It does not send an inference request.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().with_name("model_runtime.py")
spec = importlib.util.spec_from_file_location("local_model_runtime_under_test", SOURCE)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class ControlledBootstrapRetry(unittest.TestCase):
    def test_controlled_failed_pip_is_retried_without_recreating_venv(self):
        commands = []
        pip_count = 0
        with tempfile.TemporaryDirectory(prefix="vanian-prepare-fixture-") as temporary:
            root = Path(temporary)

            def subprocess_fixture(command, **_kwargs):
                nonlocal pip_count
                commands.append(command)
                if "venv" in command:
                    python = root / "venv/bin/python"
                    python.parent.mkdir(parents=True)
                    python.write_text("Controlled fixture; never executed.\n")
                elif "pip" in command:
                    pip_count += 1
                    if pip_count == 1:
                        raise subprocess.CalledProcessError(1, command)
                else:
                    raise AssertionError("unexpected controlled subprocess")
                return subprocess.CompletedProcess(command, 0)

            imported_fixture = {
                "model": "CONTROLLED_FIXTURE_NOT_INFERENCE",
                "manifest_sha256": "0" * 64,
                "weight_sha256": runtime.pins()["model"]["sha256"],
                "weight_bytes": runtime.pins()["model"]["bytes"],
            }
            with (
                mock.patch.object(runtime, "verify_binary", return_value={}),
                mock.patch.object(runtime, "verify_python", return_value=str(root / "venv/bin/python")) as verify_python,
                mock.patch.object(runtime, "_download"),
                mock.patch.object(runtime, "model_identity", return_value=imported_fixture),
                mock.patch.object(runtime, "verify", return_value={"controlled_fixture": True}),
                mock.patch.object(runtime.subprocess, "run", side_effect=subprocess_fixture),
                mock.patch.object(runtime, "_Server", side_effect=AssertionError("must not start a server")),
                mock.patch.object(runtime, "request", side_effect=AssertionError("must not call a server")),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    runtime.prepare(root)
                self.assertTrue((root / "venv/bin/python").is_file())
                self.assertFalse((root / "identity.json").exists())
                self.assertTrue(runtime.prepare(root)["controlled_fixture"])
                verify_python.assert_called_once_with(root)
            self.assertEqual(pip_count, 2)
            self.assertEqual(sum("venv" in command for command in commands), 1)
            self.assertTrue((root / "identity.json").is_file())
            for command in commands:
                if "pip" in command:
                    self.assertIn("--isolated", command)
                    self.assertIn("--no-cache-dir", command)
                    self.assertEqual(command[-2:], ["-r", str(SOURCE.parent / "requirements.lock")])


@unittest.skipUnless(
    os.environ.get("VANIAN_MODEL_TEST_ASSETS"),
    "actual prepared model assets not configured; no inference is claimed",
)
class ActualPreparedAssetReuse(unittest.TestCase):
    def test_actual_files_reused_without_install_download_or_model_service(self):
        root = Path(os.environ["VANIAN_MODEL_TEST_ASSETS"]).resolve(strict=True)
        identity_before = (root / "identity.json").read_bytes()
        commands = []
        real_run = subprocess.run

        def readonly_subprocess(command, **kwargs):
            commands.append(command)
            self.assertNotIn("pip", command)
            self.assertNotIn("serve", command)
            self.assertNotIn("create", command)
            return real_run(command, **kwargs)

        with (
            mock.patch.object(runtime.subprocess, "run", side_effect=readonly_subprocess),
            mock.patch.object(runtime, "_download", side_effect=AssertionError("must not download")),
            mock.patch.object(runtime, "request", side_effect=AssertionError("must not call a model API")),
            mock.patch.object(runtime, "_Server", side_effect=AssertionError("must not start a server")),
            mock.patch.object(runtime, "ModelProcess", side_effect=AssertionError("must not start a model")),
        ):
            result = runtime.prepare(root)
        self.assertEqual((root / "identity.json").read_bytes(), identity_before)
        self.assertEqual(result["model"]["weight_sha256"], runtime.pins()["model"]["sha256"])
        self.assertEqual(result["binary"]["version"], runtime.pins()["runtime"]["version"])
        self.assertEqual(len(commands), 2)  # Package metadata and binary version only.


if __name__ == "__main__":
    unittest.main(verbosity=2)
