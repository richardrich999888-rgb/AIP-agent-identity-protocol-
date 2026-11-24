"""Actual local API tests: historical records, restricted credentials, no model."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
spec = importlib.util.spec_from_file_location("api_runtime_under_test", HERE / "api_runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class LocalAPIControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (REPO / "target/debug/airon-aip").is_file():
            if os.environ.get("VANIAN_LOCAL_AGENT_REQUIRE_API") == "1":
                raise RuntimeError("Actual airon-aip binary required by the local-demo gate")
            raise unittest.SkipTest("Actual API binary missing; build airon-aip or require it with VANIAN_LOCAL_AGENT_REQUIRE_API=1")

    def test_actual_api_seed_reader_denials_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="local-evidence-api-") as directory:
            api = runtime.APIProcess(REPO, Path(directory), port=0)
            with api:
                token = api.reader_token
                self.assertTrue(token)
                self.assertEqual(len(api.runs), 3)
                self.assertTrue(api._listener_is_loopback())
                self.assertEqual(set(api.auth_checks.values()), {"PASS"})
                self.assertEqual(len(api.auth_checks), 5)
                self.assertEqual(api._operator_token, "")
                self.assertEqual(api._other_token, "")
                reader = api._sdk(token)
                for row in api.runs:
                    metadata = reader.get_run_metadata(row["id"])
                    self.assertEqual(metadata["run_id"], row["run_id"])
                    self.assertIn(metadata, reader.get_agent_runs(row["agent_id"], limit=10).items)
                    self.assertEqual(metadata["evaluation"], reader.evaluate_run(row["id"]))
                    self.assertEqual(metadata["evaluation"]["reconciliation"]["result"], "CannotProve")
                    self.assertEqual(row["evidence_source"], "HISTORICAL_SIGNED_LINUX_CAPTURE")
                    self.assertFalse(row["current_host_kernel_capture"])
                summary = json.dumps(api.public_summary())
                self.assertNotIn(token, summary)
                self.assertFalse(api.public_summary()["managed_evidence_signing"])
                keys = json.loads((api._private / "keys.json").read_text())["keys"]
                self.assertEqual({k["role"] for k in keys}, {"reader", "machine"})
                self.assertNotIn(token, json.dumps(keys))
                port = api.port
            self.assertEqual(api.reader_token, "")
            self.assertIsNone(api._process)
            with socket.socket() as connection:
                connection.settimeout(1)
                self.assertNotEqual(connection.connect_ex(("127.0.0.1", port)), 0)
            self.assertNotIn(token, (api._private / "service.log").read_text())
            with self.assertRaises(runtime.RuntimeSetupError):
                api.start()
            print(json.dumps({"classification": "ACTUAL_LOCAL_API_CONTROLS", "status": "PASS",
                              "api_stopped_after_test": True, "public_summary": api.public_summary()}, sort_keys=True), flush=True)

    def test_modified_historical_original_refused_before_api_starts(self):
        with tempfile.TemporaryDirectory(prefix="local-evidence-api-pin-") as directory:
            api = runtime.APIProcess(REPO, Path(directory), port=0)
            api._private = Path(directory)
            with mock.patch.object(runtime, "ZIP_SHA256", "0" * 64):
                with self.assertRaisesRegex(runtime.RuntimeSetupError, "Historical ZIP SHA"):
                    api._historical_records()
            self.assertIsNone(api._process)

    def test_invalid_bind_address_refuses_before_creating_service_state(self):
        with tempfile.TemporaryDirectory(prefix="local-evidence-api-bind-") as directory:
            state = Path(directory) / "must-not-be-created"
            reply = subprocess.run([str(REPO / "target/debug/airon-aip")],
                env={"PATH": os.defpath, "AIP_BIND_ADDRESS": "not-an-ip", "AIP_KEY_PATH": str(state / "service.key"),
                     "AIP_VAULT_PATH": str(state / "evidence.jsonl"), "AIP_ARTIFACT_PATH": str(state / "artifacts.jsonl")},
                capture_output=True, timeout=10)
            self.assertNotEqual(reply.returncode, 0)
            self.assertIn(b"AIP_BIND_ADDRESS must be a literal IP address", reply.stderr)
            self.assertFalse(state.exists())

    def test_interrupt_during_enter_reaps_actual_ready_api_and_clears_credentials(self):
        with tempfile.TemporaryDirectory(prefix="local-evidence-api-interrupt-") as directory:
            api = runtime.APIProcess(REPO, Path(directory), port=0)
            children = []

            def interrupt_after_child_is_ready():
                children.append(api._process)
                self.assertIsNone(api._process.poll())
                self.assertEqual(api._request("/v1/access", token=api.reader_token)[0], 200)
                raise KeyboardInterrupt()

            with mock.patch.object(api, "_listener_is_loopback", side_effect=interrupt_after_child_is_ready):
                with self.assertRaises(KeyboardInterrupt):
                    with api:
                        self.fail("Interrupted __enter__ unexpectedly returned")
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertIsNone(api._process)
            self.assertTrue(api._log is None)
            self.assertEqual((api.reader_token, api._operator_token, api._other_token), ("", "", ""))
            with socket.socket() as connection:
                connection.settimeout(1)
                self.assertNotEqual(connection.connect_ex(("127.0.0.1", api.port)), 0)

    def test_fresh_package_requires_separate_operator_trust(self):
        with tempfile.TemporaryDirectory(prefix="local-fresh-pair-") as directory:
            with self.assertRaisesRegex(runtime.RuntimeSetupError, "separate operator trust"):
                runtime.APIProcess(REPO, Path(directory), port=0, fresh_evidence=Path(directory))
            with self.assertRaisesRegex(runtime.RuntimeSetupError, "separate operator trust"):
                runtime.APIProcess(REPO, Path(directory), port=0, fresh_trust=Path(directory) / "trust.json")

    def test_component_fresh_verifier_failure_blocks_api_start(self):
        with tempfile.TemporaryDirectory(prefix="local-fresh-refusal-") as directory:
            api = runtime.APIProcess(REPO, Path(directory), port=0,
                fresh_evidence=Path(directory), fresh_trust=Path(directory) / "operator.json")
            # Controlled lifecycle fixture: cryptographic verifier behavior is
            # separately tested. No failed result may publish a ready service.
            with mock.patch.object(api, "_historical_records", return_value=[]), \
                    mock.patch.object(api, "_verify_fresh_observation", side_effect=runtime.RuntimeSetupError("fixture verifier refused")), \
                    mock.patch.object(runtime.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(runtime.RuntimeSetupError, "fixture verifier refused"):
                    api.start()
                spawn.assert_not_called()
            self.assertIsNone(api._process)
            self.assertIsNone(api.fresh_observation)
            self.assertEqual(api.reader_token, "")

    def test_component_fresh_summary_cached_without_relabelling_historical_api_runs(self):
        with tempfile.TemporaryDirectory(prefix="local-fresh-cache-") as directory:
            api = runtime.APIProcess(REPO, Path(directory), port=0,
                fresh_evidence=Path(directory), fresh_trust=Path(directory) / "operator.json")
            fixture = {"status": "PASS", "classification": "CONTROLLED_COMPONENT_FIXTURE_NOT_A_LINUX_RUN",
                       "run_id": "fixture", "capture": {"platform": "Linux", "task_coverage": "FIXTURE"}}
            with mock.patch.object(api, "_verify_fresh_observation", return_value=fixture) as verifier:
                with api:
                    self.assertEqual(api.fresh_observation, fixture)
                    for _ in range(3):
                        self.assertEqual(api.public_summary()["fresh_observation"], fixture)
                    self.assertEqual(len(api.runs), 3)
                    self.assertTrue(all(row["evidence_source"] == "HISTORICAL_SIGNED_LINUX_CAPTURE" for row in api.runs))
                    self.assertTrue(all(not row["current_host_kernel_capture"] for row in api.runs))
                    verifier.assert_called_once_with()


if __name__ == "__main__":
    unittest.main(verbosity=2)
