import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from service_onboard import ManifestError, main, plan  # noqa: E402


class ServicePlanTests(unittest.TestCase):
    def setUp(self):
        self.example = json.loads((ROOT / "example.json").read_text())

    def bad(self, path, value):
        m = copy.deepcopy(self.example)
        node = m
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        with self.assertRaises(ManifestError):
            plan(m)

    def test_example_is_not_pilot_proof(self):
        r = plan(self.example)
        self.assertEqual(r["institutional_pilot"], "NOT_VERIFIED")
        self.assertEqual(r["service_planes"]["PROTECT"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(r["service_planes"]["DISCOVER"]["status"], "LIMITED_TO_ENROLLED_WORKLOADS")
        self.assertEqual(r["service_planes"]["PROVE"]["status"], "REQUIRES_SAME_RUN_EVIDENCE")

    def test_collector_cannot_be_workload_host(self):
        self.bad(["collector", "host_id"], "agent-linux-01")

    def test_collector_admin_must_be_separate(self):
        self.bad(["collector", "admin_group"], "agent-platform")

    def test_rejects_unqualified_hsm(self):
        self.bad(["collector", "key_custody"], "hsm")

    def test_rejects_global_network_discovery_claim(self):
        self.bad(["integrations", "network_connector"], True)

    def test_rejects_unimplemented_guardrails(self):
        self.bad(["integrations", "inline_guardrails"], True)

    def test_rejects_transaction_gating(self):
        self.bad(["safety", "transaction_gating"], True)

    def test_rejects_automatic_containment(self):
        self.bad(["safety", "automatic_containment"], True)

    def test_rejects_prompt_capture(self):
        self.bad(["data_policy", "capture_prompts"], True)

    def test_rejects_payload_capture(self):
        self.bad(["data_policy", "capture_transaction_payloads"], True)

    def test_rejects_secret_or_unknown_keys(self):
        self.example["api_key"] = "bad-secret"
        with self.assertRaises(ManifestError):
            plan(self.example)

    def test_rejects_invalid_boolean(self):
        self.bad(["integrations", "contextforge"], "true")

    def test_rejects_mcp_without_api(self):
        m = copy.deepcopy(self.example)
        m["integrations"]["evidence_api"] = False
        with self.assertRaises(ManifestError):
            plan(m)

    def test_rejects_unsupported_os(self):
        self.bad(["agent_hosts", 0, "os"], "windows")

    def test_no_gateway_preserves_control_absence(self):
        m = copy.deepcopy(self.example)
        m["integrations"]["contextforge"] = False
        self.assertEqual(plan(m)["service_planes"]["CONTROL"]["status"], "NOT_CONFIGURED")

    def test_cli_prints_valid_plan(self):
        with tempfile.TemporaryDirectory() as path:
            output = Path(path) / "out.json"
            rc = main([str(ROOT / "example.json"), "--output", str(output)])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(output.read_text())["institutional_pilot"], "NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
