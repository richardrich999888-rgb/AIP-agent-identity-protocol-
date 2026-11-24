"""Boundary tests using real cpex hooks and the real Rust verifier/signers.

Authorization bindings come from the explicitly named existing fixture binary.
These tests establish dispatch predicates, not Linux or autonomous execution.
Run with the pinned ContextForge Python environment after building both Rust
binaries and the contextforge_fixture example.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from cpex.framework import GlobalContext, HttpHeaderPayload, PluginConfig, PluginContext
from cpex.framework.hooks.tools import ToolPreInvokePayload

from vanian_contextforge import VanianToolReceiptPlugin

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("AIP_ASSURANCE_TEST_BIN_DIR", str(REPO / "target/debug"))).resolve()


def rust(binary: Path, mode: str | None, request: dict) -> dict:
    result = subprocess.run([str(binary), *([mode] if mode else [])],
                            input=json.dumps(request), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


class AuthorizationPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vanian-auth-predicates-")
        self.directory = Path(self.temp.name).resolve()
        self.directory.chmod(0o700)
        self.tool = "bank-loan_read"
        self.arguments = {"loan_id": 1, "amount": 0}
        self.keys = rust(BIN / "aip-execution-assurance", "init-authority", {
            "directory": str(self.directory / "keys"), "model_id": "unit-test-no-model-call",
            "allowed_calls": [{"tool_id": self.tool, "arguments": self.arguments}],
            "observer_id": "collector.test", "observer_public_key_hex": "ab" * 32,
        })
        self.agent = self.keys["agent_id"]
        self.decision = uuid.uuid4().hex
        fixture = rust(BIN / "examples/contextforge_fixture", None, {
            "agent_id": self.agent, "decision_id": self.decision,
            "tool_id": self.tool, "arguments": self.arguments,
        })
        trust = json.loads(Path(self.keys["run_trust_path"]).read_text())
        # This operator-side replacement expressly anchors the test fixture.
        # No runtime agent may provide or modify this trust file.
        trust["decision_point_id"] = fixture["decision_point_id"]
        trust["decision_point_public_key_hex"] = fixture["public_key"]
        self.trust = self.directory / "gateway-trust.json"
        self.trust.write_text(json.dumps(trust))
        self.trust.chmod(0o600)
        self.decisions = self.directory / "authorized-decisions"
        self.decisions.mkdir(mode=0o700)
        self.decision_file = self.decisions / (self.decision + ".json")
        self.decision_file.write_text(json.dumps(fixture["expectation"]))
        self.decision_file.chmod(0o600)
        self.environment = {
            "AIP_GATEWAY_KEY_FILE": self.keys["gateway_key_path"],
            "AIP_GATEWAY_PUBLIC_KEY": self.keys["gateway_public_key_hex"],
            "AIP_GATEWAY_ID": self.keys["gateway_id"], "AIP_GATEWAY_KEY_VERSION": "1",
            "AIP_GATEWAY_RECEIPTS": str(self.directory / "receipts.jsonl"),
            "AIP_AUTHORIZATION_DIR": str(self.decisions), "AIP_RUN_TRUST_FILE": str(self.trust),
        }
        self.env_patch = patch.dict(os.environ, self.environment)
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.temp.cleanup()

    def plugin(self, **options):
        return VanianToolReceiptPlugin(PluginConfig(
            name="VanianToolReceipt", kind="vanian_contextforge.VanianToolReceiptPlugin",
            config={"signer_binary": str(BIN / "aip-tool-receipt"),
                    "authorization_binary": str(BIN / "aip-execution-assurance"),
                    "replay_database": str(self.directory / "replay.sqlite3"),
                    "tools": [self.tool], "agent_principals": {"validator@example.com": self.agent},
                    "require_authorization": True, **options}))

    def invoke(self, plugin, *, arguments=None, decision=None):
        context = PluginContext(global_context=GlobalContext(
            request_id=uuid.uuid4().hex, user={"email": "validator@example.com"}))
        payload = ToolPreInvokePayload(name=self.tool, args=arguments or self.arguments,
            headers=HttpHeaderPayload(root={"X-AIP-Agent-Id": self.agent,
                "X-AIP-Decision-Id": decision or self.decision, "X-AIP-Request-Id": uuid.uuid4().hex}))
        return asyncio.run(plugin.tool_pre_invoke(payload, context))

    def test_valid_signed_fixture_permits_pre_dispatch_and_replay_is_refused(self):
        plugin = self.plugin()
        self.assertTrue(self.invoke(plugin).continue_processing)
        result = self.invoke(plugin)
        self.assertFalse(result.continue_processing)
        self.assertEqual(result.violation.code, "REPLAY_REFUSED")

    def test_random_reference_and_changed_resource_fail_before_dispatch(self):
        plugin = self.plugin()
        for options in [{"decision": uuid.uuid4().hex}, {"arguments": {"loan_id": 2, "amount": 0}}]:
            result = self.invoke(plugin, **options)
            self.assertFalse(result.continue_processing)
            self.assertEqual(result.violation.code, "AUTHORIZATION_REFUSED")

    def test_modified_signed_record_is_refused(self):
        expectation = json.loads(self.decision_file.read_text())
        expectation["valid_until"] = 0
        self.decision_file.write_text(json.dumps(expectation))
        self.assertFalse(self.invoke(self.plugin()).continue_processing)

    def test_decision_symlink_and_reference_alias_are_refused(self):
        original = self.decision_file.read_text()
        alternative = self.directory / "elsewhere.json"
        alternative.write_text(original)
        self.decision_file.unlink()
        self.decision_file.symlink_to(alternative)
        self.assertFalse(self.invoke(self.plugin()).continue_processing)
        self.decision_file.unlink()
        self.decision_file.write_text(original)
        self.decision_file.chmod(0o600)
        alias = uuid.uuid4().hex
        alias_path = self.decisions / (alias + ".json")
        alias_path.write_text(original)
        alias_path.chmod(0o600)
        self.assertFalse(self.invoke(self.plugin(), decision=alias).continue_processing)

    def test_writable_decision_storage_and_string_policy_switch_are_rejected(self):
        with self.assertRaises(ValueError):
            self.plugin(require_authorization="true")
        self.decisions.chmod(0o777)
        with self.assertRaises(ValueError):
            self.plugin()
        self.decisions.chmod(0o700)


if __name__ == "__main__":
    unittest.main(verbosity=2)
