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
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from cpex.framework import GlobalContext, HttpHeaderPayload, PluginConfig, PluginContext, TenantPluginManager
from cpex.framework.hooks.tools import ToolHookType, ToolPostInvokePayload, ToolPreInvokePayload
from cpex.framework.models import Config

from vanian_contextforge import ReceiptScopeMiddleware, VanianToolReceiptPlugin

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

    def pre_payload(self, *, arguments=None, decision=None):
        return ToolPreInvokePayload(name=self.tool, args=arguments or self.arguments,
            headers=HttpHeaderPayload(root={"X-AIP-Agent-Id": self.agent,
                "X-AIP-Decision-Id": decision or self.decision, "X-AIP-Request-Id": uuid.uuid4().hex}))

    def context(self, **changes):
        fields = {"request_id": "gateway-request-1", "user": {"email": "validator@example.com"},
                  "tenant_id": "bank", "server_id": "read-service"}
        return PluginContext(global_context=GlobalContext(**{**fields, **changes}))

    def invoke(self, plugin, **options):
        return asyncio.run(plugin.tool_pre_invoke(self.pre_payload(**options), self.context()))

    @staticmethod
    async def http(handler):
        async def endpoint(scope, receive, send):
            return await handler()
        return await ReceiptScopeMiddleware(endpoint)({"type": "http"}, None, None)

    def post(self, name=None, **changes):
        return ToolPostInvokePayload(name=name or self.tool, result={"isError": False, "content": [], **changes})

    def assert_uncovered(self, result):
        payload = result.modified_payload.result
        self.assertTrue(payload["isError"])
        self.assertEqual(payload["_meta"]["vanian"], {"receipt_persisted": False, "coverage": "CANNOT_PROVE"})

    def receipts(self):
        sink = Path(self.environment["AIP_GATEWAY_RECEIPTS"])
        return [json.loads(line) for line in sink.read_text().splitlines()] if sink.exists() else []

    def test_replaced_cpex_manager_consumes_the_original_request_reservation_once(self):
        entry = {**self.plugin().config.model_dump(mode="json"), "hooks": ["tool_pre_invoke", "tool_post_invoke"],
                 "mode": "sequential", "on_error": "fail"}
        config = Config.model_validate({"plugin_dirs": [str(Path(__file__).parent.resolve())],
            "plugin_settings": {"include_user_info": True, "parallel_execution_within_band": False}, "plugins": [entry]})
        pre = self.pre_payload()
        identity = self.context().global_context

        async def replace_during_call():
            first = TenantPluginManager(config)
            await first.initialize()
            try:
                result, contexts = await first.invoke_hook(ToolHookType.TOOL_PRE_INVOKE, pre, identity)
                self.assertTrue(result.continue_processing)
                self.assertIsNotNone(result.modified_payload)
            finally:
                await first.shutdown()
            second = TenantPluginManager(config)
            await second.initialize()
            try:
                post, fresh = await second.invoke_hook(ToolHookType.TOOL_POST_INVOKE, self.post(), identity, contexts)
                self.assertTrue(set(fresh).isdisjoint(contexts))
                metadata = post.modified_payload.result["_meta"]["vanian"]
                self.assertTrue(metadata["receipt_persisted"])
                self.assertEqual(self.receipts(), [metadata["signed_receipt"]])
                duplicate, _ = await second.invoke_hook(ToolHookType.TOOL_POST_INVOKE, self.post(), identity, fresh)
                self.assert_uncovered(duplicate)
            finally:
                await second.shutdown()

        asyncio.run(self.http(replace_during_call))
        signed, = self.receipts()
        verified = rust(BIN / "aip-tool-receipt", "verify", signed)
        self.assertTrue(verified["verified"])
        receipt = verified["receipt"]
        self.assertEqual((receipt["agent_id"], bytes(receipt["decision_id"]).hex(), receipt["tool_id"],
                          receipt["tool_call_id"], receipt["disposition"]), (self.agent, self.decision, self.tool,
                          pre.headers.root["X-AIP-Request-Id"], "Forwarded"))
        with sqlite3.connect(self.directory / "replay.sqlite3") as db:
            self.assertEqual(db.execute("SELECT state FROM requests").fetchall(), [("Forwarded",)])

    def test_other_request_and_callback_after_cancellation_cannot_use_the_reservation(self):
        plugin, parent_context = self.plugin(), self.context()
        async def run():
            authorized, release = asyncio.Event(), asyncio.Event()
            children = []
            async def late_callback():
                await release.wait()
                self.assert_uncovered(await plugin.tool_post_invoke(self.post(), parent_context))
            async def owner():
                result = await plugin.tool_pre_invoke(self.pre_payload(), parent_context)
                self.assertTrue(result.continue_processing)
                children.append(asyncio.create_task(late_callback()))
                authorized.set()
                await asyncio.Future()
            async def other():
                await asyncio.wait_for(authorized.wait(), timeout=10)
                self.assert_uncovered(await plugin.tool_post_invoke(self.post(), self.context()))
            owner_task = asyncio.create_task(self.http(owner))
            await self.http(other)
            owner_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await owner_task
            release.set()
            await asyncio.gather(*children)
        asyncio.run(run())
        self.assertEqual(self.receipts(), [])
        with sqlite3.connect(self.directory / "replay.sqlite3") as db:
            self.assertEqual(db.execute("SELECT state FROM requests").fetchall(), [("pending",)])

    def test_callback_must_match_principal_tenant_server_tool_request_and_configuration(self):
        variants = ({"user": "other@example.com"}, {"tenant_id": "other"}, {"server_id": "other"},
                    {"request_id": "other"}, {"name": "other-tool"}, {"max_requests": 10})
        for index, variant in enumerate(variants):
            with self.subTest(variant=variant):
                journal = str(self.directory / f"boundary-{index}.sqlite3")
                before = self.plugin(replay_database=journal)
                policy = {"max_requests": variant["max_requests"]} if "max_requests" in variant else {}
                after = self.plugin(replay_database=journal, **policy)
                identity = {k: v for k, v in variant.items() if k not in {"name", "max_requests"}}
                async def changed_boundary():
                    pre = await before.tool_pre_invoke(self.pre_payload(), self.context())
                    self.assertTrue(pre.continue_processing)
                    post = await after.tool_post_invoke(self.post(name=variant.get("name")), self.context(**identity))
                    self.assert_uncovered(post)
                asyncio.run(self.http(changed_boundary))
        self.assertEqual(self.receipts(), [])

    def test_ambiguous_batch_preserves_the_refusal_and_never_guesses_the_success(self):
        plugin = self.plugin()
        async def run():
            self.assertTrue((await plugin.tool_pre_invoke(self.pre_payload(), self.context())).continue_processing)
            refused = await plugin.tool_pre_invoke(self.pre_payload(), self.context())
            self.assertEqual(refused.violation.code, "REPLAY_REFUSED")
            error = await plugin.tool_post_invoke(self.post(isError=True), self.context())
            self.assertIsNone(error.modified_payload)
            self.assert_uncovered(await plugin.tool_post_invoke(self.post(), self.context()))
        asyncio.run(self.http(run))
        signed, = self.receipts()
        self.assertEqual(signed["receipt"]["disposition"], "Refused")

    def test_unwrapped_unbound_success_and_untrusted_receipt_metadata_fail_closed(self):
        plugin = self.plugin()
        untrusted = {"vanian": {"receipt_persisted": True}}
        for result in (self.post(), self.post(isError=True, _meta=untrusted), self.post(isError=True, meta=untrusted)):
            self.assert_uncovered(asyncio.run(plugin.tool_post_invoke(result, self.context())))
        self.assertEqual(self.receipts(), [])

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
