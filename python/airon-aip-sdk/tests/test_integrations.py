from __future__ import annotations

import time
import unittest

from test_core import fake_token

from airon_aip.identity import AgentIdentity
from airon_aip.integrations.langchain import aip_runnable_config
from airon_aip.integrations.numpy import AipArray
from airon_aip.integrations.torch import identity_hash


def identity() -> AgentIdentity:
    return AgentIdentity(
        alias="ml-agent",
        agent_id="550e8400-e29b-41d4-a716-446655440000",
        agent_type="ai_model",
        token=fake_token("550e8400-e29b-41d4-a716-446655440000", "ai_model", exp=int(time.time()) + 3600),
        jti="jti-ml",
        issued_at="2026-06-03T00:00:00Z",
        expires_at="2026-06-03T01:00:00Z",
        public_key_fingerprint="abc123",
        metadata={"framework": "test"},
    )


class FakeArray:
    shape = (2, 2)
    dtype = "float32"

    def tobytes(self) -> bytes:
        return b"1234"


class IntegrationTests(unittest.TestCase):
    def test_langchain_config_contains_tags_and_metadata(self) -> None:
        config = aip_runnable_config(identity())
        self.assertIn("airon-aip", config["tags"])
        self.assertEqual(config["metadata"]["aip_jti"], "jti-ml")

    def test_numpy_wrapper_reports_metadata_without_numpy_dependency(self) -> None:
        wrapped = AipArray(array=FakeArray(), identity=identity())
        metadata = wrapped.metadata()
        self.assertEqual(metadata["array"]["shape"], (2, 2))
        self.assertEqual(metadata["identity"]["aip_agent_type"], "ai_model")

    def test_torch_identity_hash_is_stable_without_torch_dependency(self) -> None:
        self.assertEqual(identity_hash(identity()), identity_hash(identity()))


if __name__ == "__main__":
    unittest.main()
