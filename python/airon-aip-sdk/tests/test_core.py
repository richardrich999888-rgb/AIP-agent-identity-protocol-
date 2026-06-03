from __future__ import annotations

import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from airon_aip import (
    AIPConfig,
    AgentPassport,
    AgentPassportDocument,
    AipClient,
    CapabilityScope,
    IdentityStore,
    PersistentAgentIdentity,
)
from airon_aip.identity import AgentIdentity
from airon_aip.manifest import artifact_manifest, canonical_manifest_hash


def fake_token(agent_id: str, agent_type: str, jti: str = "jti-1", exp: Optional[int] = None) -> str:
    header = {"alg": "EdDSA", "typ": "JWT"}
    payload = {
        "sub": agent_id,
        "agt": agent_type,
        "iat": int(time.time()),
        "exp": exp or int(time.time()) + 3600,
        "jti": jti,
    }

    def segment(value: Dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{segment(header)}.{segment(payload)}.signature"


class FakeTransport:
    def __init__(self) -> None:
        self.issued = 0

    def __call__(self, method: str, url: str, body: Optional[Dict[str, Any]], timeout: float) -> Tuple[int, Dict[str, Any]]:
        if url.endswith("/health"):
            return 200, {"status": "ok"}
        if url.endswith("/v1/identity/issue"):
            assert body is not None
            self.issued += 1
            agent_id = str(body["agent_id"])
            agent_type = str(body["agent_type"])
            return 200, {
                "token": fake_token(agent_id, agent_type, jti=f"jti-{self.issued}"),
                "issued_at": "2026-06-03T00:00:00Z",
                "expires_at": "2026-06-03T01:00:00Z",
                "public_key_fingerprint": "abc123",
            }
        if url.endswith("/v1/identity/verify"):
            return 200, {
                "valid": True,
                "agent_id": "agent",
                "agent_type": "ai_model",
                "expired": False,
                "reason": None,
            }
        if url.endswith("/v1/identity/delegate"):
            assert body is not None
            return 200, {
                "delegation": {
                    "delegation_id": "del-1",
                    "parent_jti": "jti-1",
                    "delegatee_id": body["delegatee_id"],
                    "scope": body["scope"],
                    "depth": 1,
                    "issued_at": "2026-06-03T00:00:00Z",
                    "expires_at": "2026-06-03T01:00:00Z",
                    "entry_hash": "hash",
                }
            }
        if url.endswith("/v1/passports/issue"):
            assert body is not None
            now = int(time.time())
            return 200, {
                "passport": {
                    "header": {
                        "version": "1.0.0",
                        "typ": "AIP-PASSPORT",
                        "alg": "Ed25519",
                    },
                    "body": {
                        "passport_id": "urn:aip:passport:550e8400-e29b-41d4-a716-446655440010",
                        "subject": {
                            "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                            "friendly_name": body["friendly_name"],
                        },
                        "issuer": {
                            "name": "AIRON AIP Root",
                            "id": "airon.aip.root",
                            "registry_url": "http://127.0.0.1:8081",
                            "public_key_fingerprint": "abc123",
                            "classical_pubkey": "issuer-key",
                        },
                        "constraints": {
                            "issued_at": now,
                            "expires_at": now + int(body["ttl_seconds"]),
                            "capabilities": body["capabilities"],
                            "max_delegation_depth": body["max_delegation_depth"],
                        },
                        "lineage": [
                            {
                                "actor": "550e8400-e29b-41d4-a716-446655440000",
                                "action": "AUTHORIZE",
                                "timestamp": now,
                                "signature": "lineage-sig",
                            }
                        ],
                        "environmental_lock": body["environmental_lock"]
                        or {"runtime": "python-3.11", "image_hash": "sha256:unknown"},
                    },
                    "proof": {"signature": "passport-sig"},
                },
                "passport_hash": "passport-hash",
            }
        if url.endswith("/v1/passports/verify"):
            assert body is not None
            passport = body["passport"]
            return 200, {
                "valid": True,
                "status": "PASS",
                "reason": None,
                "passport_id": passport["body"]["passport_id"],
                "agent_id": passport["body"]["subject"]["agent_id"],
                "capabilities": passport["body"]["constraints"]["capabilities"],
                "expires_at": passport["body"]["constraints"]["expires_at"],
            }
        return 404, {"error": "not found"}


class CoreSdkTests(unittest.TestCase):
    def test_persistent_identity_reuses_valid_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = IdentityStore(Path(tmp) / "ids.json")
            client = AipClient(transport=FakeTransport())
            manager = PersistentAgentIdentity(client, alias="agent-a", store=store)

            first = manager.load_or_issue(agent_type="ai_model", verify_remote=True)
            second = manager.load_or_issue(agent_type="ai_model", verify_remote=True)

            self.assertEqual(first.agent_id, second.agent_id)
            self.assertEqual(first.jti, second.jti)
            self.assertEqual(store.list_aliases(), ["agent-a"])

    def test_delegation_model_uses_service_scope_shape(self) -> None:
        client = AipClient(transport=FakeTransport())
        delegation = client.delegate(
            parent_token="parent",
            delegatee_id="550e8400-e29b-41d4-a716-446655440001",
            scope=CapabilityScope.audit_reader(),
        )
        self.assertEqual(delegation.delegation_id, "del-1")
        self.assertEqual(delegation.scope["allowed"], ["read_audit_log"])

    def test_artifact_manifest_hash_is_canonical(self) -> None:
        identity = AgentIdentity(
            alias="agent-a",
            agent_id="550e8400-e29b-41d4-a716-446655440000",
            agent_type="ai_model",
            token=fake_token("550e8400-e29b-41d4-a716-446655440000", "ai_model"),
            jti="jti-1",
            issued_at="2026-06-03T00:00:00Z",
            expires_at="2026-06-03T01:00:00Z",
            public_key_fingerprint="abc123",
            metadata={"framework": "pytest"},
        )
        manifest = artifact_manifest(identity=identity, artifact_digest="00" * 32)
        digest_a = canonical_manifest_hash(manifest)
        digest_b = canonical_manifest_hash(json.loads(json.dumps(manifest)))
        self.assertEqual(digest_a, digest_b)

    def test_agent_passport_issue_save_and_verify(self) -> None:
        client = AipClient(transport=FakeTransport())
        service = AgentPassport(AIPConfig(aip_token="parent-token"), client=client)

        passport = service.issue(
            friendly_name="InvoiceBot",
            capabilities=["invoice.read", "ledger.post"],
            metadata={"runtime": "langchain-v0.2"},
        )

        self.assertEqual(passport.passport_hash, "passport-hash")
        self.assertEqual(passport.passport_id, "urn:aip:passport:550e8400-e29b-41d4-a716-446655440010")
        self.assertEqual(passport.capabilities, ["invoice.read", "ledger.post"])

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent.passport.json"
            passport.save(path)
            loaded = AgentPassportDocument.load(path)

        verification = service.verify(loaded)
        self.assertTrue(verification.is_valid)
        self.assertEqual(verification.status, "PASS")
        self.assertEqual(verification.capabilities, ["invoice.read", "ledger.post"])


if __name__ == "__main__":
    unittest.main()
