"""Locust profile for AIP identity-service load tests.

Run against a started aip-service:
  locust -f aip-service/load-tests/locustfile.py --host http://127.0.0.1:8081
"""

from __future__ import annotations

import base64
import json
import os
import random
import uuid
from typing import Optional

from locust import HttpUser, between, task


ISSUE_SCOPE = {
    "allowed": [
        "evaluate_content",
        "submit_audit_entry",
        "issue_sub_delegation",
        "read_audit_log",
    ],
    "denied": [],
}

READ_ONLY_SCOPE = {
    "allowed": ["read_audit_log"],
    "denied": [],
}


def decode_jwt_payload(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))


class AipIdentityUser(HttpUser):
    wait_time = between(0.001, 0.02)

    def on_start(self) -> None:
        self.tokens: list[str] = []
        self.root_jtis: list[str] = []
        self.delegations_by_root: dict[str, list[str]] = {}
        self.issue_root_token()

    def issue_root_token(self) -> Optional[str]:
        payload = {
            "agent_id": str(uuid.uuid4()),
            "agent_type": random.choice(["human", "ai_model", "service"]),
            "metadata": {
                "load_profile": "aip_identity",
                "worker": str(id(self)),
            },
            "ttl_seconds": 600,
        }
        with self.client.post(
            "/v1/identity/issue",
            json=payload,
            name="/v1/identity/issue",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"issue failed: {response.text[:200]}")
                return None
            token = response.json()["token"]
            claims = decode_jwt_payload(token)
            self.tokens.append(token)
            self.root_jtis.append(claims["jti"])
            self.delegations_by_root.setdefault(claims["jti"], [])
            response.success()
            return token

    @task(8)
    def verify_hot_path(self) -> None:
        token = random.choice(self.tokens) if self.tokens else self.issue_root_token()
        if not token:
            return
        with self.client.post(
            "/v1/identity/verify",
            json={"token": token},
            name="/v1/identity/verify",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"verify HTTP {response.status_code}")
                return
            body = response.json()
            if not body.get("valid"):
                response.failure(f"token rejected: {body.get('reason')}")
            else:
                response.success()

    @task(3)
    def issue_and_verify(self) -> None:
        token = self.issue_root_token()
        if token:
            self.client.post(
                "/v1/identity/verify",
                json={"token": token},
                name="/v1/identity/verify",
            )

    @task(2)
    def delegate_and_verify_chain(self) -> None:
        token = random.choice(self.tokens) if self.tokens else self.issue_root_token()
        if not token:
            return
        root_jti = decode_jwt_payload(token)["jti"]
        payload = {
            "parent_token": token,
            "delegatee_id": str(uuid.uuid4()),
            "scope": random.choice([ISSUE_SCOPE, READ_ONLY_SCOPE]),
            "ttl_seconds": 300,
        }
        with self.client.post(
            "/v1/identity/delegate",
            json=payload,
            name="/v1/identity/delegate",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"delegate failed: {response.text[:200]}")
                return
            delegation_id = response.json()["delegation"]["delegation_id"]
            self.delegations_by_root.setdefault(root_jti, []).append(delegation_id)
            response.success()

        self.client.post(
            "/v1/identity/verify-chain",
            json={"root_token": token, "delegation_ids": [delegation_id]},
            name="/v1/identity/verify-chain",
        )

    @task(1)
    def cascade_revoke_small_tree(self) -> None:
        if not self.tokens:
            token = self.issue_root_token()
            if not token:
                return
        token = random.choice(self.tokens)
        root_jti = decode_jwt_payload(token)["jti"]
        fanout = int(os.getenv("AIP_LOAD_CASCADE_FANOUT", "5"))

        for _ in range(fanout):
            self.client.post(
                "/v1/identity/delegate",
                json={
                    "parent_token": token,
                    "delegatee_id": str(uuid.uuid4()),
                    "scope": READ_ONLY_SCOPE,
                    "ttl_seconds": 300,
                },
                name="/v1/identity/delegate",
            )

        with self.client.post(
            "/v1/identity/revoke",
            json={
                "jti": root_jti,
                "revoked_by": "locust-load-test",
                "reason": "cascade revocation stress sample",
                "cascade": True,
            },
            name="/v1/identity/revoke cascade",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"cascade revoke failed: {response.text[:200]}")
                return
            if response.json().get("revoked_count", 0) < 1:
                response.failure("cascade revoke returned zero revocations")
                return
            response.success()

        self.tokens = [candidate for candidate in self.tokens if candidate != token]
        if not self.tokens:
            self.issue_root_token()
