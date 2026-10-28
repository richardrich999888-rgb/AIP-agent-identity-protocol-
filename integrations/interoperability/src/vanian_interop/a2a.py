"""A2A 1.x through the official SDK, constrained by operator endpoint policy.

Discovery authenticates the serving endpoint, not every statement in its card.
The optional delegation JWT is a VANIAN deployment profile, NOT an A2A
standard, an AIP identity, or an ExpectedExecution. Institutions must issue it
outside the agent and separately establish execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
import ssl
import stat
import time
from typing import Callable

import httpx

from .identity import JwtTrust, _verified_claims
from .records import commitment
from .transport import endpoint_origin


class DelegationGuard:
    def __init__(self, trust: JwtTrust, replay_database: str, *, allowed_subjects: frozenset[str],
                 allowed_actions: frozenset[str], revoked_jtis: frozenset[str] = frozenset()):
        if not allowed_subjects or not allowed_actions or trust.accepted_types != ("vanian-delegation+jwt",):
            raise ValueError("explicit delegation profile, delegators and actions required")
        self.trust, self.database = trust, replay_database
        self.subjects, self.actions, self.revoked = allowed_subjects, allowed_actions, revoked_jtis
        descriptor = os.open(replay_database, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise ValueError("replay database must be an owner-only regular file")
        finally:
            os.close(descriptor)
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS delegations (issuer TEXT NOT NULL, jti TEXT NOT NULL, PRIMARY KEY(issuer,jti))")

    def accept(self, token: str, *, parent_task: str, request: dict, action: str,
               resource: str, now_ms: int | None = None) -> dict:
        now_ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
        claims, _ = _verified_claims(token, self.trust, spiffe=False, now_ms=now_ms)
        expected = {"parent_task": parent_task, "request_commitment": commitment(request),
                    "action": action, "resource": resource, "tenant": self.trust.tenant}
        if claims["sub"] not in self.subjects or action not in self.actions or not parent_task or not resource:
            raise ValueError("delegation outside configured scope")
        if any(claims.get(key) != value for key, value in expected.items()):
            raise ValueError("delegation is not bound to this request/context")
        jti = claims.get("jti")
        if not isinstance(jti, str) or not 16 <= len(jti) <= 128 or jti in self.revoked:
            raise ValueError("invalid or revoked delegation")
        if claims["exp"] - claims["iat"] > self.trust.max_age_seconds:
            raise ValueError("delegation lifetime exceeds policy")
        # Reservation precedes dispatch; failures remain consumed (at-most-once).
        try:
            with sqlite3.connect(self.database) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("INSERT INTO delegations VALUES (?, ?)", (self.trust.issuer, jti))
        except sqlite3.IntegrityError as error:
            raise ValueError("delegation replay refused") from error
        return {**expected, "delegator": claims["sub"], "issuer": self.trust.issuer,
                "delegation_id": jti, "credential_sha256": hashlib.sha256(token.encode()).hexdigest(),
                "execution_authority": "NOT_ESTABLISHED", "remote_kernel": "UNOBSERVED"}


@dataclass(frozen=True)
class CardReference:
    retrieval_url: str
    card_commitment: str
    endpoint_authentication: str
    card_signature_status: str = "NOT_VERIFIED"
    capabilities_status: str = "DECLARED"


class A2AConnection:
    """One institution-approved origin. Credentials never follow card URLs."""
    def __init__(self, base_url: str, *, ca_file: str, client_cert: str,
                 client_key: str, credential_provider: Callable[[], str]):
        self.origin = endpoint_origin(base_url)
        self.base_url = base_url.rstrip("/")
        self.credential_provider = credential_provider
        context = ssl.create_default_context(cafile=ca_file)
        context.load_cert_chain(client_cert, client_key)
        self.http = httpx.AsyncClient(verify=context, follow_redirects=False, trust_env=False,
                                     timeout=60, event_hooks={"request": [self._guard_request],
                                                             "response": [self._guard_response]})
        self.client = None
        self.card_reference = None

    async def _guard_request(self, request: httpx.Request):
        if endpoint_origin(str(request.url)) != self.origin:
            raise ValueError("A2A card attempted cross-origin request")
        token = self.credential_provider()
        if not token or any(c in token for c in "\r\n"):
            raise ValueError("missing audience-scoped remote credential")
        request.headers["Authorization"] = "Bearer " + token

    @staticmethod
    async def _guard_response(response: httpx.Response):
        if 300 <= response.status_code < 400:
            raise ValueError("A2A redirect refused")
        if int(response.headers.get("content-length", "0")) > 1_048_576:
            raise ValueError("A2A response too large")
        # This profile is nonstreaming; bound even chunked response bodies.
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > 1_048_576:
                raise ValueError("A2A response too large")
        response._content = bytes(body)

    async def discover(self) -> CardReference:
        from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
        from google.protobuf.json_format import MessageToDict
        card = await A2ACardResolver(self.http, self.base_url).get_agent_card()
        if not card.supported_interfaces:
            raise ValueError("card contains no supported interface")
        for interface in card.supported_interfaces:
            if endpoint_origin(interface.url) != self.origin:
                raise ValueError("card endpoint differs from operator-approved origin")
        self.client = ClientFactory(ClientConfig(streaming=False, httpx_client=self.http)).create(card)
        self.card_reference = CardReference(self.base_url + "/.well-known/agent-card.json",
                                            commitment(MessageToDict(card)), "TLS_SERVER_CERTIFICATE")
        return self.card_reference

    async def send(self, request):
        if self.client is None:
            raise ValueError("discover and authenticate the endpoint first")
        # Official SDK owns wire serialization, task lifecycle and version rules.
        return [event async for event in self.client.send_message(request)]

    async def close(self):
        await self.http.aclose()
