from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Dict, Optional

from .client import AipClient

if TYPE_CHECKING:
    from .store import IdentityStore


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("AIP JWT must have three segments")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))


@dataclass
class AgentIdentity:
    alias: str
    agent_id: str
    agent_type: str
    token: str
    jti: str
    issued_at: str
    expires_at: str
    public_key_fingerprint: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_issue_response(
        cls,
        *,
        alias: str,
        agent_id: str,
        agent_type: str,
        metadata: Optional[Dict[str, Any]],
        response: Dict[str, Any],
    ) -> "AgentIdentity":
        claims = decode_jwt_payload(response["token"])
        return cls(
            alias=alias,
            agent_id=agent_id,
            agent_type=agent_type,
            token=response["token"],
            jti=str(claims["jti"]),
            issued_at=str(response["issued_at"]),
            expires_at=str(response["expires_at"]),
            public_key_fingerprint=str(response["public_key_fingerprint"]),
            metadata=dict(metadata or {}),
        )

    @classmethod
    def from_json(cls, payload: Dict[str, Any]) -> "AgentIdentity":
        return cls(**payload)

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    def claims(self) -> Dict[str, Any]:
        return decode_jwt_payload(self.token)

    def expires_at_epoch(self) -> int:
        return int(self.claims()["exp"])

    def is_expired(self, *, skew_seconds: int = 30) -> bool:
        return int(time.time()) + skew_seconds >= self.expires_at_epoch()

    def authorization_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "X-AIP-Agent-ID": self.agent_id,
            "X-AIP-JTI": self.jti,
            "X-AIP-Key-Fingerprint": self.public_key_fingerprint,
        }

    def public_metadata(self) -> Dict[str, Any]:
        return {
            "aip_alias": self.alias,
            "aip_agent_id": self.agent_id,
            "aip_agent_type": self.agent_type,
            "aip_jti": self.jti,
            "aip_issued_at": self.issued_at,
            "aip_expires_at": self.expires_at,
            "aip_public_key_fingerprint": self.public_key_fingerprint,
            "aip_metadata": self.metadata,
        }


class PersistentAgentIdentity:
    """High-level persistent identity manager for a single Python agent."""

    def __init__(
        self,
        client: AipClient,
        *,
        alias: str,
        store: Optional["IdentityStore"] = None,
    ) -> None:
        self.client = client
        self.alias = alias
        if store is None:
            from .store import IdentityStore

            store = IdentityStore.default()
        self.store = store
        self.identity: Optional[AgentIdentity] = self.store.get(alias)

    def load_or_issue(
        self,
        *,
        agent_type: str = "ai_model",
        metadata: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 3600,
        verify_remote: bool = True,
        agent_id: Optional[str] = None,
    ) -> AgentIdentity:
        current = self.store.get(self.alias)
        if current and not current.is_expired():
            if not verify_remote or self.client.verify(current.token).valid:
                self.identity = current
                return current

        new_agent_id = agent_id or (current.agent_id if current else str(uuid.uuid4()))
        response = self.client.issue(
            agent_id=new_agent_id,
            agent_type=agent_type,
            metadata=metadata,
            ttl_seconds=ttl_seconds,
        )
        issued = AgentIdentity.from_issue_response(
            alias=self.alias,
            agent_id=new_agent_id,
            agent_type=agent_type,
            metadata=metadata,
            response=response,
        )
        self.store.put(issued)
        self.identity = issued
        return issued

    def require_identity(self) -> AgentIdentity:
        if self.identity is None:
            self.identity = self.store.get(self.alias)
        if self.identity is None:
            raise RuntimeError("No AIP identity loaded. Call load_or_issue() first.")
        return self.identity

    def verify(self) -> bool:
        return self.client.verify(self.require_identity().token).valid

    def authorization_headers(self) -> Dict[str, str]:
        return self.require_identity().authorization_headers()

    def revoke(self, *, revoked_by: str, reason: str, cascade: bool = True) -> Dict[str, Any]:
        identity = self.require_identity()
        return self.client.revoke(
            jti=identity.jti,
            revoked_by=revoked_by,
            reason=reason,
            cascade=cascade,
        )
