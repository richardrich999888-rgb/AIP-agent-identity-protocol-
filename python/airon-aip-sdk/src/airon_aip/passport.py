from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Union

from .client import AipClient
from .config import AIPConfig

JsonDict = Dict[str, Any]
PassportInput = Union["AgentPassportDocument", JsonDict, str]


@dataclass
class AgentPassportDocument:
    """Portable AIP AgentPassport document returned by the AIP service."""

    data: JsonDict
    passport_hash: Optional[str] = None

    @classmethod
    def load(cls, path: Union[str, Path]) -> "AgentPassportDocument":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_json(self) -> JsonDict:
        return dict(self.data)

    def to_compact_json(self) -> str:
        return json.dumps(self.data, separators=(",", ":"), sort_keys=True)

    def save(self, path: Union[str, Path]) -> None:
        Path(path).write_text(
            json.dumps(self.data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @property
    def passport_id(self) -> str:
        return str(self.data.get("body", {}).get("passport_id", ""))

    @property
    def capabilities(self) -> list[str]:
        raw = self.data.get("body", {}).get("constraints", {}).get("capabilities", [])
        return [str(value) for value in raw]


@dataclass(frozen=True)
class PassportVerification:
    is_valid: bool
    status: str
    reason: Optional[str] = None
    passport_id: Optional[str] = None
    agent_id: Optional[str] = None
    capabilities: list[str] = field(default_factory=list)
    expires_at: Optional[int] = None

    @classmethod
    def from_json(cls, payload: JsonDict) -> "PassportVerification":
        return cls(
            is_valid=bool(payload.get("valid", False)),
            status=str(payload.get("status", "TOXIC")),
            reason=payload.get("reason"),
            passport_id=payload.get("passport_id"),
            agent_id=payload.get("agent_id"),
            capabilities=[str(value) for value in payload.get("capabilities", [])],
            expires_at=payload.get("expires_at"),
        )


class AgentPassport:
    """High-level service client for issuing and verifying AgentPassports."""

    def __init__(
        self,
        config: Optional[AIPConfig] = None,
        *,
        client: Optional[AipClient] = None,
        aip_token: Optional[str] = None,
    ) -> None:
        self.config = config or AIPConfig.from_env()
        self.client = client or self.config.client()
        self.aip_token = aip_token or self.config.aip_token

    def issue(
        self,
        *,
        friendly_name: str,
        capabilities: Iterable[str],
        metadata: Optional[JsonDict] = None,
        environmental_lock: Optional[JsonDict] = None,
        aip_token: Optional[str] = None,
        ttl_seconds: int = 3600,
        max_delegation_depth: int = 3,
        subject_classical_pubkey: Optional[str] = None,
        subject_pqc_pubkey: Optional[str] = None,
    ) -> AgentPassportDocument:
        payload = self.client.issue_passport(
            friendly_name=friendly_name,
            capabilities=list(capabilities),
            aip_token=aip_token or self.aip_token,
            metadata=metadata,
            environmental_lock=environmental_lock,
            ttl_seconds=ttl_seconds,
            max_delegation_depth=max_delegation_depth,
            subject_classical_pubkey=subject_classical_pubkey,
            subject_pqc_pubkey=subject_pqc_pubkey,
        )
        return AgentPassportDocument(
            data=dict(payload["passport"]),
            passport_hash=payload.get("passport_hash"),
        )

    def verify(self, passport_header: PassportInput) -> PassportVerification:
        passport = self._coerce_passport(passport_header)
        payload = self.client.verify_passport(passport)
        return PassportVerification.from_json(payload)

    @staticmethod
    def _coerce_passport(passport: PassportInput) -> JsonDict:
        if isinstance(passport, AgentPassportDocument):
            return passport.to_json()
        if isinstance(passport, str):
            return json.loads(passport)
        return dict(passport)
