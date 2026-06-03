from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class CapabilityScope:
    allowed: List[str]
    denied: List[str]

    @classmethod
    def submitter(cls) -> "CapabilityScope":
        return cls(allowed=["evaluate_content"], denied=[])

    @classmethod
    def audit_reader(cls) -> "CapabilityScope":
        return cls(allowed=["read_audit_log"], denied=[])

    @classmethod
    def orchestrator(cls) -> "CapabilityScope":
        return cls(
            allowed=[
                "evaluate_content",
                "submit_audit_entry",
                "issue_sub_delegation",
                "read_audit_log",
            ],
            denied=[],
        )

    @classmethod
    def admin(cls) -> "CapabilityScope":
        return cls(
            allowed=[
                "evaluate_content",
                "submit_audit_entry",
                "issue_sub_delegation",
                "read_audit_log",
                "revoke_token",
            ],
            denied=[],
        )

    @classmethod
    def custom(cls, *, allowed: Iterable[str], denied: Iterable[str] = ()) -> "CapabilityScope":
        return cls(allowed=list(allowed), denied=list(denied))

    def to_json(self) -> Dict[str, Any]:
        return {"allowed": list(self.allowed), "denied": list(self.denied)}


@dataclass(frozen=True)
class VerifyResult:
    valid: bool
    agent_id: str
    agent_type: str
    expired: bool
    reason: Optional[str]

    @classmethod
    def from_json(cls, payload: Dict[str, Any]) -> "VerifyResult":
        return cls(
            valid=bool(payload["valid"]),
            agent_id=str(payload.get("agent_id", "")),
            agent_type=str(payload.get("agent_type", "")),
            expired=bool(payload.get("expired", False)),
            reason=payload.get("reason"),
        )


@dataclass(frozen=True)
class Delegation:
    delegation_id: str
    parent_jti: str
    delegatee_id: str
    scope: Dict[str, Any]
    depth: int
    issued_at: str
    expires_at: str
    entry_hash: str

    @classmethod
    def from_json(cls, payload: Dict[str, Any]) -> "Delegation":
        return cls(
            delegation_id=str(payload["delegation_id"]),
            parent_jti=str(payload["parent_jti"]),
            delegatee_id=str(payload["delegatee_id"]),
            scope=dict(payload["scope"]),
            depth=int(payload["depth"]),
            issued_at=str(payload["issued_at"]),
            expires_at=str(payload["expires_at"]),
            entry_hash=str(payload["entry_hash"]),
        )
