"""Agent and operator registry, and signed revocations (native, not P0-059). Pure except load().

Registry JSON:
    {"agents": {"<agent_id>": {"public_key_hex": "...", "owner": "...", "framework": "...",
                               "host": "...", "runtime": "...", "parent": null | "<agent_id>",
                               "responsible_human": "..."}},
     "operators": {"<operator_id>": {"public_key_hex": "..."}}}

Revocations JSON (signed by a registered operator; verified, or the gate refuses to start):
    {"list": {"revoked_jtis": [...], "issued_at_ms": int, "operator_id": "..."}, "signature_hex": "..."}

Every field is validated; anything unexpected is a RegistryError (fail closed).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import signing

ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
AGENT_FIELDS = ("public_key_hex", "owner", "framework", "host", "runtime", "parent", "responsible_human")


class RegistryError(ValueError):
    """The registry or revocation list is not usable. The gate must not start."""


@dataclass(frozen=True)
class Registry:
    agents: dict[str, dict]
    operators: dict[str, str]  # operator_id -> public key hex

    def agent_key(self, agent_id: str) -> str | None:
        a = self.agents.get(agent_id)
        return a["public_key_hex"] if a else None


def parse(doc: object) -> Registry:
    """Validate a registry document."""
    if not isinstance(doc, dict) or set(doc) != {"agents", "operators"}:
        raise RegistryError("registry must have exactly 'agents' and 'operators'")
    agents, operators = doc["agents"], doc["operators"]
    if not isinstance(agents, dict) or not isinstance(operators, dict):
        raise RegistryError("agents and operators must be objects")
    for aid, a in agents.items():
        if not ID.match(aid) or not isinstance(a, dict) or set(a) != set(AGENT_FIELDS):
            raise RegistryError(f"agent {aid!r}: needs exactly {AGENT_FIELDS}")
        if not HEX64.match(str(a["public_key_hex"])):
            raise RegistryError(f"agent {aid!r}: public_key_hex must be 64 lowercase hex")
        for f in ("owner", "framework", "host", "runtime", "responsible_human"):
            if not isinstance(a[f], str) or not a[f]:
                raise RegistryError(f"agent {aid!r}: {f} must be a non-empty string")
        if a["parent"] is not None and a["parent"] not in agents:
            raise RegistryError(f"agent {aid!r}: parent {a['parent']!r} is not a registered agent")
    ops = {}
    for oid, o in operators.items():
        if not ID.match(oid) or not isinstance(o, dict) or set(o) != {"public_key_hex"} or not HEX64.match(str(o["public_key_hex"])):
            raise RegistryError(f"operator {oid!r}: needs exactly a 64-hex public_key_hex")
        ops[oid] = o["public_key_hex"]
    if set(ops) & set(agents):
        raise RegistryError("an id cannot be both an agent and an operator")
    return Registry(agents=agents, operators=ops)


def verified_revocations(doc: object, reg: Registry) -> tuple[list[str], dict]:
    """Return (revoked_jtis, list) only if signed by a registered operator."""
    if not isinstance(doc, dict) or set(doc) != {"list", "signature_hex"}:
        raise RegistryError("revocations must have exactly 'list' and 'signature_hex'")
    lst = doc["list"]
    if not isinstance(lst, dict) or set(lst) != {"revoked_jtis", "issued_at_ms", "operator_id"}:
        raise RegistryError("revocation list fields are revoked_jtis, issued_at_ms, operator_id")
    jtis, at, op = lst["revoked_jtis"], lst["issued_at_ms"], lst["operator_id"]
    if not isinstance(jtis, list) or not all(isinstance(j, str) and j for j in jtis):
        raise RegistryError("revoked_jtis must be a list of non-empty strings")
    if not isinstance(at, int) or isinstance(at, bool) or at < 0:
        raise RegistryError("issued_at_ms must be a non-negative integer")
    key = reg.operators.get(op)
    if key is None:
        raise RegistryError(f"revocations signed by unregistered operator {op!r}")
    if not signing.verify(signing.DOMAIN_REVOCATIONS, lst, doc["signature_hex"], key):
        raise RegistryError("revocation list signature does not verify")
    return sorted(set(jtis)), lst


def load(registry_path: Path, revocations_path: Path) -> tuple[Registry, list[str]]:
    """Read and validate both files; any problem raises RegistryError."""
    try:
        reg = parse(json.loads(registry_path.read_text()))
        revoked, _ = verified_revocations(json.loads(revocations_path.read_text()), reg)
    except (OSError, json.JSONDecodeError) as e:
        raise RegistryError(f"cannot read registry/revocations: {e}") from None
    return reg, revoked
