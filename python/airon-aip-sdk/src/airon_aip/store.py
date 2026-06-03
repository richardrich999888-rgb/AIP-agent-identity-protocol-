from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

from .identity import AgentIdentity


class IdentityStore:
    """JSON-backed local persistence for AIP identities."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()

    @classmethod
    def default(cls) -> "IdentityStore":
        path = os.getenv("AIP_IDENTITY_STORE", "~/.airon/aip/identities.json")
        return cls(Path(path))

    def _read_all(self) -> Dict[str, AgentIdentity]:
        if not self.path.exists():
            return {}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return {
            alias: AgentIdentity.from_json(identity)
            for alias, identity in payload.get("identities", {}).items()
        }

    def _write_all(self, identities: Dict[str, AgentIdentity]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "identities": {alias: identity.to_json() for alias, identity in identities.items()},
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def get(self, alias: str) -> Optional[AgentIdentity]:
        return self._read_all().get(alias)

    def put(self, identity: AgentIdentity) -> None:
        identities = self._read_all()
        identities[identity.alias] = identity
        self._write_all(identities)

    def delete(self, alias: str) -> None:
        identities = self._read_all()
        identities.pop(alias, None)
        self._write_all(identities)

    def list_aliases(self) -> list[str]:
        return sorted(self._read_all().keys())
