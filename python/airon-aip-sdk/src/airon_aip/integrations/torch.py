from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from airon_aip.identity import AgentIdentity


def identity_hash(identity: AgentIdentity) -> str:
    payload = json.dumps(identity.public_metadata(), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def attach_aip_to_module(module: Any, identity: AgentIdentity, *, persist_hash: bool = False) -> Any:
    """Attach AIP identity metadata to a torch.nn.Module-like object.

    The raw bearer token is not persisted into the model state dict. If
    persist_hash=True and torch is installed, only a SHA-256 identity hash is
    registered as a uint8 buffer.
    """

    module.airon_aip_identity = identity.public_metadata()
    module.airon_aip_identity_hash = identity_hash(identity)

    if persist_hash:
        try:
            import torch
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("persist_hash=True requires torch to be installed") from exc
        if not hasattr(module, "register_buffer"):
            raise TypeError("module must expose register_buffer() when persist_hash=True")
        raw = bytes.fromhex(module.airon_aip_identity_hash)
        tensor = torch.tensor(list(raw), dtype=torch.uint8)
        module.register_buffer("airon_aip_identity_hash_buffer", tensor, persistent=True)

    return module


def module_identity_metadata(module: Any) -> Dict[str, Any]:
    return {
        "identity": getattr(module, "airon_aip_identity", None),
        "identity_hash": getattr(module, "airon_aip_identity_hash", None),
    }
