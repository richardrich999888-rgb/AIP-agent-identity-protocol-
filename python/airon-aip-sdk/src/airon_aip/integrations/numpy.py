from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict

from airon_aip.identity import AgentIdentity


def array_fingerprint(array: Any) -> Dict[str, Any]:
    """Return a stable content fingerprint for a NumPy-like array."""

    if not hasattr(array, "tobytes"):
        raise TypeError("array must expose tobytes()")
    digest = hashlib.sha256()
    digest.update(str(getattr(array, "shape", "")).encode("utf-8"))
    digest.update(str(getattr(array, "dtype", "")).encode("utf-8"))
    digest.update(array.tobytes())
    return {
        "sha256": digest.hexdigest(),
        "shape": tuple(getattr(array, "shape", ())),
        "dtype": str(getattr(array, "dtype", "")),
    }


@dataclass
class AipArray:
    array: Any
    identity: AgentIdentity

    def metadata(self) -> Dict[str, Any]:
        return {
            "identity": self.identity.public_metadata(),
            "array": array_fingerprint(self.array),
        }
