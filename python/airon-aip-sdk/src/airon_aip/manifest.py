from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .identity import AgentIdentity


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_manifest(
    *,
    identity: AgentIdentity,
    artifact_path: Optional[Path] = None,
    artifact_digest: Optional[str] = None,
    artifact_type: str = "python-artifact",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if artifact_digest is None and artifact_path is None:
        raise ValueError("artifact_path or artifact_digest is required")

    digest = artifact_digest or file_sha256(Path(artifact_path))
    return {
        "schema": "airon.aip.artifact_manifest.v1",
        "generated_epoch_ns": time.time_ns(),
        "artifact": {
            "path": str(artifact_path) if artifact_path else None,
            "type": artifact_type,
            "sha256": digest,
        },
        "identity": identity.public_metadata(),
        "extra": extra or {},
    }


def canonical_manifest_hash(manifest: Dict[str, Any]) -> str:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
