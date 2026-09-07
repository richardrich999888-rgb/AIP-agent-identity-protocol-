"""Domain-separated commitments to values that must not enter evidence.

Prompts, tool arguments, model outputs and credentials are committed, never
carried. The commitment is *not* a bare SHA-256: it opens with AIRI's
parameter domain tag, so a digest computed anywhere else in the system — a
packet hash, an observer head, a Merkle leaf — cannot be presented as a
parameter commitment.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .canonical import put_bytes, put_domain
from .errors import CommitmentError

AIRI_PARAM_DOMAIN = "SYNTRIASS/AIRI/PARAM_COMMITMENT/v1"

__all__ = ["AIRI_PARAM_DOMAIN", "commit_bytes", "commit_json"]


def commit_bytes(data: bytes) -> bytes:
    """``SHA-256( put_domain(AIRI_PARAM_DOMAIN) ‖ put_bytes(data) )``.

    Matches ``aip_airi::parameter_commitment`` byte for byte.
    """
    buf = bytearray()
    put_domain(buf, AIRI_PARAM_DOMAIN)
    put_bytes(buf, data)
    return hashlib.sha256(bytes(buf)).digest()


def commit_json(value: Any) -> bytes:
    """Commit to a JSON-serialisable value under a deterministic encoding.

    ``sort_keys`` and fixed separators make the encoding independent of dict
    ordering, so the same logical arguments commit to the same digest on
    every run and in every process. Without that, a verifier comparing two
    commitments of identical arguments would see a mismatch and report a
    parameter substitution that never happened.
    """
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CommitmentError(f"value is not JSON-serialisable: {exc}") from exc
    return commit_bytes(encoded)
