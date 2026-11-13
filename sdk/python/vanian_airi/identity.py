"""The agent's own identity and signing key.

# What this module holds

The **agent's** Ed25519 private key, used to sign the agent's own statements
about what it did.

# What this module must never hold

The **observer's** key. That key lives at the collector, off the observed
host, and its whole value is that a compromised agent process cannot reach
it. An SDK that loaded an observer key into the agent's address space would
destroy the only asymmetry the architecture has. :class:`AgentIdentity`
therefore has no field, parameter or method for one, and
:func:`load_agent_identity` is the only constructor.

# Fail-closed loading

If the key file is missing, unreadable, or malformed, loading raises
:class:`~vanian_airi.errors.IdentityUnavailable`. It does not generate a
replacement. Silent regeneration is a documented defect elsewhere in this
repository (see the forensic audit, finding B-6): a process that mints a new
identity when it cannot read its own becomes a different principal while
reporting itself healthy, and every credential issued to the old identity
becomes unverifiable.
"""

from __future__ import annotations

import os
import hashlib
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from .errors import IdentityUnavailable

# `cryptography` is imported lazily, inside `load_agent_identity`, so that the
# canonical encoder, the commitment functions, the execution context and event
# construction all work in an environment with no Ed25519 backend. The
# cross-language parity tests depend on the encoder and not on signing, and
# they should not be blocked by a missing native wheel.
if TYPE_CHECKING:  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

__all__ = ["AgentIdentity", "SignatureEnvelope", "load_agent_identity"]


@dataclass(frozen=True)
class SignatureEnvelope:
    algorithm: str
    signer_id: str
    timestamp: int
    nonce: bytes
    payload_hash: bytes
    signature_bytes: bytes

    def __post_init__(self) -> None:
        if self.algorithm != "Ed25519": raise ValueError("unsupported signature algorithm")
        if not isinstance(self.signer_id, str) or not self.signer_id: raise ValueError("signer_id must not be empty")
        if not isinstance(self.timestamp, int) or isinstance(self.timestamp, bool) or not 0 <= self.timestamp < 2**64: raise ValueError("timestamp must be an unsigned 64-bit integer")
        if len(self.nonce) != 16: raise ValueError("nonce must be 16 bytes")
        if len(self.payload_hash) != 32: raise ValueError("payload_hash must be 32 bytes")
        if len(self.signature_bytes) != 64: raise ValueError("signature_bytes must be 64 bytes")

    def digest(self) -> bytes:
        return hashlib.sha256(b"\x01" + self.signer_id.encode("utf-8") + self.timestamp.to_bytes(8, "little") + self.nonce + self.payload_hash).digest()

    def to_dict(self) -> dict:
        return {"algorithm": self.algorithm, "signer_id": self.signer_id, "timestamp": self.timestamp,
                "nonce": list(self.nonce), "payload_hash": list(self.payload_hash), "signature_bytes": list(self.signature_bytes)}

#: Permission bits that must not be set on a private key file.
_FORBIDDEN_MODE = stat.S_IRWXG | stat.S_IRWXO


@dataclass(frozen=True)
class AgentIdentity:
    """An agent's AIP identity and its signing key.

    Frozen so the id and key cannot be swapped underneath an emitter that has
    already bound to them.
    """

    aip_id: str
    _private: Any  # Ed25519PrivateKey; typed loosely for the lazy import
    _public: Any  # Ed25519PublicKey

    @property
    def public_key_bytes(self) -> bytes:
        """The 32-byte raw public key, as verifier anchors record it."""
        from cryptography.hazmat.primitives import serialization

        return self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        """Sign a canonical preimage. Returns 64 raw signature bytes.

        The caller passes the *preimage*, never a hash: hashing is part of
        the signature construction and doing it twice in different places is
        how domain separation gets lost.
        """
        return self._private.sign(message)

    def sign_envelope(self, message: bytes, *, timestamp: Optional[int] = None, nonce: Optional[bytes] = None) -> SignatureEnvelope:
        ts = int(time.time() * 1000) if timestamp is None else timestamp
        n = secrets.token_bytes(16) if nonce is None else nonce
        payload_hash = hashlib.sha256(message).digest()
        envelope = SignatureEnvelope("Ed25519", self.aip_id, ts, n, payload_hash, bytes(64))
        return SignatureEnvelope("Ed25519", self.aip_id, ts, n, payload_hash, self.sign(envelope.digest()))

    def __repr__(self) -> str:  # pragma: no cover - defensive
        # Never let a key reach a log, a traceback, or an error report.
        return f"AgentIdentity(aip_id={self.aip_id!r}, private=<redacted>)"


def load_agent_identity(
    aip_id: str,
    key_path: os.PathLike[str] | str,
    *,
    require_owner_only: bool = True,
) -> AgentIdentity:
    """Load an agent identity from a raw 32-byte Ed25519 seed file.

    :param require_owner_only: refuse a key file that is group- or
        world-readable. Defaults to on. A private key at mode 0644 is
        readable by every process on the host, which makes the agent's
        signature worthless as attribution. Callers who genuinely need the
        check relaxed (a read-only secrets mount that reports odd bits) must
        say so explicitly.

    :raises IdentityUnavailable: on any failure. There is no fallback path
        and no key generation — see the module docstring.
    """
    path = Path(key_path)
    try:
        st = path.stat()
    except OSError as exc:
        raise IdentityUnavailable(
            f"cannot stat agent key at {path}: {exc}. "
            "Refusing to continue; a missing key is not a reason to become "
            "a different agent."
        ) from exc

    if require_owner_only and (st.st_mode & _FORBIDDEN_MODE):
        raise IdentityUnavailable(
            f"agent key at {path} has mode {stat.filemode(st.st_mode)}; "
            "it is readable beyond its owner. Refusing to load."
        )

    try:
        seed = path.read_bytes()
    except OSError as exc:
        raise IdentityUnavailable(f"cannot read agent key at {path}: {exc}") from exc

    if len(seed) != 32:
        raise IdentityUnavailable(
            f"agent key at {path} is {len(seed)} bytes; an Ed25519 seed is 32."
        )

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise IdentityUnavailable(
            "no Ed25519 backend available (install `cryptography`). Refusing "
            "to continue rather than emitting unsigned events."
        ) from exc

    try:
        private = Ed25519PrivateKey.from_private_bytes(seed)
    except Exception as exc:  # cryptography raises a range of types here
        raise IdentityUnavailable(f"agent key at {path} is malformed: {exc}") from exc

    if not aip_id:
        raise IdentityUnavailable("aip_id must not be empty")

    return AgentIdentity(aip_id=aip_id, _private=private, _public=private.public_key())


def _reject_observer_key(_: Optional[object] = None) -> None:
    """Placeholder that documents an absence.

    There is no ``load_observer_identity`` in this SDK and there must never
    be one. If a future change needs the agent process to verify observer
    attestations locally, it needs the observer's *public* key only, supplied
    as a verifier anchor — never the private half.
    """
    raise NotImplementedError(
        "the AIRI SDK does not load observer keys; observation is signed "
        "off-host by design"
    )
