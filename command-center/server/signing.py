"""Ed25519 signing for gate requests, revocation lists and approvals (native, not P0-059).

The only module that imports `cryptography`, pinned in
requirements-gate.lock.txt (the system package is a build for another Python
and crashes under python3.11 in this lab). Everything is
signed over domain-separated canonical JSON (sorted keys, no whitespace,
no NaN), so a signature made for one purpose cannot be replayed as another.
"""

from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

DOMAIN_REQUEST = b"vanian-gate-request/v1\n"
DOMAIN_REVOCATIONS = b"vanian-revocations/v1\n"
DOMAIN_APPROVAL = b"vanian-approval/v1\n"
KEY_BYTES = 32
SIG_BYTES = 64


class SignatureError(ValueError):
    """Malformed key or signature encoding (distinct from a signature that does not verify)."""


def canonical(obj: object) -> bytes:
    """Canonical JSON bytes; raises ValueError/TypeError for non-JSON input."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(domain: bytes, obj: object) -> str:
    """SHA-256 hex of domain || canonical(obj)."""
    return hashlib.sha256(domain + canonical(obj)).hexdigest()


def generate() -> tuple[bytes, bytes]:
    """(private_raw, public_raw), 32 bytes each."""
    k = Ed25519PrivateKey.generate()
    return (k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
            k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def sign(domain: bytes, obj: object, private_raw: bytes) -> str:
    """Hex signature over domain || canonical(obj)."""
    if len(private_raw) != KEY_BYTES:
        raise SignatureError("private key must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(private_raw).sign(domain + canonical(obj)).hex()


def verify(domain: bytes, obj: object, signature_hex: object, public_hex: str) -> bool:
    """True only for a well-formed, valid signature. Any malformed input is False."""
    try:
        pub = bytes.fromhex(public_hex)
        sig = bytes.fromhex(signature_hex) if isinstance(signature_hex, str) else b""
        if len(pub) != KEY_BYTES or len(sig) != SIG_BYTES:
            return False
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, domain + canonical(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
