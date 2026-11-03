"""Read-only native receipt verification; no Python signing or AIP hashing."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import subprocess

from .records import json_bytes, strict_json


@dataclass(frozen=True)
class ReceiptVerifier:
    """Operator-supplied executable and tenant-scoped public anchor.

    A receipt has no native tenant field. The operator must establish this
    gateway key's tenant authority independently; the receipt cannot choose it.
    """
    executable: Path
    tenant: str
    gateway_id: str
    key_version: int
    public_key_hex: str

    def __post_init__(self):
        if not self.tenant or not self.gateway_id or type(self.key_version) is not int or self.key_version < 0:
            raise ValueError("explicit tenant, gateway and key version required")
        if len(self.public_key_hex) != 64 or any(c not in "0123456789abcdef" for c in self.public_key_hex):
            raise ValueError("32-byte lowercase gateway public key required")

    def compare(self, *, tenant: str, request: dict, signed_receipt: dict) -> dict:
        if tenant != self.tenant:
            raise ValueError("cross-tenant receipt comparison refused")
        encoded = json_bytes({"request": request, "signed_receipt": signed_receipt})
        if len(encoded) > 1_048_576:
            raise ValueError("comparison exceeds native input limit")
        # Do not inherit signing keys, credential variables or receipt sinks.
        env = {"PATH": os.defpath, "AIP_GATEWAY_ID": self.gateway_id,
               "AIP_GATEWAY_KEY_VERSION": str(self.key_version),
               "AIP_GATEWAY_PUBLIC_KEY": self.public_key_hex}
        completed = subprocess.run([str(self.executable.resolve()), "compare-request"],
            input=encoded, capture_output=True, env=env, timeout=10, check=False)
        if completed.returncode:
            raise ValueError("native receipt/request verification refused")
        result = strict_json(completed.stdout)
        if (result.get("receipt_signature") != "VERIFIED"
                or result.get("kernel_execution") != "CANNOT_PROVE"
                or result.get("authorization") != "NOT_ASSESSED"):
            raise ValueError("unsupported native verifier output")
        return result
