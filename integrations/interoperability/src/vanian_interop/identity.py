"""Operator-pinned JWT identity verification; no remote key discovery from tokens.

OIDC issuer JWTs are accepted only under a configured token profile. An access
token is not an OIDC ID token. This bridge does not perform token exchange,
DPoP validation, X.509-SVID verification, or infer logical-agent identity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import time
from typing import Mapping

import jwt
from cryptography.hazmat.primitives import serialization

from .records import IdentityReference, strict_json

_ASYMMETRIC = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"})
_SPIFFE = re.compile(r"spiffe://([a-z0-9._-]+)(/[a-zA-Z0-9._~!$&'()*+,;=:@/-]*)?\Z")


def spiffe_trust_domain(subject: str) -> str:
    match = _SPIFFE.fullmatch(subject)
    if len(subject) > 2048 or not match or any(part in (".", "..", "") for part in (match[2] or "").split("/")[1:]):
        raise ValueError("invalid or unsupported SPIFFE ID")
    return match[1]


@dataclass(frozen=True)
class JwtTrust:
    issuer: str
    audience: str
    tenant: str
    keys: Mapping[str, object] = field(repr=False)
    algorithms: tuple[str, ...] = ("ES256",)
    accepted_types: tuple[str, ...] = ("at+jwt",)
    max_age_seconds: int = 300

    def __post_init__(self):
        if not self.issuer or not self.audience or not self.tenant or not self.keys:
            raise ValueError("issuer, audience, tenant and pinned keys required")
        if not self.algorithms or not set(self.algorithms) <= _ASYMMETRIC:
            raise ValueError("only explicitly pinned asymmetric algorithms are supported")
        if not 0 < self.max_age_seconds <= 86400:
            raise ValueError("invalid maximum credential age")


def _verified_claims(token: str, trust: JwtTrust, *, spiffe: bool, now_ms: int) -> tuple[dict, str]:
    if not isinstance(token, str) or len(token) > 32768 or token.count(".") != 2:
        raise ValueError("invalid credential envelope")
    try:
        header = strict_json(jwt.utils.base64url_decode(token.split(".")[0]))
        strict_json(jwt.utils.base64url_decode(token.split(".")[1]))
        if not isinstance(header, dict) or any(k in header for k in ("jku", "jwk", "x5u", "x5c", "crit")):
            raise ValueError("token-selected trust material or unsupported critical header")
        if header.get("alg") not in trust.algorithms:
            raise ValueError("unapproved algorithm")
        allowed_types = (None, "JWT", "JOSE") if spiffe else trust.accepted_types
        if header.get("typ") not in allowed_types:
            raise ValueError("wrong credential type")
        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in trust.keys:
            raise ValueError("unknown key")
        claims = jwt.decode(token, trust.keys[kid], algorithms=list(trust.algorithms),
                            audience=trust.audience, issuer=None if spiffe else trust.issuer,
                            options={"require": ["sub", "aud", "exp"] + ([] if spiffe else ["iss", "iat"]),
                                     "verify_exp": False, "verify_iat": False, "verify_nbf": False})
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise ValueError("missing subject")
        for name in ("exp", "iat", "nbf"):
            if name in claims and type(claims[name]) is not int:
                raise ValueError("NumericDate must be an integer in this profile")
        now = now_ms / 1000
        if claims["exp"] <= now or claims.get("nbf", 0) > now or claims.get("iat", 0) > now:
            raise ValueError("credential outside validity")
        if not spiffe and (now - claims["iat"] > trust.max_age_seconds or claims["exp"] <= claims["iat"]):
            raise ValueError("credential too old or invalid interval")
        if "cnf" in claims:
            raise ValueError("proof-of-possession credential requires a transport proof verifier")
        if spiffe and (header["alg"] == "EdDSA" or spiffe_trust_domain(claims["sub"]) != trust.issuer):
            raise ValueError("untrusted SPIFFE trust domain or unsupported JWT-SVID algorithm")
        return claims, kid
    except (jwt.PyJWTError, KeyError, TypeError) as error:
        raise ValueError("credential verification failed") from error


def verify_identity(token: str, trust: JwtTrust, *, jwt_svid: bool = False,
                    now_ms: int | None = None) -> IdentityReference:
    now_ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    claims, kid = _verified_claims(token, trust, spiffe=jwt_svid, now_ms=now_ms)
    key = trust.keys[kid]
    if isinstance(key, (str, bytes)):
        key = serialization.load_pem_public_key(key.encode() if isinstance(key, str) else key)
    fingerprint = hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    return IdentityReference(
        scheme="spiffe" if jwt_svid else "oauth-jwt", issuer=trust.issuer,
        subject=claims["sub"], tenant=trust.tenant,
        credential_type="JWT-SVID" if jwt_svid else "JWT_ACCESS_TOKEN",
        verified_at_ms=now_ms, expires_at_ms=claims["exp"] * 1000,
        trust_anchor=f"{trust.issuer}#configured-key:{kid};spki-sha256:{fingerprint}",
        credential_sha256=hashlib.sha256(token.encode()).hexdigest(),
        workload_identity=claims["sub"] if jwt_svid else None,
    )
