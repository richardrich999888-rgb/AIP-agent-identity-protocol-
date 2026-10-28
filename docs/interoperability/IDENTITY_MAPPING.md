# Identity mapping

`IdentityReference` retains original scheme, issuing authority, verified subject, operator tenant, credential type, verification/expiration times, public-key fingerprint, credential digest, optional workload identity, logical identity, binding references and revocation status. It is a correlation record, not an authority token. Python objects are not a trust boundary: serialize/receive them as untrusted input and reverify native credentials at an authenticated ingestion boundary.

`verify_identity` verifies configured asymmetric JWT algorithms, issuer, audience, subject and time. It rejects token-selected keys/URLs, unsupported critical headers, inappropriate token types and unsupported proof-of-possession credentials. Key IDs are qualified by issuer and SPKI digest. No bearer credential is returned in the reference.

The ordinary profile accepts configured JWT access-token types; it does not turn an access token into an OIDC ID token. IdP discovery, introspection, revocation feeds, RFC 8693 token exchange, RFC 9449 DPoP and certificate-bound access tokens are not implemented. A `cnf` claim is refused rather than ignored. Institution verification services must supply those missing guarantees.

The JWT-SVID profile validates the signature against operator-pinned trust-domain keys, audience, expiry and SPIFFE subject. This is not an X.509-SVID validator or a Workload API client. `spire_jwt_live.py` uses actual SPIRE 1.15.3 CLI Workload API issuance and a separately exported server bundle. Its registration identifies the **SPIRE CLI executable**, not the Python agent. The local run is BLOCKED by unavailable Unix sockets. Unit tests use explicitly synthetic credentials, not evidence of a live SPIRE deployment.

Existing `aip-spiffe` compares registry and runtime executable measurements. It does not supply this new JWT signature verification. Neither component alone binds a logical ADK agent to a process.

`retain_identity_claims` preserves issuer-qualified claims and refuses cross-tenant association. It deliberately returns UNRESOLVED, including when two issuers use the same subject. An institution-authorized mapping plus an actual execution binding is still required; two matching strings do not establish equivalence.

The A2A lab has ephemeral local PKI under one administrator. It exercises real TLS and JWT verification, not organizational separation. Its two logical agents share one process. Their framework names cannot prove separate kernel attribution.

OpenA2A AIP is an independent proposal, unrelated to VANIAN AIP. Its inspected specification and Internet-Draft are not an approved IETF standard. No acronym-based wire compatibility or trust-score translation is implemented. Sources and pins are in [ECOSYSTEM_MATRIX.md](ECOSYSTEM_MATRIX.md).

