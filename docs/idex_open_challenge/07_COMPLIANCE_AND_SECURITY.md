# 07 — Compliance, Security Posture & Data Sovereignty

This document states the security posture **honestly**: what is true of the
code today, and what must be achieved during the programme. Nothing here
claims a certification the applicant does not hold.

## 1. Security properties true today (in code, tested)

- **Memory-safe implementation** (Rust): eliminates buffer-overflow / use-
  after-free classes in the accountability path.
- **Standards-based cryptography:** Ed25519 (RFC 8032) signatures, SHA-256
  hashing; no home-grown primitives.
- **Tamper-evident by construction:** canonical, prefix-free encoding;
  SHA-256 packet hash; Ed25519 packet signature; embedded delegation and
  counterparty signatures are themselves covered by the packet hash.
- **No call-home:** verification is a pure function of the packet and the
  verifier's trusted keys — suitable for air-gapped and cross-domain use.
- **Least-authority by design:** delegation can only attenuate, never widen,
  scope (lattice MEET); depth-limited chains; cascade revocation.
- **Adversarial test discipline:** every tamper scenario in the suite must
  trip a specific named verification rule; `cargo test --workspace` is green
  (214 pass / 2 release-only ignored).
- **Secret hygiene:** signing keys are not logged; `.gitignore` excludes key
  material and local logs from the repository.

## 2. Known limitations today (to be closed in the programme)

Stated explicitly (see also `../../AUDIT_CORRECTIONS.md`):

- The reference `aip-service` HTTP prototype is **unauthenticated and
  single-node** — **not** for production. Hardening is Phase B.
- **No HSM/KMS integration or key rotation yet** — Phase B.
- The hardware-attestation module performs **structural checks only**; it
  does **not** verify vendor TEE/enclave quotes — roadmap.
- The provenance triple is a **commitment** supplied by the caller; binding
  it to a verified artifact (e.g. a measured model/build) is roadmap.
- No third-party security assessment yet — Phase E.

## 3. Target compliance during the programme

`[FILL IN / confirm with sponsor — these are the intended targets:]`

- **CERT-In empanelled** security assessment of the prototype (Phase E).
- Alignment with applicable **MoD / Service cyber-security guidelines** and
  the sponsor's accreditation process for the target environment.
- **Data sovereignty:** all data and key material remain within
  Government-controlled / on-premises infrastructure; no foreign cloud
  dependency in the trust path. Deployable fully on-premises and offline.
- **Cryptographic policy:** ability to operate within the sponsor's approved
  algorithm set; documented migration path to post-quantum signatures
  (algorithm identifier already reserved in the format).
- **Supply chain:** dependency inventory (SBOM) and pinned, audited
  dependencies; reproducible builds as a programme deliverable.

## 4. Data handling & classification

- AIP records **authority and integrity metadata**, not necessarily the
  underlying payloads: decision inputs, rationale, action payloads, traces,
  and receipts are referenced **by hash**, so the evidence can be retained
  and verified without storing the (potentially classified) content itself.
- Classification handling, retention, and access control to packets follow
  the **sponsor's policy**; the design supports keeping content out of the
  packet entirely (hash-only binding).

## 5. Safety boundary (reaffirmed)

AIP is an accountability/evidence layer only. It does not select targets,
make or approve operational decisions, or exercise autonomy. It records and
proves the authority and integrity of actions taken by other systems. Any
integration must preserve this boundary.

## 6. Audit & verifiability for the MoD

Because the EvidencePacket **format and verification rules are open**
(`AIP_SPEC.md`) and verification is offline, the MoD can independently verify
any packet — now and in the future — without dependence on the applicant's
servers or continued existence. This is a deliberate anti-lock-in property
appropriate to sovereign defence procurement.
