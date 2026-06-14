# 02 — Technology & Technology Readiness Level

## 1. Architecture

AIP is implemented in **Rust** (memory-safe, no garbage collector, suitable
for high-assurance and constrained environments). It is a set of small,
auditable crates with no heavyweight runtime dependencies.

```
┌──────────────────────────────────────────────────────────────────┐
│                         EvidencePacket                             │
│  agent identity · root authority · delegation chain · decision ·   │
│  signed actions · trace/receipt bindings · trust floor · signature │
└──────────────────────────────────────────────────────────────────┘
        ▲ produce (agent)                         │ verify (auditor)
        │                                         ▼
┌─────────────────┐   ┌──────────────────────────────────────────┐
│  aip-protocol   │   │  Verification engine (14 named rules)      │
│  packet builder │   │  → VerificationReport + derived TrustFloor │
│  + canonical    │   │  → AccountabilityGraph (Human→…→Receipt)   │
│    encoding     │   └──────────────────────────────────────────┘
└─────────────────┘
        │ uses
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ aip-core   delegation chains · capability scope lattice (MEET) ·   │
│            cascade revocation · hash-chained scoped audit          │
│ aip-crypto Ed25519 · SHA-256 · Base58 AIP-ID derivation+checksum   │
│ aip-types  wire-format data structures                             │
└──────────────────────────────────────────────────────────────────┘
```

| Crate | Responsibility |
|---|---|
| `aip-crypto` | Ed25519 sign/verify, SHA-256, Base58 identifier derivation with checksum |
| `aip-types` | Canonical data structures |
| `aip-core` | Delegated authority with scope attenuation, depth limits, cascade revocation, hash-chained audit |
| `aip-protocol` | **EvidencePacket, the verification engine, the accountability graph** |
| `banking_demo` | End-to-end demonstrator (authority→delegation→action→evidence→tamper) |
| `aip-cli`, `aip-service` | Local CLI; reference HTTP prototype (not hardened) |

## 2. Cryptographic design

- **Signatures:** Ed25519 (RFC 8032). Hashing: SHA-256.
- **Identity:** an `AIP-ID` is derived as
  `aip1 + base58(SHA-256(public_key ‖ provenance)[..26]) + base58(checksum)`,
  binding the identifier to the key and a provenance commitment. The
  verifier recomputes and checks this binding.
- **Canonical encoding:** every variable-length field is length-prefixed,
  making the byte stream prefix-free so two distinct packets cannot collide
  to the same bytes. Hashing and signing operate on these bytes, never on
  JSON.
- **Binding rules:** per-action signatures cover the decision ID (an action
  cannot be transplanted to another decision); counterparty receipt
  signatures cover the decision ID too.
- **Algorithm agility:** the format reserves an algorithm identifier, with a
  documented path to post-quantum signatures (e.g. ML-DSA) — see roadmap.

## 3. What exists today — with evidence

Evaluators can reproduce every item below from source:

```bash
cd aip-standalone
cargo build --workspace
cargo test  --workspace
cargo run   -p banking-demo
```

| Capability | Status | Evidence |
|---|---|---|
| Agent identity + provenance-commitment binding | Implemented | `aip-crypto`, validated by tests |
| Delegated authority with scope attenuation (subset/MEET) | Implemented | `aip-core::delegation`, `::capability` |
| Depth-limited, per-hop-signed delegation chains | Implemented | `aip-core::delegation` |
| Cascade revocation | Implemented | `aip-core::revocation` |
| Hash-chained scope-bound audit entries | Implemented | `aip-core::scoped_audit` |
| **EvidencePacket v1 (canonical encoding, signatures)** | Implemented | `aip-protocol::evidence_packet` |
| **14-rule verification engine + derived trust floor** | Implemented | `aip-protocol::verification` |
| **Accountability graph + offline verification** | Implemented | `aip-protocol::accountability_graph` |
| Tamper detection (incl. hash-recomputing attacker) | Implemented | `tests/evidence_packet.rs`, demo |
| Open specification | Implemented | `AIP_SPEC.md` |

**Test status:** `cargo test --workspace` → **214 tests pass, 0 fail, 2
ignored** (the 2 ignored are wall-clock throughput gates that run only under
`--release`, where they are meaningful). The verification test suite is
adversarial: **every tamper scenario must flip a specific named rule**, so a
change that silently weakens a check fails the build.

## 4. What does NOT yet exist (roadmap — proposed iDEX work)

Stated plainly so there is no ambiguity:

- Hardened, authenticated, multi-tenant verification **service** (current
  `aip-service` is an unauthenticated reference prototype).
- Operator/auditor **console** (issue, inspect, verify, visualise, offline).
- **SDKs** (for integrating agent frameworks and Service applications) and a
  cross-language conformance suite.
- Integration with a sovereign **Key-management/HSM** and key rotation.
- Real **TEE / hardware attestation** (the current module performs
  structural checks only — it does **not** verify vendor enclave quotes).
- **Post-quantum** signature option.
- **Field deployment**, accreditation, and trial with a Service system.

## 5. Technology Readiness Level

**System TRL: 4 — technology validated in a laboratory environment.**

Justification:
- **Component maturity is higher:** the cryptographic primitives (Ed25519,
  SHA-256) are standards-based and mature; our identity, delegation, and
  EvidencePacket logic is implemented and exercised by an automated,
  adversarial test suite and an end-to-end demonstrator.
- **Integrated-system maturity is TRL 4:** the accountability system has
  been validated in a controlled/lab setting, not yet in a relevant
  operational environment or with a Service system of record.

The proposed iDEX programme (document 05) targets **TRL 6–7** — a prototype
demonstrated in a relevant/operational environment with a sponsoring use
case.

## 6. Why Rust / why this is defensible to operate

- Memory safety eliminates a large class of exploitable defects, important
  for a component that sits in an accountability/security path.
- Small dependency surface; the core is auditable.
- Produces small static binaries suitable for constrained/edge and
  cross-domain deployment.
- Offline-verifiable design avoids a network dependency in the trust path.
