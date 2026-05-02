# AIRON Agent Identity Protocol (AIP)

**End-to-End Verifiable Identity, Provenance, and Reputation for AI Agents**

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)]()
[![Patent: Provisional Filed](https://img.shields.io/badge/Patent-Provisional%20Filed-blue.svg)]()
[![Status: Production](https://img.shields.io/badge/Status-Production-green.svg)]()

---

## What is AIP?

The Agent Identity Protocol (AIP) is a **standalone cryptographic identity system designed specifically for AI agents and autonomous workloads**. AIP provides agents with end-to-end verifiable identity, ensuring that any action, decision, or generated content can be cryptographically traced back to a specific AI model, prompt version, and execution environment.

AIP acts as the "Passport Control" for the AI agent economy. It replaces opaque, shared API keys with **provenance-bound, Ed25519-signed JSON Web Tokens (JWTs)** and introduces a mathematically rigorous **Verifiable Delegation Lattice (VDL)** to govern how agents grant capabilities to other agents.

---

## Why AIP Exists

### The Problems It Solves

| Problem | Real-World Risk | AIP Solution |
|---------|----------------|--------------|
| **Shared API Keys** | If an agent misbehaves, it's impossible to mathematically prove *which* agent instance took the action because they all share a single API key. | **Provenance-Bound AIP-IDs** cryptographically bind an agent's identity to its underlying model and environment. |
| **Confused Deputy Escalation** | An agent delegates a task to a sub-agent, accidentally granting it more permissions than the parent agent originally had. | **Lattice-Constrained Delegation** mathematically guarantees that a child agent can *never* exceed the capabilities of its ancestors. |
| **Zombie Agents** | A revoked agent continues to operate because downstream services haven't synced the revocation list. | **Cascade Revocation (BFS)** instantly and atomically revokes a root token and all of its descendant delegations with O(1) lookup. |
| **Replay Attacks** | An attacker captures a valid agent signature and re-submits it later to duplicate an action. | **Strict Nonce-Tracking** and sliding timestamp windows guarantee that no signature can ever be replayed. |

---

## The AIP Technology Stack

### Verifiable Delegation Lattice (VDL)

AIP v2 introduces a novel composite architecture known as the Verifiable Delegation Lattice. This ensures that agent authority is strictly bounded and easily verifiable by any third party.

1. **Scope-Constrained Delegation**: Delegation isn't just a list of strings. AIP computes the "lattice MEET" of the parent's scope and the requested child's scope. If a parent is denied an action, all descendants are mathematically denied that action.
2. **Verifiable Depth-Limited Chains**: Delegations reference their parent (via JTI) and enforce a maximum depth limit (default: 8 hops) to prevent unbounded agent spawning.
3. **Cascade Revocation**: Revoking a parent token performs a Breadth-First Search (BFS) walk of the delegation graph, automatically terminating all downstream delegations instantly.
4. **Audit Trail Binding**: When an agent writes to an external system (like the AIRON ChronoLattice), the exact delegation ID used is hashed into the audit log. Tampering with the authorization record breaks the cryptographic chain.

---

## Role in the AIRON Trust Pipeline

AIP is the **identity layer** of the AIRON Trust Pipeline — a production AI content verification and agent trust infrastructure.

```
┌─────────────────────────────────────────────────────────────────┐
│                     AIRON TRUST PIPELINE                         │
│                                                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────────────┐   │
│  │  PRISM  │→ │   AIP   │→ │   VCP   │→ │  CHRONOLATTICE   │   │
│  │ Content │  │ Agent   │  │Verifiable│  │ Temporal Audit   │   │
│  │Analysis │  │Identity │  │Cognition│  │ & Provenance     │   │
│  └─────────┘  └─────────┘  └─────────┘  └──────────────────┘   │
│       │            │            │               │               │
│       └────────────┴────────────┴───────────────┘               │
│                         │                                       │
│                    ┌────┴────┐                                   │
│                    │   KTS   │  AIRON Trust Standard             │
│                    │Certificate│  (Three-Layer Crypto Cert)      │
│                    └─────────┘                                   │
└─────────────────────────────────────────────────────────────────┘
```

Within the pipeline, AIP ensures that **every component, external agent, and evaluation step is cryptographically signed and provenance-bound.** 

> **AIP is architecturally independent.** While it serves as the identity layer for the AIRON Trust Pipeline, it is built as a standalone suite of Rust crates and microservices. It can be deployed in any environment that requires rigorous, verifiable identity for autonomous software agents.

---

## What Makes AIP Novel and Defensible

### Patent-Protected Innovations

AIP's Verifiable Delegation Lattice is covered under Indian Patent Office CRI Guidelines 2025 and US USPTO 35 USC §101/§103. 

| Innovation | Prior Art Limitation | AIP Advance |
|-----------|---------------------|-------------|
| **Scope-Constrained Delegation (NM-A1)** | OAuth 2.0 / ABAC use flat string sets; cannot mathematically guarantee subset properties across complex chains. | Represents scopes as lattice elements (Allowed/Denied sets). Computes delegation via lattice MEET operations. |
| **Depth-Limited Chains (NM-A2)** | Standard JWTs lack cryptographic chain linkage; verifying deep chains requires online token introspection. | Offline-verifiable chains referencing parent JTIs with hard-coded max depth limits. |
| **Cascade BFS Revocation (NM-A3)** | Revoking a root OAuth token does not automatically revoke tokens minted by the root. | Atomic BFS graph walk automatically terminates all downstream delegations with O(1) verify checks. |
| **Audit Trail Binding (NM-A4)** | Audit logs record *what* happened, but not *which specific delegation* authorized it, allowing post-hoc tampering. | The delegation ID is included in the SHA3-256 canonical input of the audit entry, cryptographically binding the action to the authority. |

---

## Production Status

### Implementation Maturity

AIP is production-ready, implemented in high-performance Rust, and heavily tested.

| Component | Technology | Status | Description |
|-----------|------------|--------|-------------|
| **AIP Core Logic** | Rust (`aip-core`) | ✅ Production | Delegation lattice, nonce-tracking, runtime binding, reputation aggregation |
| **AIP Cryptography** | Rust (`aip-crypto`) | ✅ Production | Ed25519 signing/verification, SHA-256 fingerprinting, Base58 encoding |
| **AIP Service** | Rust (`axum`) | ✅ Production | Production HTTP service for token issuance, verification, and revocation |
| **AIP CLI** | Rust (`aip-cli`) | ✅ Production | Command-line tool for identity creation, signing, and liveness simulations |
| **AIP Data Types** | Rust (`aip-types`) | ✅ Production | Core data structures (Capabilities, Scopes, Claims) |

### Verified Benchmarks

| Metric | Result |
|--------|--------|
| **Token Verification** | < 1ms (Ed25519) |
| **Revocation Check** | O(1) (In-memory HashSet lookup) |
| **Anti-Replay Protection** | 100% block rate for duplicated nonces |
| **Scope Propagation** | Mathematically guaranteed (Denied scopes always propagate) |

---

## Repository Structure

```
AIP/
│
├── aip-service/                # Production Axum microservice
│   ├── Cargo.toml              # Service dependencies (axum, jsonwebtoken, ed25519-dalek)
│   ├── Dockerfile              # Multi-stage production build
│   └── src/                    # HTTP Handlers, Key generation, Delegation processing
│       ├── main.rs             # Application entry point
│       ├── handlers.rs         # HTTP endpoints (issue, verify, delegate, revoke)
│       ├── capability.rs       # Lattice MEET operations (NM-A1)
│       ├── delegation.rs       # Chain depth limits and persistence (NM-A2)
│       ├── revocation.rs       # Cascade BFS walk and O(1) lookups (NM-A3)
│       └── wellknown.rs        # OIDC-style discovery endpoints
│
├── aip-standalone/             # Standalone Rust workspace (Library Crates)
│   ├── Cargo.toml              # Workspace configuration
│   ├── AIP_RUNTIME.md          # Runtime integration guide
│   ├── aip-types/              # Pure data structures and claims
│   ├── aip-crypto/             # Cryptographic primitives (Ed25519, Base58)
│   ├── aip-core/               # Core domain logic (NonceTracker, Store, Simulation)
│   ├── aip-test/               # Integration tests
│   ├── aip-real-tests/         # End-to-end security and adversarial tests
│   └── aip-cli/                # Command-line interface for AIP operations
│
├── docs/                       # Technical specifications and patent definitions
│   ├── AIP_v2_IDF_complete.md  # Complete Invention Disclosure Form (VDL Architecture)
│   └── AIP_v2_IDF_additions.md # Technical extensions and proofs
│
├── reports_and_patents/        # IP Strategy and Integration Reports
│   ├── PATENT_DOSSIER_CCVL_AIP.md     # Cross-Channel Verification integration
│   └── PATENT_IDF_1A_ORCHESTRATION.md # Orchestration integration
│
└── benchmark-results/          # Performance and validation reports
    └── aip_validation.json     # Automated test results
```

---

## Quick Start (CLI)

```bash
cd aip-standalone/
cargo build --workspace

# Create an identity
./target/debug/aip-cli create-identity --model "my-model" --env "production"

# List stored identities
./target/debug/aip-cli list

# Sign a payload
./target/debug/aip-cli sign --payload "Hello, AIP!"

# Issue a liveness challenge
./target/debug/aip-cli challenge --target-id <AIP-ID>

# Run 5-agent simulation
./target/debug/aip-cli simulate --agents 5
```

---

## Intellectual Property

This repository contains implementations covered by **provisional patent applications** filed with the Indian Patent Office under CRI Guidelines 2025 and the US USPTO under 35 USC §101/§103. 

**Patent Family:** AIRON Trust Pipeline  
**Filing Status:** Provisional Filed  
**IP Owner:** Vanian Technologies Private Limited  

---

## License

**Proprietary** — Vanian Technologies Private Limited. All rights reserved.

Unauthorized reproduction, distribution, or use of this technology without explicit written permission from Vanian Technologies is strictly prohibited.

---

*AIP is a standalone component of the [AIRON Trust Pipeline](https://github.com/AironTrust) — cryptographic trust infrastructure for the AI agent economy.*

**© 2025–2026 Vanian Technologies Private Limited.**
