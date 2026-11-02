# AIP Services & Test Fixtures Exploration Analysis

**Explorer 2: Services & Test Fixtures Specialist**  
**Project:** AIP Enterprise Accountability Console (`aip-console/`)  
**Date:** 2026-11-02  
**Target Integrity:** Production Enterprise Grade (Syntriass Branding)

---

## Executive Summary

This investigation covers the backend infrastructure of the Agent Identity Protocol (AIP), specifically `aip-service`, `aip-standalone`, existing test fixtures, EvidencePacket and audit bundle structures, and the specifications for the **Evidence Vault Explorer** offline mock fallback mode.

Key findings:
1. **Service Architecture (`aip-service`):** Axum 0.7 REST API built as a thin, multi-tenant layer over the core cryptographic engine (`aip-protocol` and `aip-core`). Storage is abstracted via `EvidenceStore` (JSONL and PostgreSQL backends). Authentication uses SHA-256 hashed bearer API keys bound strictly to a tenant ID and role (`Machine` vs `Admin`), preventing cross-tenant existence leaks.
2. **Accountability Endpoints:** Four core accountability endpoints exist in `aip-service`:
   - `POST /v1/evidence/verify`: Stateless cryptographic verification against caller-supplied trust anchors and revocation sets.
   - `GET /v1/evidence/{id}`: Tenant-isolated retrieval of raw EvidencePacket JSON.
   - `GET /v1/authority/{id}`: Multi-packet authority index query (reconstructing accountability DAG, answering who authorized an action, returning DOT and packet IDs).
   - `GET /v1/evidence/{id}/export`: Generation and export of signed audit ZIP bundles (`application/zip`) adhering to `aip-bundle-1` specification.
   - `POST /v1/evidence/generate`: Pilot/dev endpoint to synthesize and seal packets given agent seed and pre-signed authority tokens.
3. **EvidencePacket & Bundle Fixtures:** The repository does not store static `.json` or `.zip` files in git (except identity stores); rather, it features deterministic, high-coverage Rust programmatic generators in `aip-protocol/tests/evidence_packet.rs`, `aip-protocol/tests/bundle.rs`, `aip-service/src/test_support.rs`, and `aip-standalone/banking_demo`. These generators define 12+ concrete adversarial tamper attack vectors, two-hop delegation attenuation chains, and countersigned bilateral receipts.
4. **Offline Mock Fallback Mode Requirements:** When `aip-service` is disconnected or unreachable, the Enterprise Accountability Console's Evidence Vault Explorer must provide seamless failover using a unified `EvidenceClient` abstraction, browser IndexedDB storage seeded with pre-compiled representative packets, and client-side verification/export using WASM (`aip-wasm` or browser JSZip/Ed25519 fallback).

---

## 1. Repository Structure & Workspace Topology

The AIP codebase is organized into two primary Rust workspaces and operational directories:

```
AIP-agent-identity-protocol-/
├── AIP_SPEC.md                     # Formal normative specification of EvidencePacket v1 & 14-rule engine
├── AUDIT_CORRECTIONS.md            # Security audit remediation notes
├── CHANGELOG.md                    # Release history
├── README.md                       # Protocol overview
├── docs/                           # Architectural and audit export specs
│   ├── AUDIT_EXPORT_SPEC.md        # Specification for signed ZIP audit export bundles (aip-bundle-1)
│   ├── BACKUP_AND_RECOVERY.md      # Disaster recovery guidelines
│   └── PRODUCTION_READINESS.md     # Deployment gates
├── deploy/                         # Infrastructure deployment
│   ├── docker/keys.example.json    # Example API key store configuration (hash-stored bearer tokens)
│   └── sql/schema.sql              # PostgreSQL schema for multi-tenant metadata storage
├── aip-service/                    # Production Axum HTTP REST Service ("airon-aip" crate v0.2.0)
│   ├── Cargo.toml                  # Axum 0.7, jsonwebtoken, ed25519-dalek, deadpool-postgres
│   ├── MIGRATION_NOTES.md          # Transition from single-node JSONL to PostgreSQL
│   └── src/
│       ├── lib.rs                  # Router setup and AppState definition
│       ├── main.rs                 # Service entrypoint
│       ├── auth.rs                 # ApiKeyStore, Principal extractor, Bearer authentication
│       ├── evidence.rs             # Evidence handlers (generate, verify, get_evidence, export_evidence)
│       ├── authority.rs            # Derived AuthorityGraph, who_authorized query, DOT generator
│       ├── store.rs                # EvidenceStore trait & JsonlEvidenceStore implementation
│       ├── store/pg.rs             # PostgresEvidenceStore implementation (feature: "postgres")
│       ├── models.rs               # JSON API DTOs (IssueRequest, VerifyRequest, ErrorBody, etc.)
│       ├── handlers.rs             # Identity layer handlers (/v1/identity/*, /health)
│       └── test_support.rs         # Programmatic test fixtures (sample_packet, sample_generate_request)
└── aip-standalone/                 # Offline cryptographic core & CLI workspace (v0.4.0)
    ├── Cargo.toml                  # Workspace manifest (members: aip-types, crypto, core, protocol, etc.)
    ├── aip-types/                  # Pure wire format types (CapabilityScope, EvidencePacket, etc.)
    ├── aip-crypto/                 # Pure cryptographic primitives (Ed25519, SHA-256, Base58)
    ├── aip-core/                   # Authority lifecycle, delegation chains, lattice meet, revocation
    ├── aip-protocol/               # EvidencePacket v1, 14-rule verification engine, AccountabilityGraph, bundle ZIP
    ├── aip-verify/                 # Standalone auditor CLI tool for offline JSON/ZIP verification
    ├── aip-test/                   # Integration and lifecycle tests
    ├── aip-real-tests/             # Adversarial attack tests (tamper detection, replay, forgery)
    ├── banking_demo/               # End-to-end CFO -> Treasury -> Payments Agent -> Ledger banking pilot demo
    └── aip_store.json              # Sample agent identity database
```

---

## 2. Comprehensive Investigation of `aip-service` REST Endpoints

`aip-service` exposes endpoints divided across three layers: Identity, Accountability, and Discovery. All endpoints operate over JSON or application/zip.

### 2.1 Authentication & Multi-Tenancy Architecture

- **Auth Mechanism:** HTTP Bearer token via `Authorization: Bearer <secret>` header.
- **Key Custody & Storage:** Secrets are never stored in plaintext. `ApiKeyStore` stores `sha256(secret) -> Entry { tenant_id, key_id, role }`.
- **Roles:**
  - `Role::Machine` (`"machine"`): Automated integrations, agent runtimes, ingestion systems.
  - `Role::Admin` (`"admin"`): Human operators, token revocation, audit management.
- **Tenant Isolation:**
  - Every authenticated caller is resolved to a `Principal { tenant_id, key_id, role }`.
  - The `tenant_id` is extracted strictly from the authenticated API key, **never from the request body or query parameter**.
  - Cross-tenant queries return `404 Not Found` (indistinguishable from non-existent records) to prevent existence leakage.

---

### 2.2 Endpoint Detail: `POST /v1/evidence/verify`

- **Purpose:** Verifies an EvidencePacket against caller-supplied trust anchors and revocation sets.
- **HTTP Method:** `POST`
- **Path:** `/v1/evidence/verify`
- **Authentication:** Authenticated (`Principal` required, role `Machine` or `Admin`).
- **Stateless Nature:** Verification is purely functional: $f(\text{packet}, \text{context}) \to \text{report}$. It does not depend on database state and is not restricted by tenant boundaries.
- **Request Headers:**
  - `Content-Type: application/json`
  - `Authorization: Bearer <token>`
- **Request Body (`VerifyRequest`):**
  ```json
  {
    "packet": {
      "magic": [65, 69, 80, 49],
      "version": 1,
      "packet_id": [0, 1, 2, ...],
      "created_at": 1781769600000,
      "agent": {
        "aip_id": "aip1...",
        "public_key": { "algorithm": "Ed25519", "key_bytes": [ ... ] },
        "provenance": {
          "model_commitment": [ ... ],
          "environment_commitment": [ ... ],
          "toolchain_commitment": [ ... ]
        }
      },
      "root_authority": {
        "principal_id": "aip1cfo...",
        "display_role": "CFO",
        "root_token": { ... }
      },
      "delegation_chain": [ ... ],
      "decision": { ... },
      "actions": [ ... ],
      "trace_binding": { ... },
      "receipt_binding": { ... },
      "claimed_trust_floor": "COUNTERPARTY_SIGNED",
      "packet_hash": [ ... ],
      "agent_sig": { ... }
    },
    "trusted_issuers": {
      "aip1cfo...": "3b24...hex_pubkey...",
      "aip1orch...": "8a71...hex_pubkey..."
    },
    "trusted_counterparties": {
      "ledger.example-bank.com": "5f10...hex_pubkey..."
    },
    "revoked_jtis": [
      "0123456789abcdef0123456789abcdef"
    ],
    "trace_data": "raw trace string to hash and compare against packet.trace_binding.trace_hash",
    "receipt_data": "raw receipt string to hash and compare against packet.receipt_binding.receipt_hash"
  }
  ```
- **Response Headers:** `Content-Type: application/json`
- **Response Body (`VerificationReport` - 200 OK):**
  ```json
  {
    "valid": true,
    "trust_floor": "COUNTERPARTY_SIGNED",
    "claimed_trust_floor": "COUNTERPARTY_SIGNED",
    "tampered": false,
    "authority_chain_verified": true,
    "delegation_chain_verified": true,
    "scope_verified": true,
    "receipt_verified": true,
    "trace_verified": true,
    "revocation_clear": true,
    "packet_id": "000102030405060708090a0b0c0d0e0f",
    "agent_id": "aip1paymentsagent...",
    "verified_at": 1781769600500,
    "checks": [
      { "rule": "STRUCTURE", "pass": true, "detail": "AEP1 v1 structure valid: 1 delegation hop(s), 1 action(s)" },
      { "rule": "AGENT_ID_BINDING", "pass": true, "detail": "agent AIP-ID derives from embedded public key and provenance" },
      { "rule": "CANONICAL_HASH", "pass": true, "detail": "recomputed canonical hash matches packet_hash" },
      { "rule": "AGENT_SIGNATURE", "pass": true, "detail": "agent packet signature verifies over canonical bytes" },
      { "rule": "ROOT_TOKEN_SIGNATURE", "pass": true, "detail": "root token signed by trusted issuer aip1cfo..." },
      { "rule": "DELEGATION_CHAIN", "pass": true, "detail": "1-hop delegation chain verified (per-hop signatures, JTI linkage, depth, scope attenuation)" },
      { "rule": "AUTHORITY_CHAIN", "pass": true, "detail": "authority chain connects principal aip1cfo... to acting agent aip1paymentsagent..." },
      { "rule": "SCOPE_AUTHORITY", "pass": true, "detail": "decision and all actions fall within the effective (most-attenuated) scope" },
      { "rule": "REVOCATION", "pass": true, "detail": "no token in the authority chain is revoked" },
      { "rule": "TEMPORAL_VALIDITY", "pass": true, "detail": "decision and actions fall within the validity window of every token in the chain" },
      { "rule": "ACTION_ATTESTATIONS", "pass": true, "detail": "all 1 action attestation(s) signed by the agent and bound to decision ..." },
      { "rule": "TRACE_BINDING", "pass": true, "detail": "supplied trace data hashes to the bound trace_hash for ..." },
      { "rule": "RECEIPT_BINDING", "pass": true, "detail": "receipt LEDGER-90211 @ ledger.example-bank.com countersigned by ledger.example-bank.com" },
      { "rule": "TRUST_FLOOR", "pass": true, "detail": "derived floor CounterpartySigned supports claimed floor CounterpartySigned" }
    ]
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: `{"error": "issuer ... key hex: Odd number of digits"}`
  - `401 Unauthorized`: `{"error": "missing or malformed Authorization: Bearer header"}` or `{"error": "invalid API key"}`

---

### 2.3 Endpoint Detail: `GET /v1/evidence/{id}`

- **Purpose:** Fetches a stored EvidencePacket by its 16-byte hex packet ID.
- **HTTP Method:** `GET`
- **Path:** `/v1/evidence/{id}`
- **Path Parameter:** `id` (32-character lowercase hex string representing `packet.packet_id`).
- **Authentication:** `Authorization: Bearer <token>`
- **Tenant Isolation:** Checks `state.store.get(&principal.tenant_id, &id)`. If missing or stored under a different tenant, returns `404 Not Found`.
- **Response Headers:** `Content-Type: application/json`
- **Response Body (200 OK):** The complete serialized `EvidencePacket` JSON.
- **Error Responses:**
  - `404 Not Found`: `{"error": "no evidence packet with id {id}"}`
  - `401 Unauthorized`: `{"error": "invalid API key"}`
  - `500 Internal Server Error`: `{"error": "evidence store backend error: ..."}`

---

### 2.4 Endpoint Detail: `GET /v1/authority/{id}`

- **Purpose:** Answers cross-packet authority questions:
  1. *Who authorized this action?* (returns `AuthorityPath`)
  2. *What is the DAG visualization?* (returns Graphviz DOT)
  3. *Which packets was this ID a root principal in?*
  4. *Which packets was this ID the acting agent in?*
- **HTTP Method:** `GET`
- **Path:** `/v1/authority/{id}`
- **Path Parameter:** `id` (can be a 32-character hex `action_id`, an `aip1...` principal ID, or an `aip1...` agent ID).
- **Authentication:** `Authorization: Bearer <token>`
- **Tenant Scoping:** Index is dynamically built from `state.store.all_for_tenant(&principal.tenant_id)`.
- **Response Headers:** `Content-Type: application/json`
- **Response Body (`AuthorityResponse` - 200 OK):**
  ```json
  {
    "query": "4bf92f3577b34da6a3ce929d0e0e4736",
    "action_authority": {
      "packet_id": "000102030405060708090a0b0c0d0e0f",
      "principal_id": "aip1cfo...",
      "principal_role": "CFO",
      "agent_id": "aip1paymentsagent...",
      "delegation_hops": [
        {
          "issuer_id": "aip1cfo...",
          "grantee_id": "aip1orch...",
          "depth": 0
        },
        {
          "issuer_id": "aip1orch...",
          "grantee_id": "aip1paymentsagent...",
          "depth": 1
        }
      ],
      "effective_scope_allowed": [
        "Standard(Write)"
      ],
      "integrity_ok": true
    },
    "accountability_dot": "digraph accountability {\n  rankdir=LR;\n  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\"];\n  principal [label=\"CFO (aip1cfo...)\", fillcolor=\"#E3F2FD\"];\n  authority_grant [label=\"root token ...\", fillcolor=\"#E8F5E9\"];\n  principal -> authority_grant [label=\"issues\"];\n  ...\n}",
    "as_principal": [
      "000102030405060708090a0b0c0d0e0f"
    ],
    "as_agent": [
      "000102030405060708090a0b0c0d0e0f"
    ]
  }
  ```
- **Fallback / Empty Behavior:** When `id` does not match an action ID, `action_authority: null` and `accountability_dot: null`, while `as_principal` and `as_agent` return empty arrays `[]` (HTTP status 200 OK).
- **Error Responses:**
  - `401 Unauthorized`: `{"error": "invalid API key"}`
  - `500 Internal Server Error`: `{"error": "evidence store backend error: ..."}`

---

### 2.5 Endpoint Detail: `GET /v1/evidence/{id}/export`

- **Purpose:** Generates a cryptographically sealed, portable audit ZIP bundle (`application/zip`) suitable for offline regulator inspection.
- **HTTP Method:** `GET`
- **Path:** `/v1/evidence/{id}/export`
- **Authentication:** `Authorization: Bearer <token>` (tenant-isolated).
- **Response Headers:**
  - `Content-Type: application/zip`
  - `Content-Disposition: attachment; filename="aip-evidence-{id}.zip"`
- **Response Body:** Binary ZIP archive containing exactly 7 entries:
  1. `evidence.json`: Complete canonical `EvidencePacket` JSON.
  2. `verification_report.json`: `VerificationReport` generated at export time with an empty context (integrity verification).
  3. `verification_report.md`: Human-readable Markdown summary formatted for auditors.
  4. `authority_graph.json`: Serialized `AccountabilityGraph` (nodes, edges, trust floors).
  5. `authority_graph.dot`: Graphviz DOT representation of the DAG.
  6. `manifest.json`: Bundle metadata, file checksums, and service signer key:
     ```json
     {
       "schema_version": "aip-bundle-1",
       "bundle_id": "4a12...16_byte_jti_hex...",
       "tenant_id": "acme",
       "packet_id": "000102030405060708090a0b0c0d0e0f",
       "exported_at": 1781769600000,
       "packet_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
       "bundle_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
       "signer_algorithm": "Ed25519",
       "signer_public_key": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
       "files": [
         { "name": "evidence.json", "sha256": "..." },
         { "name": "verification_report.json", "sha256": "..." },
         { "name": "verification_report.md", "sha256": "..." },
         { "name": "authority_graph.json", "sha256": "..." },
         { "name": "authority_graph.dot", "sha256": "..." }
       ]
     }
     ```
  7. `bundle_signature.sig`: Hex-encoded 64-byte Ed25519 signature over the exact bytes of `manifest.json`, signed by `state.signer_seed`.
- **Integrity Calculation:**
  $$\text{bundle\_hash} = \text{SHA-256}\left(\sum_{\text{sorted by name}} (\text{name} \parallel \text{":"} \parallel \text{sha256} \parallel \text{"\n"})\right)$$
- **Error Responses:**
  - `404 Not Found`: Packet ID not found or belongs to another tenant.
  - `401 Unauthorized`: Missing or invalid API key.

---

### 2.6 Additional Endpoints in `aip-service`

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `GET /health` | GET | Public | Healthcheck, service version, public key fingerprint |
| `POST /v1/evidence/generate` | POST | Machine | Generates, signs with provided agent seed, and stores an EvidencePacket |
| `POST /v1/identity/issue` | POST | Machine | Issues EdDSA JWT identity token |
| `POST /v1/identity/verify` | POST | Public | Validates EdDSA JWT token |
| `GET /v1/identity/public-key` | GET | Public | Returns SPKI EdDSA public key PEM & fingerprint |
| `POST /v1/identity/delegate` | POST | Machine | Creates delegation token with lattice-attenuated scope |
| `POST /v1/identity/verify-chain`| POST | Public | Validates linear delegation chain |
| `POST /v1/identity/revoke` | POST | Admin | Revokes JTI with optional cascade revocation |
| `GET /v1/identity/revocation-status/:jti` | GET | Public | Checks revocation status of JTI |
| `GET /.well-known/aip-configuration` | GET | Public | OpenID/OAuth-like discovery metadata |
| `GET /.well-known/jwks.json` | GET | Public | RFC 7517 JWKS endpoint |

---

## 3. Sample EvidencePackets & Bundles in the Repository

### 3.1 Status of Pre-generated Files
- A search of the codebase confirms that **no pre-baked static `.json` EvidencePackets or `.zip` bundles** are checked into the Git repository (aside from `aip-standalone/aip_store.json`).
- Instead, the codebase possesses **complete, deterministic, executable Rust test suites and demo generators** that produce every required packet variant on demand.

### 3.2 Fixture Generators Catalog

#### 1. The Banking Design-Partner Pilot Demo (`banking_demo/src/main.rs`)
- **Workflow:**
  - **Principal:** Human CFO (`aip1cfo...`) creates root token with `scope_orchestrator()` (Read, Write, Execute, Delegate; Admin Denied) and 1-hour TTL.
  - **Intermediary:** Treasury Orchestrator (`aip1orch...`) delegates to Payments Agent with `scope_submitter()` (Write only - lattice meet attenuation).
  - **Agent:** Payments Agent (`aip1paymentsagent...`) executes payment approval decision (`INV-2026-0142`, $48,200).
  - **Action:** Attestation for `POST /v1/ledger/payments {"invoice":"INV-2026-0142","amount":"$48,200.00"}`.
  - **Receipt:** External Core Banking Ledger countersigns receipt `LEDGER-90211` (`ledger.example-bank.com`).
  - **Trace:** OpenTelemetry W3C trace ID and SHA-256 hash.
- **Verification:** Verifies honest packet at `COUNTERPARTY_SIGNED` floor.
- **Tampering Demonstration:** Modifies summary from `$48,200.00` to `$4,820,000.00` -> Fails `CANONICAL_HASH`. Attacker recalculates `packet_hash` -> Fails `AGENT_SIGNATURE`.

#### 2. Protocol Test Suite (`aip-standalone/aip-protocol/tests/evidence_packet.rs`)
Contains 17 distinct cryptographic test cases:
1. `test_honest_packet_verifies_at_counterparty_floor`: Full clean pass across all 14 rules.
2. `test_tamper_decision_summary_detected`: Decision summary string mutation -> Fails `CANONICAL_HASH`.
3. `test_tamper_recompute_hash_still_caught_by_signature`: Hash recomputed after tamper -> Fails `AGENT_SIGNATURE`.
4. `test_tamper_action_payload_detected`: Single action payload altered -> Fails `ACTION_ATTESTATIONS` and `CANONICAL_HASH`.
5. `test_scope_escalation_in_chain_detected`: Swapping delegated Write-only scope for `CapabilityScope::all()` -> Fails `DELEGATION_CHAIN`.
6. `test_action_outside_scope_rejected`: Agent performs Delete action under Write-only delegation -> Fails `SCOPE_AUTHORITY`.
7. `test_revoked_delegation_invalidates_packet`: Adding hop JTI to `revoked_jtis` -> Fails `REVOCATION`.
8. `test_unknown_root_issuer_fails`: Root token issuer key omitted from context -> Fails `ROOT_TOKEN_SIGNATURE`.
9. `test_agent_identity_substitution_detected`: Attacker replaces agent block and re-signs -> Fails `AUTHORITY_CHAIN` and `ACTION_ATTESTATIONS`.
10. `test_tampered_receipt_data_detected`: Modifying receipt payload bytes -> Fails `RECEIPT_BINDING`.
11. `test_trace_data_mismatch_detected`: Supplying different trace export -> Fails `TRACE_BINDING`.
12. `test_claimed_floor_above_evidence_fails`: Claiming `COUNTERPARTY_SIGNED` without countersignature -> Fails `TRUST_FLOOR`.
13. `test_action_after_token_expiry_rejected`: Action timestamp exceeds token expiration -> Fails `TEMPORAL_VALIDITY`.
14. `test_two_hop_chain_verifies_and_attenuates`: Multi-tier delegation CFO -> Treasury -> Middleman -> Submitter -> Fails if attenuation is violated.

#### 3. Audit Bundle Test Suite (`aip-standalone/aip-protocol/tests/bundle.rs`)
Contains 7 bundle test cases:
1. `test_bundle_build_and_verify_ok`: Builds valid zip and verifies all 7 bundle checks pass.
2. `test_bundle_no_trust_keys_is_warning_not_fail`: Verifying without external keys passes structure and integrity, issuing `WARNING` on `PACKET_VERIFICATION`.
3. `test_bundle_tampered_content_detected`: Appending byte to `evidence.json` inside ZIP -> Fails `FILE_HASHES`.
4. `test_bundle_missing_file_detected`: Removing `evidence.json` from ZIP -> Fails `BUNDLE_STRUCTURE`.
5. `test_bundle_signature_mismatch_detected`: Overwriting `bundle_signature.sig` -> Fails `BUNDLE_SIGNATURE`.
6. `test_bundle_manifest_edit_breaks_signature`: Editing `tenant_id` in `manifest.json` -> Fails `BUNDLE_SIGNATURE`.
7. `emit_sample_bundle`: Function to write a sample ZIP directly to disk for CLI smoke testing.

---

## 4. The 14-Rule Verification Ledger Mapping

Every verification rule defined in `aip-protocol/src/verification_report.rs` must map 1:1 to UI checks in the console:

| Rule ID | Engine Constant | Target of Verification | Failure Condition |
|---|---|---|---|
| **R1** | `STRUCTURE` | Magic bytes `b"AEP1"`, version `1`, non-empty IDs | Missing fields, bad magic, 0 actions |
| **R2** | `AGENT_ID_BINDING` | `derive_aip_id(public_key, provenance)` | Agent ID does not match cryptographic derivation |
| **R3** | `CANONICAL_HASH` | Deterministic byte canonicalization & SHA-256 | Post-sealing modification of any covered field |
| **R4** | `AGENT_SIGNATURE` | Ed25519 signature over canonical bytes | Signature invalid or wrong signer ID |
| **R5** | `ROOT_TOKEN_SIGNATURE` | Root authority scoped token signature | Token signature invalid or unknown root issuer |
| **R6** | `DELEGATION_CHAIN` | Per-hop signature, parent-JTI link, depth, lattice meet | Broken link, depth skip, scope widening |
| **R7** | `AUTHORITY_CHAIN` | End-to-end actor graph connectivity | Grantee of leaf hop is not acting agent |
| **R8** | `SCOPE_AUTHORITY` | Actions & decision within leaf allowed scope | Action not permitted by effective scope |
| **R9** | `REVOCATION` | Token JTIs checked against verifier revocation set | Any JTI in chain present in revocation set |
| **R10** | `TEMPORAL_VALIDITY` | Decided at $\ge$ issued at, action $\le$ expired at | Action post-expiry or preceding decision |
| **R11** | `ACTION_ATTESTATIONS` | Per-action signature bound to `decision_id` | Action payload modified or wrong agent signature |
| **R12** | `TRACE_BINDING` | Optional external trace hash verification | Supplied trace data does not match hash |
| **R13** | `RECEIPT_BINDING` | Optional external receipt hash & countersignature | Receipt data mismatch or invalid countersignature |
| **R14** | `TRUST_FLOOR` | Derived floor $\ge$ Claimed floor | Claimed floor exceeds cryptographic evidence |

---

## 5. Evidence Vault Explorer: Offline Mock Fallback Architecture

Requirement R5 demands that the Evidence Vault Explorer in `aip-console/`:
1. Connect to live `aip-service` REST endpoints (`/v1/evidence/verify`, `/v1/evidence/{id}`, `/v1/authority/{id}`, `/v1/evidence/{id}/export`).
2. Provide an **offline mock fallback mode** when `aip-service` is unreachable or when running standalone in client-only mode.

### 5.1 Architecture & Abstraction Strategy

To ensure zero code duplication between live and offline modes, the console must use a unified client interface:

```typescript
// aip-console/src/lib/vault/types.ts

export interface VaultRecordSummary {
  packet_id: string;
  tenant_id: string;
  agent_id: string;
  principal_id: string;
  principal_role: string;
  decision_summary: string;
  action_count: number;
  created_at: number;
  trust_floor: TrustFloor;
  integrity_status: 'integrity_ok' | 'integrity_failed';
}

export interface VaultFilterParams {
  tenant_id?: string;
  trust_floor?: TrustFloor;
  search_query?: string;
  from_date?: number;
  to_date?: number;
  limit?: number;
  offset?: number;
}

export interface IEvidenceVaultClient {
  isLive(): boolean;
  getConnectionStatus(): ConnectionStatus;
  
  // Vault Explorer operations
  listEvidence(filter?: VaultFilterParams): Promise<VaultRecordSummary[]>;
  getEvidence(id: string): Promise<EvidencePacket>;
  exportEvidenceBundle(id: string): Promise<Blob>; // ZIP blob
  getAuthority(id: string): Promise<AuthorityResponse>;
  
  // Verification engine
  verifyEvidence(req: VerifyRequest): Promise<VerificationReport>;
  ingestEvidence(packet: EvidencePacket): Promise<string>;
}
```

### 5.2 Implementation Components for Offline Mock Mode

#### 1. Embedded Fixture Seed Catalog
The console repository will bundle a pre-generated set of rich mock fixtures derived directly from the Rust tests:
- `seed_counterparty_valid.json`: Valid payment approval with bilateral countersigned receipt.
- `seed_authority_bound_valid.json`: Two-hop delegation chain with Write-only attenuation.
- `seed_tampered_decision.json`: Invoice amount modified after sealing (`CANONICAL_HASH` fail).
- `seed_tampered_recomputed.json`: Tampered invoice with recalculated packet hash (`AGENT_SIGNATURE` fail).
- `seed_scope_escalation.json`: Escalated delegation scope (`DELEGATION_CHAIN` fail).
- `seed_revoked_delegation.json`: Valid packet referencing a revoked JTI (`REVOCATION` fail).
- `seed_bundle_valid.zip`: Full 7-file signed audit ZIP.

#### 2. Local Storage Persistence (IndexedDB)
- **Engine:** Use an IndexedDB wrapper (`idb` or Dexie) to persist user-ingested packets and simulated changes across browser refreshes.
- **Multi-Tenancy Simulation:** Store records with tenant attributes (`acme`, `fintech-global`, `legacy`). A UI tenant switcher lets auditors test cross-tenant isolation in offline mode.

#### 3. Client-Side WASM / JS Verification
- Verification in offline mode is executed by `aip-wasm` (the Rust `aip-protocol` crate compiled to WebAssembly via `wasm-bindgen`).
- When WASM is loaded, `verifyEvidence(req)` calls `wasm.verify_packet(jsonPacket, jsonContext)`.
- Zero verification logic is reimplemented in JavaScript.

#### 4. Client-Side Bundle Export
- When an auditor clicks "Export Audit Bundle" in offline mode:
  1. The client retrieves the packet from IndexedDB.
  2. Runs offline verification via WASM to obtain `VerificationReport`.
  3. Generates `AccountabilityGraph` JSON and Graphviz DOT.
  4. Generates `verification_report.md`.
  5. Assembles `manifest.json` and computes `bundle_hash`.
  6. Signs `manifest.json` using a simulated or embedded demo private key.
  7. Packs all 7 files into an `application/zip` blob using client-side ZIP packaging (`jszip` or WASM `build_zip`).
  8. Triggers browser download as `aip-evidence-{id}.zip`.

#### 5. Network Failover & State Indicator
- The UI contains a connection status detector:
  - Periodically polls `GET /health` with a 2-second timeout.
  - If unreachable, automatically switches to `MockEvidenceVaultClient` and updates the navigation bar badge:
    - 🟢 `Live Connected: aip-service (v0.2.0)`
    - 🟠 `Offline Mode: Local Mock Vault (WebAssembly Engine Active)`
  - An explicit toggle allows users to force Offline Mode for air-gapped demoing.

---

## 6. Recommendations for Console Developers

1. **Static Fixture Generation Script:** Create a build-time script or Rust utility in `aip-standalone/` (e.g., `emit_console_fixtures`) that automatically runs the test generators and exports the resulting JSON packets and ZIP bundles directly into `aip-console/public/fixtures/`.
2. **React Flow Integration:** Use node types mirroring `NodeKind`: `principal`, `authority_grant`, `delegation`, `agent`, `decision`, `action`, `receipt`. Color-code nodes based on verification status (Green = Passed, Red = Failed, Amber = Warning/Revoked).
3. **Adversarial Tamper Simulator:** Allow the user to edit fields (such as `decision.summary`, `action.payload_hash`, `agent_sig.signature_bytes`) and provide a "Recalculate Packet Hash" toggle to demonstrate how the two-tier hash/signature barrier catches both naive and hash-fixing attackers.
4. **WASM Build Pipeline:** Configure Next.js webpack/turbopack to bundle the `.wasm` binary generated by `wasm-pack` from `aip-protocol` / `aip-wasm`.
