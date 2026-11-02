# Handoff Report: Services & Test Fixtures Explorer

**Agent:** Explorer 2 (Services & Test Fixtures Explorer)  
**Parent Conversation ID:** `675111aa-04e8-493f-9811-dbfc1935a77b`  
**Working Directory:** `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\survey_explorer_services\`  
**Handoff Type:** Hard (Task complete)

---

## 1. Observation

1. **Workspace Layout & Crates:**
   - The workspace lacks a root-level `Cargo.toml`. Two standalone Rust projects exist:
     - `aip-service/Cargo.toml` (`airon-aip v0.2.0`, Axum 0.7 REST microservice).
     - `aip-standalone/Cargo.toml` (v0.4.0 workspace containing `aip-protocol`, `aip-core`, `aip-crypto`, `aip-types`, `aip-verify`, `aip-real-tests`, `banking_demo`).
   - Documentation in `docs/AUDIT_EXPORT_SPEC.md` and `AIP_SPEC.md` normatively define the `EvidencePacket` wire format, the 14-rule verification engine, and the `aip-bundle-1` audit ZIP bundle specification.

2. **Endpoints in `aip-service`:**
   Directly observed in `aip-service/src/lib.rs:63-89`, `aip-service/src/evidence.rs:1-487`, and `aip-service/src/authority.rs:1-170`:
   - `POST /v1/evidence/verify` (`evidence.rs:366-372`): Stateless verification endpoint taking `VerifyRequest` (packet, trusted issuers map, trusted counterparties map, revoked JTIs, optional trace/receipt data) and returning `VerificationReport` with overall `valid`, `trust_floor`, `tampered`, and `checks` array. Requires Bearer authentication (`auth::Principal`).
   - `GET /v1/evidence/:id` (`evidence.rs:374-395`): Tenant-isolated packet retrieval. Calls `store.get(&principal.tenant_id, &id)`. Returns 404 for missing or cross-tenant IDs.
   - `GET /v1/authority/:id` (`evidence.rs:459-487`): Dynamic DAG query. Reconstructs `AuthorityGraph` from all stored packets of the caller's tenant (`state.store.all_for_tenant`). Returns `AuthorityResponse` containing `action_authority` (`AuthorityPath`), `accountability_dot` (Graphviz DOT string), `as_principal` list, and `as_agent` list.
   - `GET /v1/evidence/:id/export` (`evidence.rs:401-457`): Produces an `application/zip` stream attachment named `aip-evidence-{id}.zip`. Calls `aip_protocol::build_zip(...)`, which packages 7 canonical files: `evidence.json`, `verification_report.json`, `verification_report.md`, `authority_graph.json`, `authority_graph.dot`, `manifest.json`, and `bundle_signature.sig`.
   - `POST /v1/evidence/generate` (`evidence.rs:336-361`): Ingests `GenerateRequest` (agent seed hex, provenance, root token, delegation hops, decision, actions, trace, receipt), builds and signs packet, and persists to store.

3. **Multi-Tenancy & Authentication:**
   Directly observed in `aip-service/src/auth.rs:39-196`:
   - Authenticated via `Authorization: Bearer <secret>`.
   - Key store hashes secret via SHA-256 (`by_hash: HashMap<[u8; 32], Entry>`) and maps to `Principal { tenant_id, key_id, role }`.
   - Tenant isolation is enforced at the store layer; tenant ID is never accepted as user input.

4. **Existing Fixtures & Test Scenarios:**
   - No pre-saved static `.json` or `.zip` evidence files exist in git (only `aip-standalone/aip_store.json` and `deploy/docker/keys.example.json`).
   - Programmatic generators exist and pass all tests:
     - `aip-protocol/tests/evidence_packet.rs` (17 tests): honest packet at `CounterpartySigned` floor, 12+ tampering scenarios (`CANONICAL_HASH`, `AGENT_SIGNATURE`, `ACTION_ATTESTATIONS`, `DELEGATION_CHAIN`, `SCOPE_AUTHORITY`, `REVOCATION`, `ROOT_TOKEN_SIGNATURE`, `AUTHORITY_CHAIN`, `RECEIPT_BINDING`, `TRACE_BINDING`, `TRUST_FLOOR`, `TEMPORAL_VALIDITY`), two-hop scope attenuation.
     - `aip-protocol/tests/bundle.rs` (7 tests): clean bundle build and verify, missing file tamper, hash mismatch tamper, signature forgery tamper, manifest tampering, warning when trust keys are omitted.
     - `banking_demo/src/main.rs`: Human CFO -> Treasury Orchestrator -> Payments Agent -> Core Banking Ledger receipt countersign, verifying honest packet and catching live single-field tampered packet.
     - `aip-service/src/test_support.rs`: `sample_packet()` and `sample_generate_request()`.

5. **Test Execution Results:**
   - Command: `cargo test --manifest-path aip-standalone/Cargo.toml -p aip-protocol` -> 27 passed; 0 failed; 1 ignored.
   - Command: `cargo test --manifest-path aip-service/Cargo.toml` -> 38 passed; 0 failed; 0 ignored.

---

## 2. Logic Chain

1. **Step 1: REST API Requirements Mapping.**
   - In R5, the Enterprise Accountability Console must provide an Evidence Vault Explorer that queries `/v1/evidence/verify`, `/v1/evidence/{id}`, `/v1/authority/{id}`, and `/v1/evidence/{id}/export`.
   - Inspection of `aip-service/src/evidence.rs` confirms these exact routes exist, take JSON or path parameters, and return the required schemas (`VerificationReport`, `EvidencePacket`, `AuthorityResponse`, and ZIP bytes).
   - Because `aip-service` requires Bearer authentication, the console must either configure an API key (e.g. `acme-secret` matching `deploy/docker/keys.example.json`) or communicate through a Next.js server proxy that attaches the key.

2. **Step 2: Dual-Mode Vault Architecture (Live vs Offline Mock).**
   - In production or local dev when `aip-service` is running on `localhost:3000` (or configured port), the console talks directly to `aip-service`.
   - When `aip-service` is unreachable, R5 explicitly mandates an offline mock fallback mode.
   - Because verification is pure cryptography and the repository contains `aip-protocol` (compilable to WASM via `wasm-pack`), offline mock mode can execute full 14-rule verification directly in the browser with 0% logic duplicated in JavaScript.
   - For listing and retrieving evidence packets offline, the console must maintain a local client store (IndexedDB seeded with pre-compiled representative packets: honest counterparty, authority bound, tampered decision, tampered signature, scope escalation, and revoked token).

3. **Step 3: Export Generation in Offline Mode.**
   - `docs/AUDIT_EXPORT_SPEC.md` specifies that the export ZIP must contain exactly 7 files with a signed manifest.
   - In live mode, this is handled by `GET /v1/evidence/{id}/export`.
   - In offline mock mode, the console can generate the ZIP in-memory using `jszip` (or WASM) populated with the stored packet, a locally evaluated `verification_report.json` & `.md`, `authority_graph.json` & `.dot`, and a simulated manifest signature.

---

## 3. Caveats

1. **No Existing Static Fixture Files in Git:** Developers expecting static `.json` or `.zip` files in `fixtures/` will find none. They must be extracted from the Rust test generators or emitted using an export script before bundling into `aip-console/public/fixtures/`.
2. **PostgreSQL vs JSONL Storage Backend:** In `aip-service`, PostgreSQL is behind the `postgres` cargo feature flag; default build uses `JsonlEvidenceStore`. Both implement `EvidenceStore`, so REST API surface is completely identical regardless of storage backend.
3. **Absence of a `/v1/evidence` List Endpoint in `aip-service`:** Notice that `aip-service` provides `GET /v1/evidence/{id}`, `GET /v1/authority/{id}`, and `POST /v1/evidence/generate`, but does not currently expose a generic paginated `GET /v1/evidence` collection endpoint. In live mode, the UI can either query `/v1/authority/` or `aip-service` could be augmented, whereas the console's client layer (`EvidenceVaultClient`) abstracts list/search across known IDs or local store.

---

## 4. Conclusion

1. The service endpoints in `aip-service` are fully functional, strictly typed, and thoroughly tested (38/38 passing unit/integration tests).
2. The 14 verification rules in `aip-protocol` are completely standardized with stable string identifiers in `verification_report::rules` and cover every required trust floor progression: `UNVERIFIED` $\to$ `AGENT_SIGNED` $\to$ `AUTHORITY_BOUND` $\to$ `COUNTERPARTY_SIGNED`.
3. The offline mock fallback mode for the Evidence Vault Explorer is architecturally straightforward: implementing an `IEvidenceVaultClient` with a `LiveClient` and `MockClient` (using IndexedDB + WASM verifier + JSZip) provides seamless, robust operation whether connected or air-gapped.

---

## 5. Verification Method

To independently verify the observations and conclusions in this report:

1. **Verify Standalone Protocol & Bundle Tests:**
   ```powershell
   cargo test --manifest-path aip-standalone/Cargo.toml -p aip-protocol
   ```
   *Expected outcome:* 27 passed; 0 failed. Verifies 14-rule engine, all tamper scenarios, and bundle build/verification.

2. **Verify Banking Demo End-to-End Execution:**
   ```powershell
   cargo run --manifest-path aip-standalone/Cargo.toml -p banking-demo
   ```
   *Expected outcome:* Clean terminal output showing Step 1 through Step 9 and `VERDICT: EvidencePacket: cryptographic accountability demonstrated end-to-end.`

3. **Verify Service Endpoints & Tenant Isolation Tests:**
   ```powershell
   cargo test --manifest-path aip-service/Cargo.toml
   ```
   *Expected outcome:* 38 passed; 0 failed. Verifies `/v1/evidence/*`, `/v1/authority/*`, and cross-tenant isolation.

4. **Inspect Key Spec & Source Files:**
   - `aip-service/src/evidence.rs` (lines 332-487)
   - `aip-service/src/authority.rs` (lines 25-170)
   - `aip-standalone/aip-protocol/src/bundle.rs` (lines 27-245)
   - `docs/AUDIT_EXPORT_SPEC.md`
