# Project: AIP Enterprise Accountability Console (`aip-console`)

## Architecture
The AIP Enterprise Accountability Console is a high-assurance cyber/crypto web application providing offline and connected verification and inspection of Agent Identity Protocol (AIP) EvidencePackets with Syntriass enterprise branding.

```
+---------------------------------------------------------------------------------------+
|                                    Syntriass Console UI                               |
|   +-------------------+  +-------------------+  +-------------------+  +------------+ |
|   | 14-Rule Ledger    |  | React Flow DAG    |  | Tamper Simulator  |  | Authority  | |
|   | & Trust Floor     |  | (@xyflow/react)   |  | (14 Mutation Vec) |  | Lattice    | |
|   +-------------------+  +-------------------+  +-------------------+  +------------+ |
|             \                      |                      /                  /        |
|   +---------------------------------------------------------------------------------+ |
|   |                      WASM Bridge Provider (useAipVerifier)                      | |
|   +---------------------------------------------------------------------------------+ |
+---------------------------------------------------------------------------------------+
            | (Zero-JS verification / 1:1 rule mapping)             | (REST fallback)
            v                                                       v
+-------------------------------+                       +-------------------------------+
|     aip-wasm (WebAssembly)    |                       |      aip-service (Axum REST)  |
| - verify_evidence_packet      |                       | - /v1/evidence/verify         |
| - verify_bundle_zip           |                       | - /v1/evidence/{id}           |
| - get_accountability_graph    |                       | - /v1/authority/{id}          |
| - recompute_packet_hash       |                       | - /v1/evidence/{id}/export    |
| - meet_capability_scopes      |                       +-------------------------------+
| - extract_bundle_files        |                                       |
+-------------------------------+                       +-------------------------------+
            | (compiles directly from)                          | Evidence Vault Explorer       |
            v                                                   | (Live + Offline Mock Fallback)|
+-------------------------------+                       +-------------------------------+
|     aip-protocol & aip-core   |
+-------------------------------+
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | `aip-wasm` Rust Crate & Compilation | WebAssembly bridge crate compiling `aip-protocol` to wasm32-unknown-unknown with 10 export functions and `getrandom`/time compatibility | M1 | R1, Survey |
| F2 | Test Fixture Generation Pipeline | Sample EvidencePackets and ZIP bundles (valid, tampered, attenuated, countersigned) generated for tests and console | M1 | R1, Survey |
| F3 | Next.js 15 & React 19 App Shell | Next.js 15 App Router, React 19, TypeScript, Tailwind CSS, shadcn/ui application setup in `aip-console/` | M2 | R6, Survey |
| F4 | Syntriass Enterprise Branding & Assets | Custom inline vector SVG logo & wordmark, obsidian/cyan theme, cyber/crypto styling | M2 | R6, Survey |
| F5 | Drag-and-Drop Ingestion (JSON & ZIP) | File drop zone supporting raw EvidencePacket JSON and audit ZIP bundles | M2 | R1, Survey |
| F6 | Verifier Trust Anchor Configuration | Input panel for verifier trust keys (trusted principal issuers and counterparties) | M2 | R1, Survey |
| F7 | 14-Rule Verification Ledger | 1:1 display of the 14 engine verification rules with pass/fail badges, details, and zero JS verification | M2 | R1, Survey |
| F8 | Trust Floor Progression Ladder | Mathematical Trust Floor progression badge (UNVERIFIED -> AGENT_SIGNED -> AUTHORITY_BOUND -> COUNTERPARTY_SIGNED) | M2 | R1, Survey |
| F9 | Interactive Accountability Graph DAG | React Flow DAG visualizer with 7 node types and 6 edge relations from Principal to Countersigned Receipt | M3 | R2, Survey |
| F10 | DAG Node Inspection Sheet | Interactive drawer displaying cryptographic signatures, AIP-ID, hashes, scopes, and verification status | M3 | R2, Survey |
| F11 | Adversarial Tamper Sandbox | Field modification and payload mutation simulator with 14 attack vectors | M4 | R3, Survey |
| F12 | Smart Hash Recalculation Toggle | Hash recomputation engine demonstrating tamper detection with and without hash fixing | M4 | R3, Survey |
| F13 | Instant Rule Failure Feedback | Real-time failure ledger updates showing exact violated cryptographic rules | M4 | R3, Survey |
| F14 | Visual Scope Matrix Editor | Interactive permission editor for standard named scopes (`ADMIN`, `ORCHESTRATOR`, etc.) and custom actions | M4 | R4, Survey |
| F15 | Capability Lattice Attenuation Preview | Visual attenuation validator calculating meet operator ($\sqcap$) and warning on $\bot$ empty intersection | M4 | R4, Survey |
| F16 | Cascade Revocation Tree | Interactive tree visualization of delegated tokens with recursive subtree revocation | M4 | R4, Survey |
| F17 | Evidence Vault Explorer Table | Multi-tenant table view of evidence packets with search, filter, and sorting | M5 | R5, Survey |
| F18 | Signed ZIP Bundle Export | Export tool producing 7-file audit ZIP bundles conforming to `AUDIT_EXPORT_SPEC.md` | M5 | R5, Survey |
| F19 | Connected Service Client (`aip-service`) | REST API integration for `/v1/evidence/verify`, `/v1/evidence/{id}`, `/v1/authority/{id}`, `/v1/evidence/{id}/export` | M5 | R5, Survey |
| F20 | Offline Mock Fallback Mode | IndexedDB local repository + WASM offline verification + client-side ZIP packaging with live/offline toggle | M5 | R5, Survey |
| F21 | End-to-End Test Suite (Tiers 1-4) | Comprehensive opaque-box test suite verifying all features, boundary cases, pairwise combinations, and workflows | E2E Track & M7 | AC, Survey |
| F22 | Adversarial Coverage Hardening (Tier 5) | White-box stress testing, edge-case generation, and adversarial hardening | M7 | AC, Survey |
| F23 | Corporate Anti-Vibe Visual Redesign | Refined corporate palette (slate/navy/steel/refined emerald), structured rectangular geometry (`rounded-md`/`rounded-sm`, no pill buttons), fluid micro-interactions (no flashy animations), clean Lucide SVG icons (no emojis), clean typography (no em dashes), standard cursor (no trailers) | M6 | Follow-up, R6 |
| F24 | Content, Copy Rigor & Data Integrity | Precision technical copywriting (no AI-slop headlines), realistic architectural UI media/diagrams (no generic 3D/stock), strict removal of fake customer counters/ticking metrics/simulated tickers | M6 | Follow-up |
| F25 | Pre-Launch Compliance & Legal Infrastructure | Dedicated `/privacy` and `/terms` compliance pages, clean favicon in `app/layout.tsx` and `public/favicon.svg`, complete removal of AI watermarks, custom domain routing readiness | M6 | Follow-up |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | `aip-wasm` Core Engine & Fixtures Pipeline | F1, F2: Rust WebAssembly crate `aip-wasm`, exports, `getrandom`/WASM time support, `wasm-pack` compilation to `aip-console/public/wasm/`, fixture generator | none | DONE |
| M2 | Console Shell, Syntriass Branding & Ingestion Ledger | F3, F4, F5, F6, F7, F8: Next.js 15, React 19, Syntriass SVG branding/styling, WASM loader, drag-and-drop JSON/ZIP ingestion, 14-rule verification ledger, Trust Floor ladder | M1 | DONE |
| M3 | Interactive Accountability Graph DAG Viewer | F9, F10: React Flow DAG viewer (@xyflow/react) with 7 node types, 6 edge types, node selection, inspection sheet, and crypto verification badges | M1, M2 | DONE |
| M4 | Adversarial Tamper Simulator & Authority Lattice Builder | F11, F12, F13, F14, F15, F16: 14-vector tamper simulator, hash recomputation toggle, live rule failure feedback; Scope matrix editor, lattice meet ($\sqcap$) preview, cascade revocation tree | M1, M2 | IN_PROGRESS |
| M5 | Evidence Vault Explorer & Connected/Offline Service Client | F17, F18, F19, F20: Multi-tenant table, search/filter, ZIP export, `IEvidenceVaultClient` with `LiveClient` (`aip-service`) and `MockClient` (IndexedDB + preloaded fixtures + live/offline toggle) | M1, M2 | PLANNED |
| M6 | Corporate Anti-Vibe Redesign & Pre-Launch Compliance | F23, F24, F25: Full visual overhaul to deep slate/navy/steel/emerald, rectangular buttons, zero emojis/em dashes/fake metrics, `/privacy` and `/terms` pages, clean favicon, custom domain readiness | M2, M3, M4, M5 | PLANNED |
| M7 | Final E2E Verification & Adversarial Coverage Hardening | F21, F22: Pass 100% E2E test suite (Tiers 1-4), Tier 5 adversarial test hardening, zero regression verification | M1-M6, E2E Track | PLANNED |


## Interface Contracts

### `aip-wasm` WebAssembly Interface
```typescript
interface AipWasmExports {
  verify_evidence_packet(packetJson: string, contextJson?: string): string; // returns JSON VerificationReport
  verify_bundle_zip(zipBytes: Uint8Array, contextJson?: string): string;    // returns JSON BundleVerificationResult
  get_accountability_graph(packetJson: string, reportJson?: string): string;// returns JSON AccountabilityGraph
  recompute_packet_hash(packetJson: string): string;                        // returns hex string
  get_canonical_bytes_hex(packetJson: string): string;                      // returns hex string
  check_scope_permits(scopeJson: string, actionJson: string): boolean;
  meet_capability_scopes(parentJson: string, childJson: string): string;    // returns JSON CapabilityScope
  extract_bundle_files(zipBytes: Uint8Array): string;                       // returns JSON map of filenames -> content
  get_sample_packet(sampleType: string): string;                            // returns JSON EvidencePacket
}
```

### VerificationReport Engine Types (1:1 UI Ledger Contract)
```typescript
interface VerificationReport {
  overall_valid: boolean;
  claimed_trust_floor: TrustFloor;
  derived_trust_floor: TrustFloor;
  tamper_evidence: boolean;
  verified_at: number;
  checks: RuleResult[];
}

interface RuleResult {
  rule: "STRUCTURE" | "AGENT_ID_BINDING" | "CANONICAL_HASH" | "AGENT_SIGNATURE" |
        "ROOT_TOKEN_SIGNATURE" | "DELEGATION_CHAIN" | "AUTHORITY_CHAIN" |
        "SCOPE_AUTHORITY" | "REVOCATION" | "TEMPORAL_VALIDITY" |
        "ACTION_ATTESTATIONS" | "TRACE_BINDING" | "RECEIPT_BINDING" | "TRUST_FLOOR";
  pass: boolean;
  detail: string;
}

type TrustFloor = "UNVERIFIED" | "AGENT_SIGNED" | "AUTHORITY_BOUND" | "COUNTERPARTY_SIGNED";
```

### Vault Client Interface (`IEvidenceVaultClient`)
```typescript
interface IEvidenceVaultClient {
  isLive(): boolean;
  listEvidence(filter?: EvidenceFilter): Promise<EvidenceSummary[]>;
  getEvidence(id: string): Promise<EvidencePacket>;
  verifyEvidence(req: VerifyRequest): Promise<VerificationReport>;
  getAuthorityGraph(id: string): Promise<AuthorityResponse>;
  exportBundle(id: string): Promise<Blob>; // ZIP file blob
}
```

## Code Layout
- `aip-standalone/aip-wasm/`: Rust crate compiling to WebAssembly (`Cargo.toml`, `src/lib.rs`). Owned by M1.
- `aip-console/public/wasm/`: Compiled WebAssembly binary and JavaScript bindings (`aip_wasm.js`, `aip_wasm_bg.wasm`). Owned by M1.
- `aip-console/public/fixtures/`: Pre-compiled EvidencePackets and audit ZIP bundles. Owned by M1.
- `aip-console/src/`: Next.js 15 application source code:
  - `src/app/`: App router pages (`page.tsx`, `layout.tsx`, `globals.css`). Owned by M2.
  - `src/components/brand/`: Syntriass inline SVG logos, wordmarks, navigation header. Owned by M2.
  - `src/components/ingestion/`: Drag-and-drop zone, ledger, Trust Floor badge. Owned by M2.
  - `src/components/graph/`: React Flow DAG components, custom nodes, inspection sheet. Owned by M3.
  - `src/components/tamper/`: Tamper sandbox, mutation sliders/inputs, diff viewer. Owned by M4.
  - `src/components/authority/`: Scope matrix editor, lattice meet preview, revocation tree. Owned by M4.
  - `src/components/vault/`: Multi-tenant table, search/filter, ZIP export. Owned by M5.
  - `src/lib/wasm/`: WASM loader hook, types, bindings adapter. Owned by M2.
  - `src/lib/api/`: `IEvidenceVaultClient`, `LiveClient`, `MockClient`. Owned by M5.
- `e2e/`: Automated E2E test suites (Tiers 1-5). Owned by E2E Testing Track & M6.
