# Milestone 2 Explorer 3: 14-Rule Verification Ledger & Trust Floor Specification

**Author**: Milestone 2 Explorer 3 (14-Rule Verification Ledger & Trust Floor Specialist)  
**Date**: 2026-11-02  
**Target Codebase**: `aip-console/src/components/ingestion/` & `aip-console/src/types/`  
**Reference Implementations**:
- `aip-standalone/aip-protocol/src/verification.rs` (normative 14 rules)
- `aip-standalone/aip-protocol/src/verification_report.rs` (normative data structures)
- `aip-standalone/aip-wasm/src/lib.rs` (`verify_evidence_packet` WASM export)
- `aip-standalone/aip-wasm/src/context.rs` (verifier trust context parser)
- `aip-console/public/fixtures/index.json` (test vectors and ground truth)

---

## 1. Executive Summary & Verification Architecture

The AIP verification engine is strictly non-short-circuiting and deterministic. When `verify_evidence_packet(packetJson, contextJson)` is executed via WebAssembly (`aip-wasm`), it evaluates exactly **14 verification rules** in fixed order and generates a complete, untruncated `VerificationReport`.

### Strict Invariant: Zero-JS Verification Logic
```
+-------------------------------------------------------------------------+
|                  WASM Layer (Rust aip-protocol / aip-wasm)              |
|   - Recomputes SHA-256 canonical packet hashes                          |
|   - Verifies Ed25519 agent signatures                                   |
|   - Validates AIP-ID checksum & provenance derivation                   |
|   - Checks root issuer signature against caller-trusted keys            |
|   - Verifies N-hop delegation chain, depth monotonicity & scope MEET    |
|   - Checks JTI set against revocation registry                          |
|   - Evaluates temporal issuance/expiry windows                          |
|   - Derives mathematical Trust Floor (0..3)                             |
+-------------------------------------------------------------------------+
                                    |
          Pure Data Projection (VerificationReport JSON)
                                    v
+-------------------------------------------------------------------------+
|                React / TypeScript UI Layer (aip-console)                |
|   STRICT CONSTRAINT: ZERO verification logic in JavaScript/TypeScript   |
|   - NEVER recalculates hashes, checks lengths, or asserts pass/fail     |
|   - Pure, high-fidelity projection of RuleResult[] from WASM            |
|   - Interactive expansion of verbatim detail strings                    |
|   - Cryptographic hash extraction & visual tamper evidence badges       |
+-------------------------------------------------------------------------+
```

---

## 2. The 14-Rule Verification Ledger UI Specification (`VerificationLedger.tsx`)

### 2.1 The 14 Rules Mapped 1:1 to Rust Engine

Every check displayed in `VerificationLedger.tsx` corresponds directly to an entry in `VerificationReport.checks`:

| # | Rule Identifier | Layer | Engine Check Description | Success Condition | Tamper Evidence Condition |
|---|---|---|---|---|---|
| **01** | `STRUCTURE` | Layer 1: Integrity | Magic bytes `"AEP1"`, version `1`, non-empty IDs, summary & actions | Structural integrity intact | `false` |
| **02** | `AGENT_ID_BINDING` | Layer 1: Integrity | Base58 checksum & `derive_aip_id(pubkey, provenance)` match `aip_id` | Identity cryptographically bound | `false` (unverified identity) |
| **03** | `CANONICAL_HASH` | Layer 1: Integrity | Deterministic canonical serialization SHA-256 matches `packet_hash` | Hash matches sealed payload | **`true`** (payload altered in transit) |
| **04** | `AGENT_SIGNATURE` | Layer 1: Integrity | Agent's Ed25519 signature verifies over recomputed canonical hash | Valid cryptographic agent sig | **`true`** (forgery or payload mismatch) |
| **05** | `ROOT_TOKEN_SIGNATURE` | Layer 2: Authority | Principal's Ed25519 signature on root token under trusted key | Principal authorized root token | **`true`** (if key trusted but sig invalid) |
| **06** | `DELEGATION_CHAIN` | Layer 2: Authority | N-hop chain: JTI linkage, depth monotonicity, scope subset ($\subseteq$) | Valid monotonic delegation | **`true`** (scope escalation / lineage forgery) |
| **07** | `AUTHORITY_CHAIN` | Layer 2: Authority | Organizational continuity: Principal $\to$ Root Token $\to$ Hops $\to$ Acting Agent | Unbroken chain of authority | `false` (handoff mismatch) |
| **08** | `SCOPE_AUTHORITY` | Layer 2: Authority | Decision & every action kind permitted by effective lattice scope | All actions authorized | `false` (unauthorized action kind) |
| **09** | `REVOCATION` | Layer 3: Validity | Root token JTI & all delegation JTIs checked against verifier set | No token in chain revoked | `false` (revoked, not tampered) |
| **10** | `TEMPORAL_VALIDITY` | Layer 3: Validity | Decided/performed timestamps within token issuance/expiry; actions $\ge$ decision | Window valid & chronological | `false` (expired / retroactive) |
| **11** | `ACTION_ATTESTATIONS`| Layer 3: Validity | Per-action Ed25519 signatures and payload bindings to `decision_id` | Every action authenticated | **`true`** (action transplant / forgery) |
| **12** | `TRACE_BINDING` | Layer 4: Bilateral | Optional W3C distributed trace ID + SHA-256 hash cross-checked | Trace matches or optional pass | **`true`** (on supplied hash mismatch) |
| **13** | `RECEIPT_BINDING` | Layer 4: Bilateral | Optional external receipt hash + counterparty Ed25519 signature | Countersigned or hash bound | **`true`** (on hash or sig mismatch) |
| **14** | `TRUST_FLOOR` | Layer 4: Bilateral | Derives supported floor ($0..3$); verifies claimed floor $\le$ derived | Claimed floor supported | `false` (claim inflated) |

### 2.2 Visual Presentation Architecture

The ledger is organized into four distinct architectural layers with status counters:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 14-RULE VERIFICATION LEDGER                             [Expand All] [Filter]│
│ Verified at 2026-11-02 10:14:02 UTC | Packet ID: 4a8f9c... | Acting Agent: aip1... │
├─────────────────────────────────────────────────────────────────────────────┤
│ 🛡️ LAYER 1: CRYPTOGRAPHIC INTEGRITY & AGENT IDENTITY          [4/4 PASS]    │
│  [01] STRUCTURE              ● PASS   Magic AEP1, 1 delegation hop, 1 action  ▼│
│  [02] AGENT_ID_BINDING       ● PASS   AIP-ID derived from pubkey & provenance  ▼│
│  [03] CANONICAL_HASH         ● PASS   Recomputed SHA-256 matches packet_hash  ▼│
│  [04] AGENT_SIGNATURE        ● PASS   Ed25519 signature verifies over payload  ▼│
├─────────────────────────────────────────────────────────────────────────────┤
│ 🏛️ LAYER 2: ORGANIZATIONAL AUTHORITY & DELEGATION              [4/4 PASS]    │
│  [05] ROOT_TOKEN_SIGNATURE   ● PASS   Root token signed by trusted issuer     ▼│
│  [06] DELEGATION_CHAIN       ● PASS   1-hop delegation chain verified         ▼│
│  [07] AUTHORITY_CHAIN        ● PASS   Principal connects to acting agent       ▼│
│  [08] SCOPE_AUTHORITY        ● PASS   Decision and actions within scope       ▼│
├─────────────────────────────────────────────────────────────────────────────┤
│ ⏱️ LAYER 3: TEMPORAL VALIDITY & ACTION ATTESTATIONS           [3/3 PASS]    │
│  [09] REVOCATION             ● PASS   No token in chain revoked               ▼│
│  [10] TEMPORAL_VALIDITY      ● PASS   Timestamps within validity window       ▼│
│  [11] ACTION_ATTESTATIONS    ● PASS   All 1 action attestations signed & bound▼│
├─────────────────────────────────────────────────────────────────────────────┤
│ 🌐 LAYER 4: EXTERNAL BINDINGS & TRUST FLOOR PROOF             [3/3 PASS]    │
│  [12] TRACE_BINDING          ● PASS   Trace data hashes to bound trace_hash   ▼│
│  [13] RECEIPT_BINDING        ● PASS   Receipt countersigned by counterparty   ▼│
│  [14] TRUST_FLOOR            ● PASS   Derived floor COUNTERPARTY_SIGNED       ▼│
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Interactive Detail Expansion & Tamper Evidence Highlighting

When an auditor clicks on any rule row, it smoothly expands to reveal:
1. **Engine Verbatim Detail**: Exact string returned from the Rust engine in monospace styling.
2. **Cryptographic Hashes & Identifiers**:
   - Automatically detects 64-character SHA-256 hex strings, 32-character JTIs, and `aip1...` IDs in the detail string.
   - Formats them as clickable, copyable interactive chips with tooltip feedback.
3. **Tamper Alert Badge**:
   - If `rule.pass === false` and `report.tamper_evidence === true`:
     - Emits a high-alert crimson banner (`#FF1744` / `#EF4444`):
       `🚨 POSITIVE TAMPER EVIDENCE: Post-signing payload or signature mutation detected.`
   - If `rule.pass === false` and `report.tamper_evidence === false`:
     - Emits an informational failure banner (e.g. `⚠️ VERIFIABILITY GAP: Untrusted root issuer key` or `🚫 REVOCATION: Token revoked in verifier registry`).
4. **Normative Specification Citation**:
   - Cites the specific clause of `AIP_SPEC.md` and the Rust reference function (`aip-protocol::verification`).

---

## 3. Trust Floor Progression Badge Specification (`TrustFloorBadge.tsx`)

### 3.1 Mathematical Trust Floor Ordering
The Agent Identity Protocol defines four strictly ordered trust levels:

$$\text{UNVERIFIED (0)} < \text{AGENT\_SIGNED (1)} < \text{AUTHORITY\_BOUND (2)} < \text{COUNTERPARTY\_SIGNED (3)}$$

| Floor Level | Value Enum | Color Token | Hex Code | Cryptographic Guarantee |
|---|---|---|---|---|
| **Level 0** | `UNVERIFIED` | `slate-400` | `#94A3B8` | Structure parsed, but cryptographic signatures invalid or unverified |
| **Level 1** | `AGENT_SIGNED` | `amber-400` | `#F59E0B` | Agent's private key signed the exact payload; payload unmutated since sealing |
| **Level 2** | `AUTHORITY_BOUND` | `cyan-400` | `#00E5FF` | Agent acted under valid organizational delegation from a trusted principal |
| **Level 3** | `COUNTERPARTY_SIGNED` | `emerald-400` | `#00E676` | Full bilateral accountability with external counterparty receipt signature |

### 3.2 Component Visual Design & Modes

The `TrustFloorBadge` supports two operational modes:

#### 1. Stepped Progression Ladder Mode (`variant="ladder"`)
A horizontal 4-step progress rail:
- Connectors between steps show active cyan/emerald glow when passed, or dashed slate when unreached.
- **Derived Marker**: Shows where the verification engine placed the packet.
- **Claimed Marker**: Displays a ghost pin indicating the producer's declared trust floor.
- **Downgrade Alert**:
  - If $\text{Derived} < \text{Claimed}$: An urgent warning flag appears:
    `⚠️ TRUST FLOOR DOWNGRADE: Producer claimed [COUNTERPARTY_SIGNED] but evidence only supports [AGENT_SIGNED]!`
  - If `tamper_evidence === true`:
    `🚨 TAMPERED EVIDENCE: Trust Floor reduced to UNVERIFIED (0)`

#### 2. Compact Badge Mode (`variant="compact"`)
A dense pill badge for headers and list items:
- Features glowing status dot, floor title, numerical tier (`[L3]`), and optional tooltip comparing claimed vs derived.

---

## 4. Verifier Trust Anchor Configuration Specification (`TrustAnchorConfig.tsx`)

### 4.1 Purpose & Role in Verification
AIP evidence packets do not assert their own trust roots. The verifier supplies a `VerificationContext` defining:
1. **`trusted_issuers` (`issuer_public_keys`)**: Map of `principal_aip_id -> Ed25519 public key (hex)`.
2. **`trusted_counterparties` (`counterparty_public_keys`)**: Map of `counterparty_id -> Ed25519 public key (hex)`.
3. **`revoked_jtis`**: List of 16-byte hex tokens known to be revoked.
4. **`trace_data` & `receipt_data`**: Optional raw payload strings to cross-check against bindings.

### 4.2 Interactive Features
1. **Key Management Tables**:
   - Add, edit, or delete trusted principal issuer keys with instant hex validation (must be 64 hex characters / 32 bytes).
   - Add, edit, or delete trusted counterparties (e.g. `ledger.example-bank.com`).
   - Add or delete revoked token JTIs (32 hex characters / 16 bytes).
2. **Preset Context Switcher**:
   - **"Standard Production"**: Preloads Alice CFO root key & Bank Ledger counterparty (validates honest packets to Level 3).
   - **"Untrusted Principal"**: Clears Alice's key (demonstrates Rule 5 failure & downgrade to Level 1).
   - **"Cascade Revoked"**: Injects revoked token `489f6880...` (demonstrates Rule 9 failure).
   - **"Zero Trust (Empty)"**: Clears all anchors.
3. **Instant Re-Verification Mechanism**:
   - Every change to trust anchors fires `onContextChange(newContextJson)`.
   - The parent component triggers an immediate in-memory re-verification via WASM (`verify_evidence_packet`).
   - The ledger and Trust Floor badge update instantaneously with zero page refresh!

---

## 5. Complete Implementation Blueprints for Worker

We formulate the exact, production-ready TypeScript code for the Worker to create in `aip-console/src/`:

1. `src/types/verification.ts`
2. `src/components/ingestion/TrustFloorBadge.tsx`
3. `src/components/ingestion/VerificationLedger.tsx`
4. `src/components/ingestion/TrustAnchorConfig.tsx`
