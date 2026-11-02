# Architectural Blueprint & Handoff Report: Adversarial Tamper Simulator (Features F11, F12, F13)

**Author:** M4 Explorer 1 (Tamper Simulator & Attack Vectors Specialist)  
**Date:** 2026-11-02  
**Target Subsystems:** Feature F11 (Adversarial Field Mutation Engine), Feature F12 (Smart Hash Recalculation Toggle), Feature F13 (Instant Rule Failure Feedback)  
**Working Directory:** `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_explorer_1\`

---

## 1. Observation

Direct investigation of the codebase, Rust verification engine, WebAssembly bindings, React application shell, and automated E2E test suites revealed the following authoritative facts:

### 1.1 WebAssembly & Verification Contracts
- **WASM Exports** (`aip-console/public/wasm/aip_wasm.d.ts`, lines 44–59, and `aip-standalone/aip-wasm/src/lib.rs`, lines 26–59, 158–173):
  - `verify_evidence_packet(packet_json: string, context_json?: string | null): string`: Executes non-short-circuiting 14-rule evaluation in compiled Rust and returns JSON `VerificationReport` with dual compatibility keys (`overall_valid` & `valid`, `derived_trust_floor` & `trust_floor`, `tamper_evidence` & `tampered`, `checks: RuleResult[]`).
  - `recompute_packet_hash(packet_json: string): string`: Returns the 64-character lowercase hex SHA-256 digest over the canonical byte serialization of the packet (excluding `packet_hash` and `agent_sig`).
  - `get_canonical_bytes_hex(packet_json: string): string`: Returns the raw canonical serialization bytes formatted as lowercase hex string.
- **Client React Context** (`aip-console/src/lib/wasm/useAipVerifier.tsx`, lines 87–99, 129–142):
  - Exposes `verifyPacket(packetJson, contextJson)`, `recomputeHash(packetJson)`, and `getCanonicalBytesHex(packetJson)`.
  - Execution runs fully client-side inside WebAssembly memory with zero network latency (<1ms per verification).

### 1.2 The 14 Engine Verification Rules
Inspecting `aip-standalone/aip-protocol/src/verification.rs` (lines 98–322) and `aip-console/src/types/verification.ts` (lines 107–248) confirms the normative 14-rule sequence:
1. `STRUCTURE`: Magic header `0x41 0x45 0x50 0x31` (`"AEP1"`), version `1`, non-empty IDs, non-empty `actions`, non-empty `summary`.
2. `AGENT_ID_BINDING`: Base58 checksum format and derivation $AIP\_ID == \text{derive}(pubkey, provenance)$.
3. `CANONICAL_HASH`: Recomputed canonical hash equals `packet.packet_hash`. Sets `tamper_evidence = true` on mismatch.
4. `AGENT_SIGNATURE`: Checks `sig.signer_id == agent.aip_id`, `sig.payload_hash == recomputed_hash`, and verifies Ed25519 signature. Sets `tamper_evidence = true` on failure.
5. `ROOT_TOKEN_SIGNATURE`: Ed25519 signature on root token under trusted issuer public key. Sets `tamper_evidence = true` if key exists but signature fails.
6. `DELEGATION_CHAIN`: JTI linkage, monotonic depth ($d_i = d_{i-1} + 1$), chain length $< 8$, scope attenuation ($Scope_i \subseteq Scope_{i-1}$), and per-hop signatures. Sets `tamper_evidence = true` on forgery/escalation.
7. `AUTHORITY_CHAIN`: Continuity from root token grantee to acting agent through consecutive hops ($hop[i].issuer == hop[i-1].grantee$).
8. `SCOPE_AUTHORITY`: Effective lattice scope permits decision action and all action attestations.
9. `REVOCATION`: Verifies zero JTIs in root token or delegation hops match `context.revoked_jtis`.
10. `TEMPORAL_VALIDITY`: Verifies $decided\_at \ge issued\_at$, $performed\_at \ge decided\_at$, and both $\le expires\_at$.
11. `ACTION_ATTESTATIONS`: Verifies each action's Ed25519 signature bound to `decision_id` and action canonical bytes. Sets `tamper_evidence = true` on failure.
12. `TRACE_BINDING`: If present and trace data supplied, verifies $SHA256(data) == trace\_hash$. Sets `tamper_evidence = true` on mismatch.
13. `RECEIPT_BINDING`: If present, verifies receipt system, receipt ID, and countersignature over canonical receipt payload. Sets `tamper_evidence = true` on failure.
14. `TRUST_FLOOR`: Derives mathematical floor (`UNVERIFIED` $\to$ `AGENT_SIGNED` $\to$ `AUTHORITY_BOUND` $\to$ `COUNTERPARTY_SIGNED`) and asserts $derived\_floor \ge claimed\_floor$.

### 1.3 Existing E2E Test Suite Assertions
Execution of the test suite via Vitest demonstrated 100% pass rate across 40 tamper-related test specifications:
- Command: `npx vitest run e2e/tier1-features/f11_tamper_sandbox.spec.ts e2e/tier1-features/f12_hash_toggle.spec.ts e2e/tier1-features/f13_failure_feedback.spec.ts`
  - Output: `Test Files 3 passed (3), Tests 15 passed (15), Duration 519ms`.
- Command: `npx vitest run e2e/tier2-boundary/f11_tamper_boundary.spec.ts e2e/tier2-boundary/f12_hash_toggle_boundary.spec.ts e2e/tier2-boundary/f13_failure_boundary.spec.ts e2e/tier3-combinations/pipeline2_tamper_hash_ledger.spec.ts e2e/tier4-scenarios/scenario3_forensic_tamper.spec.ts`
  - Output: `Test Files 5 passed (5), Tests 25 passed (25), Duration 507ms`.
- Key specific assertions tested:
  - `f11_tamper_sandbox.spec.ts` tests: summary tampering (`CANONICAL_HASH`), payload hash mutation (`ACTION_ATTESTATIONS`), scope escalation (`DELEGATION_CHAIN`), identity hijacking (`AGENT_ID_BINDING`), counterparty signature corruption (`RECEIPT_BINDING`).
  - `f12_hash_toggle.spec.ts` tests: naive attacker fails `CANONICAL_HASH`; smart attacker with hash recalculation fixes `CANONICAL_HASH` (line 21: `hashCheck?.pass === true`, line 22: detail contains `"matches packet_hash"`), but still fails `AGENT_SIGNATURE` (line 29: `sigCheck?.pass === false`, line 30: detail contains `"signature payload hash does not cover current packet contents"`), maintaining `tamper_evidence: true` and `overall_valid: false`.
  - `f13_failure_feedback.spec.ts` tests: exact count of failing rules, rule-specific failure detail without generic fallbacks, instant update to `overall_valid: false`, and distinction between verifiability gaps and cryptographic tampering.
  - `pipeline2_tamper_hash_ledger.spec.ts` tests: tampering cascades to downgrade Trust Floor to `UNVERIFIED` (line 48), and full revert restores 100% pass across all 14 rules (line 76).

### 1.4 Current App Shell & Tab 3 State
- `aip-console/src/app/page.tsx` (lines 129–148): Tab 3 (`activeTab === "tamper"`) currently renders an un-implemented placeholder with `<ShieldAlert />`.
- `aip-console/src/app/tamper/page.tsx`: Sets `setActiveTab("tamper")` and redirects to `/`.
- `aip-console/src/components/tamper/`: Directory does not yet exist.

---

## 2. Logic Chain

From the observed contracts and requirements, the implementation architecture is derived through the following deductive steps:

```
[User Action / Preset Selection]
               │
               ▼
┌───────────────────────────────────────┐
│  Adversarial Field Mutation Engine    │
│  - 14 Attack Presets (F11)            │
│  - Manual Field Tampering Form        │
│  - Raw JSON Editor                    │
└──────────────────┬────────────────────┘
                   │ Emits Mutated JSON
                   ▼
┌───────────────────────────────────────┐
│ Smart Hash Recalculation Toggle (F12) │
│ - If OFF: preserve mutated JSON       │
│ - If ON:  call recompute_packet_hash  │
│           update packet.packet_hash   │
└──────────────────┬────────────────────┘
                   │
         ┌─────────┴─────────────────────┐
         │                               │
         ▼                               ▼
┌───────────────────┐           ┌─────────────────────────────────────────┐
│ JSON Diff Viewer  │           │ Live Verification Feedback (F13)        │
│ - Original vs     │           │ - Call WASM verify_evidence_packet      │
│   Mutated JSON    │           │ - ZERO JS verification logic            │
│ - Visual +/- diff │           │ - 14-rule status & verbatim Rust detail │
└───────────────────┘           │ - Derived Trust Floor downgrade         │
                                │ - Tamper Alert (Flame pulse)            │
                                └─────────────────────────────────────────┘
```

1. **Step 1: 1:1 Mapping of Presets to Engine Rules (Feature F11)**
   Because the Rust verification engine evaluates exactly 14 non-short-circuiting rules, the simulator must provide 14 distinct pre-configured attack vector presets. Each preset must mutate precisely the field governing that rule so an auditor can observe each rule failing in isolation and in cascading combinations.

2. **Step 2: Mathematical Proof of Cryptographic Non-Repudiation (Feature F12)**
   - When a field (e.g. `decision.summary`) is mutated, the canonical byte hash changes from $H$ to $H'$.
   - If "Smart Hash Recalculation" is OFF:
     - `packet.packet_hash` is $H \ne H'$.
     - Rule 3 (`CANONICAL_HASH`) compares $H'$ with stored $H \implies$ **FAILS**.
   - If "Smart Hash Recalculation" is ON:
     - `recompute_packet_hash(mutatedJson)` recalculates $H' = \text{SHA-256}(\text{canonical\_bytes}(packet))$.
     - `packet.packet_hash` is set to $H'$.
     - Rule 3 (`CANONICAL_HASH`) compares $H'$ with stored $H' \implies$ **PASSES**.
     - BUT `packet.agent_sig.payload_hash` is still $H$.
     - In Rust `aip-protocol/src/verification.rs` (line 141), `sig.payload_hash == recomputed` fails because $H \ne H'$.
     - Rule 4 (`AGENT_SIGNATURE`) $\implies$ **FAILS** with `"signature payload hash does not cover current packet contents"`.
     - Even if the attacker mutates `sig.payload_hash = H'`, Ed25519 signature verification fails because the attacker lacks the agent's private key.
     - Therefore, `tamper_evidence = true` is unconditionally preserved! This proves non-repudiation.

3. **Step 3: Zero-JS Instant Rule Failure Feedback (Feature F13)**
   - Per Requirement R1 and R3, zero verification logic may be written in TypeScript/JavaScript.
   - The UI component must subscribe to state changes, pass `mutatedJson` directly to `useAipVerifier().verifyPacket(mutatedJson, contextJson)`, and project the returned `VerificationReport` into the UI ledger.
   - The UI displays:
     - The exact verbatim `checks[i].detail` string from Rust.
     - The cryptographic tamper state: `tamper_evidence === true` displays a crimson glowing banner with animated `Flame`.
     - Verifiability gaps (such as unknown root issuer key) display amber `AlertTriangle` without triggering `tamper_evidence`.
     - The Trust Floor ladder immediately drops (e.g. from `COUNTERPARTY_SIGNED` to `UNVERIFIED`).

4. **Step 4: JSON Diff Visualization**
   - The auditor must see *what* changed between the sealed baseline packet and the mutated packet.
   - A deterministic diff calculator compares `originalPacketJson` and `mutatedPacketJson` line-by-line, highlighting inserted lines (`+` in cyber-cyan/emerald), deleted lines (`-` in cyber-red), and modified hash fields.

---

## 3. Caveats

1. **WASM In-Memory State**: `aip-wasm` does not mutate memory across invocations; every call to `verify_evidence_packet` and `recompute_packet_hash` is pure and functional. The React component owns the working mutated state.
2. **Authority Lattice Division of Labor**: Feature F11–F13 covers the Tamper Sandbox, Smart Hash Recalculation, and Live Failure Feedback. Features F14–F16 (Scope Matrix Editor, Lattice Meet Preview $\sqcap$, and Cascade Revocation Tree) are assigned to M4 Explorer 2 / Authority specialist. The tamper sandbox allows tampering of delegation chains and scopes, which will interoperate seamlessly with the authority visualizer.
3. **Cryptographic Tamper Evidence vs Verifiability Gaps**: In the Rust engine, an invalid signature or altered hash sets `tamper_evidence = true`. A missing trusted public key in `VerificationContext` sets `pass = false` for `ROOT_TOKEN_SIGNATURE`, but does *not* set `tamper_evidence = true` because lack of trust configuration is an audit gap, not physical post-sealing tampering. The UI must clearly reflect this difference.

---

## 4. Conclusion & Technical Implementation Blueprint

### 4.1 The 14 Attack Vector Presets Specification (F11)

The simulator must register the following 14 presets mapped 1:1 to the 14 engine verification rules:

| Preset ID | Targeted Rule | Preset Name | Mutation Operation on Baseline Packet | Expected Rule Failure & Detail |
|---|---|---|---|---|
| `p01_structure` | `STRUCTURE` | Malformed Wire Format | Set `magic = [0x42, 0x41, 0x44, 0x31]` (`"BAD1"`), `version = 99`, or clear `actions = []` | `STRUCTURE` fails: `"structural problems: bad magic, unsupported version"`. |
| `p02_agent_id` | `AGENT_ID_BINDING` | Agent Identity Hijacking | Set `agent.aip_id = "aip1mismatchidentity99887766554433221122"` | `AGENT_ID_BINDING` fails: `"agent AIP-ID ... does not match derived ID"`. |
| `p03_canonical_hash` | `CANONICAL_HASH` | Decision Summary Tampering | Modify `decision.summary = "TAMPERED: Divert $5,000,000 to offshore account"` (Hash toggle OFF) | `CANONICAL_HASH` fails: `"packet_hash mismatch: stored ... recomputed ... — packet modified after sealing"`. `tamper_evidence = true`. |
| `p04_agent_sig` | `AGENT_SIGNATURE` | Agent Signature Corruption | Mutate `agent_sig.signature_bytes = "corrupted_sig_hex_bytes"` | `AGENT_SIGNATURE` fails: `"agent signature cryptographic verification failed"`. `tamper_evidence = true`. |
| `p05_root_sig` | `ROOT_TOKEN_SIGNATURE` | Root Token Signature Forgery | Mutate `root_authority.root_token.issuer_sig.signature_bytes = "bad_root_sig"` | `ROOT_TOKEN_SIGNATURE` fails: `"root token signature verification failed"`. `tamper_evidence = true`. |
| `p06_delegation` | `DELEGATION_CHAIN` | Scope Escalation Attack | Append `{ kind: "Standard", action: "Admin" }` into `delegation_chain[0].scope.allowed` | `DELEGATION_CHAIN` fails: `"delegation chain invalid: hop 0 attenuation violation: scope expanded beyond parent"`. `tamper_evidence = true`. |
| `p07_authority` | `AUTHORITY_CHAIN` | Broken Authority Handoff | Set `delegation_chain[0].grantee_id = "unexpected-middleman"` | `AUTHORITY_CHAIN` fails: `"leaf delegation grantee unexpected-middleman is not acting agent"`. |
| `p08_scope` | `SCOPE_AUTHORITY` | Unpermitted Action Execution | Add action with `action_kind = { kind: "Custom", name: "unpermitted:action" }` | `SCOPE_AUTHORITY` fails: `"prohibited outside effective scope: action ..."`. |
| `p09_revocation` | `REVOCATION` | Revoked Credential Injection | Add `root_authority.root_token.jti` or `delegation_chain[0].jti` to `context.revoked_jtis` | `REVOCATION` fails: `"revoked tokens in chain: ..."`. |
| `p10_temporal` | `TEMPORAL_VALIDITY` | Inverted Timestamp Fraud | Set `actions[0].performed_at = decision.decided_at - 100000` | `TEMPORAL_VALIDITY` fails: `"temporal violations: action ... performed before authorizing decision"`. |
| `p11_actions` | `ACTION_ATTESTATIONS` | Action Payload Mutation | Mutate `actions[0].payload_hash = "ffffffff...tampered"` or corrupt `actions[0].agent_sig.signature_bytes` | `ACTION_ATTESTATIONS` fails: `"action ...: signature does not cover current action contents"`. `tamper_evidence = true`. |
| `p12_trace` | `TRACE_BINDING` | Distributed Trace Spoofing | Alter `trace_binding.trace_hash = "000000...0000"` when trace data is supplied | `TRACE_BINDING` fails: `"supplied trace data does NOT match the bound trace_hash"`. `tamper_evidence = true`. |
| `p13_receipt` | `RECEIPT_BINDING` | Counterparty Signature Corruption | Mutate `receipt_binding.counterparty_sig.signature_bytes = "corrupted_sig_hex_bytes"` | `RECEIPT_BINDING` fails: `"counterparty signature verification failed"`. `tamper_evidence = true`. |
| `p14_trust_floor` | `TRUST_FLOOR` | Trust Floor Claim Inflation | Modify decision summary (dropping derived floor to `UNVERIFIED`) while keeping `claimed_trust_floor = "COUNTERPARTY_SIGNED"` | `TRUST_FLOOR` fails: `"claimed floor CounterpartySigned exceeds what the evidence supports (Unverified)"`. |

### 4.2 Component Architecture & File Layout

Implement the following files in `aip-console/src/components/tamper/`:

```
aip-console/src/components/tamper/
├── TamperSimulator.tsx           # Main container component (exported to page.tsx)
├── PresetSelector.tsx            # 14-Attack Vector preset cards / dropdown with category filters
├── attackPresets.ts              # Definitions of 14 presets, descriptions, and immutable mutator functions
├── SmartHashToggle.tsx           # Auto-recalculate toggle, stored vs recomputed hash banner
├── FieldTamperPanel.tsx          # Manual input fields for Decision, Agent, Authority, Actions, Timestamps
├── JsonPayloadEditor.tsx         # Raw JSON textarea / editor with syntax validation & format button
├── JsonDiffViewer.tsx            # Visual diff viewer comparing Original JSON vs Mutated JSON
├── LiveTamperLedger.tsx          # Live 14-rule feedback ledger integrating VerificationLedger
└── diffUtils.ts                  # Deterministic line-by-line diff computation utility
```

### 4.3 Detailed Component Contracts

#### 1. `attackPresets.ts`
```typescript
export interface AttackPreset {
  id: string;
  name: string;
  targetRule: RuleIdentifier;
  category: "INTEGRITY" | "AUTHORITY" | "VALIDITY" | "BILATERAL";
  description: string;
  mutationExplanation: string;
  mutate: (packet: EvidencePacket, context?: VerificationContext) => {
    packet: EvidencePacket;
    context?: VerificationContext;
  };
}
```

#### 2. `SmartHashToggle.tsx`
- **Props**:
  - `autoRecalculate: boolean`
  - `onToggle: (enabled: boolean) => void`
  - `storedHash: string`
  - `recomputedHash: string`
  - `canonicalBytesHex?: string`
- **UI Elements**:
  - Cyber-styled toggle switch with neon glow when active.
  - Explanatory callout:
    - *When ON*: "Smart Attacker Mode: Canonical hash recomputed via WASM SHA-256. `CANONICAL_HASH` will PASS, but `AGENT_SIGNATURE` will FAIL due to cryptographic binding."
    - *When OFF*: "Naive Attacker Mode: Stored hash preserved. `CANONICAL_HASH` will FAIL immediately."
  - Hash Comparison Display:
    - `Stored Hash:     [ 4f53cda18c2baa... ]`
    - `Recomputed Hash: [ 8e11ba873c2f11... ]`
    - Indicator: `MATCH (Fixed)` (green) vs `MISMATCH (Tampered)` (crimson).

#### 3. `JsonDiffViewer.tsx`
- **Props**:
  - `originalJson: string`
  - `mutatedJson: string`
  - `viewMode?: "split" | "unified"`
- **Visuals**:
  - Unified view showing line-by-line diff.
  - Added lines styled with `bg-emerald-950/40 text-emerald-300 border-l-2 border-emerald-500` with `+` gutter icon.
  - Deleted lines styled with `bg-red-950/40 text-red-300 border-l-2 border-red-500` with `-` gutter icon.
  - Unchanged lines in muted slate mono.

#### 4. `FieldTamperPanel.tsx`
- Interactive accordion / tabbed panel with manual mutation inputs:
  - **Decision Tab**: Text input for `summary`, input for `action_kind`, input for `input_hash`.
  - **Agent Tab**: Input for `aip_id`, button for "Flip Public Key Byte", button for "Corrupt Provenance Hash".
  - **Authority Tab**: Input for `root_token.jti`, checkbox to inject forbidden `Admin` scope, button to break delegation handoff.
  - **Actions Tab**: Stepper for `performed_at` (to test temporal violations), input for `payload_hash`, button to corrupt action signature.
  - **Receipt & Trace Tab**: Stepper for trace hash, button to corrupt counterparty signature.

#### 5. `TamperSimulator.tsx` (Top-Level Container)
- Replaces the placeholder in `aip-console/src/app/page.tsx` under Tab 3 (`activeTab === "tamper"`).
- State flow:
  1. Reads `loadedPacket` / `rawPacketJson` from `useConsole()` / `useEvidence()`. (Defaults to `validHonestCounterpartyPacket` if none loaded).
  2. Maintains `mutatedPacket` object and `mutatedJson` string.
  3. Maintains `autoRecalculateHash` boolean state.
  4. React `useEffect` runs on `[mutatedPacket, autoRecalculateHash, contextJson]`:
     - If `autoRecalculateHash`: calls `verifier.recomputeHash(json)`, updates `packet.packet_hash = newHash`.
     - Calls `verifier.verifyPacket(finalJson, contextJson)`.
     - Sets `liveReport` state.
  5. Header action bar:
     - "Reset / Revert to Pristine" button (restores original unmodified packet).
     - "Export Tampered JSON" button (downloads tampered JSON for offline auditing or test generation).
     - Active Preset indicator badge.

---

## 5. Verification Method

To independently verify this implementation blueprint once coded:

### 5.1 Automated Test Execution Commands
Run the authoritative test suites from repository root:
```powershell
# Tier 1 Feature Coverage (15 tests)
npx vitest run e2e/tier1-features/f11_tamper_sandbox.spec.ts e2e/tier1-features/f12_hash_toggle.spec.ts e2e/tier1-features/f13_failure_feedback.spec.ts

# Tier 2 Boundary Suites (15 tests)
npx vitest run e2e/tier2-boundary/f11_tamper_boundary.spec.ts e2e/tier2-boundary/f12_hash_toggle_boundary.spec.ts e2e/tier2-boundary/f13_failure_boundary.spec.ts

# Tier 3 Combination Pipeline (5 tests)
npx vitest run e2e/tier3-combinations/pipeline2_tamper_hash_ledger.spec.ts

# Tier 4 Real-World Forensic Scenario (5 tests)
npx vitest run e2e/tier4-scenarios/scenario3_forensic_tamper.spec.ts
```
Expected result: **40 passed (100% pass rate)**.

### 5.2 TypeScript Compilation Check
Verify type soundness in `aip-console/`:
```powershell
cd aip-console
npm run lint
```
Expected result: `tsc --noEmit` exits with code 0.

### 5.3 UI Invalidation & Acceptance Conditions
The implementation is verified when:
1. Selecting any of the 14 presets causes the corresponding engine rule to fail immediately in the ledger with verbatim Rust engine details.
2. When Preset 3 (`CANONICAL_HASH`) is active and Smart Hash Recalculation is toggled ON:
   - Rule 3 `CANONICAL_HASH` transitions from FAIL to PASS.
   - Rule 4 `AGENT_SIGNATURE` remains FAIL (`"signature payload hash does not cover current packet contents"`).
   - Overall badge shows `TAMPER DETECTED` with red pulsating flame.
3. Clicking "Reset / Revert" restores the baseline packet, immediately transitioning all 14 rules to PASS and restoring the Trust Floor badge to `COUNTERPARTY_SIGNED`.
4. The JSON Diff Viewer highlights the modified keys accurately with `+` and `-` indicators.
