# Handoff Report: Attack Presets Dual-Format Normalization

**Agent:** M4 Iteration 2 Explorer 1 (`m4_iter2_explorer_1`)  
**Role:** Attack Presets Dual-Format Normalization Specialist  
**Working Directory:** `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_iter2_explorer_1\`  
**Milestone:** Milestone 4 (Adversarial Tamper Simulator & Authority Lattice Builder — Requirements R3 & R4)  
**Parent Agent:** `675111aa-04e8-493f-9811-dbfc1935a77b`  
**Date:** 2026-11-02  
**Verdict:** **`ANALYSIS_COMPLETE`** (All 14 presets analyzed, dual-format strategies formulated, 100% verified against live WebAssembly)

---

## 1. Observation

Direct empirical investigation of the codebase, compiled WebAssembly engine, and empirical test harness (`tests/m4_empirical_challenger.mjs`) revealed the exact structural causes of the 7 failing attack presets in `aip-console/src/components/tamper/attackPresets.ts`.

### 1.1 Tool Commands and Verbatim Outputs
1. **Authoritative Adversarial Stress Harness**:
   - Command: `node tests/m4_empirical_challenger.mjs`
   - Exit Code: `1`
   - Output: `TOTAL TESTS EXECUTED: 238 | PASSED: 234 | FAILED: 4`
   - Assertion 12 Failure:
     ```
     [FAIL] #12: All 14 presets pass WASM EvidencePacket deserialization (actually passed: 7/14) -> 7 presets failed deserialization: p04_agent_sig, p05_root_sig, p06_delegation, p08_scope, p11_actions, p12_trace, p13_receipt
     ```

### 1.2 Rust Serde Type Contracts vs Preset Mutations
In `aip-standalone/aip-protocol/src/evidence_packet.rs` and `aip-standalone/aip-types/src/lib.rs`, the Rust definitions for `EvidencePacket` define all cryptographic identifiers, signatures, hashes, and nonces as numeric arrays rather than hex strings:

| Field Path | Rust Type | Expected JSON Format | What `attackPresets.ts` Injected | Verbatim Serde Rejection Error |
|---|---|---|---|---|
| `agent_sig.signature_bytes` | `Vec<u8>` | `number[]` | String `"9f8e7d...dead"` | `invalid type: string "...", expected a sequence at line 1 column 5878` |
| `root_authority.root_token.issuer_sig.signature_bytes` | `Vec<u8>` | `number[]` | String `"bad_root_signature_hex..."` | `invalid type: string "...", expected a sequence at line 1 column 1693` |
| `delegation_chain[0].scope.allowed` | `Vec<ScopeAction>` | `[{"Standard": "..."}]` | `[{ kind: "Standard", action: "Admin" }]` or `"Admin"` | `unknown variant 'Admin', expected 'Standard' or 'Custom' at line 1 column 2188` |
| `actions[].action_id` | `[u8; 16]` | `number[]` (len 16) | String `"act-unpermitted-999"` | `invalid type: string "act-unpermitted-999", expected an array of length 16 at line 1 column 4332` |
| `actions[].action_kind` | `ScopeAction` | `{"Custom": "..."}` | Object `{ kind: "Custom", name: "..." }` | Deserialization mismatch for externally tagged enum |
| `actions[].payload_hash` | `[u8; 32]` | `number[]` (len 32) | String `"3b6a27..."` | `invalid type: string "...", expected an array of length 32` |
| `actions[0].payload_hash` | `[u8; 32]` | `number[]` (len 32) | String `"ffff...tampered"` | `invalid type: string "...", expected an array of length 32 at line 1 column 3663` |
| `trace_binding.trace_hash` | `[u8; 32]` | `number[]` (len 32) | String `"000000..."` | `invalid type: string "...", expected an array of length 32 at line 1 column 4441` |
| `receipt_binding.counterparty_sig.signature_bytes` | `Vec<u8>` | `number[]` | String `"corrupted_sig_hex_bytes..."` | `invalid type: string "...", expected a sequence at line 1 column 5144` |

### 1.3 Empirical Verification of Scratch Remediation
When the dual-format normalization logic is applied in our test scratch script (`.agents/teamwork/m4_iter2_explorer_1/test_scratch.mjs`) against the live compiled WebAssembly (`public/wasm/aip_wasm.js` and `public/wasm/aip_wasm_bg.wasm`), the output is:
```
[PASS] p01_structure (STRUCTURE): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p02_agent_id (AGENT_ID_BINDING): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p03_canonical_hash (CANONICAL_HASH): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p04_agent_sig (AGENT_SIGNATURE): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p05_root_sig (ROOT_TOKEN_SIGNATURE): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p06_delegation (DELEGATION_CHAIN): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p07_authority (AUTHORITY_CHAIN): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p08_scope (SCOPE_AUTHORITY): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p09_revocation (REVOCATION): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p10_temporal (TEMPORAL_VALIDITY): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p11_actions (ACTION_ATTESTATIONS): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p12_trace (TRACE_BINDING): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p13_receipt (RECEIPT_BINDING): Deserialized OK | Target rule failed: true (overall valid: false)
[PASS] p14_trust_floor (TRUST_FLOOR): Deserialized OK | Target rule failed: true (overall valid: false)

Result: 14/14 presets successfully deserialized and triggered target rule failure!
```

---

## 2. Logic Chain

1. **Why the presets were originally authored with strings**:
   Early development and reference mocks (such as `reference_oracle.js`) accepted relaxed string-based representations of hashes and signatures. However, the production verification path executes through `wasm.verify_evidence_packet(packetJson, contextJson)`.
2. **Serde Deserialization Precedes Verification Evaluation**:
   In `aip-standalone/aip-wasm/src/lib.rs:31`, `EvidencePacket::from_json(packet_json)` is executed BEFORE `verify_packet(&packet, &ctx)`. If serde encounters a string where an array is required, or an unknown enum tag, it aborts immediately with an `Err`.
3. **Dual-Format Polymorphism**:
   Evidence packets entering the tamper simulator can come from:
   - Official WASM-generated samples / audit bundles (which are pure wire format, with byte arrays represented as `number[]`).
   - Mock datasets or loose JSON payloads (which may represent byte arrays as hex strings).
   Therefore, every preset mutation function MUST inspect the runtime type of the field:
   - If `Array.isArray(...)`: apply an in-place byte mutation (e.g. `arr[0] ^= 0xff`). This preserves the array type and exact byte length (e.g. 64 bytes for Ed25519 signature, 32 bytes for SHA-256 hash, 16 bytes for JTI/action_id) while rendering the cryptographic content provably invalid.
   - If `typeof ... === "string"`: assign a corrupted hexadecimal string literal.
   - If missing/empty: supply a conformant fallback byte array matching the Rust struct's required array length.
4. **Externally Tagged Rust Enums**:
   In Rust `serde`, `enum ScopeAction { Standard(Action), Custom(String) }` serializes as:
   - Standard action: `{"Standard": "Admin"}` (NOT `{ kind: "Standard", action: "Admin" }` and NOT `"Admin"`).
   - Custom action: `{"Custom": "unpermitted:action_divert"}` (NOT `{ kind: "Custom", name: "..." }`).
   Presets mutating scope (`p06_delegation` and `p08_scope`) must inspect existing items, but crucially default to the Rust serde externally tagged format `{"Standard": "Admin"}` and `{"Custom": "..."}`.
5. **Zero-JS Invariant Preservation**:
   All cryptographic evaluation remains 100% inside `aip_wasm.verify_evidence_packet`. The presets perform purely syntactic mutations on the JSON data model. No JavaScript WebCrypto, SubtleCrypto, TweetNaCl, Noble Ed25519, or Node `createHash` is introduced.

---

## 3. Caveats

1. **Field Scope of `attackPresets.ts`**:
   The attack presets intentionally corrupt only the fields needed to trigger the specific target rule (or drop the trust floor). They do not recalculate hashes unless the Smart Mode toggle is activated in `TamperSimulator.tsx`.
2. **Preset 9 (`p09_revocation`)**:
   Preset 9 mutates `context.revoked_jtis`. As observed in `aip-wasm/src/context.rs`, `revoked_jtis` accepts both hex strings and byte arrays of length 16. The preset extracts `p.delegation_chain?.[0]?.jti || p.root_authority?.root_token?.jti`.
3. **Preset 8 Action Template**:
   To ensure that `p08_scope` does not inadvertently trigger Rule 11 (`ACTION_ATTESTATIONS`) or Rule 4 (`AGENT_SIGNATURE`) due to missing signature fields, it clones an existing action's `agent_sig` or `p.agent_sig`.

---

## 4. Conclusion & Required Changes

The 14 presets in `aip-console/src/components/tamper/attackPresets.ts` must be updated with dual-format normalization. Below is the complete, recommended implementation for `attackPresets.ts`.

### Full Proposed Content for `aip-console/src/components/tamper/attackPresets.ts`

```typescript
import type { RuleIdentifier, RuleLayer } from "@/types/verification";

export interface AttackPreset {
  id: string;
  index: number;
  name: string;
  targetRule: RuleIdentifier;
  category: RuleLayer;
  description: string;
  mutationExplanation: string;
  mutate: (
    packet: any,
    context?: any
  ) => {
    packet: any;
    context?: any;
  };
}

export const ATTACK_PRESETS: AttackPreset[] = [
  {
    id: "p01_structure",
    index: 1,
    name: "Malformed Wire Format Header",
    targetRule: "STRUCTURE",
    category: "INTEGRITY",
    description: "Corrupts protocol magic header bytes from 'AEP1' to 'BAD1' and sets invalid version 99.",
    mutationExplanation: "Sets packet.magic = [0x42, 0x41, 0x44, 0x31] ('BAD1') and packet.version = 99.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (typeof p.magic === "string") {
        p.magic = "BAD1";
      } else {
        p.magic = [0x42, 0x41, 0x44, 0x31]; // "BAD1"
      }
      p.version = 99;
      return { packet: p, context };
    },
  },
  {
    id: "p02_agent_id",
    index: 2,
    name: "Agent Identity Hijacking",
    targetRule: "AGENT_ID_BINDING",
    category: "INTEGRITY",
    description: "Replaces the acting agent's AIP-ID with an unregistered foreign identifier.",
    mutationExplanation: "Sets packet.agent.aip_id = 'aip1mismatchidentity99887766554433221122'.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.agent = {
        ...p.agent,
        aip_id: "aip1mismatchidentity99887766554433221122",
      };
      return { packet: p, context };
    },
  },
  {
    id: "p03_canonical_hash",
    index: 3,
    name: "Decision Summary Tampering",
    targetRule: "CANONICAL_HASH",
    category: "INTEGRITY",
    description: "Modifies the decision summary text without recalculating canonical hash, simulating in-flight payload alteration.",
    mutationExplanation: "Sets packet.decision.summary = 'TAMPERED: Divert $5,000,000 to offshore unauthorized facility'.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.decision = {
        ...p.decision,
        summary: "TAMPERED: Divert $5,000,000 to offshore unauthorized facility",
      };
      return { packet: p, context };
    },
  },
  {
    id: "p04_agent_sig",
    index: 4,
    name: "Agent Signature Corruption",
    targetRule: "AGENT_SIGNATURE",
    category: "INTEGRITY",
    description: "Corrupts the agent's Ed25519 signature bytes over the sealed packet.",
    mutationExplanation: "Flips bits in packet.agent_sig.signature_bytes or assigns corrupted hex string.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const corruptedHex = "9f8e7d6c5b4a392817061524334251607f8e9d0c1b2a3948576675849302dead";
      if (p.agent_sig) {
        if (Array.isArray(p.agent_sig.signature_bytes) && p.agent_sig.signature_bytes.length > 0) {
          p.agent_sig.signature_bytes[0] ^= 0xff;
        } else if (typeof p.agent_sig.signature_bytes === "string") {
          p.agent_sig.signature_bytes = corruptedHex;
        } else {
          p.agent_sig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in p.agent_sig) {
          p.agent_sig.sig_hex = corruptedHex;
        }
      }
      return { packet: p, context };
    },
  },
  {
    id: "p05_root_sig",
    index: 5,
    name: "Root Authority Token Forgery",
    targetRule: "ROOT_TOKEN_SIGNATURE",
    category: "AUTHORITY",
    description: "Mutates the principal root authority issuer signature, simulating a forged root grant.",
    mutationExplanation: "Flips bits in packet.root_authority.root_token.issuer_sig.signature_bytes or assigns corrupted hex string.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const badSigHex = "bad_root_signature_hex_000000000000000000000000000000000000000000000000";
      const rtSig = p.root_authority?.root_token?.issuer_sig;
      if (rtSig) {
        if (Array.isArray(rtSig.signature_bytes) && rtSig.signature_bytes.length > 0) {
          rtSig.signature_bytes[0] ^= 0xff;
        } else if (typeof rtSig.signature_bytes === "string") {
          rtSig.signature_bytes = badSigHex;
        } else {
          rtSig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in rtSig) {
          rtSig.sig_hex = badSigHex;
        }
      }
      return { packet: p, context };
    },
  },
  {
    id: "p06_delegation",
    index: 6,
    name: "Scope Escalation Attack",
    targetRule: "DELEGATION_CHAIN",
    category: "AUTHORITY",
    description: "Injects forbidden 'Admin' permission into delegation hop scope, violating monotonic attenuation.",
    mutationExplanation: "Appends { Standard: 'Admin' } to delegation_chain[0].scope.allowed.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.delegation_chain) && p.delegation_chain.length > 0) {
        const firstHop = p.delegation_chain[0];
        if (firstHop.scope && Array.isArray(firstHop.scope.allowed)) {
          const first = firstHop.scope.allowed[0];
          if (first && typeof first === "object" && "Standard" in first) {
            firstHop.scope.allowed.push({ Standard: "Admin" });
          } else if (first && typeof first === "object" && "kind" in first) {
            firstHop.scope.allowed.push({ kind: "Standard", action: "Admin" });
          } else if (typeof first === "string") {
            firstHop.scope.allowed.push("Admin");
          } else {
            firstHop.scope.allowed.push({ Standard: "Admin" });
          }
        }
      }
      return { packet: p, context };
    },
  },
  {
    id: "p07_authority",
    index: 7,
    name: "Broken Authority Chain Handoff",
    targetRule: "AUTHORITY_CHAIN",
    category: "AUTHORITY",
    description: "Modifies downstream delegation grantee ID to an unknown middleman, breaking cryptographic continuity to the acting agent.",
    mutationExplanation: "Sets packet.delegation_chain[last].grantee_id = 'unexpected-middleman-agent'.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.delegation_chain) && p.delegation_chain.length > 0) {
        p.delegation_chain[p.delegation_chain.length - 1].grantee_id = "unexpected-middleman-agent";
      } else if (p.root_authority?.root_token) {
        p.root_authority.root_token.agent_id = "unexpected-middleman-agent";
      }
      return { packet: p, context };
    },
  },
  {
    id: "p08_scope",
    index: 8,
    name: "Unpermitted Action Execution",
    targetRule: "SCOPE_AUTHORITY",
    category: "AUTHORITY",
    description: "Appends an ungranted custom action verb outside the effective capability lattice scope.",
    mutationExplanation: "Appends action with action_kind { Custom: 'unpermitted:action_divert' } outside effective scope.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.actions)) {
        const hasExisting = p.actions.length > 0;
        const template = hasExisting ? JSON.parse(JSON.stringify(p.actions[0])) : null;
        const isWireFormat = !template || Array.isArray(template.action_id);

        const unpermittedActionId = isWireFormat
          ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
          : "0102030405060708090a0b0c0d0e0f10";

        const unpermittedActionKind =
          template && template.action_kind && "kind" in template.action_kind
            ? { kind: "Custom", name: "unpermitted:action_divert" }
            : { Custom: "unpermitted:action_divert" };

        const unpermittedPayloadHash = isWireFormat
          ? new Array(32).fill(0)
          : "0000000000000000000000000000000000000000000000000000000000000000";

        const unpermittedAgentSig = template?.agent_sig
          ? JSON.parse(JSON.stringify(template.agent_sig))
          : p.agent_sig
          ? JSON.parse(JSON.stringify(p.agent_sig))
          : {
              algorithm: "Ed25519",
              signer_id: p.agent?.aip_id || "aip12x9K8yM4QvB7eR6tP3sW1uZbAcD5fGhJ7",
              timestamp: Date.now(),
              nonce: isWireFormat ? new Array(16).fill(0) : "00".repeat(16),
              payload_hash: unpermittedPayloadHash,
              signature_bytes: isWireFormat ? new Array(64).fill(0) : "00".repeat(64),
            };

        p.actions.push({
          action_id: unpermittedActionId,
          action_kind: unpermittedActionKind,
          description: "Unauthorized funds transfer outside authority scope",
          payload_hash: unpermittedPayloadHash,
          performed_at: Date.now(),
          agent_sig: unpermittedAgentSig,
        });
      }
      return { packet: p, context };
    },
  },
  {
    id: "p09_revocation",
    index: 9,
    name: "Revoked Credential Injection",
    targetRule: "REVOCATION",
    category: "AUTHORITY",
    description: "Injects delegation token JTI into verifier revocation blacklist, simulating an operational revocation event.",
    mutationExplanation: "Adds delegation token JTI to context.revoked_jtis and context.revoked_token_ids.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const ctx = context ? JSON.parse(JSON.stringify(context)) : {};
      const targetJti =
        p.delegation_chain?.[0]?.jti ||
        p.root_authority?.root_token?.jti ||
        "a1b2c3d4e5f60718293a4b5c6d7e8f90";

      const currentJtis = Array.isArray(ctx.revoked_jtis) ? ctx.revoked_jtis : [];
      ctx.revoked_jtis = [...currentJtis, targetJti];
      ctx.revoked_token_ids = ctx.revoked_jtis;
      return { packet: p, context: ctx };
    },
  },
  {
    id: "p10_temporal",
    index: 10,
    name: "Inverted Timestamp Fraud",
    targetRule: "TEMPORAL_VALIDITY",
    category: "VALIDITY",
    description: "Sets an action execution timestamp prior to the authorizing decision timestamp, proving causality fraud.",
    mutationExplanation: "Sets actions[0].performed_at = decision.decided_at - 1000000 ms.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.actions) && p.actions.length > 0 && p.decision?.decided_at) {
        p.actions[0].performed_at = p.decision.decided_at - 1000000;
      } else if (p.decision?.decided_at) {
        p.decision.decided_at = (p.root_authority?.root_token?.issued_at || 1000000) - 500000;
      }
      return { packet: p, context };
    },
  },
  {
    id: "p11_actions",
    index: 11,
    name: "Action Payload Mutation",
    targetRule: "ACTION_ATTESTATIONS",
    category: "VALIDITY",
    description: "Modifies an action's attested payload hash without updating its cryptographic signature.",
    mutationExplanation: "Flips bits in actions[0].payload_hash or assigns corrupted hex string.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const tamperedHex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffftampered";
      if (Array.isArray(p.actions) && p.actions.length > 0) {
        if (Array.isArray(p.actions[0].payload_hash) && p.actions[0].payload_hash.length > 0) {
          p.actions[0].payload_hash[0] ^= 0xff;
        } else if (typeof p.actions[0].payload_hash === "string") {
          p.actions[0].payload_hash = tamperedHex;
        } else {
          p.actions[0].payload_hash = new Array(32).fill(0xff);
        }
      }
      return { packet: p, context };
    },
  },
  {
    id: "p12_trace",
    index: 12,
    name: "Distributed Trace Spoofing",
    targetRule: "TRACE_BINDING",
    category: "VALIDITY",
    description: "Alters the SHA-256 trace commitment hash bound to distributed telemetry.",
    mutationExplanation: "Flips bits in packet.trace_binding.trace_hash or assigns corrupted hex string.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const zeroHex = "0000000000000000000000000000000000000000000000000000000000000000";
      if (p.trace_binding) {
        if (Array.isArray(p.trace_binding.trace_hash) && p.trace_binding.trace_hash.length > 0) {
          p.trace_binding.trace_hash[0] ^= 0xff;
        } else if (typeof p.trace_binding.trace_hash === "string") {
          p.trace_binding.trace_hash = zeroHex;
        } else {
          p.trace_binding.trace_hash = new Array(32).fill(0);
        }
      } else {
        p.trace_binding = {
          trace_id: "trace-tampered-001",
          trace_hash: new Array(32).fill(0),
        };
      }
      return { packet: p, context };
    },
  },
  {
    id: "p13_receipt",
    index: 13,
    name: "Counterparty Signature Corruption",
    targetRule: "RECEIPT_BINDING",
    category: "BILATERAL",
    description: "Corrupts the external bilateral countersignature bytes on the execution receipt.",
    mutationExplanation: "Flips bits in packet.receipt_binding.counterparty_sig.signature_bytes or assigns corrupted hex string.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const corruptHex = "corrupted_sig_hex_bytes_000000000000000000000000000000000000000000";
      const cpSig = p.receipt_binding?.counterparty_sig;
      if (cpSig) {
        if (Array.isArray(cpSig.signature_bytes) && cpSig.signature_bytes.length > 0) {
          cpSig.signature_bytes[0] ^= 0xff;
        } else if (typeof cpSig.signature_bytes === "string") {
          cpSig.signature_bytes = corruptHex;
        } else {
          cpSig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in cpSig) {
          cpSig.sig_hex = corruptHex;
        }
      }
      return { packet: p, context };
    },
  },
  {
    id: "p14_trust_floor",
    index: 14,
    name: "Trust Floor Claim Inflation",
    targetRule: "TRUST_FLOOR",
    category: "INTEGRITY",
    description: "Mutates packet fields dropping the engine-derived floor to UNVERIFIED while keeping claimed_trust_floor at COUNTERPARTY_SIGNED.",
    mutationExplanation: "Sets claimed_trust_floor = 'COUNTERPARTY_SIGNED' while altering decision summary to invalidate cryptographic floor.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.claimed_trust_floor = "COUNTERPARTY_SIGNED";
      p.decision = {
        ...p.decision,
        summary: "FORCED_UNVERIFIED: Manipulated summary forcing derived trust floor drop",
      };
      return { packet: p, context };
    },
  },
];
```

---

## 5. Verification Method

Once Worker implements the proposed changes to `attackPresets.ts` and `TamperSimulator.tsx`:

1. **Adversarial Stress Harness**:
   ```powershell
   node tests/m4_empirical_challenger.mjs
   ```
   **Expected Result**:
   - `TOTAL TESTS EXECUTED: 238 | PASSED: 238 | FAILED: 0`
   - `EMPIRICAL CHALLENGER VERDICT: APPROVE (100% Pass)`

2. **Console Static Analysis & Build**:
   ```powershell
   npm --prefix aip-console run lint
   npm --prefix aip-console run build
   ```
   **Expected Result**: Clean pass with 0 warnings or type errors.

3. **End-to-End Suite**:
   ```powershell
   npm run test:e2e
   ```
   **Expected Result**: 52/52 suites pass, 260/260 tests pass.

4. **Invalidation Conditions**:
   - Any preset throwing `Invalid EvidencePacket JSON: invalid type: string ...` when passed to `wasm.verify_evidence_packet`.
   - Any preset failing to cause its specific target check (`check.pass === false`).
   - Any occurrence of JavaScript verification logic in `attackPresets.ts`.
