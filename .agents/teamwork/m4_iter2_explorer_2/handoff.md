# Handoff Report: Smart Hash Wire-Format Byte-Packing Investigation

**Agent:** M4 Iteration 2 Explorer 2 (`m4_iter2_explorer_2`)  
**Role:** Smart Hash Wire-Format Byte-Packing Specialist  
**Working Directory:** `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_iter2_explorer_2\`  
**Milestone:** Milestone 4 (Adversarial Tamper Simulator & Authority Lattice Builder)  
**Date:** 2026-11-02  
**Status:** Investigation Complete (Read-Only)  

---

## 1. Observation

### 1.1 Direct Source Code Observations
1. **Rust Serde EvidencePacket Definition**:
   - File: `aip-standalone/aip-protocol/src/evidence_packet.rs`, lines 210-246:
     ```rust
     #[derive(Debug, Clone, Serialize, Deserialize)]
     pub struct EvidencePacket {
         ...
         // Integrity (excluded from canonical bytes)
         /// SHA-256 of the canonical encoding of all fields above.
         pub packet_hash: [u8; 32],
         /// Agent signature whose payload is exactly the canonical bytes
         /// (`agent_sig.payload_hash == packet_hash`).
         pub agent_sig: Signature,
     }
     ```
   - In serde, `[u8; 32]` strictly serializes to and deserializes from a JSON array of 32 numbers (`number[]`).

2. **WASM Export `recompute_packet_hash`**:
   - File: `aip-standalone/aip-wasm/src/lib.rs`, lines 159-164:
     ```rust
     #[wasm_bindgen]
     pub fn recompute_packet_hash(packet_json: &str) -> Result<String, JsValue> {
         let packet = EvidencePacket::from_json(packet_json)
             .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;
         Ok(hex::encode(packet.compute_hash()))
     }
     ```
   - Returns a 64-character lowercase hexadecimal string (`string`).

3. **TamperSimulator.tsx Smart Mode Recalculation & Mutation**:
   - File: `aip-console/src/components/tamper/TamperSimulator.tsx`, lines 94-105:
     ```typescript
     // Handle Smart Hash Recalculation (Feature F12)
     if (autoRecalculate && currentObj) {
       try {
         const freshHash = verifier.recomputeHash(currentJson);
         if (currentObj.packet_hash !== freshHash) {
           currentObj = { ...currentObj, packet_hash: freshHash };
           currentJson = JSON.stringify(currentObj, null, 2);
           setMutatedPacket(currentObj);
           setMutatedJson(currentJson);
         }
       } catch (hashErr) {
         console.warn("Failed to recompute hash:", hashErr);
       }
     }
     ```
   - Line 98 overwrites `currentObj.packet_hash` with `freshHash` (a 64-character string).
   - Line 97 compares `currentObj.packet_hash !== freshHash`, which compares an array `[u8; 32]` to a `string` (always true), or once set to string, compares string to string.
   - File: `aip-console/src/components/tamper/TamperSimulator.tsx`, lines 256-266 (`onRecomputeManual`):
     ```typescript
     onRecomputeManual={() => {
       if (!mutatedPacket || !verifier.isReady) return;
       try {
         const h = verifier.recomputeHash(mutatedJson);
         const updated = { ...mutatedPacket, packet_hash: h };
         setMutatedPacket(updated);
         setMutatedJson(JSON.stringify(updated, null, 2));
       } catch (err) {
         console.error(err);
       }
     }}
     ```
   - Line 260 also overwrites `packet_hash` with `h` (a 64-character string).

4. **TamperSimulator.tsx Stored Hash Passing**:
   - File: `aip-console/src/components/tamper/TamperSimulator.tsx`, line 195:
     ```typescript
     const storedHash = mutatedPacket?.packet_hash || "";
     ```
   - Passed directly to `<SmartHashToggle storedHash={storedHash} ... />`. When `mutatedPacket.packet_hash` is an array of 32 numbers (`number[]`), `storedHash` is passed as `number[]` at runtime.

5. **SmartHashToggle.tsx Stored Hash Crash Hazard**:
   - File: `aip-console/src/components/tamper/SmartHashToggle.tsx`, lines 19, 38-41, 165-167:
     ```typescript
     export interface SmartHashToggleProps {
       ...
       storedHash: string;
       recomputedHash: string;
       ...
     }
     ```
     ```typescript
     const isHashMatch =
       storedHash &&
       recomputedHash &&
       storedHash.toLowerCase() === recomputedHash.toLowerCase();
     ```
     ```typescript
     <div className="break-all text-slate-300 bg-[#0E131F] p-2 rounded border border-slate-850 select-text">
       {storedHash || <span className="text-slate-600">None</span>}
     </div>
     ```
   - When `storedHash` is `number[]` at runtime, calling `storedHash.toLowerCase()` throws `TypeError: storedHash.toLowerCase is not a function`, crashing the React component tree.
   - In addition, `{storedHash}` renders as a raw comma-separated array of 32 numbers (e.g. `173,172,122,...`) rather than a cryptographic hex string.

### 1.2 Verbatim Tool Outputs and Reproductions
1. **Authoritative Adversarial Stress Harness Reproduction**:
   - Command: `node tests/m4_empirical_challenger.mjs`
   - Exit Code: `1`
   - Tests 47, 51, 55 failed:
     ```
     [TamperSimulator Bug Reproduced] Assigning hex string to packet_hash crashes WASM serde: Invalid EvidencePacket JSON: invalid type: string "9db4849b3111033cf8ac7a167f524ac137bc1aa4328eef0797575ec5f8a70826", expected an array of length 32 at line 1 column 5409
     [FAIL] #47: TamperSimulator.tsx string assignment to packet_hash passes WASM deserialization for Decision Summary Tampering -> Assigning hex string to packet_hash ([u8; 32]) causes WASM serde deserialization failure
     [FAIL] #51: TamperSimulator.tsx string assignment to packet_hash passes WASM deserialization for Decision Rationale Hash Tampering -> Assigning hex string to packet_hash ([u8; 32]) causes WASM serde deserialization failure
     [FAIL] #55: TamperSimulator.tsx string assignment to packet_hash passes WASM deserialization for Action Description Tampering -> Assigning hex string to packet_hash ([u8; 32]) causes WASM serde deserialization failure
     ```

2. **Empirical Verification of Byte Packing and Cryptographic Non-Repudiation**:
   - Executed live against compiled `aip_wasm.js` and `aip_wasm_bg.wasm`:
     ```
     Original packet_hash is array: true length: 32
     Original packet_hash hex: adac7a2b74ea4635ecd18897c236b9177ba402072943054bd08528924d57aee7
     Recomputed hex matches stored hex: true
     [Naive Mode] CANONICAL_HASH pass: false (expected: false)
     [Naive Mode] tamper_evidence: true (expected: true)
     [Smart Mode] Fresh hash hex: 18c29903352e81e3d7d6bf713448ad765c0666caa497049ac46862b4ade20267
     [Smart Mode] Fresh hash != old hash: true
     [Smart Mode] CANONICAL_HASH pass: true (expected: true)
     [Smart Mode] AGENT_SIGNATURE pass: false (expected: false)
     [Smart Mode] tamper_evidence: true (expected: true)
     [Smart Mode] overall valid: false (expected: false)
     [Smart Mode] derived trust_floor: UNVERIFIED (expected: UNVERIFIED)
     ```

3. **Empirical Verification of `storedHash.toLowerCase` Failure**:
   - `const storedHash = [173, 172, 122, 43]; storedHash.toLowerCase()` -> `Crash confirmed: storedHash.toLowerCase is not a function`.

4. **Audit of All Components in `components/tamper/`**:
   - `attackPresets.ts`: None of the presets mutate `packet_hash` directly. (Presets mutate target payload/signature/scope fields; Explorer 1 handles dual-format byte arrays there).
   - `PresetSelector.tsx`: Pure selector UI, does not touch `packet_hash`.
   - `JsonDiffViewer.tsx`: Diff visualization component, treats input as raw JSON strings.
   - `JsonPayloadEditor.tsx`: Textarea JSON editor, treats input as raw JSON strings.
   - `LiveTamperLedger.tsx`: Pure report renderer (`VerificationReport`), does not touch `packet_hash`.
   - `diffUtils.ts`: Line-diff helper, does not touch `packet_hash`.
   - `FieldTamperPanel.tsx`: Does not touch `packet_hash`, but has parallel fields (`decision.input_hash` and `actions[0].payload_hash`) which should defensively support byte arrays.

---

## 2. Logic Chain

1. **Root Cause**:
   - Rust's `EvidencePacket` defines `pub packet_hash: [u8; 32]`. Serde strictly expects a 32-element array of numbers (`number[]`).
   - WebAssembly's `recompute_packet_hash` returns a 64-character lowercase hex string (`string`).
   - Assigning `freshHash` directly to `currentObj.packet_hash` replaces `[u8; 32]` with `string`, breaking Rust's JSON deserialization on subsequent calls to `verify_evidence_packet`.

2. **Impact on User Experience & Milestone 4 Demonstration**:
   - In `TamperSimulator.tsx`, when `autoRecalculate` (Smart Attacker Mode) is enabled or when "Recompute" is clicked, the packet JSON receives a string hash.
   - The reactive verification effect calls `verifier.verifyPacket(currentJson, activeCtx)`.
   - WASM throws `Invalid EvidencePacket JSON: invalid type: string ... expected an array of length 32`.
   - Line 128 catches the error and logs to `console.error`. `setLiveReport` is never called.
   - The Live Tamper Ledger freezes or remains blank, completely blocking the live demonstration of cryptographic non-repudiation (`CANONICAL_HASH: PASS` and `AGENT_SIGNATURE: FAIL`).

3. **Infinite Render Loop Prevention**:
   - In React, arrays are compared by reference, not value (`[1, 2] !== [1, 2]`).
   - If line 97 did `if (currentObj.packet_hash !== targetHash)`, because `hexToBytes` returns a new array reference every call, the condition would always evaluate to `true`.
   - Inside `useEffect([mutatedJson, ...])`, this would call `setMutatedJson` on every render, triggering an infinite render loop.
   - Therefore, a value comparison (such as `areByteArraysEqual(a, b)` or `JSON.stringify(a) !== JSON.stringify(b)`) is mathematically necessary before updating state.

4. **Cryptographic Non-Repudiation Mechanics**:
   - When an adversary tampers with payload data (e.g. `packet.decision.summary`), the canonical byte serialization of the packet changes.
   - In Naive Mode (Smart Hash toggle OFF), the original stored hash is preserved. The verifier recomputes the SHA-256 hash over the canonical bytes and finds that `packet.packet_hash != computed_hash`. Result: Rule 3 `CANONICAL_HASH: FAIL`, `tamper_evidence: true`.
   - In Smart Mode (Smart Hash toggle ON), the adversary recalculates `packet.packet_hash = sha256(mutated_canonical_bytes)` and packs it as `[u8; 32]`.
   - When `verifier.verifyPacket` runs:
     - Rule 3 `CANONICAL_HASH` compares `packet.packet_hash` to `sha256(mutated_canonical_bytes)`. They match! Rule 3 **PASSES**.
     - Rule 4 `AGENT_SIGNATURE` verifies the agent's Ed25519 signature over the canonical bytes. Because the adversary does not possess the agent's private signing key, the signature over the mutated canonical bytes is invalid. Rule 4 **FAILS**.
     - Result: `CANONICAL_HASH: PASS`, `AGENT_SIGNATURE: FAIL`, `tamper_evidence: true`, `overall_valid: false`, `derived_trust_floor: UNVERIFIED`.
   - Packing `packet_hash` as `[u8; 32]` allows the WASM engine to deserialize the packet, evaluate both rules, and display this exact cryptographic non-repudiation in the UI.

5. **Defensive Normalization for `SmartHashToggle.tsx`**:
   - Pristine packets store `packet_hash` as `[u8; 32]` (an array of numbers).
   - In `TamperSimulator.tsx`, converting `storedHash` via `bytesToHex` before passing to `SmartHashToggle` ensures `storedHash` is always a 64-character hex string.
   - In `SmartHashToggle.tsx`, accepting `storedHash: string | number[]` and normalizing it ensures `storedHash.toLowerCase()` never throws `TypeError`, renders cleanly in the card, and correctly checks `isHashMatch`.

6. **Preservation of Zero-JS Verification Invariant**:
   - `hexToBytes` and `bytesToHex` are purely encoding/formatting utilities (string hex $\leftrightarrow$ byte array).
   - 0 cryptographic hash calculations or signature verifications occur in JavaScript.
   - All cryptographic operations (SHA-256 hash recalculation and Ed25519 signature verification) remain 100% delegated to compiled Rust WebAssembly.

---

## 3. Caveats

1. **Scope of Explorer Role**:
   - As an Explorer agent, this investigation is read-only. Source files were NOT modified. The complete drop-in code modifications are specified below for the implementer agent.
2. **`attackPresets.ts` Dual-Format Requirement**:
   - This handoff focuses on `TamperSimulator.tsx` and `SmartHashToggle.tsx`. Explorer 1 (`m4_iter2_explorer_1`) is formulating the dual-format mutations for the 7 presets in `attackPresets.ts`.
3. **`FieldTamperPanel.tsx` Defensive Hardening**:
   - In `FieldTamperPanel.tsx`, quick-action buttons mutate `decision.input_hash` and `actions[0].payload_hash` with string constants (e.g. `"0000..."` and `"ffff...tampered"`). While these are manual simulation buttons, applying dual-format checking there will ensure manual visual editing never triggers serde deserialization errors.

---

## 4. Conclusion & Precise Code Solutions

### 4.1 Solution in `aip-console/src/components/tamper/TamperSimulator.tsx`

Add utility helpers at module scope (outside component):

```typescript
/**
 * Convert 64-character hexadecimal string to an array of 32 bytes for Rust serde [u8; 32] wire compatibility.
 */
function hexToBytes(hex: string): number[] {
  const cleanHex = hex.trim().replace(/^0x/i, "");
  const bytes: number[] = [];
  for (let c = 0; c < cleanHex.length; c += 2) {
    bytes.push(parseInt(cleanHex.substring(c, c + 2), 16));
  }
  return bytes;
}

/**
 * Convert a byte array ([u8; 32]) or hex string to normalized 64-char lowercase hex string for display.
 */
function bytesToHex(bytes: number[]): string {
  return bytes.map((b) => Number(b).toString(16).padStart(2, "0")).join("");
}

/**
 * Value equality check for byte arrays or strings to prevent React infinite re-render loops.
 */
function areByteArraysEqual(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
  return a === b;
}
```

Update lines 93-106 in `TamperSimulator.tsx`:
```typescript
<<<< BEFORE
      // Handle Smart Hash Recalculation (Feature F12)
      if (autoRecalculate && currentObj) {
        try {
          const freshHash = verifier.recomputeHash(currentJson);
          if (currentObj.packet_hash !== freshHash) {
            currentObj = { ...currentObj, packet_hash: freshHash };
            currentJson = JSON.stringify(currentObj, null, 2);
            setMutatedPacket(currentObj);
            setMutatedJson(currentJson);
          }
        } catch (hashErr) {
          console.warn("Failed to recompute hash:", hashErr);
        }
      }
====
>>>> AFTER
      // Handle Smart Hash Recalculation (Feature F12)
      if (autoRecalculate && currentObj) {
        try {
          const freshHash = verifier.recomputeHash(currentJson);
          const targetHash = Array.isArray(currentObj.packet_hash)
            ? hexToBytes(freshHash)
            : freshHash;

          if (!areByteArraysEqual(currentObj.packet_hash, targetHash)) {
            currentObj = { ...currentObj, packet_hash: targetHash };
            currentJson = JSON.stringify(currentObj, null, 2);
            setMutatedPacket(currentObj);
            setMutatedJson(currentJson);
          }
        } catch (hashErr) {
          console.warn("Failed to recompute hash:", hashErr);
        }
      }
<<<<
```

Update line 195 in `TamperSimulator.tsx`:
```typescript
<<<< BEFORE
  const storedHash = mutatedPacket?.packet_hash || "";
====
>>>> AFTER
  const storedHash = Array.isArray(mutatedPacket?.packet_hash)
    ? bytesToHex(mutatedPacket.packet_hash)
    : (typeof mutatedPacket?.packet_hash === "string" ? mutatedPacket.packet_hash : "");
<<<<
```

Update lines 256-266 (`onRecomputeManual`) in `TamperSimulator.tsx`:
```typescript
<<<< BEFORE
        onRecomputeManual={() => {
          if (!mutatedPacket || !verifier.isReady) return;
          try {
            const h = verifier.recomputeHash(mutatedJson);
            const updated = { ...mutatedPacket, packet_hash: h };
            setMutatedPacket(updated);
            setMutatedJson(JSON.stringify(updated, null, 2));
          } catch (err) {
            console.error(err);
          }
        }}
====
>>>> AFTER
        onRecomputeManual={() => {
          if (!mutatedPacket || !verifier.isReady) return;
          try {
            const h = verifier.recomputeHash(mutatedJson);
            const targetHash = Array.isArray(mutatedPacket.packet_hash)
              ? hexToBytes(h)
              : h;
            const updated = { ...mutatedPacket, packet_hash: targetHash };
            setMutatedPacket(updated);
            setMutatedJson(JSON.stringify(updated, null, 2));
          } catch (err) {
            console.error("Failed to manually recompute hash:", err);
          }
        }}
<<<<
```

---

### 4.2 Solution in `aip-console/src/components/tamper/SmartHashToggle.tsx`

Update props interface and defensive normalization in `SmartHashToggle.tsx`:

```typescript
export interface SmartHashToggleProps {
  autoRecalculate: boolean;
  onToggle: (enabled: boolean) => void;
  storedHash: string | number[];
  recomputedHash: string;
  canonicalBytesHex?: string;
  onRecomputeManual?: () => void;
  className?: string;
}

export const SmartHashToggle: React.FC<SmartHashToggleProps> = ({
  autoRecalculate,
  onToggle,
  storedHash,
  recomputedHash,
  canonicalBytesHex,
  onRecomputeManual,
  className = "",
}) => {
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showCanonicalBytes, setShowCanonicalBytes] = useState(false);

  // Normalize storedHash to string whether passed as number[] or string
  const normalizedStoredHash = Array.isArray(storedHash)
    ? storedHash.map((b) => Number(b).toString(16).padStart(2, "0")).join("")
    : (typeof storedHash === "string" ? storedHash : "");

  const isHashMatch =
    Boolean(normalizedStoredHash) &&
    Boolean(recomputedHash) &&
    normalizedStoredHash.toLowerCase() === recomputedHash.toLowerCase();

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };
```

And in the JSX:
- Line 149: `onClick={() => copyToClipboard(normalizedStoredHash, "stored")}`
- Line 166: `{normalizedStoredHash || <span className="text-slate-600">None</span>}`

---

## 5. Verification Method

To verify the implementation once applied:

1. **Empirical Harness Check**:
   ```powershell
   node tests/m4_empirical_challenger.mjs
   ```
   *Expected Outcome*: All 3 Smart Mode tests pass:
   - `[Smart Wire Mode] Decision Summary Tampering: CANONICAL_HASH PASSES`
   - `[Smart Wire Mode] Decision Summary Tampering: AGENT_SIGNATURE FAILS`
   - `[Smart Wire Mode] Decision Summary Tampering: tamper_evidence REMAINS TRUE`
   - With `attackPresets.ts` also resolved, `TOTAL TESTS: 238 | PASSED: 238 | FAILED: 0`.

2. **TypeScript Compilation & Lint Check**:
   ```powershell
   npm --prefix aip-console run lint
   ```
   *Expected Outcome*: Exit code 0, 0 type errors.

3. **Production Build**:
   ```powershell
   npm --prefix aip-console run build
   ```
   *Expected Outcome*: Exit code 0, all routes compile cleanly.

4. **Zero-JS Invariant Static Analysis**:
   - Ensure 0 instances of `crypto.subtle`, `createHash`, `tweetnacl`, or `noble` exist in `TamperSimulator.tsx` and `SmartHashToggle.tsx`.

5. **Invalidation Conditions**:
   - Any throw of `Invalid EvidencePacket JSON: invalid type: string ... expected an array of length 32` when toggling Smart Mode or clicking Recompute.
   - Any crash of `storedHash.toLowerCase is not a function` when opening the Tamper Simulator.
   - Any failure of `CANONICAL_HASH: PASS` and `AGENT_SIGNATURE: FAIL` when Smart Mode is active with a tampered field.
