# Handoff Report: UI Deserialization Resilience & Live Tamper Ledger Breakdown

**Agent:** Milestone 4 Iteration 2 Explorer 3 (`m4_iter2_explorer_3` - UI Deserialization Resilience & Ledger Specialist)  
**Working Directory:** `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_iter2_explorer_3\`  
**Date:** 2026-11-02  
**Milestone:** M4 (Adversarial Tamper Simulator & Authority Lattice Builder — Requirements R3 & R4)  
**Parent Agent:** `675111aa-04e8-493f-9811-dbfc1935a77b`  
**Verdict:** **`ANALYSIS_COMPLETE`** (Comprehensive diagnosis and concrete mitigation architecture provided)

---

## 1. Observation

Direct code inspection, WebAssembly runtime analysis, and execution of the authoritative 238-assertion adversarial stress harness (`tests/m4_empirical_challenger.mjs`) revealed the following empirical facts regarding error propagation, serde deserialization boundaries, and live ledger rendering:

### 1.1 Tool Execution and Empirical Reproduction
1. **Authoritative Adversarial Stress Harness**:
   - Command: `node tests/m4_empirical_challenger.mjs`
   - Exit Code: `1` (234 Passed, 4 Failed)
   - Verbatim Defect 1: `[FAIL] #12: All 14 presets pass WASM EvidencePacket deserialization (actually passed: 7/14) -> 7 presets failed deserialization: p04_agent_sig, p05_root_sig, p06_delegation, p08_scope, p11_actions, p12_trace, p13_receipt`
   - Verbatim Defect 2: `[FAIL] #67: TamperSimulator.tsx string assignment to packet_hash passes WASM deserialization for Decision Summary Tampering -> Assigning hex string to packet_hash ([u8; 32]) causes WASM serde deserialization failure`

2. **WebAssembly Deserialization Boundary Behavior in Rust**:
   - In `aip-standalone/aip-wasm/src/lib.rs` (lines 30-33):
     ```rust
     #[wasm_bindgen]
     pub fn verify_evidence_packet(
         packet_json: &str,
         context_json: Option<String>,
     ) -> Result<String, JsValue> {
         let packet = EvidencePacket::from_json(packet_json)
             .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;
     ```
   - When a packet contains malformed JSON syntax or type mismatches against the Rust struct definition (e.g. string literals assigned to `[u8; 32]`, `[u8; 64]`, or `[u8; 16]`), `EvidencePacket::from_json` fails immediately.
   - Rust returns `Err(JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))`.
   - In the compiled WebAssembly JS bindings (`public/wasm/aip_wasm.js`), returning `Err(JsValue)` causes `wasm.verify_evidence_packet` to **throw a JavaScript exception** with a string value (e.g., `Invalid EvidencePacket JSON: invalid type: string "...", expected an array of length 32 at line 1 column 5409`).
   - Consequently, line 40 (`let report = verify_packet(&packet, &ctx);`) is **never reached**. Serde rejects the payload before any of the 14 cryptographic verification rules can be evaluated.

3. **Silent Exception Swallowing and Stale State Retention in `TamperSimulator.tsx`**:
   - In `aip-console/src/components/tamper/TamperSimulator.tsx` (lines 86-131):
     ```typescript
     // Live report from WASM verify_evidence_packet (zero JS verification)
     const [liveReport, setLiveReport] = useState<VerificationReport | null>(null);
     ...
     useEffect(() => {
       if (!verifier.isReady || !mutatedJson) return;

       try {
         ...
         // Zero-JS verification: delegate 100% to Rust WebAssembly
         const activeCtx = contextJson || "{}";
         const rep = verifier.verifyPacket(currentJson, activeCtx);
         setLiveReport(rep);
       } catch (err) {
         console.error("Verification execution error:", err);
       }
     }, [mutatedJson, autoRecalculate, contextJson, verifier]);
     ```
   - When `verifier.verifyPacket` throws an engine deserialization error:
     1. The error is caught by `catch (err)` and dumped to `console.error`.
     2. `setLiveReport` is never called.
     3. `liveReport` retains its **stale previous value** (e.g., "PRISTINE & VERIFIED: ALL 14 RULES PASS" from the initial baseline load).
     4. No error state (e.g., `engineError`) is captured, stored in React state, or passed down to child components.
     5. The UI appears frozen or unresponsive to user mutations.

4. **Absence of Error Banner and Fallback State in `LiveTamperLedger.tsx`**:
   - In `aip-console/src/components/tamper/LiveTamperLedger.tsx` (lines 9-19):
     ```typescript
     export interface LiveTamperLedgerProps {
       report: VerificationReport | null;
       className?: string;
       onRuleSelect?: (rule: RuleIdentifier) => void;
     }
     ```
   - `LiveTamperLedger` has no prop for error surfacing.
   - When `report` is stale, it displays stale passing checks and a green "PRISTINE & VERIFIED" badge, misleading the operator into believing a tampered payload passed verification.
   - When `report` is `null` (e.g. on cold start before verification completes), `VerificationLedger.tsx` (lines 123-138) displays a generic dashed box: `"Awaiting Evidence Verification: Load an EvidencePacket (.json)..."`, which does not inform the user that a deserialization error took place.

5. **Type Mismatch in `SmartHashToggle.tsx` and `TamperSimulator.tsx`**:
   - In `TamperSimulator.tsx` (line 195):
     ```typescript
     const storedHash = mutatedPacket?.packet_hash || "";
     ```
   - In standard `EvidencePacket` JSON, `packet_hash` is a numeric array `[u8; 32]` (e.g., `[173, 172, 122, 43, ...]`).
   - In `SmartHashToggle.tsx` (lines 19, 38-41):
     ```typescript
     export interface SmartHashToggleProps {
       storedHash: string;
       ...
     }
     ...
     const isHashMatch =
       storedHash &&
       recomputedHash &&
       storedHash.toLowerCase() === recomputedHash.toLowerCase();
     ```
   - Because `storedHash` is passed an array of numbers (`number[]`) instead of a 64-character hex string, calling `storedHash.toLowerCase()` fails or evaluates `isHashMatch` to false at all times.
   - In `SmartHashToggle.tsx` (line 165), `{storedHash}` renders as unformatted numbers concatenated without hex encoding.

6. **Targeted Rule Failure Breakdown in Live WASM (Vector 1B Empirical Pass)**:
   - When byte arrays are properly manipulated using numeric array bit-flips (Vector 1B in `tests/m4_empirical_challenger.mjs`), `verify_evidence_packet` completes in <1ms and yields 100% precise rule evaluations:
     - **Preset 4 (`AGENT_SIGNATURE`)**: `overall_valid: false`, `tamper_evidence: true`, failing rules: `AGENT_SIGNATURE` ("agent signature cryptographic verification failed"), `TRUST_FLOOR` ("claimed floor CounterpartySigned exceeds what the evidence supports (Unverified)").
     - **Preset 3 (`CANONICAL_HASH` Naive)**: `overall_valid: false`, `tamper_evidence: true`, failing rules: `CANONICAL_HASH` ("packet_hash mismatch: stored adac... recomputed 6769... - packet modified after sealing"), `AGENT_SIGNATURE`, `TRUST_FLOOR`.
     - **Preset 3 (`CANONICAL_HASH` Smart Non-Repudiation)**: When `freshHash` is packed into `[u8; 32]` via `hexToBytes`: `CANONICAL_HASH: PASS` (`pass: true`), `AGENT_SIGNATURE: FAIL` (`pass: false`, "signature payload hash does not cover current packet contents"), `tamper_evidence: true`.

---

## 2. Logic Chain

1. **Root Mechanism of the Defect**:
   - Rust's `serde` framework parses incoming JSON into strongly typed Rust structs defined in `aip-types` and `aip-protocol`.
   - Fields such as `packet_hash`, `payload_hash`, `trace_hash`, `signature_bytes`, and `action_id` are strictly typed as `[u8; 32]`, `[u8; 64]`, or `[u8; 16]`.
   - When string literals (or incorrect enum shapes such as `{ kind: "Standard", action: "Admin" }`) are injected into these fields, `EvidencePacket::from_json` fails serde deserialization.
   - Serde deserialization is an unrecoverable parse boundary; it aborts before `verify_packet(&packet, &ctx)` is reached.

2. **UI Failure Mechanism**:
   - `verifier.verifyPacket` re-throws the WASM string exception to the caller.
   - `TamperSimulator.tsx` catches the exception in `useEffect`, logs it to `console.error`, and terminates without clearing `liveReport` or setting an error state.
   - Because React preserves existing state unless explicitly replaced, `liveReport` continues holding the prior valid report.
   - `LiveTamperLedger.tsx` renders this stale report, showing "ALL 14 RULES PASS" despite the presence of invalid wire-format mutations.

3. **Zero-JS Verification Invariant**:
   - In accordance with `PROJECT.md` Requirement R1, the console must NEVER execute verification logic in JavaScript or TypeScript.
   - When an engine deserialization error occurs, JavaScript must NOT attempt to synthesize fake rule passes or fake rule failures (e.g. guessing that `STRUCTURE` failed).
   - Instead, the UI must truthfully surface the exact error string emitted by Rust WASM and clearly indicate that automated rule evaluation is suspended pending wire-format conformance.

4. **Impact of Proper Byte-Array Handling**:
   - When wire-format conversions (`hexToBytes` and byte array bit-flips) are used, serde deserializes smoothly.
   - The engine evaluates all 14 rules and emits a structured `VerificationReport`.
   - `LiveTamperLedger.tsx` renders the exact failing rules (`AGENT_SIGNATURE`, `CANONICAL_HASH`, `ROOT_TOKEN_SIGNATURE`, etc.) with 100% clarity, including pass/fail icons, tamper badges, and the verbatim Rust error rationale.

---

## 3. Caveats

- **Rule 1 (`STRUCTURE`) Boundary Scope**: Rule 1 (`STRUCTURE`) inside `aip-protocol` evaluates semantic wire format invariants (such as matching magic bytes `AEP1` and version numbers `1`) on an already deserialized `EvidencePacket` struct. It does NOT intercept malformed JSON syntax or serde type mismatches because serde fails prior to `verify_packet`. Deserialization errors must therefore be handled at the transport/harness boundary in the UI.
- **Read-Only Scope**: In adherence to the Teamwork Explorer protocol, no source files were directly modified in the repository. All recommendations are presented as concrete, drop-in code snippets and diffs.
- **Corporate Anti-Vibe Styling Compliance**: In adherence to `ORIGINAL_REQUEST.md`, all recommended UI alerts avoid purple gradients, neon glow effects, pill-shaped buttons, amateur emojis, and em dashes, using structured rectangular geometry (`rounded-lg`/`rounded-md`), Lucide SVG icons, and a deep slate/red/steel palette.

---

## 4. Conclusion & Recommended Fix Strategy

To resolve UI freezing, stale report retention, and wire-format incompatibilities, three coordinated modifications must be implemented:

### Remediation Step 1: Engine Error State & Stale Invalidation in `TamperSimulator.tsx`

Update `aip-console/src/components/tamper/TamperSimulator.tsx`:
1. Add state for `engineError`:
   ```typescript
   const [engineError, setEngineError] = useState<string | null>(null);
   ```
2. Helper functions for wire-format conversion:
   ```typescript
   function hexToBytes(hex: string): number[] {
     const bytes: number[] = [];
     for (let c = 0; c < hex.length; c += 2) {
       bytes.push(parseInt(hex.substr(c, 2), 16));
     }
     return bytes;
   }

   function bytesToHex(bytes: number[]): string {
     return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
   }
   ```
3. Update reactive verification effect (lines 86-131) to:
   - Handle byte-array packing for smart hash recalculation.
   - Clear stale report on error and capture the engine error message.
   - Clear engine error on successful verification:
   ```typescript
   useEffect(() => {
     if (!verifier.isReady || !mutatedJson) return;

     try {
       let currentJson = mutatedJson;
       let currentObj = mutatedPacket;

       // Handle Smart Hash Recalculation (Feature F12)
       if (autoRecalculate && currentObj) {
         try {
           const freshHash = verifier.recomputeHash(currentJson);
           const targetHash = Array.isArray(currentObj.packet_hash)
             ? hexToBytes(freshHash)
             : freshHash;

           if (JSON.stringify(currentObj.packet_hash) !== JSON.stringify(targetHash)) {
             currentObj = { ...currentObj, packet_hash: targetHash };
             currentJson = JSON.stringify(currentObj, null, 2);
             setMutatedPacket(currentObj);
             setMutatedJson(currentJson);
           }
         } catch (hashErr) {
           console.warn("Failed to recompute hash:", hashErr);
         }
       }

       // Recompute hash for comparison display
       try {
         const compHash = verifier.recomputeHash(currentJson);
         setRecomputedHash(compHash);
       } catch {
         setRecomputedHash("");
       }

       // Get canonical bytes hex
       try {
         const cBytes = verifier.getCanonicalBytesHex(currentJson);
         setCanonicalBytesHex(cBytes);
       } catch {
         setCanonicalBytesHex("");
       }

       // Zero-JS verification: delegate 100% to Rust WebAssembly
       const activeCtx = contextJson || "{}";
       const rep = verifier.verifyPacket(currentJson, activeCtx);
       setLiveReport(rep);
       setEngineError(null); // Clear previous errors
     } catch (err: unknown) {
       const msg = typeof err === "string" ? err : err instanceof Error ? err.message : String(err);
       console.error("Verification execution error:", err);
       setLiveReport(null); // Clear stale report immediately
       setEngineError(msg); // Surface verbatim WASM engine error
     }
   }, [mutatedJson, autoRecalculate, contextJson, verifier]);
   ```
4. Format `storedHash` properly as hex string for `SmartHashToggle`:
   ```typescript
   const storedHashHex = React.useMemo(() => {
     if (!mutatedPacket?.packet_hash) return "";
     if (Array.isArray(mutatedPacket.packet_hash)) {
       return bytesToHex(mutatedPacket.packet_hash);
     }
     return String(mutatedPacket.packet_hash);
   }, [mutatedPacket?.packet_hash]);
   ```
5. Pass `storedHashHex` and `engineError` down to child components:
   ```tsx
   <SmartHashToggle
     autoRecalculate={autoRecalculate}
     onToggle={setAutoRecalculate}
     storedHash={storedHashHex}
     recomputedHash={recomputedHash}
     canonicalBytesHex={canonicalBytesHex}
     onRecomputeManual={handleManualRecompute}
   />

   <LiveTamperLedger
     report={liveReport}
     engineError={engineError}
     onReset={handleResetToBaseline}
   />
   ```

---

### Remediation Step 2: Error Banner & Suspended State in `LiveTamperLedger.tsx`

Update `aip-console/src/components/tamper/LiveTamperLedger.tsx`:
1. Expand `LiveTamperLedgerProps`:
   ```typescript
   export interface LiveTamperLedgerProps {
     report: VerificationReport | null;
     engineError?: string | null;
     className?: string;
     onRuleSelect?: (rule: RuleIdentifier) => void;
     onReset?: () => void;
   }
   ```
2. Add copy state and clipboard handler for the error message:
   ```typescript
   const [copiedError, setCopiedError] = useState(false);

   const copyError = () => {
     if (!engineError) return;
     navigator.clipboard.writeText(engineError);
     setCopiedError(true);
     setTimeout(() => setCopiedError(false), 2000);
   };
   ```
3. Insert the high-assurance corporate alert banner and suspended ledger fallback:
   ```tsx
   export const LiveTamperLedger: React.FC<LiveTamperLedgerProps> = ({
     report,
     engineError,
     className = "",
     onRuleSelect,
     onReset,
   }) => {
     const stats = useMemo(() => {
       if (!report || !report.checks) {
         return { total: 0, passed: 0, failed: 0, failingRules: [] as string[] };
       }
       const total = report.checks.length;
       const passed = report.checks.filter((c) => c.pass).length;
       const failed = total - passed;
       const failingRules = report.checks.filter((c) => !c.pass).map((c) => c.rule);
       return { total, passed, failed, failingRules };
     }, [report]);

     const isTampered = Boolean(report?.tamper_evidence || (report as any)?.tampered);
     const isValid = Boolean(report?.overall_valid || (report as any)?.valid);

     return (
       <div className={`space-y-4 ${className}`}>
         {/* ── Engine Deserialization Error Alert Banner ─────────────────────── */}
         {engineError && (
           <div className="p-4 rounded-lg border border-red-500/50 bg-red-950/30 text-red-200 font-mono text-xs shadow-md space-y-3">
             <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-red-900/60 pb-3">
               <div className="flex items-center gap-2.5">
                 <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
                 <div>
                   <div className="flex items-center gap-2">
                     <span className="font-bold text-sm text-red-100 tracking-wide">
                       Engine Deserialization Error
                     </span>
                     <span className="text-[10px] px-2 py-0.5 rounded bg-red-900/60 text-red-200 border border-red-700/60 font-bold uppercase">
                       Wire-Format Rejection
                     </span>
                   </div>
                   <p className="text-[11px] text-red-300/80 mt-0.5 font-sans">
                     The WebAssembly verification engine rejected this payload prior to rule evaluation.
                   </p>
                 </div>
               </div>

               <div className="flex items-center gap-2 self-end sm:self-auto">
                 <button
                   type="button"
                   onClick={copyError}
                   className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-red-900/40 hover:bg-red-900/70 border border-red-700/60 text-red-200 text-[11px] transition-colors"
                   title="Copy raw engine error string"
                 >
                   {copiedError ? (
                     <>
                       <Check className="w-3 h-3 text-emerald-400" />
                       <span className="text-emerald-400">Copied</span>
                     </>
                   ) : (
                     <>
                       <Copy className="w-3 h-3" />
                       <span>Copy Error</span>
                     </>
                   )}
                 </button>

                 {onReset && (
                   <button
                     type="button"
                     onClick={onReset}
                     className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-[11px] transition-colors"
                     title="Revert payload to baseline honest packet"
                   >
                     <RotateCcw className="w-3 h-3 text-cyan-400" />
                     <span>Revert to Pristine</span>
                   </button>
                 )}
               </div>
             </div>

             {/* Verbatim Serde / Engine Error Message */}
             <div className="p-3 rounded bg-black/60 border border-red-900/60 font-mono text-[11px] text-red-300 break-all select-text leading-relaxed">
               <span className="text-slate-500 select-none">$ wasm_engine: </span>
               {engineError}
             </div>

             {/* Diagnostic Guidance & Zero-JS Notice */}
             <div className="text-[11px] text-slate-400 font-sans leading-relaxed">
               <strong className="text-slate-300 font-mono">Zero-JS Compliance Notice:</strong> In accordance with strict cryptographic guarantees, verification rules are executed solely inside compiled WebAssembly. When packet fields violate binary wire-format types (e.g., passing string literals for numeric byte arrays <code className="text-red-300 font-mono">[u8; 32]</code> or <code className="text-red-300 font-mono">[u8; 64]</code>, or invalid enum representations), Rust Serde aborts evaluation immediately.
             </div>
           </div>
         )}

         {/* ── Suspended Ledger Fallback Card ────────────────────────────────── */}
         {engineError && !report && (
           <div className="rounded-lg border border-dashed border-red-900/50 bg-[#0E131F]/40 p-6 text-center font-mono">
             <ShieldAlert className="w-8 h-8 text-red-500/70 mx-auto mb-2" />
             <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wide">
               14 Engine Verification Checks Suspended
             </h4>
             <p className="text-[11px] text-slate-400 mt-1 max-w-md mx-auto font-sans">
               Payload deserialization failed. Resolve wire-format schema issues above or revert to a pristine baseline packet to resume automated 14-rule cryptographic evaluation.
             </p>
           </div>
         )}

         {/* ── Active Verification Report View (Rendered when engine succeeds) ── */}
         {!engineError && (
           <>
             {/* Dynamic Status Notification Banner */}
             {report && (
               <div
                 className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono text-xs transition-all ${
                   isValid
                     ? "bg-emerald-950/30 border-emerald-500/50 text-emerald-200 shadow-[0_0_15px_rgba(16,185,129,0.15)]"
                     : isTampered
                     ? "bg-red-950/40 border-red-500/60 text-red-200 shadow-[0_0_20px_rgba(239,68,68,0.3)] animate-pulse"
                     : "bg-amber-950/30 border-amber-500/50 text-amber-200 shadow-[0_0_15px_rgba(245,158,11,0.15)]"
                 }`}
               >
                 <div className="flex items-center gap-3">
                   {isValid ? (
                     <CheckCircle2 className="w-6 h-6 text-emerald-400 flex-shrink-0" />
                   ) : isTampered ? (
                     <Flame className="w-6 h-6 text-red-400 flex-shrink-0 animate-bounce" />
                   ) : (
                     <AlertTriangle className="w-6 h-6 text-amber-400 flex-shrink-0" />
                   )}

                   <div>
                     <div className="flex items-center gap-2">
                       <span className="font-bold text-sm tracking-wide">
                         {isValid
                           ? "PRISTINE & VERIFIED: ALL 14 RULES PASS"
                           : isTampered
                           ? "CRYPTOGRAPHIC TAMPER DETECTED"
                           : "VERIFICATION FAILED (POLICY GAP)"}
                       </span>
                       <span className="text-[10px] px-2 py-0.5 rounded bg-black/40 border border-current font-bold">
                         {stats.failed} FAILING RULES
                       </span>
                     </div>
                     <p className="text-[11px] opacity-80 mt-0.5 font-sans">
                       {isValid
                         ? "Every cryptographic signature, canonical hash, and authority delegation hop verified cleanly via WebAssembly."
                         : isTampered
                         ? "Sealed payload, canonical hash, or cryptographic signature modified after sealing. Mathematical non-repudiation enforced."
                         : "Administrative or policy configuration requirement not met (e.g. untrusted root key or revoked credential)."}
                     </p>
                   </div>
                 </div>

                 {/* Quick failing rules chips */}
                 {stats.failed > 0 && (
                   <div className="flex flex-wrap items-center gap-1.5 justify-end">
                     {stats.failingRules.map((rule) => (
                       <span
                         key={rule}
                         className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-900/60 text-red-200 border border-red-700/60"
                       >
                         {rule}
                       </span>
                     ))}
                   </div>
                 )}
               </div>
             )}

             {/* Trust Floor Progression Ladder Badge */}
             {report && (
               <TrustFloorBadge
                 derivedFloor={report.derived_trust_floor || (report as any).trust_floor}
                 claimedFloor={report.claimed_trust_floor}
                 tamperEvidence={isTampered}
                 variant="ladder"
               />
             )}

             {/* Embedded 14-Rule Verification Ledger */}
             <VerificationLedger report={report} onRuleSelect={onRuleSelect} />
           </>
         )}
       </div>
     );
   };
   ```

---

### Remediation Step 3: Wire-Format Compatibility in Attack Presets & Field Editors

To ensure attack presets and UI editor buttons do not trigger unintentional serde rejections, apply wire-format dual-mode checks:
1. In `aip-console/src/components/tamper/attackPresets.ts`:
   - Inspect whether fields are byte arrays (`Array.isArray(...)`) and perform numeric bit-flips (e.g. `p.agent_sig.signature_bytes[0] ^= 0xff;`).
   - Use `{ Standard: "Admin" }` for `DELEGATION_CHAIN` enum variants.
   - Use 16-byte numeric array `[1, 2, ..., 16]` for `action_id` and 32-byte zero array for `payload_hash` in `p08_scope`.
2. In `aip-console/src/components/tamper/FieldTamperPanel.tsx`:
   - In lines 288-298 ("Corrupt Agent Digital Signature"): mutate via `p.agent_sig.signature_bytes[0] ^= 0xff` when `Array.isArray(...)`.
   - In lines 403-413 ("Corrupt Root Token Signature"): mutate via `p.root_authority.root_token.issuer_sig.signature_bytes[0] ^= 0xff`.
   - In lines 477-483 ("Mutate Action Payload Hash"): mutate via `p.actions[0].payload_hash[0] ^= 0xff`.
   - In lines 545-555 ("Corrupt Counterparty Signature"): mutate via `p.receipt_binding.counterparty_sig.signature_bytes[0] ^= 0xff`.

---

## 5. Verification Method

Once the implementer applies the recommended code changes:

1. **Adversarial Empirical Stress Harness**:
   ```powershell
   node tests/m4_empirical_challenger.mjs
   ```
   - **Expected Outcome**: Exit code `0`.
   - `TOTAL TESTS EXECUTED: 238 | PASSED TESTS: 238 | FAILED TESTS: 0 | SUCCESS RATE: 100.00%`.
   - `VERDICT: APPROVE`.

2. **TypeScript Compilation & ESLint**:
   ```powershell
   npm --prefix aip-console run lint
   ```
   - **Expected Outcome**: Exit code `0`, 0 errors, 0 warnings.

3. **Production Next.js Build**:
   ```powershell
   npm --prefix aip-console run build
   ```
   - **Expected Outcome**: Exit code `0`, all routes statically rendered.

4. **UI Error Banner Verification in Dev Server**:
   - In `JsonPayloadEditor`, input an invalid string into a numeric field (e.g. `"packet_hash": "malformed"`).
   - Verify that:
     1. The red `Engine Deserialization Error: Wire-Format Rejection` alert appears in `LiveTamperLedger`.
     2. Stale reports are not displayed.
     3. The verbatim error message `$ wasm_engine: Invalid EvidencePacket JSON: invalid type: string ...` is shown.
     4. Clicking "Copy Error" copies the error string to clipboard.
     5. Clicking "Revert to Pristine" immediately restores the honest packet and renders all 14 passed checks.

5. **Invalidation Conditions**:
   - Any scenario where a serde exception leaves a stale green "PRISTINE & VERIFIED" report on screen.
   - Any client-side verification logic implemented in TypeScript or JavaScript.
   - Any crash or unhandled `TypeError` when `storedHash` is compared in `SmartHashToggle`.
