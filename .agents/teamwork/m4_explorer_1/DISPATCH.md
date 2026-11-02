# Dispatch: M4 Explorer 1 (Tamper Simulator & Attack Vectors Specialist)

## Mission
Investigate and design the complete technical architecture for Requirement R3 (Adversarial Tamper Simulator — Features F11, F12, F13):
1. **Feature F11 — Adversarial Field Mutation Engine**:
   - 14 pre-configured attack vector presets covering all 14 verification checks.
   - Interactive field editor / mutation controls for manual tampering of headers, signatures, tokens, hashes, and action attestations.
   - Presets for:
     1. Hash mismatch (mutating action or payload without updating canonical hash)
     2. Signature corruption (invalid Ed25519 signature bytes)
     3. Root token signature corruption
     4. Delegation chain break (corrupted parent token ID or invalid delegation hop)
     5. Scope escalation (action outside permitted scope)
     6. Temporal expiration (token expired relative to packet timestamp)
     7. Token revocation (token ID matching revoked token list)
     8. Trust anchor mismatch (root authority key does not match trusted anchors)
     9. Agent ID binding mismatch (agent pubkey != token subject)
     10. Action attestation signature failure
     11. Trace binding corruption (invalid decision ID or trace link)
     12. Receipt binding corruption (corrupted receipt signature or action hash)
     13. Trust floor violation (claimed floor > derived floor)
     14. Malformed JSON structure (missing envelope keys, invalid types)
2. **Feature F12 — Smart Hash Recalculation Toggle**:
   - Toggle: "Auto-recalculate Canonical Hash".
   - Using WASM `recompute_packet_hash(packetJson)` or `get_canonical_bytes_hex(packetJson)`.
   - Visual Diff Viewer comparing Original JSON vs Mutated JSON with colored additions/deletions.
   - Demonstration of cryptographic invariant: recomputing hash fixes CANONICAL_HASH rule, but fails AGENT_SIGNATURE rule.
3. **Feature F13 — Instant Rule Failure Feedback**:
   - Real-time verification against WASM `verify_evidence_packet` on every mutation keystroke / preset switch.
   - Live 14-rule ledger showing exact failing rule(s) and detail strings directly from engine report.
4. **Inspect Existing Code & Tests**:
   - `e2e/tier1-features/f11_tamper_sandbox.spec.ts`
   - `e2e/tier1-features/f12_hash_toggle.spec.ts`
   - `e2e/tier1-features/f13_failure_feedback.spec.ts`
   - `e2e/tier2-boundary/f11_tamper_boundary.spec.ts`
   - `e2e/tier2-boundary/f12_hash_toggle_boundary.spec.ts`
   - `e2e/tier2-boundary/f13_failure_boundary.spec.ts`
   - `e2e/tier3-combinations/pipeline2_tamper_recompute_ledger.spec.ts`
   - `e2e/tier4-scenarios/scenario2_tamper_incident_response.spec.ts`
   - `aip-console/src/components/ingestion/VerificationLedger.tsx`
   - `aip-console/src/lib/wasm/useAipVerifier.tsx`
   - `aip-console/public/wasm/aip_wasm.d.ts`

## Output
Write comprehensive handoff report to:
`.agents/teamwork/m4_explorer_1/handoff.md`


## 2026-11-02T13:53:46Z
From: 675111aa-04e8-493f-9811-dbfc1935a77b (orchestrator)
Content:
You are M4 Explorer 1 (Tamper Simulator & Attack Vectors Specialist).
Your working directory is:
c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_explorer_1\

You MUST read the following authoritative files before starting your investigation:
- c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\ORIGINAL_REQUEST.md
- c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\PROJECT.md
- c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\TEST_INFRA.md
- c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_explorer_1\DISPATCH.md

Investigate the technical implementation requirements for:
1. Feature F11 (Adversarial Field Mutation Engine): 14 attack vector presets mapped to the 14 engine verification rules, manual field tampering controls, and JSON payload editing.
2. Feature F12 (Smart Hash Recalculation Toggle): WASM hash recomputation via `recompute_packet_hash` / `get_canonical_bytes_hex`, proving the cryptographic reality (fixes CANONICAL_HASH, breaks AGENT_SIGNATURE), and JSON diff visualization.
3. Feature F13 (Instant Rule Failure Feedback): Live ledger updates calling WASM `verify_evidence_packet` with exact failure details.
4. E2E test assertions in `e2e/tier1-features/f11_tamper_sandbox.spec.ts`, `f12_hash_toggle.spec.ts`, `f13_failure_feedback.spec.ts`, and corresponding tier 2, 3, 4 specs.

Produce an actionable architecture blueprint in:
c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_explorer_1\handoff.md
Follow the standard Handoff Protocol (Observation, Logic Chain, Caveats, Conclusion, Verification Method).
When complete, notify the orchestrator with send_message.
