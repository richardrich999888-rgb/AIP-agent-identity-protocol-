# Dispatch: Milestone 4 Implementation Worker

## Mission
Implement the complete Requirement R3 (Adversarial Tamper Simulator — Features F11, F12, F13) and Requirement R4 (Authority Management & Visual Lattice Builder — Features F14, F15, F16) in `aip-console/`.

## Authoritative Inputs to Read
1. `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\ORIGINAL_REQUEST.md`
2. `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\PROJECT.md`
3. `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\TEST_INFRA.md`
4. Architectural Blueprint 1 (Tamper Simulator): `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_explorer_1\handoff.md`
5. Architectural Blueprint 2 (Scope Matrix & Lattice Attenuation): `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_explorer_2\handoff.md`
6. Architectural Blueprint 3 (Cascade Revocation Tree & Route Integration): `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_explorer_3\handoff.md`

## Write Ownership
You exclusively own and may create/modify:
- `aip-console/src/components/tamper/*`
- `aip-console/src/components/authority/*`
- `aip-console/src/app/page.tsx` (Tabs 3 & 4)
- `aip-console/src/app/tamper/page.tsx`
- `aip-console/src/app/authority/page.tsx`

DO NOT modify files outside your write ownership without explicit orchestrator instruction.

## Implementation Tasks
### Part 1: Requirement R3 — Adversarial Tamper Simulator (`src/components/tamper/`)
- `attackPresets.ts`: Define 14 attack vector presets mapped 1:1 to the 14 engine verification rules.
- `SmartHashToggle.tsx`: Toggle button calling WASM `recompute_packet_hash` to prove cryptographic non-repudiation (fixes CANONICAL_HASH, breaks AGENT_SIGNATURE).
- `FieldTamperPanel.tsx`: Manual field mutation accordion/tabs for Decision, Agent, Authority, Actions, Timestamps, Trace, Receipt.
- `JsonPayloadEditor.tsx`: Raw JSON editor with format & syntax validation.
- `JsonDiffViewer.tsx` & `diffUtils.ts`: Line-by-line visual diff highlighting additions (+) in cyan/emerald and deletions (-) in crimson.
- `LiveTamperLedger.tsx`: Reactive ledger binding to WASM `verify_evidence_packet` with zero JS verification logic.
- `PresetSelector.tsx`: Category-filtered preset cards.
- `TamperSimulator.tsx`: Main container component with reset, export, and active preset indicators.

### Part 2: Requirement R4 — Authority Management & Lattice Builder (`src/components/authority/`)
- `types.ts`: TypeScript models for ActionVerb, CapabilityScope, StandardScopePreset, LatticeMeetResult, TokenStatus, DelegationTreeNode, RevocationImpact.
- `presetScopes.ts`: Presets for `ADMIN`, `ORCHESTRATOR`, `AUDITOR` (`AUDIT_READER`), `WORKER` (`SUBMITTER`), and `READ_ONLY`.
- `scopeNormalization.ts`: Bidirectional translation between UI models and WASM serde formats.
- `ScopeMatrixEditor.tsx`: 6 standard actions with 3-state Allow/Deny/Unset toggles and Admin inheritance; custom action manager (regex `^[a-zA-Z0-9_\-\:\.\/]+$`, case-sensitive); security constraints key-value editor; resource patterns manager with interactive path tester.
- `LatticeAttenuationPreview.tsx`: Dual-scope comparator, meet operator ($\sqcap$) preview via WASM `meet_capability_scopes`, 4-partition Venn/Lattice diagram, Escalation Warning banner, Bottom Conflict ($\bot$) banner, Valid Monotonic Attenuation banner, interactive permission probe calling WASM `check_scope_permits`.
- `revocationCascade.ts`: Pure BFS cascade invalidation algorithm and impact calculator matching `e2e/support/lattice_oracle.ts`.
- `CascadeRevocationTree.tsx`: Interactive tree visualization with crimson `#FF1744` styling, strikethroughs, and cascade markers.
- `RevocationImpactSummary.tsx`: Statistics card with verifier context synchronization (`revoked_jtis` and `revoked_token_ids`) triggering engine Rule 9 `REVOCATION` failure and Trust Floor downgrade.
- `AuthorityManagement.tsx`: Top-level view container with sub-tab navigation.

### Part 3: Console Integration
- Mount `<TamperSimulator />` in Tab 3 of `aip-console/src/app/page.tsx`.
- Mount `<AuthorityManagement />` in Tab 4 of `aip-console/src/app/page.tsx`.
- Connect to `EvidenceContext` and `ConsoleContext` for zero-loss packet synchronization.

## Verification Requirements
Before delivering `handoff.md`, you MUST execute and document:
1. `npm --prefix aip-console run lint` (0 TypeScript / lint errors)
2. `npm --prefix aip-console run build` (Next.js build passes cleanly, 8 static routes)
3. `npx vitest run e2e/tier1-features/f11_tamper_sandbox.spec.ts e2e/tier1-features/f12_hash_toggle.spec.ts e2e/tier1-features/f13_failure_feedback.spec.ts e2e/tier1-features/f14_scope_matrix.spec.ts e2e/tier1-features/f15_lattice_preview.spec.ts e2e/tier1-features/f16_revocation_tree.spec.ts`
4. `npx vitest run e2e/tier2-boundary/f11_tamper_boundary.spec.ts e2e/tier2-boundary/f12_hash_toggle_boundary.spec.ts e2e/tier2-boundary/f13_failure_boundary.spec.ts e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts e2e/tier2-boundary/f15_lattice_boundary.spec.ts e2e/tier2-boundary/f16_revocation_boundary.spec.ts`
5. `npx vitest run e2e/tier3-combinations/pipeline2_tamper_hash_ledger.spec.ts e2e/tier3-combinations/pipeline3_matrix_lattice_revoke.spec.ts`
6. `npx vitest run e2e/tier4-scenarios/scenario3_forensic_tamper.spec.ts e2e/tier4-scenarios/scenario1_enterprise_loan.spec.ts e2e/tier4-scenarios/scenario2_delegation_chain.spec.ts`
7. Entire test suite: `npm run test:e2e` (260/260 tests passing, 0 regressions).

## Output
Write completion report to:
`c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_worker\handoff.md`


## 2026-11-02T14:07:13Z
You are the Milestone 4 Implementation Worker (`m4_worker`).
Your working directory is:
c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_worker\

Implement:
1. Requirement R3 (Features F11, F12, F13): Adversarial Tamper Simulator with 14 attack vector presets mapped 1:1 to the 14 engine verification rules, smart hash recalculation toggle via WASM recompute_packet_hash, visual JSON diff viewer, and instant live feedback ledger with ZERO verification logic in JavaScript/TypeScript (delegating 100% to WASM verify_evidence_packet).
2. Requirement R4 (Features F14, F15, F16): Authority Management & Visual Lattice Builder with Visual Scope Matrix Editor (presets ADMIN, ORCHESTRATOR, AUDITOR/AUDIT_READER, WORKER/SUBMITTER, READ_ONLY; 6 standard actions with 3-state toggle and Admin inheritance; custom actions manager with regex and case sensitivity; constraints and resource patterns), Capability Lattice Attenuation Preview (meet operator ⊓ via WASM meet_capability_scopes, 4-partition diagram, Escalation Warning banner, Bottom Conflict ⊥ banner, Valid Monotonic banner, permission probe via WASM check_scope_permits), and Cascade Revocation Tree (delegation tree visualization, crimson #FF1744 styling, strikethroughs, pure BFS cascade invalidation matching lattice_oracle.ts, impact summary card, WASM context synchronization with revoked_jtis/revoked_token_ids).
3. Connect Tab 3 (<TamperSimulator />) and Tab 4 (<AuthorityManagement />) in aip-console/src/app/page.tsx and ensure seamless routing for /tamper and /authority.
