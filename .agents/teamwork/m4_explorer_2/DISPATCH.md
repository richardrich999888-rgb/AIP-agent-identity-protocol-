# Dispatch: M4 Explorer 2 (Visual Scope Matrix & Lattice Attenuation Specialist)

## Mission
Investigate and design the complete technical architecture for Requirement R4 (Authority Management & Visual Lattice Builder — Features F14, F15):
1. **Feature F14 — Visual Scope Matrix Editor**:
   - Scope model representing `CapabilityScope` (`allowed_actions: string[]`, `denied_actions: string[]`, `constraints: Record<string, string>`, `resource_patterns: string[]`).
   - Standard named scopes presets (`ADMIN`, `ORCHESTRATOR`, `AUDITOR`, `WORKER`, `READ_ONLY`).
   - Interactive matrix / CRUD for custom actions: add, remove, toggle allow/deny.
   - Resource path matching and constraint key-value editor.
2. **Feature F15 — Capability Lattice Attenuation Preview**:
   - Visual meet operator ($\sqcap$) preview between Parent Scope and Child Scope.
   - Integration with WASM exports: `meet_capability_scopes(parentJson, childJson)` and `check_scope_permits(scopeJson, actionJson)`.
   - Visual badges and Venn/Lattice diagram showing:
     - Parent Scope actions
     - Requested Child Scope actions
     - Attenuated Scope ($\text{Parent} \sqcap \text{Child}$)
     - Escalation Warning banner when child requested actions not in parent (attenuated away).
     - Bottom ($\bot$) conflict indicator when meet results in empty or mutually contradictory permissions.
3. **Inspect Existing Code & Tests**:
   - `e2e/tier1-features/f14_scope_matrix.spec.ts`
   - `e2e/tier1-features/f15_lattice_preview.spec.ts`
   - `e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts`
   - `e2e/tier2-boundary/f15_lattice_boundary.spec.ts`
   - `e2e/support/lattice_oracle.ts`
   - `aip-console/public/wasm/aip_wasm.d.ts`

## Output
Write comprehensive handoff report to:
`.agents/teamwork/m4_explorer_2/handoff.md`


## 2026-11-02T13:53:53Z
From: 675111aa-04e8-493f-9811-dbfc1935a77b
[Message] You are M4 Explorer 2 (Visual Scope Matrix & Lattice Attenuation Specialist).
Investigate the technical implementation requirements for:
1. Feature F14 (Visual Scope Matrix Editor)
2. Feature F15 (Capability Lattice Attenuation Preview)
3. E2E test assertions in e2e/tier1-features/f14_scope_matrix.spec.ts, f15_lattice_preview.spec.ts, e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts, f15_lattice_boundary.spec.ts, and e2e/support/lattice_oracle.ts.


## 2026-11-02T14:03:46Z
From: 675111aa-04e8-493f-9811-dbfc1935a77b
[Message] Context: Milestone 4 Investigation (Scope Matrix & Lattice Attenuation Specialist)
Content: Checking on your investigation progress for Features F14 (Visual Scope Matrix Editor) and F15 (Capability Lattice Attenuation Preview). M4 Explorer 1 and M4 Explorer 3 have completed their blueprints. What is your current status?
Action: Please provide an update or submit your handoff report when ready.
