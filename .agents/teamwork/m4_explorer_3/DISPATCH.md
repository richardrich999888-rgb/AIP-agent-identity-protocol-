# Dispatch: M4 Explorer 3 (Cascade Revocation Tree & Tab/Route Integration Specialist)

## Mission
Investigate and design the complete technical architecture for Feature F16 and Console Navigation Integration:
1. **Feature F16 — Cascade Revocation Tree**:
   - Interactive tree visualization of delegated tokens:
     - Root Authority Token -> Delegated Intermediate Tokens -> Leaf Agent Tokens.
     - Token status badges (`VALID`, `EXPIRED`, `REVOKED`, `CASCADE_REVOKED`).
   - Interactive revocation trigger:
     - Ability to click any node to revoke it.
     - Live cascade calculation: revoking an intermediate token immediately invalidates its entire downstream subtree.
     - Visual styling: revoked subtree nodes turn crimson `#FF1744` with revocation icons and strike-throughs.
     - Revocation Impact Summary Card: displays total revoked tokens, affected downstream agents, and disrupted delegations.
     - Integration with verification context: revoked token list passed into WASM verification context `{"revoked_token_ids": [...]}` to verify engine detects `REVOCATION` failure.
2. **Console Navigation & Routing Integration**:
   - Tab 3 ("Tamper Sandbox") in `aip-console/src/app/page.tsx` and dedicated page `/tamper`.
   - Tab 4 ("Authority & Revocation") in `aip-console/src/app/page.tsx` and dedicated page `/authority`.
   - State synchronization: loaded packet in `EvidenceContext` seamlessly available to Tamper Sandbox and Authority view.
3. **Inspect Existing Code & Tests**:
   - `e2e/tier1-features/f16_revocation_tree.spec.ts`
   - `e2e/tier2-boundary/f16_revocation_boundary.spec.ts`
   - `e2e/tier3-combinations/pipeline3_authority_lattice_revoke.spec.ts`
   - `e2e/tier4-scenarios/scenario3_authority_delegation_audit.spec.ts`
   - `aip-console/src/app/page.tsx`
   - `aip-console/src/app/tamper/page.tsx`
   - `aip-console/src/app/authority/page.tsx`
   - `aip-console/src/context/EvidenceContext.tsx`

## Output
Write comprehensive handoff report to:
`.agents/teamwork/m4_explorer_3/handoff.md`
