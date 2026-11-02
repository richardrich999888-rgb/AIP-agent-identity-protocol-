# Handoff Report: Feature F16 (Cascade Revocation Tree) & Tab/Route Integration

**Agent:** M4 Explorer 3 (Cascade Revocation Tree & Tab/Route Integration Specialist)  
**Working Directory:** `c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m4_explorer_3\`  
**Milestone:** M4 (Adversarial Tamper Simulator & Authority Lattice Builder)  
**Date:** 2026-11-02  

---

## 1. Observation

### 1.1 Specification & Requirement Contracts
1. **`ORIGINAL_REQUEST.md` (lines 21–23)**:
   > "### R4. Authority Management & Visual Lattice Builder
   > Provide a visual scope matrix editor, lattice attenuation preview, and cascade revocation tree. Allow inspection and construction of authority grants, delegation hops, and permission attenuation rules."
2. **`PROJECT.md` (lines 52–54, 128–138)**:
   - Feature **F14**: Visual Scope Matrix Editor (named scopes `ADMIN`, `ORCHESTRATOR`, custom actions).
   - Feature **F15**: Capability Lattice Attenuation Preview (meet operator $\sqcap$, $\bot$ warning).
   - Feature **F16**: Cascade Revocation Tree ("Interactive tree visualization of delegated tokens with recursive subtree revocation").
   - Code Layout specifies: `aip-console/src/components/authority/`: Scope matrix editor, lattice meet preview, revocation tree.
   - Code Layout specifies: `aip-console/src/components/tamper/`: Tamper sandbox, mutation sliders/inputs, diff viewer.
3. **`TEST_INFRA.md` (lines 120–124, 227)**:
   - Pipeline 3: Visual Scope Matrix $\to$ Lattice Meet Attenuation $\to$ Cascade Revocation.
   - "Rule 9 `REVOCATION`: Verifies neither root token JTI nor any delegation JTI exists in `context.revoked_jtis`."
   - Quality Gate 8.3: "Any mutation to sealed packets must assert both `overall_valid == false` and `tamper_evidence == true` (with the exception of configuration/revocation gaps)."

### 1.2 Existing E2E Test Suites & Verification Oracles
1. **`e2e/tier1-features/f16_revocation_tree.spec.ts` (lines 4–50)**:
   - Tree topology tested: Root (`token-root`) $\to$ Intermediate (`token-hop-1a`, `token-hop-1b`) $\to$ Leaves (`token-hop-2a`, `token-hop-2b`).
   - Assertion F16.1: Revoking primary token records primary reason `"Compromise"`, `revoked_by: "security-admin"`.
   - Assertion F16.2: Cascades revocation down child subtree with reason `"AdminRevocation"`.
   - Assertion F16.3: Leaves independent sibling branches unaffected (`token-hop-1b`, `token-hop-2b`, `token-root` not revoked).
   - Assertion F16.4: Root revocation invalidates entire tree (5 entries).
   - Assertion F16.5: All entries have `cascade: true` and `revoked_at > 0`.
2. **`e2e/tier2-boundary/f16_revocation_boundary.spec.ts` (lines 4–49)**:
   - Assertion F16.B1: Leaf revocation produces exactly 1 revocation entry (0 descendants).
   - Assertion F16.B2: Depth-4 chain traverses descendants in BFS order (`["hop-1-jti", "hop-2-jti", "hop-3-jti"]`).
   - Assertion F16.B3: Non-existent JTI terminates cleanly with 1 entry.
   - Assertion F16.B4: Wide tree (1 parent with 10 child tokens) cascades to all 10 children (11 total entries).
   - Assertion F16.B5: All entries retain timestamps within invocation (`now - 1000 <= revoked_at <= now + 1000`).
3. **`e2e/tier3-combinations/pipeline3_matrix_lattice_revoke.spec.ts` (lines 32–65)**:
   - Assertion P3.2: Intermediate hop revocation propagates cascade entries.
   - Assertion P3.3: Revoked token injected into context causes Rule 9 `REVOCATION` failure in engine:
     `revCheck.pass === false; revCheck.detail.includes("revoked tokens in chain: hop_1 (...)"); report.overall_valid === false;`
4. **`e2e/support/lattice_oracle.ts` (lines 101–146)**:
   - Pure algorithm for `computeCascadeRevocations(targetJti, delegationTree, revokedBy)`:
     - Push `targetJti` with reason `"Compromise"`, `cascade: true`.
     - Queue BFS; for each child with `parent_jti === current`, push with reason `"AdminRevocation"`, `cascade: true`.
5. **Vitest Execution Result**:
   `npx vitest run e2e/tier1-features/f16_revocation_tree.spec.ts e2e/tier2-boundary/f16_revocation_boundary.spec.ts e2e/tier3-combinations/pipeline3_matrix_lattice_revoke.spec.ts`
   **Result: 3 passed, 15 tests passed, 0 failures.**

### 1.3 Rust Verification Engine & WASM Context Contract
1. **`aip-standalone/aip-protocol/src/verification.rs` (lines 232–251)**:
   ```rust
   // ── R9 REVOCATION ─────────────────────────────────────────────────────
   let mut revoked: Vec<String> = vec![];
   if ctx.revoked_jtis.contains(&root.root_token.jti) {
       revoked.push(format!("root token {}", hex::encode(root.root_token.jti)));
   }
   for hop in &packet.delegation_chain {
       if ctx.revoked_jtis.contains(&hop.jti) {
           revoked.push(format!("delegation {}", hex::encode(hop.jti)));
       }
   }
   let revocation_ok = revoked.is_empty();
   e.record(
       rules::REVOCATION,
       revocation_ok,
       if revocation_ok {
           "no token in the authority chain is revoked".to_string()
       } else {
           format!("revoked tokens in chain: {}", revoked.join(", "))
       },
   );
   ```
2. **`aip-standalone/aip-protocol/src/verification_report.rs` (lines 7–8, 49–57)**:
   - Revocation failure marks packet `valid = false`, but NOT `tampered = true` (it is an administrative revocation, not an active cryptographic forge).
3. **`aip-standalone/aip-wasm/src/context.rs` (lines 5–17, 73–96)**:
   - Expects `revoked_jtis: Vec<serde_json::Value>` where each JTI is a 32-character hexadecimal string or 16-byte array.
   - To support both `revoked_jtis` and `revoked_token_ids` seamlessly, the UI context must serialize both keys:
     `{"revoked_jtis": [...], "revoked_token_ids": [...]}`.

### 1.4 App Routing & State Architecture Observations
1. **`aip-console/src/app/page.tsx` (lines 129–167)**:
   - Tab 3 ("tamper") is currently a placeholder (`<div className={activeTab === "tamper" ? "block" : "hidden"}>...</div>`).
   - Tab 4 ("authority") is currently a placeholder (`<div className={activeTab === "authority" ? "block" : "hidden"}>...</div>`).
2. **`aip-console/src/app/tamper/page.tsx` & `aip-console/src/app/authority/page.tsx`**:
   - Both pages use client-side redirect:
     ```typescript
     useEffect(() => { setActiveTab("tamper"|"authority"); router.replace("/"); }, [...]);
     ```
   - Matches the architecture of `/graph` and `/vault`. Ensures SPA tab state is retained without unmounting React components.
3. **`aip-console/src/lib/wasm/EvidenceContext.tsx` & `aip-console/src/lib/context/ConsoleContext.tsx`**:
   - `EvidenceContext` provides `evidence` (`packetJson`), `report`, `contextJson`, `loadPacket`, `updateContext`, `reverify`.
   - `ConsoleContext` exposes `loadedPacket` (`EvidencePacket | null`), `activeTab`, `setActiveTab`, `rawPacketJson`, `verificationReport`.
   - Currently, `aip-console/src/components/authority/` does not exist and must be created.

---

## 2. Logic Chain

1. **Hierarchy Extraction**:
   - The loaded `EvidencePacket` possesses a strict two-tier authority structure:
     `packet.root_authority.root_token` (Root Token, depth 0) $\to$ `packet.delegation_chain` (Array of `DelegationHop`s, depth 1..$N$) $\to$ `packet.agent.aip_id` (Acting Agent Subject).
   - In the absence of an ingested packet (or for testing arbitrary DAG topologies), a built-in topology selector must allow switching between:
     - `Active Packet` (derived directly from `EvidenceContext`)
     - `Enterprise Loan Approval` (Chief Risk Officer $\to$ Treasury VP $\to$ Acting Agent)
     - `Multi-Branch Organization` (Root $\to$ Hop 1a/1b $\to$ Hop 2a/2b)
     - `Wide Branching Tree` (1 Root $\to$ 10 child agents)
     - `Deep Delegation Chain` (4 Hops linear)

2. **Cascade Invalidation Semantics**:
   - When a node with identifier $T$ is revoked, all downstream nodes whose parent link traces back to $T$ must be revoked recursively.
   - The primary node receives `status: "REVOKED"` with reason `"Compromise"`.
   - All descendant nodes in its subtree receive `status: "CASCADE_REVOKED"` with reason `"AdminRevocation"`.
   - Independent sibling branches remain in `status: "VALID"`.
   - Expired tokens (`expires_at < Date.now()`) display `status: "EXPIRED"`.

3. **Visual Feedback Requirements**:
   - Revoked nodes (primary and cascaded) must visually change:
     - Crimson background tint: `bg-[#FF1744]/10`
     - Crimson border and glow: `border-[#FF1744] shadow-[0_0_12px_rgba(255,23,68,0.25)]`
     - Crimson badge: `bg-[#FF1744] text-white font-bold` (`REVOKED` or `CASCADE REVOKED`)
     - Revocation icon: `ShieldAlert` or `Ban`
     - Strikethrough on token identifier / grantee: `line-through decoration-[#FF1744] decoration-2`
     - Downstream connector branches turn crimson dashed lines (`stroke-[#FF1744] stroke-dasharray="4,4"`).

4. **Revocation Impact Summary Card**:
   - Must calculate and display in real time:
     - Total Revoked Tokens: count of all invalidated JTIs
     - Direct vs Cascaded breakdown (e.g. 1 direct, 2 cascaded)
     - Affected Downstream Agents: unique agent / grantee AIP-IDs disabled
     - Disrupted Delegations: count of broken links
     - Engine Security Rule: Rule 9 (`REVOCATION`) failure preview
     - Action buttons: "Apply to Verifier Context", "Reset Revocations", "Export Revocation Log (CRL JSON)".

5. **WASM Engine Synchronization**:
   - Applying revocations updates the active verifier context:
     ```json
     {
       "revoked_jtis": ["<hex_jti_1>", "<hex_jti_2>"],
       "revoked_token_ids": ["<hex_jti_1>", "<hex_jti_2>"]
     }
     ```
   - Calling `loadPacket(evidence.packetJson, evidence.fileName, contextJson)` re-runs the Rust engine.
   - Engine evaluates Rule 9 `REVOCATION` $\to$ fails with `"revoked tokens in chain: ..."`.
   - Engine recalculates Trust Floor: since `revocation_ok == false`, `authority_bound` becomes false, downgrading the derived Trust Floor to `AGENT_SIGNED` or `UNVERIFIED`.
   - If user navigates to Tab 1 (Ingestion & Ledger), the Verification Ledger immediately shows Rule 9 as failed and the Trust Floor badge reflects the downgrade.

6. **Tab and Route Integration**:
   - Tab 3 in `aip-console/src/app/page.tsx` must render `<TamperSandbox />`.
   - Tab 4 in `aip-console/src/app/page.tsx` must render `<AuthorityManagement />`.
   - Route `/tamper` sets `activeTab = "tamper"` and redirects to `/`.
   - Route `/authority` sets `activeTab = "authority"` and redirects to `/`.
   - All state is anchored in `EvidenceContext` and `ConsoleContext`, preventing component tearing and maintaining zero-loss state between tabs.

---

## 3. Caveats

1. **Rust Engine Context Key Alias**: In `aip-standalone/aip-wasm/src/context.rs`, `VerificationContextInput` deserializes `pub revoked_jtis: Vec<serde_json::Value>`. It does not currently contain `#[serde(alias = "revoked_token_ids")]`. Therefore, to guarantee 100% interoperability with both the existing compiled WASM binary and any future updates, the UI context MUST emit both keys:
   `{"revoked_jtis": [...], "revoked_token_ids": [...]}`.
2. **Revocation vs Tamper Evidence**: Per `aip-protocol/src/verification_report.rs` and `TEST_INFRA.md` section 8.3, token revocation marks the packet invalid (`valid = false`, `overall_valid = false`), but does NOT mark `tamper_evidence = true` because revocation is an operational key management lifecycle event, not a signature payload corruption.
3. **Single-Page Application Route Architecture**: `/tamper` and `/authority` use Next.js client redirect to `/` with tab activation. This is intentional and matches `/graph` and `/vault` to preserve WebAssembly memory and loaded file state.
4. **Mock vs Real Packet Ingestion**: When the console launches without a loaded file, the app pre-loads `honest_counterparty` (verified in `ConsolePage.tsx:38-44`). Thus, Tab 4 always has valid live token data to render on first view.

---

## 4. Conclusion & Actionable Implementation Architecture

### 4.1 Component Blueprint

We specify four new components in `aip-console/src/components/authority/`:

```
aip-console/src/components/authority/
├── types.ts                     # Token node, status, impact, and CRL types
├── revocationCascade.ts         # Pure BFS cascade algorithm, impact metrics, and tree builder
├── CascadeRevocationTree.tsx    # Interactive tree visualization with crimson styling
├── RevocationImpactSummary.tsx  # Impact summary card with metrics & verifier context sync
└── AuthorityManagement.tsx      # Tab 4 view container combining F14, F15, and F16
```

#### Detailed Specification of `revocationCascade.ts`
```typescript
import { CapabilityScope } from "@/lib/types";

export type TokenStatus = "VALID" | "EXPIRED" | "REVOKED" | "CASCADE_REVOKED";

export interface DelegationTreeNode {
  jti: string;
  parent_jti?: string;
  type: "root" | "intermediate" | "leaf";
  depth: number;
  issuer_id: string;
  grantee_id: string;
  role: string;
  scope?: CapabilityScope;
  issued_at: number;
  expires_at?: number | null;
  status: TokenStatus;
  revocationReason?: string;
  revoked_at?: number;
  revoked_by?: string;
  children?: DelegationTreeNode[];
}

export interface RevocationEntry {
  jti: string;
  revoked_at: number;
  reason: "Compromise" | "AdminRevocation" | "KeyRotation" | "Expired";
  cascade: boolean;
  revoked_by: string;
}

export interface RevocationImpact {
  totalRevoked: number;
  primaryRevocations: number;
  cascadedRevocations: number;
  affectedAgents: string[];
  brokenDelegations: number;
  maxCascadeDepth: number;
}

/**
 * Pure BFS cascade revocation traversal matching e2e/support/lattice_oracle.ts
 */
export function computeCascadeRevocations(
  targetJti: string,
  tree: { jti: string; parent_jti?: string }[],
  revokedBy: string = "security-admin",
  primaryReason: "Compromise" | "AdminRevocation" | "KeyRotation" | "Expired" = "Compromise"
): RevocationEntry[] {
  const result: RevocationEntry[] = [];
  const queue: string[] = [targetJti];

  // Primary revocation
  result.push({
    jti: targetJti,
    revoked_at: Date.now(),
    reason: primaryReason,
    cascade: true,
    revoked_by: revokedBy,
  });

  while (queue.length > 0) {
    const current = queue.shift()!;
    const children = tree.filter((node) => node.parent_jti === current);
    for (const child of children) {
      result.push({
        jti: child.jti,
        revoked_at: Date.now(),
        reason: "AdminRevocation",
        cascade: true,
        revoked_by: revokedBy,
      });
      queue.push(child.jti);
    }
  }

  return result;
}

/**
 * Extracts flat tree nodes from EvidencePacket
 */
export function extractDelegationTree(packet: any): DelegationTreeNode[] {
  if (!packet) return [];
  const nodes: DelegationTreeNode[] = [];

  if (packet.root_authority?.root_token) {
    const root = packet.root_authority.root_token;
    nodes.push({
      jti: root.jti,
      parent_jti: undefined,
      type: "root",
      depth: 0,
      issuer_id: packet.root_authority.principal_id,
      grantee_id: root.agent_id,
      role: packet.root_authority.display_role || "Chief Risk Officer",
      scope: root.scope,
      issued_at: root.issued_at,
      expires_at: root.expires_at,
      status: "VALID",
    });
  }

  if (Array.isArray(packet.delegation_chain)) {
    packet.delegation_chain.forEach((hop: any, idx: number) => {
      const isLeaf = idx === packet.delegation_chain.length - 1;
      nodes.push({
        jti: hop.jti,
        parent_jti: hop.parent_jti,
        type: isLeaf ? "leaf" : "intermediate",
        depth: hop.depth,
        issuer_id: hop.issuer_id,
        grantee_id: hop.grantee_id,
        role: isLeaf ? `Acting Autonomous Agent` : `Intermediate Delegate (Hop ${hop.depth})`,
        scope: hop.scope,
        issued_at: hop.issued_at,
        expires_at: hop.expires_at,
        status: "VALID",
      });
    });
  }

  return nodes;
}
```

#### Detailed Specification of `CascadeRevocationTree.tsx`
- **Node Cards**:
  - Container: `p-4 rounded-xl border transition-all duration-200`
  - Normal: `bg-obsidian-900 border-obsidian-700 hover:border-slate-600`
  - Revoked: `bg-cyber-red/10 border-cyber-red shadow-[0_0_15px_rgba(255,23,68,0.3)] animate-fadeIn`
  - Expired: `bg-cyber-amber/10 border-cyber-amber/50`
  - Node Title:
    - Normal: `text-sm font-bold text-slate-100 font-mono`
    - Revoked: `text-sm font-bold text-slate-400 font-mono line-through decoration-cyber-red decoration-2`
  - JTI Token Identifier:
    - Monospace font `text-xs text-cyber-cyan truncate font-mono`
    - If revoked: `line-through decoration-cyber-red text-slate-500`
  - Status Badges:
    - `VALID`: `bg-cyber-green/15 text-cyber-green border border-cyber-green/40`
    - `EXPIRED`: `bg-cyber-amber/15 text-cyber-amber border border-cyber-amber/40`
    - `REVOKED`: `bg-cyber-red text-obsidian-950 font-bold border border-cyber-red`
    - `CASCADE_REVOKED`: `bg-cyber-red/20 text-cyber-red border border-cyber-red/50`
  - Interactive Revocation Button:
    - Button: "Revoke Token" (`text-xs font-mono px-3 py-1 rounded bg-obsidian-800 hover:bg-cyber-red hover:text-white border border-obsidian-700 transition-colors`)
    - When active, clicking invokes `onRevoke(node.jti)`.
    - Revoked nodes show "Restore Token" or "Revoked (Compromise)".
- **Tree Branch Connectors**:
  - Rendered with hierarchical indentation and SVG connector lines:
    - Active edge: `stroke-cyber-cyan/50 stroke-1`
    - Revoked edge: `stroke-cyber-red stroke-2 stroke-dasharray="4,4" animate-pulse`

#### Detailed Specification of `RevocationImpactSummary.tsx`
- **Metrics Grid**:
  1. *Invalidated Tokens*: `revocations.length` (crimson counter with `ShieldAlert`)
  2. *Compromise Origins*: count of primary revocations
  3. *Downstream Cascades*: count of child invalidations
  4. *Cut-off Agents*: count of affected grantee IDs
  5. *Broken Delegations*: count of interrupted parent-child links
- **Revocation CRL Log Table**:
  - Columns: Timestamp, JTI (32 hex), Reason (`Compromise` vs `AdminRevocation`), Cascade Flag (`true`), Revoking Authority (`security-admin`).
- **Synchronize to Engine Action**:
  - `Apply Revocations to Verifier`:
    ```typescript
    const updatedRevokedJtis = Array.from(new Set([...currentJtis, ...revokedJtis]));
    const newContext = {
      ...currentContextObj,
      revoked_jtis: updatedRevokedJtis,
      revoked_token_ids: updatedRevokedJtis,
    };
    const ctxString = JSON.stringify(newContext, null, 2);
    updateContext(ctxString);
    loadPacket(evidence.packetJson, evidence.fileName, ctxString);
    ```

#### Detailed Specification of `AuthorityManagement.tsx`
Tab 4 top-level container component:
- Sub-Navigation / Segmented Bar:
  - Tab A: "Cascade Revocation Tree (F16)" (default)
  - Tab B: "Visual Scope Matrix (F14)"
  - Tab C: "Lattice Attenuation Preview (F15)"
  - Tab D: "Unified Authority Dashboard"
- Integrates `CascadeRevocationTree`, `RevocationImpactSummary`, `ScopeMatrixEditor` (F14), and `LatticeAttenuationPreview` (F15).
- Directly binds to `ConsoleContext` (`loadedPacket`) and `EvidenceContext`.

### 4.2 Tab & Route Wiring in `src/app/page.tsx`

```tsx
// Before (Lines 129-167 of aip-console/src/app/page.tsx):
{/* Tab 3 (R3): Adversarial Tamper Simulator Placeholder View */}
<div className={activeTab === "tamper" ? "block" : "hidden"}>
  <div className="cyber-panel p-8 text-center min-h-[480px] flex flex-col items-center justify-center">
    ...placeholder...
  </div>
</div>

{/* Tab 4 (R4): Authority Management & Visual Lattice Builder Placeholder View */}
<div className={activeTab === "authority" ? "block" : "hidden"}>
  <div className="cyber-panel p-8 text-center min-h-[480px] flex flex-col items-center justify-center">
    ...placeholder...
  </div>
</div>

// After (Drop-in replacement in aip-console/src/app/page.tsx):
{/* Tab 3 (R3): Adversarial Tamper Simulator */}
<div className={activeTab === "tamper" ? "block space-y-4" : "hidden"}>
  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-obsidian-700">
    <div>
      <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2 font-mono">
        <ShieldAlert className="w-5 h-5 text-cyber-red" />
        Adversarial Tamper Simulator (R3)
      </h1>
      <p className="text-xs text-slate-400 mt-1 font-mono">
        Field mutation sandbox demonstrating cryptographic tamper detection across 14 attack vectors with smart hash recalculation toggling.
      </p>
    </div>
  </div>
  <TamperSandbox />
</div>

{/* Tab 4 (R4): Authority Management & Visual Lattice Builder */}
<div className={activeTab === "authority" ? "block space-y-4" : "hidden"}>
  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-obsidian-700">
    <div>
      <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2 font-mono">
        <Layers className="w-5 h-5 text-cyber-indigo" />
        Authority Management & Visual Lattice Builder (R4)
      </h1>
      <p className="text-xs text-slate-400 mt-1 font-mono">
        Visual scope matrix editor, capability meet operator preview (⊓), and cascade revocation tree with recursive subtree invalidation.
      </p>
    </div>
  </div>
  <AuthorityManagement />
</div>
```

---

## 5. Verification Method

### 5.1 Automated Test Execution Commands
The worker agent can independently verify this architecture and all implementation targets using the following exact commands:

1. **Verify Cascade Revocation Tree Feature Coverage (F16.1 to F16.5)**:
   ```bash
   npx vitest run e2e/tier1-features/f16_revocation_tree.spec.ts
   ```
   *Expected:* 5/5 passed.

2. **Verify Cascade Revocation Tree Boundaries (F16.B1 to F16.B5)**:
   ```bash
   npx vitest run e2e/tier2-boundary/f16_revocation_boundary.spec.ts
   ```
   *Expected:* 5/5 passed.

3. **Verify Pipeline 3 Combination (Scope Matrix $\to$ Lattice Meet $\to$ Cascade Revocation)**:
   ```bash
   npx vitest run e2e/tier3-combinations/pipeline3_matrix_lattice_revoke.spec.ts
   ```
   *Expected:* 5/5 passed.

4. **Verify Tier 4 Delegation Chain & Loan Lifecycle Scenarios**:
   ```bash
   npx vitest run e2e/tier4-scenarios/scenario1_enterprise_loan.spec.ts e2e/tier4-scenarios/scenario2_delegation_chain.spec.ts
   ```
   *Expected:* 10/10 passed.

5. **Verify Full Next.js 15 TypeScript Build in `aip-console`**:
   ```bash
   npm --prefix aip-console run lint
   ```
   *Expected:* 0 errors (`tsc --noEmit` exits with code 0).

6. **Verify Console Route Existence**:
   ```bash
   npx vitest run e2e/tier1-features/f03_app_shell.spec.ts
   ```
   *Expected:* 5/5 passed (`/`, `/graph`, `/tamper`, `/authority`, `/vault` all present).

### 5.2 Files to Inspect
- `aip-console/src/components/authority/CascadeRevocationTree.tsx`
- `aip-console/src/components/authority/RevocationImpactSummary.tsx`
- `aip-console/src/components/authority/revocationCascade.ts`
- `aip-console/src/components/authority/AuthorityManagement.tsx`
- `aip-console/src/app/page.tsx` (Tabs 3 and 4)
- `aip-console/src/app/tamper/page.tsx` & `aip-console/src/app/authority/page.tsx`
- `aip-console/src/lib/wasm/EvidenceContext.tsx`

### 5.3 Invalidation Conditions
- Any revocation algorithm that revokes sibling branches or omits recursive children fails `f16_revocation_tree.spec.ts`.
- Any context update that does not serialize `revoked_jtis` in 16-byte hex fails Rule 9 in the Rust WASM verifier.
- Any UI verification logic implemented in TypeScript instead of calling WASM violates Requirement R1 and Acceptance Criterion AC1.
