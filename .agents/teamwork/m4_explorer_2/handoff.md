# Architectural Blueprint: Visual Scope Matrix Editor (F14) & Capability Lattice Attenuation Preview (F15)

**Author:** M4 Explorer 2 (Visual Scope Matrix & Lattice Attenuation Specialist)  
**Milestone:** M4 (Authority Management & Visual Lattice Builder)  
**Requirement Reference:** R4 (`ORIGINAL_REQUEST.md`), F14, F15 (`PROJECT.md`), `TEST_INFRA.md`  
**Date:** 2026-11-02  

---

## 1. Executive Summary

Feature F14 (**Visual Scope Matrix Editor**) and Feature F15 (**Capability Lattice Attenuation Preview**) provide the core cryptographic capability modeling and attenuation simulation UI for the AIP Enterprise Accountability Console.

In accordance with AIP Novel Mechanism NM-A1 (Capability Lattice Algebra) and zero-JS verification principles:
1. **F14 (Scope Matrix Editor)** enables visual authoring, inspection, and manipulation of `CapabilityScope` structures containing standard actions (`Read`, `Write`, `Delete`, `Admin`, `Execute`, `Delegate`), custom enterprise action verbs (e.g. `loan:approve`, `ledger/treasury:transfer-wire_v2`), constraint key-value policies, and resource path patterns with built-in presets (`ADMIN`, `ORCHESTRATOR`, `AUDITOR`/`AUDIT_READER`, `WORKER`/`SUBMITTER`, `READ_ONLY`).
2. **F15 (Lattice Attenuation Preview)** calculates the mathematical meet operator ($\sqcap$) between a Parent Grantor Scope and a Child Grantee Scope via WebAssembly bindings (`meet_capability_scopes` and `check_scope_permits`), visually identifies stripped actions, warns on scope escalation attempts, and prominently flags bottom ($\bot$ / empty intersection) conflicts where delegation would result in zero privileges.

This report establishes the complete, production-grade architecture blueprint, data schemas, normalization adapters, UI component hierarchy, and verification procedures for implementation in `aip-console/src/components/authority/`.

---

## 2. Component 1: Observation

### 2.1 E2E Test Suite Ground Truth
Direct observation of the automated test specifications across Tier 1, Tier 2, and Tier 3 confirms the normative behavior required for F14 and F15:

| Test File | Test Case | Line | Direct Observation / Test Assertion |
|---|---|---|---|
| `e2e/tier1-features/f14_scope_matrix.spec.ts` | F14.1 | 7–12 | `STANDARD_SCOPES` must export `ADMIN`, `ORCHESTRATOR`, `AUDIT_READER`, `SUBMITTER`. |
| `e2e/tier1-features/f14_scope_matrix.spec.ts` | F14.2 | 14–19 | `SUBMITTER` scope allows `Write` (true), but denies `Admin` (false) and `Delete` (false). |
| `e2e/tier1-features/f14_scope_matrix.spec.ts` | F14.3 | 21–25 | `AUDIT_READER` scope allows `Read` (true) and denies `Write` (false). |
| `e2e/tier1-features/f14_scope_matrix.spec.ts` | F14.4 | 27–34 | Custom enterprise action verbs in scope: `{ kind: "Custom", name: "wire:transfer" }` permits `wire:transfer`, rejects `wire:reversal`. |
| `e2e/tier1-features/f14_scope_matrix.spec.ts` | F14.5 | 36–47 | Dynamic mutation in editor: adding `Write` to allowed makes it permitted; filtering out `Read` makes it unpermitted. |
| `e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts` | F14.B1 | 6–13 | Explicit deny takes absolute precedence over allowed list for same action (`allowed: [Write]`, `denied: [Write]` $\to$ `permits = false`). |
| `e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts` | F14.B2 | 15–22 | Empty allowed array (`allowed: []`, `denied: []`) yields zero permitted actions for any verb. |
| `e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts` | F14.B3 | 24–31 | Custom action names with slashes, colons, hyphens supported (`ledger/treasury:transfer-wire_v2`). |
| `e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts` | F14.B4 | 33–40 | Strict case sensitivity on action verbs: `loan:approve` does not permit `LOAN:APPROVE` or `Loan:Approve`. |
| `e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts` | F14.B5 | 42–50 | `Admin` standard action grants all standard verbs (`Read`, `Write`, `Execute`, `Delegate`) when not explicitly denied, but respects explicit deny (`denied: [Delete]` $\to$ `Delete` is false). |
| `e2e/tier1-features/f15_lattice_preview.spec.ts` | F15.1 | 6–13 | Meet ($\sqcap$) between `ADMIN` and `ORCHESTRATOR` yields 4 allowed actions (`Read`, `Write`, `Execute`, `Delegate`) and denied `Admin`. |
| `e2e/tier1-features/f15_lattice_preview.spec.ts` | F15.2 | 15–20 | Meet between `AUDIT_READER` (Read) and `SUBMITTER` (Write) yields `null` (Bottom $\bot$ / empty intersection). |
| `e2e/tier1-features/f15_lattice_preview.spec.ts` | F15.3 | 22–26 | `isScopeSubset(ADMIN, AUDIT_READER)` evaluates to `true`. |
| `e2e/tier1-features/f15_lattice_preview.spec.ts` | F15.4 | 28–32 | `isScopeSubset(SUBMITTER, ADMIN)` evaluates to `false` (prevents scope expansion). |
| `e2e/tier1-features/f15_lattice_preview.spec.ts` | F15.5 | 34–48 | Denied sets union monotonically across successive attenuation levels ($P_1.\text{denied} \cup P_2.\text{denied}$). |
| `e2e/tier2-boundary/f15_lattice_boundary.spec.ts` | F15.B1 | 6–12 | Idempotence property: $S \sqcap S = S$ holds strictly. |
| `e2e/tier2-boundary/f15_lattice_boundary.spec.ts` | F15.B2 | 14–19 | Identity element: $ADMIN \sqcap S = S$ holds for any subset $S$. |
| `e2e/tier2-boundary/f15_lattice_boundary.spec.ts` | F15.B3 | 21–32 | Disjoint custom scopes (`action:a` $\sqcap$ `action:b`) produce bottom ($\bot$). |
| `e2e/tier2-boundary/f15_lattice_boundary.spec.ts` | F15.B4 | 34–46 | Associativity property: $(A \sqcap B) \sqcap C = A \sqcap (B \sqcap C)$. |
| `e2e/tier2-boundary/f15_lattice_boundary.spec.ts` | F15.B5 | 48–61 | Commutativity on allowed intersection: $\text{Allowed}(A \sqcap B) == \text{Allowed}(B \sqcap A)$. |
| `e2e/tier3-combinations/pipeline3_matrix_lattice_revoke.spec.ts` | P3.1, P3.4 | 8–30, 66–72 | Custom action matrix configuration attenuates via meet operator; empty intersection ($\bot$) prevents invalid delegation creation. |

### 2.2 WebAssembly Core Engine Interface (`aip-wasm`)
Direct observation of the compiled WASM bindings (`aip-standalone/aip-wasm/src/lib.rs` and `public/wasm/aip_wasm.js`):
1. **`meet_capability_scopes(parent_json: &str, child_json: &str) -> Result<String, JsValue>`**:
   - Defined at `aip-standalone/aip-wasm/src/lib.rs:187`.
   - Executes `aip_core::capability::scope_intersection(&parent, &child)`.
   - Returns a serialized JSON object:
     ```json
     {
       "allowed": [
         { "Standard": "Read" },
         { "Custom": "wire:transfer" }
       ],
       "denied": [
         { "Standard": "Admin" }
       ],
       "is_bottom": false
     }
     ```
   - When intersection is empty, returns:
     ```json
     {
       "allowed": [],
       "denied": [ ... ],
       "is_bottom": true
     }
     ```
2. **`check_scope_permits(scope_json: &str, action_json: &str) -> Result<bool, JsValue>`**:
   - Defined at `aip-standalone/aip-wasm/src/lib.rs:176`.
   - Uses `parse_scope_loose` and `parse_action_loose`.
   - Returns boolean `true` if permitted (in `allowed` and not in `denied`), `false` otherwise.
3. **`useAipVerifier.tsx` React Hook Integration**:
   - Located at `aip-console/src/lib/wasm/useAipVerifier.tsx:143–155`.
   - Exposes:
     - `checkScope(scopeJson: string, actionJson: string): boolean`
     - `meetScopes(parentJson: string, childJson: string): string`
     - `isReady: boolean`, `isLoading: boolean`, `error: string | null`.

### 2.3 Serialization Format Discrepancy & Loose Parsing
Empirical execution revealed a critical data representation nuance:
- `aip-types` in Rust serializes `ScopeAction` with externally-tagged enums:
  `{ "Standard": "Read" }` and `{ "Custom": "wire:transfer" }`.
- `parse_scope_loose` in `aip-standalone/aip-wasm/src/scope.rs` also parses plain string arrays:
  `["Read", "Write", "wire:transfer"]`.
- `e2e/support/types.ts` defines `ActionVerb` as:
  `{ kind: "Standard", action: "Read" }` or `{ kind: "Custom", name: "wire:transfer" }`.
- Direct empirical test: Passing `{ kind: "Custom", name: "wire:transfer" }` directly into `parse_scope_loose` fails serde deserialization in Rust because `#[serde(tag = "kind")]` is not present on `aip_types::ScopeAction`.
- **Finding:** A UI normalization adapter must serialize scopes into strings or Rust-tagged format before passing to WASM, and deserialize WASM outputs back into normalized UI `ActionVerb` objects.

---

## 3. Component 2: Logic Chain

### 3.1 Mapping User Requirements to Component Architecture
The prompt requires:
1. Feature F14 (Visual Scope Matrix Editor) with standard presets (`ADMIN`, `ORCHESTRATOR`, `AUDITOR`, `WORKER`, `READ_ONLY`), custom action list with allow/deny toggles, constraint key-value pairs, and resource patterns.
2. Feature F15 (Capability Lattice Attenuation Preview) with meet operator ($\sqcap$), WASM integration, $\bot$ bottom detection, and escalation warnings.

To achieve this cleanly within Next.js 15 / React 19:
```
aip-console/src/components/authority/
├── types.ts                        # Unified types for scopes, presets, constraints, meet results
├── scopeNormalization.ts           # Bidirectional normalization between UI, E2E, and WASM
├── presetScopes.ts                 # Authoritative presets (ADMIN, ORCHESTRATOR, AUDITOR, WORKER, READ_ONLY)
├── ScopeMatrixEditor.tsx           # Feature F14: Interactive permission matrix, custom actions, constraints
├── LatticeAttenuationPreview.tsx   # Feature F15: Dual-scope comparison, meet engine, Venn diagram, warnings
└── AuthorityManagement.tsx         # Tab 4 view container integrating F14, F15, and F16
```

### 3.2 Standard Presets Reconciliation
The Rust core protocol and E2E tests define 4 authoritative named scopes, while enterprise security requirements define role aliases and read-only observers:

```typescript
// aip-console/src/components/authority/presetScopes.ts

export const PRESET_SCOPES: Record<string, {
  name: string;
  roleId: "ADMIN" | "ORCHESTRATOR" | "AUDITOR" | "WORKER" | "READ_ONLY";
  protocolScope: "ADMIN" | "ORCHESTRATOR" | "AUDIT_READER" | "SUBMITTER" | "CUSTOM";
  description: string;
  scope: CapabilityScope;
}> = {
  ADMIN: {
    name: "System Administrator",
    roleId: "ADMIN",
    protocolScope: "ADMIN",
    description: "Full administrative access. Grants all standard verbs and token delegation.",
    scope: {
      allowed: [
        { kind: "Standard", action: "Read" },
        { kind: "Standard", action: "Write" },
        { kind: "Standard", action: "Delete" },
        { kind: "Standard", action: "Admin" },
        { kind: "Standard", action: "Execute" },
        { kind: "Standard", action: "Delegate" },
      ],
      denied: [],
    },
  },
  ORCHESTRATOR: {
    name: "Task Orchestrator",
    roleId: "ORCHESTRATOR",
    protocolScope: "ORCHESTRATOR",
    description: "Workflow coordination and sub-agent delegation. Explicitly denies Admin.",
    scope: {
      allowed: [
        { kind: "Standard", action: "Read" },
        { kind: "Standard", action: "Write" },
        { kind: "Standard", action: "Execute" },
        { kind: "Standard", action: "Delegate" },
      ],
      denied: [{ kind: "Standard", action: "Admin" }],
    },
  },
  AUDITOR: {
    name: "Compliance Auditor (AUDIT_READER)",
    roleId: "AUDITOR",
    protocolScope: "AUDIT_READER",
    description: "Read-only audit log inspection. Explicitly denies Write, Admin, Delete.",
    scope: {
      allowed: [{ kind: "Standard", action: "Read" }],
      denied: [
        { kind: "Standard", action: "Write" },
        { kind: "Standard", action: "Admin" },
        { kind: "Standard", action: "Delete" },
      ],
    },
  },
  WORKER: {
    name: "Worker Submitter (SUBMITTER)",
    roleId: "WORKER",
    protocolScope: "SUBMITTER",
    description: "Task submission and evidence generation. Allows Write, denies Admin and Delete.",
    scope: {
      allowed: [{ kind: "Standard", action: "Write" }],
      denied: [
        { kind: "Standard", action: "Admin" },
        { kind: "Standard", action: "Delete" },
      ],
    },
  },
  READ_ONLY: {
    name: "Read-Only Observer",
    roleId: "READ_ONLY",
    protocolScope: "CUSTOM",
    description: "Inspection and operational monitoring without state mutation or token delegation.",
    scope: {
      allowed: [
        { kind: "Standard", action: "Read" },
        { kind: "Standard", action: "Execute" },
      ],
      denied: [
        { kind: "Standard", action: "Write" },
        { kind: "Standard", action: "Delete" },
        { kind: "Standard", action: "Admin" },
        { kind: "Standard", action: "Delegate" },
      ],
    },
  },
};
```
*Note on Protocol Compatibility:* Selecting `AUDITOR` populates the exact scope for `STANDARD_SCOPES.AUDIT_READER`, and selecting `WORKER` populates `STANDARD_SCOPES.SUBMITTER`. This satisfies 100% of the prompt requirements while strictly conforming to `e2e/tier1-features/f14_scope_matrix.spec.ts`.

### 3.3 Scope Normalization & WASM Adapter (`scopeNormalization.ts`)
To bridge between TypeScript UI models and Rust WebAssembly without errors:

```typescript
// aip-console/src/components/authority/scopeNormalization.ts

import { ActionVerb, CapabilityScope, StandardActionName } from "./types";

export function actionToString(verb: ActionVerb): string {
  return verb.kind === "Standard" ? verb.action : verb.name;
}

export function stringToAction(str: string): ActionVerb {
  const standardActions: StandardActionName[] = ["Read", "Write", "Delete", "Admin", "Execute", "Delegate"];
  const match = standardActions.find((a) => a.toLowerCase() === str.trim().toLowerCase());
  if (match) {
    return { kind: "Standard", action: match };
  }
  return { kind: "Custom", name: str.trim() };
}

/**
 * Prepares a CapabilityScope for WASM functions (meet_capability_scopes, check_scope_permits).
 * Uses string representation strings which parse_scope_loose safely handles.
 */
export function scopeToWasmJson(scope: CapabilityScope): string {
  const allowedStrings = scope.allowed.map(actionToString);
  const deniedStrings = scope.denied.map(actionToString);
  return JSON.stringify({
    allowed: allowedStrings,
    denied: deniedStrings,
  });
}

/**
 * Parses WASM meet_capability_scopes JSON output back into normalized CapabilityScope.
 */
export function wasmJsonToMeetResult(jsonStr: string): {
  scope: CapabilityScope;
  isBottom: boolean;
} {
  const parsed = JSON.parse(jsonStr);
  const isBottom = Boolean(parsed.is_bottom || (Array.isArray(parsed.allowed) && parsed.allowed.length === 0));

  const allowed: ActionVerb[] = (parsed.allowed || []).map((item: any) => {
    if (typeof item === "string") return stringToAction(item);
    if (item.Standard) return { kind: "Standard", action: item.Standard };
    if (item.Custom) return { kind: "Custom", name: item.Custom };
    if (item.kind === "Standard") return item;
    if (item.kind === "Custom") return item;
    return stringToAction(String(item));
  });

  const denied: ActionVerb[] = (parsed.denied || []).map((item: any) => {
    if (typeof item === "string") return stringToAction(item);
    if (item.Standard) return { kind: "Standard", action: item.Standard };
    if (item.Custom) return { kind: "Custom", name: item.Custom };
    if (item.kind === "Standard") return item;
    if (item.kind === "Custom") return item;
    return stringToAction(String(item));
  });

  return {
    scope: { allowed, denied },
    isBottom,
  };
}
```

### 3.4 Feature F14: Visual Scope Matrix Editor Architecture

#### State Model
```typescript
export interface MatrixScopeState {
  allowed: ActionVerb[];
  denied: ActionVerb[];
  constraints: Record<string, string>;
  resource_patterns: string[];
  depth_remaining?: number;
}
```

#### Standard Actions Table
The 6 standard actions are permanently anchored:
1. `Read` (0x01) — Inspect packets, audit logs, and verified DAG state.
2. `Write` (0x02) — Submit evidence, generate decisions, attest operations.
3. `Delete` (0x03) — Invalidate or expunge stored evidence artifacts.
4. `Admin` (0x04) — Manage KMS credentials, revoke tokens, reconfigure trust anchors.
5. `Execute` (0x05) — Trigger autonomous AI tool execution and workflow operations.
6. `Delegate` (0x06) — Issue child tokens and transfer authority to downstream agents.

#### 3-State Toggle Semantics
For each action $A$:
- **ALLOW**: $A \in \text{allowed} \land A \notin \text{denied}$.
- **DENY**: $A \in \text{denied}$ (even if $A \in \text{allowed}$, explicit deny overrides allow per F14.B1).
- **UNSET**: $A \notin \text{allowed} \land A \notin \text{denied}$ (default closed).

#### Effective Status Badge Logic
```typescript
function getEffectiveActionStatus(action: ActionVerb, scope: CapabilityScope): {
  status: "ALLOWED" | "DENIED" | "INHERITED_ADMIN" | "PROHIBITED";
  label: string;
  badgeClass: string;
} {
  // 1. Explicit deny takes absolute priority (F14.B1)
  const isDenied = scope.denied.some((d) => verbEquals(d, action));
  if (isDenied) {
    return {
      status: "DENIED",
      label: "Explicitly Denied",
      badgeClass: "bg-cyber-red/10 text-cyber-red border-cyber-red/30",
    };
  }

  // 2. Direct allow check
  const isAllowed = scope.allowed.some((a) => verbEquals(a, action));
  if (isAllowed) {
    return {
      status: "ALLOWED",
      label: "Directly Allowed",
      badgeClass: "bg-cyber-green/10 text-cyber-green border-cyber-green/30",
    };
  }

  // 3. Admin inheritance for standard actions (F14.B5)
  const hasAdmin = scope.allowed.some((a) => a.kind === "Standard" && a.action === "Admin");
  if (hasAdmin && action.kind === "Standard") {
    return {
      status: "INHERITED_ADMIN",
      label: "Inherited from Admin",
      badgeClass: "bg-cyber-indigo/10 text-cyber-indigo border-cyber-indigo/30",
    };
  }

  // 4. Default closed (F14.B2)
  return {
    status: "PROHIBITED",
    label: "Prohibited (Default Closed)",
    badgeClass: "bg-slate-800 text-slate-400 border-obsidian-700",
  };
}
```

#### Custom Actions Management
- Input field accepting arbitrary strings up to 64 bytes.
- Regex validation: `^[a-zA-Z0-9_\-\:\.\/]+$` (enforces F14.B3 for slashes, colons, hyphens).
- Exact case preservation (enforces F14.B4: `loan:approve` is distinct from `LOAN:APPROVE`).
- Quick-add chip buttons for enterprise domains:
  - `loan:approve`
  - `credit:underwrite`
  - `wire:transfer`
  - `ledger/treasury:transfer-wire_v2`
  - `audit:export`

#### Security Constraints Key-Value Editor
- Key-value pair editor with Add, Edit, and Delete controls.
- Common security constraint presets:
  - `max_amount`: `"5000000"` (Acme Corp facility)
  - `currency`: `"USD"`
  - `environment`: `"production"`
  - `tenant_id`: `"acme-corp"`
  - `risk_score_max`: `"75"`

#### Resource Patterns Manager
- Glob patterns list restricting the scope to specific resources:
  - `treasury/transfers/*`
  - `vault:acme:**`
  - `ledger/accounts/us-east-*`
- Includes interactive Resource Path Tester: User enters `treasury/transfers/batch_99` and gets instant visual feedback: `MATCHED (Allowed)` or `UNMATCHED (Prohibited)`.

### 3.5 Feature F15: Capability Lattice Attenuation Preview Architecture

#### Dual Scope Comparison Interface
The UI provides two interactive scope panels:
- **Left Panel (Grantor / Parent Scope $P$):**
  - Source: Quick preset buttons (`ADMIN`, `ORCHESTRATOR`, `AUDITOR`, `WORKER`), "Load from Active Root Grant", or current F14 editor scope.
- **Right Panel (Grantee / Requested Child Scope $C$):**
  - Source: Quick preset buttons, "Load from Active Delegation Hop", or current F14 editor scope.
- **Center Controls:**
  - "Compute Meet ($\sqcap$)" trigger.
  - "Swap Parent/Child" toggle (for testing reverse monotonicity and escalation detection).

#### Mathematical Meet Calculation Engine
The meet operator executes:
$$\text{Allowed}(P \sqcap C) = C.\text{Allowed} \cap (P.\text{Allowed} \setminus P.\text{Denied})$$
$$\text{Denied}(P \sqcap C) = P.\text{Denied} \cup C.\text{Denied}$$

Special rule for Admin in Parent:
If `Admin` $\in P.\text{Allowed}$, then all standard actions not in $P.\text{Denied}$ are treated as in $P.\text{Allowed} \setminus P.\text{Denied}$.

#### Venn / Lattice Attenuation Diagram
The result divides into four distinct, visually badge-coded partitions:
1. **Retained by Parent (Muted Slate / Ghost):**
   $$P.\text{Allowed} \setminus \text{Allowed}(P \sqcap C)$$
   Actions the grantor possesses but chose not to delegate.
2. **Attenuated Grant ($P \sqcap C$) (Cyber Cyan / Emerald):**
   $$\text{Allowed}(P \sqcap C)$$
   Legitimate, verified capabilities granted to the sub-agent.
3. **Escalation Attempts (Strikethrough Cyber Red with Warning Icon):**
   $$C.\text{Allowed} \setminus (P.\text{Allowed} \setminus P.\text{Denied})$$
   Permissions requested by child that parent does not hold or explicitly denies. Attenuated away by the engine.
4. **Cumulative Denials (Amber / Crimson Outline):**
   $$P.\text{Denied} \cup C.\text{Denied}$$
   Monotonically accumulated explicit prohibitions.

#### Status Banners

##### 1. Bottom ($\bot$) Conflict Banner
Triggered when $\text{Allowed}(P \sqcap C) = \emptyset$ (F15.2, F15.B3):
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🚫 LATTICE BOTTOM CONFLICT (⊥): ZERO CAPABILITIES GRANTED                    │
│ Parent and Child capability scopes are disjoint or mutually contradictory.  │
│ The meet operator evaluates to bottom (⊥). A delegated agent with this scope│
│ cannot perform any action and will fail Rule 8 (SCOPE_AUTHORITY).           │
└─────────────────────────────────────────────────────────────────────────────┘
```

##### 2. Scope Escalation Warning Banner
Triggered when child requests ungranted actions (F15.4):
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ⚠️ SCOPE ESCALATION BLOCKED (NM-A1 ENFORCEMENT)                              │
│ Child requested permissions exceeding Parent authority:                     │
│ [ Admin, Delete ].                                                          │
│ In accordance with AIP Novel Mechanism NM-A1, these actions have been       │
│ stripped from the effective grant. Authority expansion is impossible.       │
└─────────────────────────────────────────────────────────────────────────────┘
```

##### 3. Valid Monotonic Attenuation Banner
Triggered when $C \subseteq P$ and $\text{Allowed}(P \sqcap C) \ne \emptyset$ (F15.3):
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ✓ VALID MONOTONIC ATTENUATION (C ⊆ P)                                       │
│ Requested child scope strictly attenuates parent authority. Monotonicity    │
│ invariant satisfied. Safe for cryptographic delegation token issuance.      │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Real-Time Permission Testing Sandbox
An interactive probe below the preview allows auditors to test arbitrary actions against the effective scope:
- User selects or types an action verb (e.g. `loan:approve` or standard `Write`).
- Calls WASM `check_scope_permits(effectiveScopeJson, actionJson)`.
- Displays:
  - Green Check `[PERMITTED]` or Red Cross `[PROHIBITED]`.
  - Explanatory rationale: "Directly permitted in effective scope", "Prohibited: stripped during delegation meet", or "Prohibited: blocked by cumulative denial".

---

## 4. Component 3: Caveats

1. **WASM Externally-Tagged Enum Serialization:**
   - In `aip-wasm`, `meet_capability_scopes` outputs serde externally-tagged objects (`{"Standard": "Read"}`) rather than `{ kind: "Standard", action: "Read" }`.
   - *Mitigation:* The `scopeNormalization.ts` module explicitly translates between the UI representation and WASM JSON formats, ensuring zero runtime parsing mismatch.
2. **Admin Inheritance vs Rust `scope.contains`:**
   - In `aip-core/src/capability.rs`, `contains` performs exact array lookup, while `scope_admin()` populates all 6 actions. In `reference_oracle.ts`, Admin implies all standard actions unless denied.
   - *Mitigation:* When creating the `ADMIN` preset in the UI, all 6 standard actions are explicitly marked allowed, ensuring identical behavior across both Rust engine and TypeScript oracle.
3. **Multi-Hop Chains vs Pairwise Meet:**
   - Feature F15 focuses on pairwise parent-child meet ($P \sqcap C$). However, enterprise delegation chains can reach depth 4 or more (`scenario2_delegation_chain.spec.ts`).
   - *Mitigation:* The component provides a "Chain Stepper" mode allowing iterative evaluation: $P \sqcap C_1 \sqcap C_2 \sqcap \dots \sqcap C_n$.
4. **Boundary with Explorer 3 (Cascade Revocation Tree):**
   - Explorer 3 owns Feature F16 (Cascade Revocation Tree) and overall Tab 4 route integration.
   - *Mitigation:* Clear component boundaries are maintained. F14 and F15 are exportable standalone components mounted inside `AuthorityManagement.tsx` alongside `CascadeRevocationTree.tsx`.

---

## 5. Component 4: Conclusion

The technical architecture for R4 Features F14 (Visual Scope Matrix Editor) and F15 (Capability Lattice Attenuation Preview) is fully defined and aligned with the cryptographic specifications.

### Key Deliverables Designed for Worker Implementation:
1. `aip-console/src/components/authority/types.ts`: TypeScript contracts for `ActionVerb`, `CapabilityScope`, `StandardScopePreset`, and `LatticeMeetResult`.
2. `aip-console/src/components/authority/presetScopes.ts`: Authoritative presets (`ADMIN`, `ORCHESTRATOR`, `AUDITOR`/`AUDIT_READER`, `WORKER`/`SUBMITTER`, `READ_ONLY`).
3. `aip-console/src/components/authority/scopeNormalization.ts`: Resilient normalization layer bridging UI, test oracles, and WebAssembly bindings.
4. `aip-console/src/components/authority/ScopeMatrixEditor.tsx`: High-assurance visual editor with 6 standard actions, custom enterprise action manager (regex validated, case-sensitive), security constraints key-value table, and resource patterns manager.
5. `aip-console/src/components/authority/LatticeAttenuationPreview.tsx`: Visual meet operator ($\sqcap$) calculator, dual-scope comparator, Venn/lattice diagram, scope escalation banner, bottom ($\bot$) conflict indicator, and live permission probe.
6. `aip-console/src/components/authority/AuthorityManagement.tsx`: Tab 4 top-level view orchestrating F14, F15, and F16 with seamless packet synchronization from `EvidenceContext`.

---

## 6. Component 5: Verification Method

The implementation can be independently verified against both automated E2E test suites and UI component checks:

### 6.1 Automated E2E Test Execution
Run the authoritative Vitest suites covering F14, F15, boundaries, and combinations:

```bash
# Verify Tier 1 Feature Coverage (10 tests)
npx vitest run e2e/tier1-features/f14_scope_matrix.spec.ts e2e/tier1-features/f15_lattice_preview.spec.ts

# Verify Tier 2 Boundary & Corner Cases (10 tests)
npx vitest run e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts e2e/tier2-boundary/f15_lattice_boundary.spec.ts

# Verify Tier 3 Cross-Feature Combination (Pipeline 3)
npx vitest run e2e/tier3-combinations/pipeline3_matrix_lattice_revoke.spec.ts
```

### 6.2 Expected Test Results
- `e2e/tier1-features/f14_scope_matrix.spec.ts`: 5/5 passed (presets, submitter, audit_reader, custom actions, dynamic add/remove).
- `e2e/tier1-features/f15_lattice_preview.spec.ts`: 5/5 passed (meet calculation, bottom detection, subset monotonicity, scope expansion rejection, denied union).
- `e2e/tier2-boundary/f14_scope_matrix_boundary.spec.ts`: 5/5 passed (explicit deny priority, empty allowed array, complex custom verbs with slashes/colons, case sensitivity, admin inheritance).
- `e2e/tier2-boundary/f15_lattice_boundary.spec.ts`: 5/5 passed (idempotence $S \sqcap S = S$, identity $ADMIN \sqcap S = S$, disjoint bottom $\bot$, associativity, commutativity).

### 6.3 UI Test IDs & Selector Verification Matrix
For automated UI and Playwright inspection:

| Element / Feature | `data-testid` | Expected Behavior |
|---|---|---|
| Scope Matrix Editor Container | `scope-matrix-editor` | Visible in Authority Tab |
| Preset Selectors | `preset-select-[ADMIN\|ORCHESTRATOR\|AUDITOR\|WORKER\|READ_ONLY]` | Updates matrix state to match preset |
| Standard Action Rows | `standard-action-row-[Read\|Write\|Delete\|Admin\|Execute\|Delegate]` | Shows action name, opcode, status |
| Allow/Deny Toggles | `toggle-allow-[action]`, `toggle-deny-[action]` | Toggles action state; updates status badge |
| Custom Action Input | `custom-action-input` | Accepts custom verbs, validates regex |
| Add Custom Action Button | `add-custom-action-btn` | Appends new custom verb |
| Custom Action Item | `custom-action-item-[name]` | Displays chip with Allow/Deny toggle |
| Constraints Key/Val Inputs | `constraint-key-input`, `constraint-val-input` | Adds key-value constraint pairs |
| Resource Pattern Input | `resource-pattern-input` | Adds glob pattern |
| Lattice Preview Container | `lattice-preview-container` | Displays dual panels and meet operator |
| Parent / Child Selectors | `parent-scope-selector`, `child-scope-selector` | Selects presets or loaded packet scopes |
| Escalation Warning Banner | `escalation-warning-banner` | Visible when child exceeds parent |
| Bottom Conflict Banner | `bottom-conflict-banner` | Visible when intersection is empty ($\bot$) |
| Valid Monotonic Banner | `valid-attenuation-banner` | Visible when $C \subseteq P$ and non-empty |
| Action Test Input / Button | `test-action-input`, `test-action-btn` | Queries `check_scope_permits` in WASM |
| Action Test Result Badge | `test-action-result` | Renders `PERMITTED` or `PROHIBITED` |

### 6.4 Invalidation Conditions
The conclusion is invalidated if:
1. `meet_capability_scopes` or `check_scope_permits` fail to execute in client browser WebAssembly environment.
2. Custom actions with special characters (`/`, `:`, `-`, `_`, `.`) fail regex validation or produce WASM parse errors.
3. Explicit deny does not take precedence over allow for the same action.
4. An empty intersection between disjoint scopes does not return $\bot$ (`is_bottom: true`).
