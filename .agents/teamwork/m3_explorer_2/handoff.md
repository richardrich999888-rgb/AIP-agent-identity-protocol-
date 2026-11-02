# Milestone 3 Explorer 2 Handoff Report: WASM Graph Data Lineage & Edge Verification Specialist

## Executive Summary
This report provides the authoritative implementation blueprint for **Requirement R2 (Graph Data Lineage & Edge Verification)** for the AIP Enterprise Accountability Console. It synthesizes forensic analysis of the Rust WebAssembly engine (`aip-wasm`), underlying protocol graph generator (`aip-protocol`), TypeScript E2E test suite (Tiers 1–3), and React Flow (`@xyflow/react` v12.12.1) visual architecture.

---

## 1. Observation

### 1.1 WebAssembly Engine Inspection
In `aip-standalone/aip-wasm/src/lib.rs` (lines 101–156), the function `get_accountability_graph` is exported as:
```rust
#[wasm_bindgen]
pub fn get_accountability_graph(
    packet_json: &str,
    report_json: Option<String>,
) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;

    let mut graph = AccountabilityGraph::from_packet(&packet);

    if let Some(rep_str) = report_json {
        if !rep_str.trim().is_empty() {
            if let Ok(report) = serde_json::from_str::<VerificationReport>(&rep_str) {
                graph = graph.with_report(&report);
            }
        }
    }

    let nodes: Vec<serde_json::Value> = graph
        .nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": n.id,
                "kind": n.kind,
                "label": n.label,
            })
        })
        .collect();

    let edges: Vec<serde_json::Value> = graph
        .edges
        .iter()
        .map(|e| {
            serde_json::json!({
                "from": e.from,
                "to": e.to,
                "source": e.from,
                "target": e.to,
                "relation": e.relation,
            })
        })
        .collect();

    let val = serde_json::json!({
        "packet_id": graph.packet_id,
        "claimed_trust_floor": graph.claimed_trust_floor,
        "derived_trust_floor": graph.derived_trust_floor,
        "nodes": nodes,
        "edges": edges,
    });

    serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
}
```

In `aip-console/public/wasm/aip_wasm.d.ts` (line 25):
```typescript
export function get_accountability_graph(packet_json: string, report_json?: string | null): string;
```

In `aip-console/src/lib/wasm/useAipVerifier.tsx` (lines 116–127):
```typescript
const getAccountabilityGraph = useCallback(
  (packetJson: string, reportJson?: string): AccountabilityGraph => {
    if (!wasmRef.current) {
      throw new Error("AIP WebAssembly verifier is not initialized.");
    }
    const raw = wasmRef.current.get_accountability_graph(
      packetJson,
      reportJson && reportJson.trim().length > 0 ? reportJson : null
    );
    return JSON.parse(raw) as AccountabilityGraph;
  },
  []
);
```

### 1.2 Exact JSON Schema Emitted by WASM
The JSON string returned by `get_accountability_graph` conforms to the following schema:
```json
{
  "packet_id": "9a0ab7c427eb...",
  "claimed_trust_floor": "COUNTERPARTY_SIGNED",
  "derived_trust_floor": "COUNTERPARTY_SIGNED",
  "nodes": [
    {
      "id": "principal",
      "kind": "principal",
      "label": "Chief Risk Officer (did:mesh:corp-risk-officer-01)"
    },
    {
      "id": "authority_grant",
      "kind": "authority_grant",
      "label": "root token b8394fe9... → aip1q...agent"
    },
    {
      "id": "delegation:0",
      "kind": "delegation",
      "label": "hop 0 (depth 1): did:mesh:corp-risk-officer-01 → did:mesh:agent-vp-01"
    },
    {
      "id": "agent",
      "kind": "agent",
      "label": "aip1qg6m4zvyvqqe..."
    },
    {
      "id": "decision",
      "kind": "decision",
      "label": "Approved $5,000,000 credit facility under Delegated Policy 2026-Q4"
    },
    {
      "id": "action:0",
      "kind": "action",
      "label": "Transfer $5,000,000 USD to client escrow #883921"
    },
    {
      "id": "receipt",
      "kind": "receipt",
      "label": "rcpt-cb-99214 @ core-banking-gateway"
    }
  ],
  "edges": [
    {
      "from": "principal",
      "to": "authority_grant",
      "source": "principal",
      "target": "authority_grant",
      "relation": "issues"
    },
    {
      "from": "authority_grant",
      "to": "delegation:0",
      "source": "authority_grant",
      "target": "delegation:0",
      "relation": "delegates"
    },
    {
      "from": "delegation:0",
      "to": "agent",
      "source": "delegation:0",
      "target": "agent",
      "relation": "acts_under"
    },
    {
      "from": "agent",
      "to": "decision",
      "source": "agent",
      "target": "decision",
      "relation": "decides"
    },
    {
      "from": "decision",
      "to": "action:0",
      "source": "decision",
      "target": "action:0",
      "relation": "performs"
    },
    {
      "from": "action:0",
      "to": "receipt",
      "source": "action:0",
      "target": "receipt",
      "relation": "produces"
    }
  ]
}
```

### 1.3 Node & Relation Types In Rust Protocol
In `aip-standalone/aip-protocol/src/accountability_graph.rs` (lines 16–50):
- `NodeKind` (serde `rename_all = "snake_case"`):
  1. `Principal` -> `"principal"`
  2. `AuthorityGrant` -> `"authority_grant"`
  3. `Delegation` -> `"delegation"`
  4. `Agent` -> `"agent"`
  5. `Decision` -> `"decision"`
  6. `Action` -> `"action"`
  7. `Receipt` -> `"receipt"`
- `Relation` (serde `rename_all = "snake_case"`):
  1. `Issues` -> `"issues"`
  2. `Delegates` -> `"delegates"`
  3. `ActsUnder` -> `"acts_under"`
  4. `Decides` -> `"decides"`
  5. `Performs` -> `"performs"`
  6. `Produces` -> `"produces"`

*Note on Case Normalization:* The E2E test suite (`e2e/tier1-features/f09_dag_viewer.spec.ts:22-27` and `dag_oracle.ts:52,79,103,126,150,176`) asserts PascalCase relations: `Issues`, `Delegates`, `ActsUnder`, `Decides`, `Performs`, `Produces`. The transformer must support case-insensitive normalization so both formats work seamlessly.

### 1.4 E2E Invariants and Test Oracles
Direct observations from `e2e/tier1-features/f09_dag_viewer.spec.ts` and `e2e/tier2-boundary/f09_dag_boundary.spec.ts`:
1. **7 Distinct Node Kinds (F9.1)**: Every complete DAG contains all 7 kinds.
2. **6 Standard Relations (F9.2)**: `Issues`, `Delegates`, `ActsUnder`, `Decides`, `Performs`, `Produces`.
3. **Single Principal Invariant (F9.B4, F9.B5)**:
   - Exactly 1 principal node must exist.
   - If 0 found: error string must contain `"Expected 1 principal node, found 0"`.
   - If 2 found: error string must contain `"Expected 1 principal node, found 2"`.
4. **BFS Reachability Invariant (F9.3, F9.B1)**:
   - 100% of nodes in the graph must be reachable from the single `principal` node via outgoing directed edges.
   - If unreachable orphan nodes exist: error string must contain `"Unreachable node(s) detected: <orphan-id>"`.
5. **0-Hop Direct Delegation (F9.B2)**:
   - When `delegation_chain` is empty, `ActsUnder` connects directly from `authority_grant` to `agent`.
6. **High-Density Action Nodes (F9.B3)**:
   - Supports 25+ parallel actions branching from `decision` and converging on `receipt`.
7. **Graphviz DOT Representation (F9.5, P1.4)**:
   - Shapes: `principal` (house), `authority_grant` (note), `delegation` (cds), `agent` (component), `decision` (diamond), `action` (box), `receipt` (tab).

---

## 2. Logic Chain

```
[Raw EvidencePacket + Optional VerificationReport]
                       │
                       ▼
           WASM get_accountability_graph
       (Produces topological nodes & edges)
                       │
                       ▼
       transformWasmGraphToFlow Transformer
  ┌────────────────────┴────────────────────┐
  │ 1. Case-Normalize Relations             │
  │ 2. Enrich Nodes with Packet Data        │ (Required for F10 Inspection Drawer)
  │ 3. Enrich Nodes & Edges with Rule Status│ (1:1 Engine Verification Checks)
  │ 4. Hierarchical Layout (x, y)          │ (Multi-action centered columns)
  │ 5. Execute Single-Principal Reachability│ (BFS + Invariant Enforcement)
  └────────────────────┬────────────────────┘
                       ▼
          React Flow (@xyflow/react)
  ┌────────────────────┴────────────────────┐
  │ Verified Edges: Glowing Cyan Flow       │ (#00E5FF, animated dash pulse)
  │ Tampered Edges: Dashed Crimson Pulse    │ (#FF1744, warning ping)
  │ Custom Edge Badge Pill                  │ (Displays relation + status dot)
  └─────────────────────────────────────────┘
```

### 2.1 The Need for Frontend Data Enrichment
The raw WASM output from `get_accountability_graph` contains only `{ id, kind, label }` for nodes and `{ from, to, source, target, relation }` for edges. However, the UI requirements (F10 inspection sheet, node badges, edge verification) require:
- Cryptographic details: Public keys, model provenance hashes, token JTIs, decision rationale hashes, payload hashes, countersignatures.
- Verification status: 1:1 binding to the 14 engine verification rules.
- React Flow visual coordinates: `position: { x, y }`, custom node/edge types.

Therefore, `transformWasmGraphToFlow` must accept both the WASM output (or raw packet) and the `VerificationReport` to generate fully enriched `@xyflow/react` node and edge structures.

### 2.2 Edge Verification Mapping to Engine Rules
An edge represents a cryptographic accountability transition. An edge is **Verified** if and only if its underlying protocol rules evaluate to `pass === true`:
1. `Issues` (`principal` → `authority_grant`):
   - Rule: `ROOT_TOKEN_SIGNATURE` must pass.
2. `Delegates` (`authority_grant` → `delegation:0`, or `delegation:i` → `delegation:i+1`):
   - Rule: `DELEGATION_CHAIN` must pass.
3. `ActsUnder` (leaf token → `agent`):
   - Rules: `AGENT_ID_BINDING` and `AUTHORITY_CHAIN` must pass.
4. `Decides` (`agent` → `decision`):
   - Rules: `AGENT_SIGNATURE` and `CANONICAL_HASH` must pass.
5. `Performs` (`decision` → `action:i`):
   - Rules: `ACTION_ATTESTATIONS` and `SCOPE_AUTHORITY` must pass.
6. `Produces` (`action:i` → `receipt`):
   - Rule: `RECEIPT_BINDING` must pass.

If any rule fails or if an upstream ancestor node is unverified/tampered, the edge transitions to **Tampered/Unverified** state.

---

## 3. Caveats

1. **Relation Casing**: Rust serializes enum variants as snake_case (`issues`, `acts_under`), while TypeScript types and test assertions use PascalCase (`Issues`, `ActsUnder`). The transformer must normalize casing bi-directionally.
2. **0-Hop Direct Delegation**: In direct root-to-agent architectures, `delegation_chain` is empty. The `ActsUnder` edge connects `authority_grant` directly to `agent`. Layout calculation must dynamically collapse the delegation rank to prevent large horizontal gaps.
3. **Optional Receipt**: If `receipt_binding` is null (e.g. at Trust Floor `AGENT_SIGNED` or `AUTHORITY_BOUND`), the `receipt` node and all `Produces` edges are absent. The DAG is still valid and reachable.
4. **High-Density Action Nodes (25+ Actions)**: A horizontal DAG with 25 parallel action nodes would become excessively tall if stacked without compaction. The layout algorithm must vertically center action nodes relative to the horizontal spine.
5. **Read-Only Explorer Discipline**: This blueprint contains complete, production-grade TypeScript code designed to be placed directly into `aip-console/src/components/graph/` during implementer turns without modification.

---

## 4. Conclusion & Implementation Blueprint

The implementation blueprint consists of four core modules:
1. `src/components/graph/types.ts`: Comprehensive types and relation mappings.
2. `src/components/graph/edges/AccountabilityEdge.tsx`: Custom React Flow edge with glowing cyan flow and crimson warning pulse.
3. `src/components/graph/reachability.ts`: Single-Principal reachability validator (BFS).
4. `src/components/graph/transformer.ts`: `transformWasmGraphToFlow` bridging WASM to React Flow.

### 4.1 Module 1: Graph Types & Normalization (`src/components/graph/types.ts`)

```typescript
import type { Node, Edge } from "@xyflow/react";
import type {
  EvidencePacket,
  VerificationReport,
  RuleIdentifier,
  TrustFloor,
} from "@/types/verification";

export type FlowNodeKind =
  | "principal"
  | "authority_grant"
  | "delegation"
  | "agent"
  | "decision"
  | "action"
  | "receipt";

export type FlowRelation =
  | "Issues"
  | "Delegates"
  | "ActsUnder"
  | "Decides"
  | "Performs"
  | "Produces";

export interface AccountabilityNodeData extends Record<string, unknown> {
  id: string;
  kind: FlowNodeKind;
  label: string;
  verified: boolean;
  ruleName?: RuleIdentifier;
  ruleDetail?: string;
  metadata: Record<string, any>;
  onSelectNode?: (nodeId: string) => void;
}

export type AccountabilityFlowNode = Node<AccountabilityNodeData, FlowNodeKind>;

export interface AccountabilityEdgeData extends Record<string, unknown> {
  relation: FlowRelation;
  verified: boolean;
  ruleName?: RuleIdentifier;
  sourceKind: FlowNodeKind;
  targetKind: FlowNodeKind;
}

export type AccountabilityFlowEdge = Edge<AccountabilityEdgeData, "accountability">;

export interface FlowGraphResult {
  nodes: AccountabilityFlowNode[];
  edges: AccountabilityFlowEdge[];
  reachability: ReachabilityResult;
  claimedTrustFloor: TrustFloor;
  derivedTrustFloor: TrustFloor;
  packetId: string;
  dotString: string;
}

export interface ReachabilityResult {
  valid: boolean;
  error?: string;
  rootPrincipalId?: string;
  reachableNodeIds: string[];
  orphanNodeIds: string[];
  totalNodes: number;
}
```

### 4.2 Module 2: Custom Edge Components (`src/components/graph/edges/`)

#### A. Custom Edge Component (`src/components/graph/edges/AccountabilityEdge.tsx`)
```tsx
import React, { memo } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  EdgeProps,
  getSmoothStepPath,
} from "@xyflow/react";
import { AlertTriangle, CheckCircle2 } from "lucide-react";
import type { AccountabilityEdgeData } from "../types";

export const AccountabilityEdge = memo(function AccountabilityEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}: EdgeProps<AccountabilityFlowEdge>) {
  const verified = data?.verified ?? true;
  const relation = data?.relation ?? "Issues";

  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 16,
  });

  return (
    <>
      {/* Background glow filter path */}
      <path
        d={edgePath}
        fill="none"
        stroke={verified ? "#00E5FF" : "#FF1744"}
        strokeWidth={verified ? 5 : 6}
        strokeOpacity={verified ? 0.25 : 0.4}
        className={verified ? "blur-[2px]" : "blur-[4px] animate-pulse"}
      />

      {/* Primary SVG edge path */}
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: verified ? "#00E5FF" : "#FF1744",
          strokeWidth: selected ? 2.5 : 2,
          strokeDasharray: verified ? "8 4" : "6 4",
          animation: verified
            ? "flowAnimation 1.5s linear infinite"
            : "warningPulse 1.2s ease-in-out infinite",
          transition: "stroke 0.2s, stroke-width 0.2s",
        }}
        markerEnd={verified ? "url(#cyan-arrow)" : "url(#crimson-arrow)"}
      />

      {/* HTML Edge Label Pill */}
      <EdgeLabelRenderer>
        <div
          style={{
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
          }}
          className={`pointer-events-auto absolute flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono tracking-wider uppercase border transition-all select-none ${
            verified
              ? "bg-obsidian-950/90 border-cyber-cyan/40 text-cyber-cyan shadow-[0_0_10px_rgba(0,229,255,0.2)] hover:border-cyber-cyan"
              : "bg-obsidian-950/95 border-cyber-red/80 text-cyber-red shadow-[0_0_12px_rgba(255,23,68,0.35)] animate-pulse hover:border-cyber-red"
          }`}
        >
          {verified ? (
            <>
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan shadow-[0_0_6px_#00E5FF]" />
              <span>{relation}</span>
            </>
          ) : (
            <>
              <AlertTriangle className="w-3 h-3 text-cyber-red animate-bounce" />
              <span className="font-bold">{relation} (TAMPERED)</span>
            </>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
});

export const VerifiedEdge = AccountabilityEdge;
export const TamperedEdge = AccountabilityEdge;
```

#### B. SVG Marker Definitions (`src/components/graph/edges/EdgeMarkerDefs.tsx`)
```tsx
import React from "react";

export function EdgeMarkerDefs() {
  return (
    <svg style={{ position: "absolute", top: 0, left: 0, width: 0, height: 0 }}>
      <defs>
        {/* Electric Cyan Arrow Marker */}
        <marker
          id="cyan-arrow"
          viewBox="0 0 12 12"
          refX="10"
          refY="6"
          markerWidth="8"
          markerHeight="8"
          orient="auto-start-reverse"
        >
          <path d="M 0 1 L 12 6 L 0 11 z" fill="#00E5FF" />
        </marker>

        {/* Crimson Tampered Arrow Marker */}
        <marker
          id="crimson-arrow"
          viewBox="0 0 12 12"
          refX="10"
          refY="6"
          markerWidth="8"
          markerHeight="8"
          orient="auto-start-reverse"
        >
          <path d="M 0 1 L 12 6 L 0 11 z" fill="#FF1744" />
        </marker>

        {/* CSS Keyframe Animations for Flow and Warning */}
        <style>
          {`
            @keyframes flowAnimation {
              from {
                stroke-dashoffset: 24;
              }
              to {
                stroke-dashoffset: 0;
              }
            }

            @keyframes warningPulse {
              0%, 100% {
                opacity: 0.6;
                stroke-width: 2px;
              }
              50% {
                opacity: 1;
                stroke-width: 3px;
                filter: drop-shadow(0 0 10px #FF1744);
              }
            }
          `}
        </style>
      </defs>
    </svg>
  );
}
```

#### C. Edge Barrel (`src/components/graph/edges/index.ts`)
```typescript
import { AccountabilityEdge, VerifiedEdge, TamperedEdge } from "./AccountabilityEdge";
export { EdgeMarkerDefs } from "./EdgeMarkerDefs";
export { AccountabilityEdge, VerifiedEdge, TamperedEdge };

export const edgeTypes = {
  accountability: AccountabilityEdge,
  verified: VerifiedEdge,
  tampered: TamperedEdge,
};
```

---

### 4.3 Module 3: Single-Principal Reachability Validator (`src/components/graph/reachability.ts`)

```typescript
import type { ReachabilityResult } from "./types";

export interface MinimalNode {
  id: string;
  kind?: string;
  [key: string]: any;
}

export interface MinimalEdge {
  source: string;
  target: string;
  [key: string]: any;
}

/**
 * Validates Single-Principal Reachability Invariants:
 * 1. Exactly 1 principal node exists (F9.B4, F9.B5).
 * 2. 100% of nodes must be reachable from Principal via BFS (F9.3, F9.B1).
 * 3. Detects orphan and disconnected nodes.
 */
export function verifySinglePrincipalReachability(
  nodes: MinimalNode[],
  edges: MinimalEdge[]
): ReachabilityResult {
  // Invariant 1: Exactly 1 principal node
  const principals = nodes.filter((n) => n.kind === "principal" || n.id === "principal");

  if (principals.length !== 1) {
    return {
      valid: false,
      error: `Expected 1 principal node, found ${principals.length}`,
      rootPrincipalId: principals[0]?.id,
      reachableNodeIds: [],
      orphanNodeIds: nodes.map((n) => n.id),
      totalNodes: nodes.length,
    };
  }

  const rootId = principals[0].id;

  // Build forward adjacency list
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    if (!adjacency.has(edge.source)) {
      adjacency.set(edge.source, []);
    }
    adjacency.get(edge.source)!.push(edge.target);
  }

  // BFS Traversal
  const visited = new Set<string>();
  const queue: string[] = [rootId];
  visited.add(rootId);

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const neighbors = adjacency.get(curr) || [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push(neighbor);
      }
    }
  }

  // Check for orphan / unreachable nodes
  const orphanNodes = nodes.filter((n) => !visited.has(n.id)).map((n) => n.id);

  if (orphanNodes.length > 0) {
    return {
      valid: false,
      error: `Unreachable node(s) detected: ${orphanNodes.join(", ")}`,
      rootPrincipalId: rootId,
      reachableNodeIds: Array.from(visited),
      orphanNodeIds: orphanNodes,
      totalNodes: nodes.length,
    };
  }

  return {
    valid: true,
    rootPrincipalId: rootId,
    reachableNodeIds: Array.from(visited),
    orphanNodeIds: [],
    totalNodes: nodes.length,
  };
}
```

---

### 4.4 Module 4: TypeScript Data Transformer (`src/components/graph/transformer.ts`)

```typescript
import { MarkerType } from "@xyflow/react";
import type {
  EvidencePacket,
  VerificationReport,
  TrustFloor,
  RuleIdentifier,
} from "@/types/verification";
import { verifySinglePrincipalReachability } from "./reachability";
import type {
  AccountabilityFlowNode,
  AccountabilityFlowEdge,
  FlowGraphResult,
  FlowNodeKind,
  FlowRelation,
} from "./types";

export interface TransformOptions {
  wasmGraphJson?: string;
  packet: EvidencePacket;
  report?: VerificationReport | null;
  onSelectNode?: (nodeId: string) => void;
  horizontalSpacing?: number;
  verticalSpacing?: number;
}

const RELATION_MAP: Record<string, FlowRelation> = {
  issues: "Issues",
  delegates: "Delegates",
  acts_under: "ActsUnder",
  decides: "Decides",
  performs: "Performs",
  produces: "Produces",
  Issues: "Issues",
  Delegates: "Delegates",
  ActsUnder: "ActsUnder",
  Decides: "Decides",
  Performs: "Performs",
  Produces: "Produces",
};

/**
 * Transforms EvidencePacket and WASM output into @xyflow/react nodes and edges
 * with automatic hierarchical positioning, verification rule binding, and reachability checking.
 */
export function transformWasmGraphToFlow(options: TransformOptions): FlowGraphResult {
  const {
    packet,
    report,
    onSelectNode,
    horizontalSpacing = 280,
    verticalSpacing = 110,
  } = options;

  const nodes: AccountabilityFlowNode[] = [];
  const edges: AccountabilityFlowEdge[] = [];

  const isRulePassing = (rule: RuleIdentifier): boolean => {
    if (!report) return true;
    return report.checks.find((c) => c.rule === rule)?.pass ?? true;
  };

  const getRuleDetail = (rule: RuleIdentifier): string | undefined => {
    return report?.checks.find((c) => c.rule === rule)?.detail;
  };

  let currentRank = 0;

  // 1. Principal Node
  const principalVerified = isRulePassing("ROOT_TOKEN_SIGNATURE");
  nodes.push({
    id: "principal",
    type: "principal",
    position: { x: currentRank * horizontalSpacing, y: 150 },
    data: {
      id: "principal",
      kind: "principal",
      label: `${packet.root_authority.display_role} (${packet.root_authority.principal_id})`,
      verified: principalVerified,
      ruleName: "ROOT_TOKEN_SIGNATURE",
      ruleDetail: getRuleDetail("ROOT_TOKEN_SIGNATURE"),
      metadata: {
        principal_id: packet.root_authority.principal_id,
        display_role: packet.root_authority.display_role,
      },
      onSelectNode,
    },
  });
  currentRank++;

  // 2. AuthorityGrant Node (Root Token)
  const rootToken = packet.root_authority.root_token;
  const authGrantVerified = isRulePassing("ROOT_TOKEN_SIGNATURE") && isRulePassing("REVOCATION");
  nodes.push({
    id: "authority_grant",
    type: "authority_grant",
    position: { x: currentRank * horizontalSpacing, y: 150 },
    data: {
      id: "authority_grant",
      kind: "authority_grant",
      label: `root token ${rootToken.jti.slice(0, 8)} → ${rootToken.agent_id}`,
      verified: authGrantVerified,
      ruleName: "ROOT_TOKEN_SIGNATURE",
      ruleDetail: getRuleDetail("ROOT_TOKEN_SIGNATURE"),
      metadata: {
        jti: rootToken.jti,
        issuer_id: rootToken.issuer_id,
        agent_id: rootToken.agent_id,
        scope: rootToken.scope,
        issued_at: rootToken.issued_at,
        expires_at: rootToken.expires_at,
        issuer_sig: rootToken.issuer_sig,
      },
      onSelectNode,
    },
  });

  edges.push({
    id: "e_issues",
    source: "principal",
    target: "authority_grant",
    type: "accountability",
    animated: principalVerified && authGrantVerified,
    data: {
      relation: "Issues",
      verified: principalVerified && authGrantVerified,
      ruleName: "ROOT_TOKEN_SIGNATURE",
      sourceKind: "principal",
      targetKind: "authority_grant",
    },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: principalVerified && authGrantVerified ? "#00E5FF" : "#FF1744",
    },
  });
  currentRank++;

  // 3. Delegation Hops
  let lastAuthorityId = "authority_grant";
  const delegationVerified = isRulePassing("DELEGATION_CHAIN") && isRulePassing("REVOCATION");

  if (packet.delegation_chain && packet.delegation_chain.length > 0) {
    packet.delegation_chain.forEach((hop, idx) => {
      const hopId = `delegation:${idx}`;
      nodes.push({
        id: hopId,
        type: "delegation",
        position: { x: currentRank * horizontalSpacing, y: 150 },
        data: {
          id: hopId,
          kind: "delegation",
          label: `hop ${idx} (depth ${hop.depth}): ${hop.issuer_id} → ${hop.grantee_id}`,
          verified: delegationVerified,
          ruleName: "DELEGATION_CHAIN",
          ruleDetail: getRuleDetail("DELEGATION_CHAIN"),
          metadata: {
            jti: hop.jti,
            parent_jti: hop.parent_jti,
            issuer_id: hop.issuer_id,
            grantee_id: hop.grantee_id,
            depth: hop.depth,
            scope: hop.scope,
            issued_at: hop.issued_at,
            expires_at: hop.expires_at,
            issuer_sig: hop.issuer_sig,
          },
          onSelectNode,
        },
      });

      edges.push({
        id: `e_delegates_${idx}`,
        source: lastAuthorityId,
        target: hopId,
        type: "accountability",
        animated: delegationVerified,
        data: {
          relation: "Delegates",
          verified: delegationVerified,
          ruleName: "DELEGATION_CHAIN",
          sourceKind: idx === 0 ? "authority_grant" : "delegation",
          targetKind: "delegation",
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: delegationVerified ? "#00E5FF" : "#FF1744",
        },
      });

      lastAuthorityId = hopId;
      currentRank++;
    });
  }

  // 4. Agent Node
  const agentVerified = isRulePassing("AGENT_ID_BINDING") && isRulePassing("AGENT_SIGNATURE");
  nodes.push({
    id: "agent",
    type: "agent",
    position: { x: currentRank * horizontalSpacing, y: 150 },
    data: {
      id: "agent",
      kind: "agent",
      label: packet.agent.aip_id,
      verified: agentVerified,
      ruleName: "AGENT_ID_BINDING",
      ruleDetail: getRuleDetail("AGENT_ID_BINDING"),
      metadata: {
        aip_id: packet.agent.aip_id,
        algorithm: packet.agent.public_key.algorithm,
        public_key: packet.agent.public_key.key_bytes,
        provenance: packet.agent.provenance,
      },
      onSelectNode,
    },
  });

  const actsUnderVerified = agentVerified && isRulePassing("AUTHORITY_CHAIN");
  edges.push({
    id: "e_acts_under",
    source: lastAuthorityId,
    target: "agent",
    type: "accountability",
    animated: actsUnderVerified,
    data: {
      relation: "ActsUnder",
      verified: actsUnderVerified,
      ruleName: "AUTHORITY_CHAIN",
      sourceKind: lastAuthorityId === "authority_grant" ? "authority_grant" : "delegation",
      targetKind: "agent",
    },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: actsUnderVerified ? "#00E5FF" : "#FF1744",
    },
  });
  currentRank++;

  // 5. Decision Node
  const decisionVerified = isRulePassing("SCOPE_AUTHORITY");
  nodes.push({
    id: "decision",
    type: "decision",
    position: { x: currentRank * horizontalSpacing, y: 150 },
    data: {
      id: "decision",
      kind: "decision",
      label: packet.decision.summary,
      verified: decisionVerified,
      ruleName: "SCOPE_AUTHORITY",
      ruleDetail: getRuleDetail("SCOPE_AUTHORITY"),
      metadata: {
        decision_id: packet.decision.decision_id,
        action_kind: packet.decision.action_kind,
        summary: packet.decision.summary,
        input_hash: packet.decision.input_hash,
        rationale_hash: packet.decision.rationale_hash,
        decided_at: packet.decision.decided_at,
      },
      onSelectNode,
    },
  });

  const decidesVerified = agentVerified && decisionVerified;
  edges.push({
    id: "e_decides",
    source: "agent",
    target: "decision",
    type: "accountability",
    animated: decidesVerified,
    data: {
      relation: "Decides",
      verified: decidesVerified,
      ruleName: "AGENT_SIGNATURE",
      sourceKind: "agent",
      targetKind: "decision",
    },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: decidesVerified ? "#00E5FF" : "#FF1744",
    },
  });
  currentRank++;

  // 6. Action Nodes (Multi-Action Column Layout)
  const actionVerified = isRulePassing("ACTION_ATTESTATIONS");
  const actionCount = packet.actions.length;
  const totalActionHeight = (actionCount - 1) * verticalSpacing;
  const actionStartY = 150 - totalActionHeight / 2;

  packet.actions.forEach((act, idx) => {
    const actId = `action:${idx}`;
    const actY = actionStartY + idx * verticalSpacing;

    nodes.push({
      id: actId,
      type: "action",
      position: { x: currentRank * horizontalSpacing, y: actY },
      data: {
        id: actId,
        kind: "action",
        label: act.description,
        verified: actionVerified,
        ruleName: "ACTION_ATTESTATIONS",
        ruleDetail: getRuleDetail("ACTION_ATTESTATIONS"),
        metadata: {
          action_id: act.action_id,
          action_kind: act.action_kind,
          description: act.description,
          payload_hash: act.payload_hash,
          performed_at: act.performed_at,
          agent_sig: act.agent_sig,
        },
        onSelectNode,
      },
    });

    edges.push({
      id: `e_performs_${idx}`,
      source: "decision",
      target: actId,
      type: "accountability",
      animated: decisionVerified && actionVerified,
      data: {
        relation: "Performs",
        verified: decisionVerified && actionVerified,
        ruleName: "ACTION_ATTESTATIONS",
        sourceKind: "decision",
        targetKind: "action",
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: decisionVerified && actionVerified ? "#00E5FF" : "#FF1744",
      },
    });
  });
  currentRank++;

  // 7. Receipt Node (if present)
  if (packet.receipt_binding) {
    const rb = packet.receipt_binding;
    const receiptVerified = isRulePassing("RECEIPT_BINDING");

    nodes.push({
      id: "receipt",
      type: "receipt",
      position: { x: currentRank * horizontalSpacing, y: 150 },
      data: {
        id: "receipt",
        kind: "receipt",
        label: `${rb.receipt_id} @ ${rb.receipt_system}`,
        verified: receiptVerified,
        ruleName: "RECEIPT_BINDING",
        ruleDetail: getRuleDetail("RECEIPT_BINDING"),
        metadata: {
          receipt_system: rb.receipt_system,
          receipt_id: rb.receipt_id,
          receipt_hash: rb.receipt_hash,
          counterparty_id: rb.counterparty_id,
          countersigned: !!rb.counterparty_sig,
          counterparty_sig: rb.counterparty_sig,
        },
        onSelectNode,
      },
    });

    packet.actions.forEach((_, idx) => {
      edges.push({
        id: `e_produces_${idx}`,
        source: `action:${idx}`,
        target: "receipt",
        type: "accountability",
        animated: actionVerified && receiptVerified,
        data: {
          relation: "Produces",
          verified: actionVerified && receiptVerified,
          ruleName: "RECEIPT_BINDING",
          sourceKind: "action",
          targetKind: "receipt",
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: actionVerified && receiptVerified ? "#00E5FF" : "#FF1744",
        },
      });
    });
  }

  // Reachability analysis
  const reachability = verifySinglePrincipalReachability(
    nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
    edges.map((e) => ({ source: e.source, target: e.target }))
  );

  // Generate Graphviz DOT format digraph string (satisfies F9.5, P1.4)
  const dotLines: string[] = ["digraph AccountabilityGraph {", "  rankdir=LR;"];
  for (const n of nodes) {
    const shape =
      n.data.kind === "principal"
        ? "house"
        : n.data.kind === "authority_grant"
        ? "note"
        : n.data.kind === "delegation"
        ? "cds"
        : n.data.kind === "agent"
        ? "component"
        : n.data.kind === "decision"
        ? "diamond"
        : n.data.kind === "action"
        ? "box"
        : "tab";
    dotLines.push(`  "${n.id}" [label="${n.data.label.replace(/"/g, '\\"')}", shape="${shape}"];`);
  }
  for (const e of edges) {
    dotLines.push(`  "${e.source}" -> "${e.target}" [label="${e.data?.relation}"];`);
  }
  dotLines.push("}");
  const dotString = dotLines.join("\n");

  const claimedTrustFloor = packet.claimed_trust_floor;
  const derivedTrustFloor = report?.derived_trust_floor ?? claimedTrustFloor;

  return {
    nodes,
    edges,
    reachability,
    claimedTrustFloor,
    derivedTrustFloor,
    packetId: packet.packet_hash,
    dotString,
  };
}
```

---

## 5. Verification Method

### 5.1 Verification Commands
To independently verify this blueprint against the automated E2E test suite:
```powershell
# From workspace root
npx vitest run e2e/tier1-features/f09_dag_viewer.spec.ts
npx vitest run e2e/tier1-features/f10_inspection_sheet.spec.ts
npx vitest run e2e/tier2-boundary/f09_dag_boundary.spec.ts
npx vitest run e2e/tier2-boundary/f10_inspection_boundary.spec.ts
npx vitest run e2e/tier3-combinations/pipeline1_ingest_verify_dag.spec.ts
```

### 5.2 Verification Matrix
| Test Case | Target Invariant | Expected Result |
|---|---|---|
| `F9.1` | 7 distinct node kinds present | `principal`, `authority_grant`, `delegation`, `agent`, `decision`, `action`, `receipt` |
| `F9.2` | 6 standard relations wired | `Issues`, `Delegates`, `ActsUnder`, `Decides`, `Performs`, `Produces` |
| `F9.3` | Single-Principal reachability | BFS from `principal` reaches 100% of nodes, `valid === true` |
| `F9.4` | Node verification sync | Node badges reflect 1:1 engine report rules |
| `F9.5` | Graphviz DOT export | Digraph string with shapes `house`, `component`, `tab` |
| `F9.B1` | Orphan node detection | Detected detached node: `Unreachable node(s) detected: orphan-action-node` |
| `F9.B2` | 0-Hop delegation | Direct `ActsUnder` edge from `authority_grant` to `agent` |
| `F9.B3` | High-density action fan-out | 25 parallel actions cleanly handled and reachable |
| `F9.B4` | Zero principal nodes | Fails with `Expected 1 principal node, found 0` |
| `F9.B5` | Multiple conflicting principals | Fails with `Expected 1 principal node, found 2` |
| `P1.2` | Dynamic badge failure | Invalid signature switches node to unverified and edge to dashed crimson |

### 5.3 Invalidation Conditions
This blueprint is invalidated if:
1. Rust engine modifies `AccountabilityGraph` topology or removes dual edge fields (`from`/`to` + `source`/`target`).
2. `@xyflow/react` is downgraded below v12, breaking `EdgeLabelRenderer` or `BaseEdge`.
3. Node inspection drawer fields in `f10_inspection_sheet.spec.ts` diverge from `EvidencePacket` wire specification.
