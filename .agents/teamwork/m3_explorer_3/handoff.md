# Handoff Report: Milestone 3 Explorer 3
**Role:** Interactive Inspection Sheet & Controls Specialist  
**Milestone:** Milestone 3 (Console R2 — Interactive Accountability Graph)  
**Date:** 2026-11-02  
**Target Components:**
- `src/components/graph/InspectionSheet.tsx`
- `src/components/graph/BreadcrumbTrail.tsx`
- `src/components/graph/GraphControls.tsx`
- `src/components/graph/AccountabilityGraph.tsx`
- `src/lib/graph/exportUtils.ts`

---

## 1. Observation

### Codebase & Ecosystem State
1. **Dependency Verification (`aip-console/package.json:13-19`)**:
   - `@xyflow/react`: `^12.4.0` is already installed and compatible with React 19 and Next.js 15.
   - `lucide-react`: `^1.16.0` is installed for all iconography.
   - `clsx` (`^2.1.1`) and `tailwind-merge` (`^2.6.0`) are installed for class variance utilities.
2. **Current Page Placeholders**:
   - In `src/app/page.tsx:112-141`: Tab 2 (`activeTab === "graph"`) currently renders a static placeholder div with `Workflow` icon and notice `Load a fixture in Ingestion view to populate the DAG visualizer`.
   - In `src/app/graph/page.tsx:7-17`: Dedicated `/graph` route performs client-side redirect (`setActiveTab("graph"); router.replace("/")`).
3. **Styling & CSS (`src/app/globals.css:1-70`)**:
   - Syntriass cyber obsidian palette configured in `tailwind.config.ts`:
     - Obsidian background: `#080B11`, Surface 1: `#0E131F`, Surface 2: `#161F33`, Border: `#222F46`.
     - Brand accents: Electric cyan `#00E5FF`, Green `#00E676`, Amber `#FFB300`, Red `#FF1744`, Indigo `#6366F1`.
   - **Crucial Observation**: `@xyflow/react/dist/style.css` is NOT yet imported in `globals.css` or the graph components. Without this import, React Flow canvas, node handles, controls, and minimap will render unstyled.
4. **Context Layer (`src/lib/context/ConsoleContext.tsx`, `src/lib/wasm/EvidenceContext.tsx`)**:
   - `useConsole()` exposes: `loadedPacket: EvidencePacket | null`, `activeTab`, `setActiveTab`, `loadFixture`, `resetEvidence`.
   - `useEvidence()` exposes: `evidence: LoadedEvidence | null`, `report: VerificationReport | null`, `graph: AccountabilityGraph | null`, `isVerifying: boolean`, `error: string | null`, `loadFixture(id)`.
5. **E2E Test Suite Contracts (`e2e/tier1-features/f10_inspection_sheet.spec.ts`, `e2e/tier2-boundary/f10_inspection_boundary.spec.ts`)**:
   - `F10.1`: Inspects `agent` node: `aip_id`, `public_key`, `provenance.model_hash` / model details.
   - `F10.2`: Inspects `authority_grant` node: `jti`, `issuer_id`, `scope.allowed.length > 0`.
   - `F10.3`: Inspects `decision` node: `decision_id`, `summary`, `decided_at` (> 0).
   - `F10.4`: Inspects `action` node: `action_id`, `payload_hash` matching `^[0-9a-f]{64}$`.
   - `F10.5`: Inspects `receipt` node: `receipt_system`, `countersigned: boolean`.
   - `F10.B1`: Empty metadata fallback must display `"N/A (Not Provided)"`.
   - `F10.B2`: 64-character public key hex formatted into 19-char fingerprint `${hex.slice(0, 8)}...${hex.slice(-8)}`.
   - `F10.B3`: Unverified status handled gracefully with error details and visual badge.
   - `F10.B4`: Unix epoch millisecond timestamps formatted to standard ISO-8601 strings (`new Date(ts).toISOString()`).
   - `F10.B5`: Receipt node handles missing counterparty signature gracefully ("Hash Only mode").
   - `F9.5` / `P1.4`: Graph export requires Graphviz DOT digraph support (`toDot(graph)`).

---

## 2. Logic Chain

1. **Node Selection to Drawer Activation**:
   - When a node is clicked in the React Flow canvas via `onNodeClick`, the node's `id` and data payload are stored in `selectedNodeId` state in `AccountabilityGraph`.
   - Setting `selectedNodeId` opens `InspectionSheet` (`isOpen = true`). Clicking the drawer close button or canvas pane resets selection or hides the drawer.
2. **Metadata Fallbacks & Boundary Defense**:
   - Following `F10.B1`, any null, undefined, or empty string field in node data is guarded by a formatting helper `getDisplayField(val, fallback = "N/A (Not Provided)")`.
   - Timestamps (`issued_at`, `expires_at`, `decided_at`, `performed_at`) are parsed safely into ISO-8601 strings via `formatTimestamp(epochMs)` (`F10.B4`).
   - Cryptographic keys and hashes (public keys, payload hashes, canonical hashes, signatures) provide truncated fingerprints `${hex.slice(0, 8)}...${hex.slice(-8)}` for compact reading plus copy-to-clipboard buttons for full hex values (`F10.B2`).
3. **1:1 Engine Verification Rule Alignment**:
   - In accordance with the project rule of zero verification logic in UI, `InspectionSheet` filters `report.checks` strictly matching the selected node's kind:
     - `principal` $\to$ `ROOT_TOKEN_SIGNATURE`, `AUTHORITY_CHAIN`
     - `authority_grant` $\to$ `ROOT_TOKEN_SIGNATURE`, `TEMPORAL_VALIDITY`, `REVOCATION`
     - `delegation` $\to$ `DELEGATION_CHAIN`, `AUTHORITY_CHAIN`, `REVOCATION`, `TEMPORAL_VALIDITY`
     - `agent` $\to$ `AGENT_ID_BINDING`, `AGENT_SIGNATURE`, `CANONICAL_HASH`
     - `decision` $\to$ `SCOPE_AUTHORITY`, `TEMPORAL_VALIDITY`
     - `action` $\to$ `ACTION_ATTESTATIONS`, `SCOPE_AUTHORITY`
     - `receipt` $\to$ `RECEIPT_BINDING`, `TRUST_FLOOR`
   - Unverified nodes display exact engine error details and a crimson badge (`F10.B3`).
4. **Custody Chain Breadcrumb Derivation**:
   - In a directed acyclic accountability graph, every node descends from the root `principal`.
   - Given `selectedNodeId`, we trace backwards along incoming edges (`edge.target === currNodeId`) up to the root `principal`.
   - Reversing this array produces the complete linear custody sequence `[Principal, AuthorityGrant, Hop 0, ..., SelectedNode]`.
   - Clicking any ancestor breadcrumb immediately selects that ancestor node and smoothly pans the React Flow canvas to it.
5. **Canvas Controls, Layout Switching & Multi-Format Exports**:
   - Viewport controls call standard React Flow hooks (`fitView`, `zoomIn`, `zoomOut`, `setViewport`).
   - Orientation switcher alternates between `LR` (horizontal) and `TB` (vertical), recalculating layout coordinates and refitting the view.
   - Node visibility filters maintain a `visibleKinds: Set<string>`, filtering nodes and edge attachments dynamically while displaying item counts.
   - Export utilities handle SVG serialization (extracting canvas SVG elements), PNG rasterization via Canvas drawing, Graphviz DOT export (`toDot`), and raw JSON export.

---

## 3. Caveats

1. **DAG Layout Dependency**:
   - Explorer 1 is designing the layout algorithm (dagre or tree-based). Explorer 3's controls will invoke the layout algorithm via a clean callback prop `onLayoutChange(direction: 'LR' | 'TB')`.
2. **Custom Node and Edge Rendering**:
   - Custom node cards are implemented by Explorer 1, and custom edges (cyan flow vs dashed red) by Explorer 2. Explorer 3's `AccountabilityGraph` root container provides the integration scaffolding where `nodeTypes` and `edgeTypes` are registered.
3. **Large Action Batches**:
   - When evidence packets contain 25+ parallel action attestations (tested in `F9.B3`), the Action filter switch in `GraphControls` allows users to toggle action visibility to keep the canvas uncluttered.

---

## 4. Conclusion & Complete Implementation Blueprint

### Architecture Map

```
src/components/graph/
├── AccountabilityGraph.tsx   <-- Root container (Context, Empty/Loading/Error, React Flow)
├── GraphControls.tsx         <-- Toolbar (Fit, Zoom, Reset, LR/TB, Filters, Export Menu)
├── InspectionSheet.tsx       <-- Slide-out Drawer (Payload, Crypto, Rules, Syntax JSON)
├── BreadcrumbTrail.tsx       <-- Custody Chain Navigator (Principal -> Selected Node)
└── nodes/ & edges/           <-- Registered custom components from Explorer 1 & 2
src/lib/graph/
└── exportUtils.ts            <-- PNG, SVG, Graphviz DOT, and JSON export utilities
```

---

### Component 1: `src/components/graph/InspectionSheet.tsx`

```typescript
"use client";

import React, { useState, useMemo } from "react";
import {
  X,
  Copy,
  Check,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Key,
  FileCode,
  Hash,
  ExternalLink,
  ChevronRight,
  Clock,
  Layers,
  Cpu,
  Fingerprint,
} from "lucide-react";
import type { GraphNode, GraphEdge } from "@/lib/wasm/types";
import type { VerificationReport, RuleResult } from "@/types/verification";
import { BreadcrumbTrail } from "./BreadcrumbTrail";

export interface InspectionSheetProps {
  isOpen: boolean;
  onClose: () => void;
  selectedNode: GraphNode | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  report: VerificationReport | null;
  onSelectNode: (nodeId: string) => void;
}

// Map node kind to associated 1:1 engine rules
const NODE_RULE_MAPPINGS: Record<string, string[]> = {
  principal: ["ROOT_TOKEN_SIGNATURE", "AUTHORITY_CHAIN"],
  authority_grant: ["ROOT_TOKEN_SIGNATURE", "TEMPORAL_VALIDITY", "REVOCATION"],
  delegation: ["DELEGATION_CHAIN", "AUTHORITY_CHAIN", "REVOCATION", "TEMPORAL_VALIDITY"],
  agent: ["AGENT_ID_BINDING", "AGENT_SIGNATURE", "CANONICAL_HASH"],
  decision: ["SCOPE_AUTHORITY", "TEMPORAL_VALIDITY"],
  action: ["ACTION_ATTESTATIONS", "SCOPE_AUTHORITY"],
  receipt: ["RECEIPT_BINDING", "TRUST_FLOOR"],
};

export const InspectionSheet: React.FC<InspectionSheetProps> = ({
  isOpen,
  onClose,
  selectedNode,
  nodes,
  edges,
  report,
  onSelectNode,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"details" | "rules" | "json">("details");

  if (!isOpen || !selectedNode) return null;

  const nodeData = (selectedNode.data as Record<string, any>) || {};
  const kind = (selectedNode.kind || "unknown").toLowerCase();

  const handleCopy = (text: string, keyId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(keyId);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const formatFingerprint = (hex?: string) => {
    if (!hex || hex.length < 16) return hex || "N/A (Not Provided)";
    return `${hex.slice(0, 8)}...${hex.slice(-8)}`;
  };

  const formatTimestamp = (epochMs?: number | null) => {
    if (!epochMs || isNaN(epochMs)) return "N/A (Not Provided)";
    return new Date(epochMs).toISOString();
  };

  // Associated rules for this node
  const associatedRules = useMemo(() => {
    if (!report || !report.checks) return [];
    const expected = NODE_RULE_MAPPINGS[kind] || [];
    return report.checks.filter((c) => expected.includes(c.rule));
  }, [report, kind]);

  const isVerified = selectedNode.verified ?? true;

  return (
    <aside
      className="fixed top-16 right-0 bottom-0 w-full sm:w-[520px] bg-obsidian-900 border-l border-obsidian-700 shadow-2xl z-40 flex flex-col transition-transform duration-300 ease-in-out font-sans overflow-hidden"
      aria-label="DAG Node Inspection Sheet"
    >
      {/* ── Header ── */}
      <div className="p-4 border-b border-obsidian-700 bg-obsidian-950 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className={`p-2 rounded-lg border ${
              isVerified
                ? "bg-cyber-cyan/10 border-cyber-cyan/30 text-cyber-cyan"
                : "bg-cyber-red/10 border-cyber-red/30 text-cyber-red"
            }`}
          >
            {kind === "agent" && <Cpu className="w-5 h-5" />}
            {kind === "principal" && <ShieldCheck className="w-5 h-5" />}
            {kind === "authority_grant" && <Key className="w-5 h-5" />}
            {kind === "delegation" && <Layers className="w-5 h-5" />}
            {kind === "decision" && <Fingerprint className="w-5 h-5" />}
            {kind === "action" && <Clock className="w-5 h-5" />}
            {kind === "receipt" && <Shield className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                {kind.replace("_", " ")}
              </span>
              <span
                className={`px-2 py-0.5 text-[10px] font-mono rounded-full font-bold border ${
                  isVerified
                    ? "bg-cyber-green/10 text-cyber-green border-cyber-green/40 shadow-green-glow"
                    : "bg-cyber-red/10 text-cyber-red border-cyber-red/40 shadow-red-glow"
                }`}
              >
                {isVerified ? "VERIFIED" : "UNVERIFIED / TAMPERED"}
              </span>
            </div>
            <h2 className="text-sm font-bold text-slate-100 truncate max-w-[280px]">
              {selectedNode.label || selectedNode.id}
            </h2>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-obsidian-800 rounded-lg transition-colors"
          title="Close Inspection Sheet"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* ── Breadcrumb Custody Trail ── */}
      <div className="px-4 py-2 bg-obsidian-850 border-b border-obsidian-750">
        <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
          Chain of Custody
        </div>
        <BreadcrumbTrail
          selectedNodeId={selectedNode.id}
          nodes={nodes}
          edges={edges}
          onSelectNode={onSelectNode}
        />
      </div>

      {/* ── Tabs Navigation ── */}
      <div className="flex border-b border-obsidian-700 bg-obsidian-950 px-4">
        <button
          onClick={() => setActiveTab("details")}
          className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors ${
            activeTab === "details"
              ? "border-cyber-cyan text-cyber-cyan font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Node Details & Crypto
        </button>
        <button
          onClick={() => setActiveTab("rules")}
          className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
            activeTab === "rules"
              ? "border-cyber-cyan text-cyber-cyan font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>Rule Checks</span>
          <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-obsidian-800 text-slate-300">
            {associatedRules.length}
          </span>
        </button>
        <button
          onClick={() => setActiveTab("json")}
          className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors ${
            activeTab === "json"
              ? "border-cyber-cyan text-cyber-cyan font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Raw JSON Payload
        </button>
      </div>

      {/* ── Tab Content ── */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {activeTab === "details" && (
          <div className="space-y-4">
            {/* Unverified Alert */}
            {!isVerified && (
              <div className="p-3 rounded-lg bg-cyber-red/10 border border-cyber-red/40 flex items-start gap-2.5">
                <ShieldAlert className="w-5 h-5 text-cyber-red shrink-0 mt-0.5" />
                <div className="text-xs">
                  <div className="font-bold text-cyber-red">Verification Failed for Node</div>
                  <div className="text-slate-300 mt-0.5">
                    {nodeData.error || "Cryptographic binding or signature check failed engine validation."}
                  </div>
                </div>
              </div>
            )}

            {/* Principal Node Details */}
            {kind === "principal" && (
              <div className="space-y-3">
                <DetailRow
                  label="Principal ID"
                  value={nodeData.principal_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.principal_id, "principal_id")}
                  isCopied={copiedKey === "principal_id"}
                />
                <DetailRow
                  label="Display Role"
                  value={nodeData.display_role || "N/A (Not Provided)"}
                />
              </div>
            )}

            {/* Authority Grant Node Details */}
            {kind === "authority_grant" && (
              <div className="space-y-3">
                <DetailRow
                  label="Root Token JTI"
                  value={nodeData.jti || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.jti, "jti")}
                  isCopied={copiedKey === "jti"}
                />
                <DetailRow
                  label="Issuer ID"
                  value={nodeData.issuer_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.issuer_id, "issuer_id")}
                  isCopied={copiedKey === "issuer_id"}
                />
                <DetailRow
                  label="Grantee Agent ID"
                  value={nodeData.agent_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.agent_id, "agent_id")}
                  isCopied={copiedKey === "agent_id"}
                />
                <DetailRow
                  label="Issued At"
                  value={formatTimestamp(nodeData.issued_at)}
                />
                <DetailRow
                  label="Expires At"
                  value={formatTimestamp(nodeData.expires_at)}
                />
                {/* Scope Matrix */}
                <div className="pt-2 border-t border-obsidian-750">
                  <div className="text-[11px] font-mono text-slate-400 mb-1.5">Allowed Scope</div>
                  <div className="flex flex-wrap gap-1.5">
                    {nodeData.scope?.allowed?.map((s: string) => (
                      <span
                        key={s}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30"
                      >
                        {s}
                      </span>
                    )) || <span className="text-xs text-slate-500">None</span>}
                  </div>
                </div>
              </div>
            )}

            {/* Delegation Node Details */}
            {kind === "delegation" && (
              <div className="space-y-3">
                <DetailRow
                  label="Delegation JTI"
                  value={nodeData.jti || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.jti, "jti")}
                  isCopied={copiedKey === "jti"}
                />
                <DetailRow
                  label="Parent JTI"
                  value={nodeData.parent_jti || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.parent_jti, "parent_jti")}
                  isCopied={copiedKey === "parent_jti"}
                />
                <DetailRow
                  label="Delegation Depth"
                  value={`Depth ${nodeData.depth ?? 0}`}
                />
                <DetailRow
                  label="Issuer ID"
                  value={nodeData.issuer_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.issuer_id, "issuer_id")}
                  isCopied={copiedKey === "issuer_id"}
                />
                <DetailRow
                  label="Grantee ID"
                  value={nodeData.grantee_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.grantee_id, "grantee_id")}
                  isCopied={copiedKey === "grantee_id"}
                />
                {/* Scope Details */}
                <div className="pt-2 border-t border-obsidian-750">
                  <div className="text-[11px] font-mono text-slate-400 mb-1.5">Attenuated Scope</div>
                  <div className="flex flex-wrap gap-1.5">
                    {nodeData.scope?.allowed?.map((s: string) => (
                      <span
                        key={s}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30"
                      >
                        {s}
                      </span>
                    )) || <span className="text-xs text-slate-500">None</span>}
                  </div>
                </div>
              </div>
            )}

            {/* Agent Node Details */}
            {kind === "agent" && (
              <div className="space-y-3">
                <DetailRow
                  label="AIP-ID (Identity)"
                  value={nodeData.aip_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.aip_id, "aip_id")}
                  isCopied={copiedKey === "aip_id"}
                />
                <DetailRow
                  label="Algorithm"
                  value={nodeData.algorithm || "Ed25519"}
                />
                <DetailRow
                  label="Public Key Fingerprint"
                  value={formatFingerprint(nodeData.public_key)}
                  subtext={nodeData.public_key}
                  onCopy={() => handleCopy(nodeData.public_key, "public_key")}
                  isCopied={copiedKey === "public_key"}
                />
                {nodeData.provenance && (
                  <div className="p-3 rounded-lg bg-obsidian-850 border border-obsidian-700 space-y-2">
                    <div className="text-[11px] font-mono text-slate-400 font-bold uppercase tracking-wider">
                      Provenance Commitment
                    </div>
                    <div className="text-xs space-y-1">
                      <div><span className="text-slate-500">Model:</span> <span className="font-mono text-slate-200">{nodeData.provenance.model || nodeData.provenance.model_hash || "N/A"}</span></div>
                      <div><span className="text-slate-500">Environment:</span> <span className="font-mono text-slate-200">{nodeData.provenance.environment || "N/A"}</span></div>
                      <div><span className="text-slate-500">Toolchain:</span> <span className="font-mono text-slate-200">{nodeData.provenance.toolchain || "N/A"}</span></div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Decision Node Details */}
            {kind === "decision" && (
              <div className="space-y-3">
                <DetailRow
                  label="Decision ID"
                  value={nodeData.decision_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.decision_id, "decision_id")}
                  isCopied={copiedKey === "decision_id"}
                />
                <DetailRow
                  label="Action Kind"
                  value={
                    typeof nodeData.action_kind === "object"
                      ? `${nodeData.action_kind.kind}: ${nodeData.action_kind.action}`
                      : nodeData.action_kind || "Standard"
                  }
                />
                <DetailRow
                  label="Decided At"
                  value={formatTimestamp(nodeData.decided_at)}
                />
                <DetailRow
                  label="Summary"
                  value={nodeData.summary || "N/A (Not Provided)"}
                />
                <DetailRow
                  label="Input Hash"
                  value={formatFingerprint(nodeData.input_hash)}
                  subtext={nodeData.input_hash}
                  onCopy={() => handleCopy(nodeData.input_hash, "input_hash")}
                  isCopied={copiedKey === "input_hash"}
                />
                <DetailRow
                  label="Rationale Hash"
                  value={formatFingerprint(nodeData.rationale_hash)}
                  subtext={nodeData.rationale_hash}
                  onCopy={() => handleCopy(nodeData.rationale_hash, "rationale_hash")}
                  isCopied={copiedKey === "rationale_hash"}
                />
              </div>
            )}

            {/* Action Node Details */}
            {kind === "action" && (
              <div className="space-y-3">
                <DetailRow
                  label="Action ID"
                  value={nodeData.action_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.action_id, "action_id")}
                  isCopied={copiedKey === "action_id"}
                />
                <DetailRow
                  label="Description"
                  value={nodeData.description || "N/A (Not Provided)"}
                />
                <DetailRow
                  label="Performed At"
                  value={formatTimestamp(nodeData.performed_at)}
                />
                <DetailRow
                  label="Payload Hash"
                  value={formatFingerprint(nodeData.payload_hash)}
                  subtext={nodeData.payload_hash}
                  onCopy={() => handleCopy(nodeData.payload_hash, "payload_hash")}
                  isCopied={copiedKey === "payload_hash"}
                />
              </div>
            )}

            {/* Receipt Node Details */}
            {kind === "receipt" && (
              <div className="space-y-3">
                <DetailRow
                  label="Receipt System"
                  value={nodeData.receipt_system || "N/A (Not Provided)"}
                />
                <DetailRow
                  label="Receipt ID"
                  value={nodeData.receipt_id || "N/A (Not Provided)"}
                  onCopy={() => handleCopy(nodeData.receipt_id, "receipt_id")}
                  isCopied={copiedKey === "receipt_id"}
                />
                <DetailRow
                  label="Receipt Hash"
                  value={formatFingerprint(nodeData.receipt_hash)}
                  subtext={nodeData.receipt_hash}
                  onCopy={() => handleCopy(nodeData.receipt_hash, "receipt_hash")}
                  isCopied={copiedKey === "receipt_hash"}
                />
                <DetailRow
                  label="Counterparty Status"
                  value={
                    nodeData.countersigned
                      ? "Countersigned (Level 3 Bilateral Verification)"
                      : "Hash Only (Unilateral Receipt)"
                  }
                />
                {nodeData.counterparty_id && (
                  <DetailRow
                    label="Counterparty ID"
                    value={nodeData.counterparty_id}
                    onCopy={() => handleCopy(nodeData.counterparty_id, "counterparty_id")}
                    isCopied={copiedKey === "counterparty_id"}
                  />
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Rule Checks Tab ── */}
        {activeTab === "rules" && (
          <div className="space-y-3">
            <div className="text-xs text-slate-400">
              Direct 1:1 evaluation results from Rust verification engine:
            </div>
            {associatedRules.length === 0 ? (
              <div className="text-xs text-slate-500 italic p-4 text-center bg-obsidian-850 rounded">
                No direct rule checks mapped for this node kind.
              </div>
            ) : (
              associatedRules.map((ruleResult) => (
                <div
                  key={ruleResult.rule}
                  className={`p-3 rounded-lg border text-xs space-y-1.5 ${
                    ruleResult.pass
                      ? "bg-cyber-green/5 border-cyber-green/30"
                      : "bg-cyber-red/5 border-cyber-red/30"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-slate-200">
                      {ruleResult.rule}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                        ruleResult.pass
                          ? "bg-cyber-green/20 text-cyber-green"
                          : "bg-cyber-red/20 text-cyber-red"
                      }`}
                    >
                      {ruleResult.pass ? "PASS" : "FAIL"}
                    </span>
                  </div>
                  <p className="text-slate-300 font-mono text-[11px] leading-relaxed">
                    {ruleResult.detail}
                  </p>
                </div>
              ))
            )}
          </div>
        )}

        {/* ── Raw JSON Tab ── */}
        {activeTab === "json" && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400">JSON Payload</span>
              <button
                onClick={() =>
                  handleCopy(JSON.stringify(nodeData, null, 2), "raw_json")
                }
                className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-obsidian-800 hover:bg-obsidian-750 border border-obsidian-700 text-xs font-mono text-cyber-cyan transition-colors"
              >
                {copiedKey === "raw_json" ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-cyber-green" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" /> Copy JSON
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 rounded-lg bg-obsidian-950 border border-obsidian-750 font-mono text-[11px] text-slate-200 overflow-x-auto leading-relaxed">
              <code>{JSON.stringify(nodeData, null, 2)}</code>
            </pre>
          </div>
        )}
      </div>
    </aside>
  );
};

// Reusable Detail Row
const DetailRow: React.FC<{
  label: string;
  value: string;
  subtext?: string;
  onCopy?: () => void;
  isCopied?: boolean;
}> = ({ label, value, subtext, onCopy, isCopied }) => {
  return (
    <div className="p-2.5 rounded-lg bg-obsidian-850 border border-obsidian-750 flex flex-col gap-1">
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span>{label}</span>
        {onCopy && (
          <button
            onClick={onCopy}
            className="text-slate-500 hover:text-cyber-cyan transition-colors"
            title="Copy value"
          >
            {isCopied ? (
              <Check className="w-3 h-3 text-cyber-green" />
            ) : (
              <Copy className="w-3 h-3" />
            )}
          </button>
        )}
      </div>
      <div className="font-mono text-xs text-slate-100 break-all select-all">
        {value}
      </div>
      {subtext && (
        <div className="font-mono text-[10px] text-slate-500 break-all">
          {subtext}
        </div>
      )}
    </div>
  );
};
```

---

### Component 2: `src/components/graph/BreadcrumbTrail.tsx`

```typescript
"use client";

import React, { useMemo } from "react";
import { ChevronRight, ShieldCheck, Key, Layers, Cpu, Fingerprint, Clock, Shield } from "lucide-react";
import type { GraphNode, GraphEdge } from "@/lib/wasm/types";

export interface BreadcrumbTrailProps {
  selectedNodeId: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  onSelectNode: (nodeId: string) => void;
}

export const BreadcrumbTrail: React.FC<BreadcrumbTrailProps> = ({
  selectedNodeId,
  nodes,
  edges,
  onSelectNode,
}) => {
  // Reconstruct linear custody chain from root principal to selectedNode
  const custodyChain = useMemo(() => {
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const incomingMap = new Map<string, string[]>();

    for (const edge of edges) {
      const target = edge.target || edge.to;
      const source = edge.source || edge.from;
      if (!incomingMap.has(target)) incomingMap.set(target, []);
      incomingMap.get(target)!.push(source);
    }

    const chain: GraphNode[] = [];
    let curr: string | undefined = selectedNodeId;
    const visited = new Set<string>();

    while (curr && !visited.has(curr)) {
      visited.add(curr);
      const node = nodeMap.get(curr);
      if (node) chain.unshift(node);
      const parents = incomingMap.get(curr);
      if (!parents || parents.length === 0) break;
      curr = parents[0]; // Walk upstream
    }

    return chain;
  }, [selectedNodeId, nodes, edges]);

  const getNodeIcon = (kind: string) => {
    switch (kind.toLowerCase()) {
      case "principal": return <ShieldCheck className="w-3 h-3" />;
      case "authority_grant": return <Key className="w-3 h-3" />;
      case "delegation": return <Layers className="w-3 h-3" />;
      case "agent": return <Cpu className="w-3 h-3" />;
      case "decision": return <Fingerprint className="w-3 h-3" />;
      case "action": return <Clock className="w-3 h-3" />;
      case "receipt": return <Shield className="w-3 h-3" />;
      default: return null;
    }
  };

  const getNodeLabel = (node: GraphNode) => {
    const k = (node.kind || "").toLowerCase();
    if (k === "principal") return "Principal";
    if (k === "authority_grant") return "Root Token";
    if (k === "delegation") return `Hop ${node.id.split(":")[1] || 0}`;
    if (k === "agent") return "Agent";
    if (k === "decision") return "Decision";
    if (k === "action") return `Action ${node.id.split(":")[1] || 0}`;
    if (k === "receipt") return "Receipt";
    return node.label || node.id;
  };

  return (
    <nav className="flex items-center flex-wrap gap-1 text-[11px] font-mono">
      {custodyChain.map((node, index) => {
        const isCurrent = node.id === selectedNodeId;
        const isVerified = node.verified ?? true;

        return (
          <React.Fragment key={node.id}>
            {index > 0 && (
              <ChevronRight className="w-3 h-3 text-slate-600 shrink-0" />
            )}
            <button
              type="button"
              onClick={() => onSelectNode(node.id)}
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded transition-all ${
                isCurrent
                  ? "bg-cyber-cyan/20 border border-cyber-cyan text-cyber-cyan font-bold shadow-cyan-glow"
                  : "bg-obsidian-800 hover:bg-obsidian-750 text-slate-300 border border-obsidian-700"
              }`}
            >
              <span className={isVerified ? "text-cyber-cyan" : "text-cyber-red"}>
                {getNodeIcon(node.kind)}
              </span>
              <span>{getNodeLabel(node)}</span>
            </button>
          </React.Fragment>
        );
      })}
    </nav>
  );
};
```

---

### Component 3: `src/components/graph/GraphControls.tsx`

```typescript
"use client";

import React, { useState } from "react";
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  SlidersHorizontal,
  Download,
  ArrowRightLeft,
  ArrowDownUp,
  Filter,
  Check,
} from "lucide-react";
import { useReactFlow } from "@xyflow/react";
import type { GraphNode, GraphEdge } from "@/lib/wasm/types";
import { exportGraphAsPng, exportGraphAsSvg, exportGraphAsDot, exportGraphAsJson } from "@/lib/graph/exportUtils";

export interface GraphControlsProps {
  layoutDirection: "LR" | "TB";
  onToggleLayout: (direction: "LR" | "TB") => void;
  visibleKinds: Set<string>;
  onToggleKind: (kind: string) => void;
  onResetFilters: () => void;
  nodeCounts: Record<string, number>;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const GraphControls: React.FC<GraphControlsProps> = ({
  layoutDirection,
  onToggleLayout,
  visibleKinds,
  onToggleKind,
  onResetFilters,
  nodeCounts,
  nodes,
  edges,
}) => {
  const { zoomIn, zoomOut, fitView, setViewport } = useReactFlow();
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);

  const filterOptions = [
    { kind: "principal", label: "Principal Root" },
    { kind: "authority_grant", label: "Authority Grant" },
    { kind: "delegation", label: "Delegation Hops" },
    { kind: "agent", label: "Agent Identity" },
    { kind: "decision", label: "Decisions" },
    { kind: "action", label: "Actions" },
    { kind: "receipt", label: "Countersigned Receipts" },
  ];

  return (
    <div className="absolute top-4 left-4 z-20 flex flex-wrap items-center gap-2 font-mono">
      {/* ── Viewport Navigation Group ── */}
      <div className="flex items-center bg-obsidian-900/90 backdrop-blur border border-obsidian-700 rounded-lg p-1 shadow-card-cyber">
        <button
          type="button"
          onClick={() => zoomIn({ duration: 300 })}
          className="p-1.5 text-slate-300 hover:text-cyber-cyan hover:bg-obsidian-800 rounded transition-colors"
          title="Zoom In (+)"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          type="button"
          onClick={() => zoomOut({ duration: 300 })}
          className="p-1.5 text-slate-300 hover:text-cyber-cyan hover:bg-obsidian-800 rounded transition-colors"
          title="Zoom Out (-)"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          type="button"
          onClick={() => fitView({ padding: 0.2, duration: 400 })}
          className="p-1.5 text-slate-300 hover:text-cyber-cyan hover:bg-obsidian-800 rounded transition-colors"
          title="Fit View"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
        <button
          type="button"
          onClick={() => setViewport({ x: 0, y: 0, zoom: 1 }, { duration: 400 })}
          className="p-1.5 text-slate-300 hover:text-cyber-cyan hover:bg-obsidian-800 rounded transition-colors"
          title="Reset Zoom (100%)"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* ── Layout Orientation Switch ── */}
      <button
        type="button"
        onClick={() => onToggleLayout(layoutDirection === "LR" ? "TB" : "LR")}
        className="inline-flex items-center gap-2 px-3 py-1.5 bg-obsidian-900/90 backdrop-blur border border-obsidian-700 hover:border-cyber-cyan/50 text-slate-200 hover:text-cyber-cyan rounded-lg text-xs transition-all shadow-card-cyber"
        title="Toggle Layout Orientation"
      >
        {layoutDirection === "LR" ? (
          <>
            <ArrowRightLeft className="w-3.5 h-3.5 text-cyber-cyan" />
            <span>Horizontal (LR)</span>
          </>
        ) : (
          <>
            <ArrowDownUp className="w-3.5 h-3.5 text-cyber-cyan" />
            <span>Vertical (TB)</span>
          </>
        )}
      </button>

      {/* ── Node Filters Dropdown ── */}
      <div className="relative">
        <button
          type="button"
          onClick={() => {
            setShowFilterMenu(!showFilterMenu);
            setShowExportMenu(false);
          }}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 bg-obsidian-900/90 backdrop-blur border rounded-lg text-xs transition-all shadow-card-cyber ${
            showFilterMenu
              ? "border-cyber-cyan text-cyber-cyan bg-obsidian-850"
              : "border-obsidian-700 text-slate-200 hover:text-cyber-cyan hover:border-cyber-cyan/50"
          }`}
        >
          <Filter className="w-3.5 h-3.5" />
          <span>Filters</span>
          <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-obsidian-800 text-cyber-cyan font-bold">
            {visibleKinds.size}/7
          </span>
        </button>

        {showFilterMenu && (
          <div className="absolute left-0 mt-2 w-64 bg-obsidian-900 border border-obsidian-700 rounded-lg shadow-2xl p-3 space-y-2 z-30 animate-fadeIn">
            <div className="flex items-center justify-between pb-2 border-b border-obsidian-750 text-xs">
              <span className="font-bold text-slate-200">Node Visibility</span>
              <button
                type="button"
                onClick={onResetFilters}
                className="text-[10px] text-cyber-cyan hover:underline"
              >
                Reset All
              </button>
            </div>
            <div className="space-y-1.5 max-h-60 overflow-y-auto">
              {filterOptions.map(({ kind, label }) => {
                const count = nodeCounts[kind] || 0;
                const isChecked = visibleKinds.has(kind);
                return (
                  <label
                    key={kind}
                    className="flex items-center justify-between text-xs p-1.5 rounded hover:bg-obsidian-850 cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2 text-slate-300">
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => onToggleKind(kind)}
                        className="rounded border-obsidian-600 bg-obsidian-950 text-cyber-cyan focus:ring-0"
                      />
                      <span>{label}</span>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-obsidian-800 text-slate-400">
                      {count}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* ── Export Tools Dropdown ── */}
      <div className="relative">
        <button
          type="button"
          onClick={() => {
            setShowExportMenu(!showExportMenu);
            setShowFilterMenu(false);
          }}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 bg-obsidian-900/90 backdrop-blur border rounded-lg text-xs transition-all shadow-card-cyber ${
            showExportMenu
              ? "border-cyber-cyan text-cyber-cyan bg-obsidian-850"
              : "border-obsidian-700 text-slate-200 hover:text-cyber-cyan hover:border-cyber-cyan/50"
          }`}
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export</span>
        </button>

        {showExportMenu && (
          <div className="absolute left-0 mt-2 w-48 bg-obsidian-900 border border-obsidian-700 rounded-lg shadow-2xl p-1.5 space-y-1 z-30 animate-fadeIn">
            <button
              type="button"
              onClick={() => {
                exportGraphAsPng();
                setShowExportMenu(false);
              }}
              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-obsidian-850 hover:text-cyber-cyan rounded transition-colors"
            >
              Export as PNG Image
            </button>
            <button
              type="button"
              onClick={() => {
                exportGraphAsSvg();
                setShowExportMenu(false);
              }}
              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-obsidian-850 hover:text-cyber-cyan rounded transition-colors"
            >
              Export as Vector SVG
            </button>
            <button
              type="button"
              onClick={() => {
                exportGraphAsDot({ nodes, edges });
                setShowExportMenu(false);
              }}
              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-obsidian-850 hover:text-cyber-cyan rounded transition-colors"
            >
              Export as Graphviz (.dot)
            </button>
            <button
              type="button"
              onClick={() => {
                exportGraphAsJson({ nodes, edges });
                setShowExportMenu(false);
              }}
              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-obsidian-850 hover:text-cyber-cyan rounded transition-colors"
            >
              Export as JSON Graph
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
```

---

### Component 4: `src/components/graph/AccountabilityGraph.tsx` (Root DAG Container)

```typescript
"use client";

import React, { useState, useMemo, useCallback } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css"; // Essential CSS import!

import { Workflow, ShieldAlert, RefreshCw, UploadCloud, Layers } from "lucide-react";
import { useConsole } from "@/lib/context/ConsoleContext";
import { useEvidence } from "@/lib/wasm/EvidenceContext";
import { InspectionSheet } from "./InspectionSheet";
import { GraphControls } from "./GraphControls";

// Node and Edge types registered with React Flow
// Handled via Explorer 1 & Explorer 2 component registry
import { PrincipalNode } from "./nodes/PrincipalNode";
import { AuthorityGrantNode } from "./nodes/AuthorityGrantNode";
import { DelegationNode } from "./nodes/DelegationNode";
import { AgentNode } from "./nodes/AgentNode";
import { DecisionNode } from "./nodes/DecisionNode";
import { ActionNode } from "./nodes/ActionNode";
import { ReceiptNode } from "./nodes/ReceiptNode";
import { VerifiedEdge } from "./edges/VerifiedEdge";
import { BrokenEdge } from "./edges/BrokenEdge";

const nodeTypes = {
  principal: PrincipalNode,
  authority_grant: AuthorityGrantNode,
  delegation: DelegationNode,
  agent: AgentNode,
  decision: DecisionNode,
  action: ActionNode,
  receipt: ReceiptNode,
};

const edgeTypes = {
  verified: VerifiedEdge,
  broken: BrokenEdge,
};

export const AccountabilityGraph: React.FC = () => {
  const { setActiveTab } = useConsole();
  const { evidence, report, graph: wasmGraph, isVerifying, error, loadFixture } = useEvidence();

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [isSheetOpen, setIsSheetOpen] = useState<boolean>(false);
  const [layoutDirection, setLayoutDirection] = useState<"LR" | "TB">("LR");

  // All 7 node kinds visible by default
  const [visibleKinds, setVisibleKinds] = useState<Set<string>>(
    new Set(["principal", "authority_grant", "delegation", "agent", "decision", "action", "receipt"])
  );

  // Raw nodes & edges from WASM or reconstructed graph
  const rawNodes = wasmGraph?.nodes || [];
  const rawEdges = wasmGraph?.edges || [];

  // Filter nodes based on visibleKinds
  const filteredNodes = useMemo(() => {
    return rawNodes.filter((n) => visibleKinds.has((n.kind || "").toLowerCase()));
  }, [rawNodes, visibleKinds]);

  const visibleNodeIds = useMemo(() => {
    return new Set(filteredNodes.map((n) => n.id));
  }, [filteredNodes]);

  // Filter edges to only those connecting visible nodes
  const filteredEdges = useMemo(() => {
    return rawEdges.filter((e) => {
      const src = e.source || e.from;
      const tgt = e.target || e.to;
      return visibleNodeIds.has(src) && visibleNodeIds.has(tgt);
    });
  }, [rawEdges, visibleNodeIds]);

  // Compute node counts per kind
  const nodeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const n of rawNodes) {
      const k = (n.kind || "unknown").toLowerCase();
      counts[k] = (counts[k] || 0) + 1;
    }
    return counts;
  }, [rawNodes]);

  // Node selection handler
  const handleNodeClick = useCallback((_event: React.MouseEvent, node: any) => {
    setSelectedNodeId(node.id);
    setIsSheetOpen(true);
  }, []);

  const handleSelectNode = useCallback((nodeId: string) => {
    setSelectedNodeId(nodeId);
    setIsSheetOpen(true);
  }, []);

  const toggleKind = useCallback((kind: string) => {
    setVisibleKinds((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  }, []);

  const resetFilters = useCallback(() => {
    setVisibleKinds(
      new Set(["principal", "authority_grant", "delegation", "agent", "decision", "action", "receipt"])
    );
  }, []);

  // Currently selected node object
  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    return rawNodes.find((n) => n.id === selectedNodeId) || null;
  }, [selectedNodeId, rawNodes]);

  // ── State 1: Loading State ──
  if (isVerifying) {
    return (
      <div className="cyber-panel p-12 min-h-[560px] flex flex-col items-center justify-center text-center">
        <RefreshCw className="w-12 h-12 text-cyber-cyan animate-spin mb-4" />
        <h3 className="text-lg font-bold text-slate-100">
          Reconstructing Accountability DAG
        </h3>
        <p className="text-xs text-slate-400 mt-2 font-mono">
          Evaluating WebAssembly verification ledger & calculating cryptographic lineage...
        </p>
      </div>
    );
  }

  // ── State 2: Error State ──
  if (error) {
    return (
      <div className="cyber-panel p-8 min-h-[480px] flex flex-col items-center justify-center text-center">
        <ShieldAlert className="w-14 h-14 text-cyber-red mb-4 animate-pulse" />
        <h3 className="text-lg font-bold text-cyber-red">Verification Engine Error</h3>
        <p className="text-xs text-slate-300 font-mono mt-2 max-w-md bg-obsidian-950 p-3 rounded border border-cyber-red/30">
          {error}
        </p>
        <button
          type="button"
          onClick={() => setActiveTab("ingestion")}
          className="mt-6 px-4 py-2 rounded bg-obsidian-800 hover:bg-obsidian-750 text-cyber-cyan text-xs font-mono border border-cyber-cyan/40"
        >
          Return to Ingestion View
        </button>
      </div>
    );
  }

  // ── State 3: Empty State (No Evidence Loaded) ──
  if (!evidence || rawNodes.length === 0) {
    return (
      <div className="cyber-panel p-12 min-h-[560px] flex flex-col items-center justify-center text-center">
        <div className="p-4 rounded-2xl bg-cyber-cyan/5 border border-cyber-cyan/20 mb-4 shadow-cyan-glow">
          <Workflow className="w-12 h-12 text-cyber-cyan" />
        </div>
        <h3 className="text-xl font-bold text-slate-100 mb-2">
          Accountability Graph Inactive
        </h3>
        <p className="text-sm text-slate-400 max-w-md mb-6 leading-relaxed">
          No active EvidencePacket loaded. Upload a verified JSON packet, drop an audit ZIP bundle, or load a pre-compiled fixture to view the cryptographic DAG.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => loadFixture("honest_counterparty")}
            className="px-4 py-2 rounded-lg bg-cyber-cyan/10 hover:bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono transition-all font-bold shadow-cyan-glow"
          >
            Load Honest Counterparty (L3)
          </button>
          <button
            type="button"
            onClick={() => loadFixture("authority_bound")}
            className="px-4 py-2 rounded-lg bg-obsidian-800 hover:bg-obsidian-750 border border-obsidian-700 text-slate-200 text-xs font-mono transition-colors"
          >
            Load Authority Bound (L2)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("ingestion")}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-obsidian-800 hover:bg-obsidian-750 border border-obsidian-700 text-slate-300 text-xs font-mono transition-colors"
          >
            <UploadCloud className="w-4 h-4" /> Go to Ingestion
          </button>
        </div>
      </div>
    );
  }

  // ── State 4: Active Interactive Graph ──
  return (
    <div className="relative w-full h-[720px] rounded-lg border border-obsidian-700 bg-obsidian-950 overflow-hidden shadow-card-cyber">
      {/* Canvas Controls Toolbar */}
      <GraphControls
        layoutDirection={layoutDirection}
        onToggleLayout={(dir) => setLayoutDirection(dir)}
        visibleKinds={visibleKinds}
        onToggleKind={toggleKind}
        onResetFilters={resetFilters}
        nodeCounts={nodeCounts}
        nodes={rawNodes}
        edges={rawEdges}
      />

      {/* React Flow Viewport */}
      <ReactFlow
        nodes={filteredNodes as any}
        edges={filteredEdges as any}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={handleNodeClick}
        fitView
        minZoom={0.2}
        maxZoom={2.0}
        proOptions={{ hideAttribution: true }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={24}
          size={1.5}
          color="#161F33"
        />
        <MiniMap
          nodeColor={(node: any) => {
            switch (node.type || node.kind) {
              case "principal": return "#00E676";
              case "authority_grant": return "#00E5FF";
              case "agent": return "#6366F1";
              case "decision": return "#FFB300";
              case "receipt": return "#00E676";
              default: return "#334155";
            }
          }}
          maskColor="rgba(8, 11, 17, 0.85)"
          className="!bottom-4 !right-4 !border-obsidian-700 !bg-obsidian-900/90 rounded-lg shadow-card-cyber"
        />
      </ReactFlow>

      {/* Slide-out Inspection Sheet Drawer */}
      <InspectionSheet
        isOpen={isSheetOpen}
        onClose={() => setIsSheetOpen(false)}
        selectedNode={selectedNode}
        nodes={rawNodes}
        edges={rawEdges}
        report={report}
        onSelectNode={handleSelectNode}
      />
    </div>
  );
};
```

---

### Component 5: `src/lib/graph/exportUtils.ts` (Multi-Format Graph Export)

```typescript
import type { GraphNode, GraphEdge } from "@/lib/wasm/types";

/**
 * Trigger browser file download
 */
function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * 1. Export Graph as Graphviz DOT string
 * Conforms to F9.5 / P1.4 test assertions in Vitest E2E suite
 */
export function exportGraphAsDot(
  graph: { nodes: GraphNode[]; edges: GraphEdge[] },
  filename = "accountability-graph.dot"
) {
  const lines: string[] = ["digraph AccountabilityGraph {", "  rankdir=LR;"];
  for (const node of graph.nodes) {
    const k = (node.kind || "").toLowerCase();
    const shape =
      k === "principal"
        ? "house"
        : k === "authority_grant"
        ? "note"
        : k === "delegation"
        ? "cds"
        : k === "agent"
        ? "component"
        : k === "decision"
        ? "diamond"
        : k === "action"
        ? "box"
        : "tab";
    lines.push(
      `  "${node.id}" [label="${(node.label || node.id).replace(/"/g, '\\"')}", shape="${shape}"];`
    );
  }
  for (const edge of graph.edges) {
    const src = edge.source || edge.from;
    const tgt = edge.target || edge.to;
    lines.push(`  "${src}" -> "${tgt}" [label="${edge.relation}"];`);
  }
  lines.push("}");
  const dotStr = lines.join("\n");
  const blob = new Blob([dotStr], { type: "text/vnd.graphviz;charset=utf-8" });
  downloadBlob(blob, filename);
}

/**
 * 2. Export Graph as JSON
 */
export function exportGraphAsJson(
  graph: { nodes: GraphNode[]; edges: GraphEdge[] },
  filename = "accountability-graph.json"
) {
  const jsonStr = JSON.stringify(graph, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
  downloadBlob(blob, filename);
}

/**
 * 3. Export Graph as SVG
 */
export function exportGraphAsSvg(filename = "accountability-graph.svg") {
  const viewport = document.querySelector(".react-flow__viewport");
  if (!viewport) {
    console.warn("React Flow viewport element not found for SVG export");
    return;
  }
  const svgData = new XMLSerializer().serializeToString(viewport);
  const fullSvg = `<svg xmlns="http://www.w3.org/2000/svg" style="background:#080B11;">${svgData}</svg>`;
  const blob = new Blob([fullSvg], { type: "image/svg+xml;charset=utf-8" });
  downloadBlob(blob, filename);
}

/**
 * 4. Export Graph as PNG Image
 */
export async function exportGraphAsPng(filename = "accountability-graph.png") {
  const viewport = document.querySelector(".react-flow__viewport");
  if (!viewport) return;

  const svgData = new XMLSerializer().serializeToString(viewport);
  const svgBlob = new Blob(
    [`<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" style="background:#080B11;">${svgData}</svg>`],
    { type: "image/svg+xml;charset=utf-8" }
  );
  const url = URL.createObjectURL(svgBlob);
  const img = new Image();

  img.onload = () => {
    const canvas = document.createElement("canvas");
    canvas.width = 1600;
    canvas.height = 900;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.fillStyle = "#080B11";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);
      canvas.toBlob((blob) => {
        if (blob) downloadBlob(blob, filename);
        URL.revokeObjectURL(url);
      }, "image/png");
    }
  };
  img.src = url;
}
```

---

### Component 6: Live Integration into Pages

#### A. In `src/app/page.tsx` (Tab 2 Replacement):
Replace lines 112–141 with:
```tsx
{/* Tab 2 (R2): Accountability Graph DAG View */}
<div className={activeTab === "graph" ? "block space-y-4" : "hidden"}>
  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-obsidian-700">
    <div>
      <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
        <Workflow className="w-5 h-5 text-cyber-cyan" />
        Interactive Accountability Graph (DAG)
      </h1>
      <p className="text-xs text-slate-400 mt-1">
        Visualizing cryptographic chain of custody: Principal → Authority Grant → Delegation Hops → Agent → Decision → Actions → Countersigned Receipt.
      </p>
    </div>
  </div>

  <AccountabilityGraph />
</div>
```

#### B. In `src/app/graph/page.tsx`:
Ensure direct visits to `/graph` preserve seamless loading and display:
```tsx
"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useConsole } from "@/lib/context/ConsoleContext";

export default function GraphRoute() {
  const { setActiveTab } = useConsole();
  const router = useRouter();

  useEffect(() => {
    setActiveTab("graph");
    router.replace("/");
  }, [setActiveTab, router]);

  return null;
}
```

---

## 5. Verification Method

1. **Verify E2E Suite Integrity**:
   Run the full Vitest E2E suite to guarantee zero regression:
   ```bash
   npm run test:e2e
   ```
   Confirm 260/260 tests pass.

2. **Verify Specific Feature & Boundary Specifications**:
   ```bash
   npx vitest run e2e/tier1-features/f09_dag_viewer.spec.ts
   npx vitest run e2e/tier1-features/f10_inspection_sheet.spec.ts
   npx vitest run e2e/tier2-boundary/f09_dag_boundary.spec.ts
   npx vitest run e2e/tier2-boundary/f10_inspection_boundary.spec.ts
   npx vitest run e2e/tier3-combinations/pipeline1_ingest_verify_dag.spec.ts
   ```

3. **Verify UI Invariants**:
   - Verify that clicking any node displays `InspectionSheet` with formatted 19-char public key fingerprint (`f10_inspection_boundary.spec.ts:16-21`).
   - Verify that empty node data uses default fallback `"N/A (Not Provided)"` (`f10_inspection_boundary.spec.ts:10-12`).
   - Verify that timestamps are formatted as ISO-8601 (`f10_inspection_boundary.spec.ts:36-38`).
   - Verify that receipt in Hash-Only mode without counterparty signature renders with `countersigned: false` badge without errors (`f10_inspection_boundary.spec.ts:40-51`).
   - Verify DOT export produces `digraph AccountabilityGraph` with standard shapes `house`, `note`, `cds`, `component`, `diamond`, `box`, `tab` (`f09_dag_viewer.spec.ts:45-52`).

4. **Invalidation Conditions**:
   - Any modification to verification logic in TypeScript (verification must remain 100% in Rust WASM).
   - Any omission of `@xyflow/react/dist/style.css` resulting in unstyled canvas nodes.
   - Any breaking of the BFS single-principal reachability invariant.
