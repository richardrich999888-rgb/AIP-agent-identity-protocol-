"use client";

import React, { useState, useMemo, useCallback } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  MiniMap,
  BackgroundVariant,
  type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { Workflow, ShieldAlert, RefreshCw, UploadCloud } from "lucide-react";
import { useConsole } from "@/lib/context/ConsoleContext";
import { useEvidence } from "@/lib/wasm/EvidenceContext";
import { nodeTypes } from "./nodes";
import { edgeTypes, EdgeMarkerDefs } from "./edges";
import { GraphControls } from "./GraphControls";
import { InspectionSheet } from "./InspectionSheet";
import { transformWasmGraphToFlow } from "./transformer";
import type { LayoutDirection, AccountabilityFlowNode } from "./types";

export const AccountabilityGraph: React.FC = () => {
  const { loadedPacket, setActiveTab } = useConsole();
  const { evidence, report, graph: wasmGraph, isVerifying, error, loadFixture } = useEvidence();

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [isSheetOpen, setIsSheetOpen] = useState<boolean>(false);
  const [layoutDirection, setLayoutDirection] = useState<LayoutDirection>("LR");

  // All 7 node kinds visible by default
  const [visibleKinds, setVisibleKinds] = useState<Set<string>>(
    new Set(["principal", "authority_grant", "delegation", "agent", "decision", "action", "receipt"])
  );

  // Derive enriched graph data
  const flowGraph = useMemo(() => {
    if (!loadedPacket) return null;
    try {
      return transformWasmGraphToFlow({
        packet: loadedPacket,
        report,
        direction: layoutDirection,
        onSelectNode: (id: string) => {
          setSelectedNodeId(id);
          setIsSheetOpen(true);
        },
      });
    } catch (err) {
      console.warn("Failed to transform graph to flow:", err);
      return null;
    }
  }, [loadedPacket, report, layoutDirection]);

  const rawNodes = useMemo(() => flowGraph?.nodes || [], [flowGraph]);
  const rawEdges = useMemo(() => flowGraph?.edges || [], [flowGraph]);

  // Compute node counts per kind
  const nodeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const n of rawNodes) {
      const k = (n.data?.kind || n.type || "unknown").toLowerCase();
      counts[k] = (counts[k] || 0) + 1;
    }
    return counts;
  }, [rawNodes]);

  // Filter nodes based on visibleKinds
  const filteredNodes = useMemo(() => {
    return rawNodes.filter((n) => visibleKinds.has((n.data?.kind || n.type || "").toLowerCase()));
  }, [rawNodes, visibleKinds]);

  const visibleNodeIds = useMemo(() => {
    return new Set(filteredNodes.map((n) => n.id));
  }, [filteredNodes]);

  // Filter edges to only those connecting visible nodes
  const filteredEdges = useMemo(() => {
    return rawEdges.filter((e) => {
      const src = e.source || (e as any).from;
      const tgt = e.target || (e as any).to;
      return visibleNodeIds.has(src) && visibleNodeIds.has(tgt);
    });
  }, [rawEdges, visibleNodeIds]);

  // Node selection handlers
  const handleNodeClick: NodeMouseHandler<AccountabilityFlowNode> = useCallback(
    (_event, node) => {
      setSelectedNodeId(node.id);
      setIsSheetOpen(true);
    },
    []
  );

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

  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    return rawNodes.find((n) => n.id === selectedNodeId) || null;
  }, [selectedNodeId, rawNodes]);

  // ── State 1: Loading State ──
  if (isVerifying) {
    return (
      <div className="corporate-panel p-12 min-h-[560px] flex flex-col items-center justify-center text-center">
        <RefreshCw className="w-12 h-12 text-corporate-steel-light animate-spin mb-4" />
        <h3 className="text-lg font-bold text-slate-100 font-mono">
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
      <div className="corporate-panel p-8 min-h-[480px] flex flex-col items-center justify-center text-center">
        <ShieldAlert className="w-14 h-14 text-corporate-danger-light mb-4" />
        <h3 className="text-lg font-bold text-corporate-danger-light font-mono">Verification Engine Error</h3>
        <p className="text-xs text-slate-300 font-mono mt-2 max-w-md bg-obsidian-950 p-3 rounded border border-corporate-danger/30">
          {error}
        </p>
        <button
          type="button"
          onClick={() => setActiveTab("ingestion")}
          className="mt-6 px-4 py-2 rounded bg-obsidian-800 hover:bg-obsidian-700 text-corporate-steel-light text-xs font-mono border border-corporate-steel/40 transition-colors cursor-pointer"
        >
          Return to Ingestion View
        </button>
      </div>
    );
  }

  // ── State 3: Empty State (No Evidence Loaded) ──
  if (!loadedPacket || rawNodes.length === 0) {
    return (
      <div className="corporate-panel p-12 min-h-[560px] flex flex-col items-center justify-center text-center">
        <div className="p-4 rounded-md bg-corporate-steel/5 border border-corporate-steel/20 mb-4">
          <Workflow className="w-12 h-12 text-corporate-steel-light" />
        </div>
        <h3 className="text-xl font-bold text-slate-100 mb-2 font-mono">
          Accountability Graph Inactive
        </h3>
        <p className="text-sm text-slate-400 max-w-md mb-6 leading-relaxed">
          No active EvidencePacket loaded. Upload a verified JSON packet, drop an audit ZIP bundle, or load a pre-compiled fixture to inspect the cryptographic DAG.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => loadFixture("honest_counterparty")}
            className="px-4 py-2 rounded-md bg-corporate-steel/10 hover:bg-corporate-steel/20 border border-corporate-steel/40 text-corporate-steel-light text-xs font-mono transition-all font-bold cursor-pointer"
          >
            Load Honest Counterparty (L3)
          </button>
          <button
            type="button"
            onClick={() => loadFixture("authority_bound")}
            className="px-4 py-2 rounded-md bg-obsidian-800 hover:bg-obsidian-700 border border-obsidian-700 text-slate-200 text-xs font-mono transition-colors cursor-pointer"
          >
            Load Authority Bound (L2)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("ingestion")}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-obsidian-800 hover:bg-obsidian-700 border border-obsidian-700 text-slate-300 text-xs font-mono transition-colors cursor-pointer"
          >
            <UploadCloud className="w-4 h-4" /> Go to Ingestion
          </button>
        </div>
      </div>
    );
  }

  // ── State 4: Active Interactive DAG ──
  // ReactFlowProvider lets GraphControls (a sibling of <ReactFlow>) use useReactFlow().
  return (
    <ReactFlowProvider>
    <div className="relative w-full h-[740px] rounded-md border border-obsidian-700 bg-obsidian-950 overflow-hidden shadow-card">
      {/* SVG Marker Definitions for Cyan / Crimson edge arrows */}
      <EdgeMarkerDefs />

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

      {/* React Flow Viewport Canvas */}
      <ReactFlow
        nodes={filteredNodes}
        edges={filteredEdges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={handleNodeClick}
        fitView
        minZoom={0.15}
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
            const kind = (node.data?.kind || node.type || "").toLowerCase();
            switch (kind) {
              case "principal":
                return "#607D8B";
              case "authority_grant":
              case "delegation":
                return "#3F6E9A";
              case "agent":
                return "#B7791F";
              case "decision":
                return "#3F6E9A";
              case "action":
                return "#607D8B";
              case "receipt":
                return "#2E7D32";
              default:
                return "#334155";
            }
          }}
          maskColor="rgba(8, 11, 17, 0.85)"
          className="!bottom-4 !right-4 !border-obsidian-700 !bg-obsidian-900/90 rounded-md shadow-card"
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
    </ReactFlowProvider>
  );
};
