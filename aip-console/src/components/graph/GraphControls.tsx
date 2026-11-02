"use client";

import React, { useState } from "react";
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Download,
  ArrowRightLeft,
  ArrowDownUp,
  Filter,
} from "lucide-react";
import { useReactFlow } from "@xyflow/react";
import type { AccountabilityFlowNode, AccountabilityFlowEdge, LayoutDirection } from "./types";
import {
  exportGraphAsPng,
  exportGraphAsSvg,
  exportGraphAsDot,
  exportGraphAsJson,
} from "./exportUtils";

export interface GraphControlsProps {
  layoutDirection: LayoutDirection;
  onToggleLayout: (direction: LayoutDirection) => void;
  visibleKinds: Set<string>;
  onToggleKind: (kind: string) => void;
  onResetFilters: () => void;
  nodeCounts: Record<string, number>;
  nodes: AccountabilityFlowNode[];
  edges: AccountabilityFlowEdge[];
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
      <div className="flex items-center bg-obsidian-900/95 backdrop-blur border border-obsidian-700 rounded-md p-1 shadow-card">
        <button
          type="button"
          onClick={() => zoomIn({ duration: 300 })}
          className="p-1.5 text-slate-300 hover:text-corporate-steel-light hover:bg-obsidian-800 rounded transition-colors cursor-pointer"
          title="Zoom In (+)"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          type="button"
          onClick={() => zoomOut({ duration: 300 })}
          className="p-1.5 text-slate-300 hover:text-corporate-steel-light hover:bg-obsidian-800 rounded transition-colors cursor-pointer"
          title="Zoom Out (-)"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          type="button"
          onClick={() => fitView({ padding: 0.2, duration: 400 })}
          className="p-1.5 text-slate-300 hover:text-corporate-steel-light hover:bg-obsidian-800 rounded transition-colors cursor-pointer"
          title="Fit View"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
        <button
          type="button"
          onClick={() => setViewport({ x: 40, y: 40, zoom: 1 }, { duration: 400 })}
          className="p-1.5 text-slate-300 hover:text-corporate-steel-light hover:bg-obsidian-800 rounded transition-colors cursor-pointer"
          title="Reset View (100%)"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* ── Layout Direction Switcher ── */}
      <button
        type="button"
        onClick={() => onToggleLayout(layoutDirection === "LR" ? "TB" : "LR")}
        className="inline-flex items-center gap-2 px-3 py-1.5 bg-obsidian-900/95 backdrop-blur border border-obsidian-700 hover:border-corporate-steel/50 text-slate-200 hover:text-corporate-steel-light rounded-md text-xs transition-all shadow-card cursor-pointer"
        title="Toggle Layout Direction (Horizontal vs Vertical)"
      >
        {layoutDirection === "LR" ? (
          <>
            <ArrowRightLeft className="w-3.5 h-3.5 text-corporate-steel-light" />
            <span>Horizontal (LR)</span>
          </>
        ) : (
          <>
            <ArrowDownUp className="w-3.5 h-3.5 text-corporate-steel-light" />
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
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 bg-obsidian-900/95 backdrop-blur border rounded-md text-xs transition-all shadow-card cursor-pointer ${
            showFilterMenu
              ? "border-corporate-steel text-corporate-steel-light bg-obsidian-850"
              : "border-obsidian-700 text-slate-200 hover:text-corporate-steel-light hover:border-corporate-steel/50"
          }`}
        >
          <Filter className="w-3.5 h-3.5" />
          <span>Filters</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] bg-obsidian-800 text-corporate-steel-light font-bold">
            {visibleKinds.size}/7
          </span>
        </button>

        {showFilterMenu && (
          <div className="absolute left-0 mt-2 w-64 bg-obsidian-900 border border-obsidian-700 rounded-md shadow-2xl p-3 space-y-2 z-30">
            <div className="flex items-center justify-between pb-2 border-b border-obsidian-700 text-xs">
              <span className="font-bold text-slate-200">Node Visibility</span>
              <button
                type="button"
                onClick={onResetFilters}
                className="text-[10px] text-corporate-steel-light hover:underline cursor-pointer"
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
                        className="rounded border-obsidian-600 bg-obsidian-950 text-corporate-steel-light focus:ring-0 cursor-pointer"
                      />
                      <span>{label}</span>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-obsidian-800 text-slate-400 font-bold">
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
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 bg-obsidian-900/95 backdrop-blur border rounded-md text-xs transition-all shadow-card cursor-pointer ${
            showExportMenu
              ? "border-corporate-steel text-corporate-steel-light bg-obsidian-850"
              : "border-obsidian-700 text-slate-200 hover:text-corporate-steel-light hover:border-corporate-steel/50"
          }`}
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export</span>
        </button>

        {showExportMenu && (
          <div className="absolute left-0 mt-2 w-52 bg-obsidian-900 border border-obsidian-700 rounded-md shadow-2xl p-1.5 space-y-1 z-30">
            <button
              type="button"
              onClick={() => {
                exportGraphAsPng();
                setShowExportMenu(false);
              }}
              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-obsidian-850 hover:text-corporate-steel-light rounded transition-colors cursor-pointer"
            >
              Export as PNG Image
            </button>
            <button
              type="button"
              onClick={() => {
                exportGraphAsSvg();
                setShowExportMenu(false);
              }}
              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-obsidian-850 hover:text-corporate-steel-light rounded transition-colors cursor-pointer"
            >
              Export as Vector SVG
            </button>
            <button
              type="button"
              onClick={() => {
                exportGraphAsDot({ nodes, edges });
                setShowExportMenu(false);
              }}
              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-obsidian-850 hover:text-corporate-steel-light rounded transition-colors cursor-pointer"
            >
              Export as Graphviz (.dot)
            </button>
            <button
              type="button"
              onClick={() => {
                exportGraphAsJson({ nodes, edges });
                setShowExportMenu(false);
              }}
              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-obsidian-850 hover:text-corporate-steel-light rounded transition-colors cursor-pointer"
            >
              Export as JSON Graph
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
