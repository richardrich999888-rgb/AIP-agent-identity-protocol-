"use client";

import React, { useMemo } from "react";
import {
  ChevronRight,
  ShieldCheck,
  Key,
  Layers,
  Cpu,
  Fingerprint,
  Zap,
  Receipt,
} from "lucide-react";
import type { AccountabilityFlowNode, AccountabilityFlowEdge } from "./types";

export interface BreadcrumbTrailProps {
  selectedNodeId: string;
  nodes: AccountabilityFlowNode[];
  edges: AccountabilityFlowEdge[];
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
      const target = (edge.target || (edge as any).to) as string;
      const source = (edge.source || (edge as any).from) as string;
      if (!incomingMap.has(target)) incomingMap.set(target, []);
      incomingMap.get(target)!.push(source);
    }

    const chain: AccountabilityFlowNode[] = [];
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
      case "principal":
        return <ShieldCheck className="w-3 h-3" />;
      case "authority_grant":
        return <Key className="w-3 h-3" />;
      case "delegation":
        return <Layers className="w-3 h-3" />;
      case "agent":
        return <Cpu className="w-3 h-3" />;
      case "decision":
        return <Fingerprint className="w-3 h-3" />;
      case "action":
        return <Zap className="w-3 h-3" />;
      case "receipt":
        return <Receipt className="w-3 h-3" />;
      default:
        return null;
    }
  };

  const getNodeLabel = (node: AccountabilityFlowNode) => {
    const k = (node.data?.kind || node.type || "").toLowerCase();
    if (k === "principal") return "Principal";
    if (k === "authority_grant") return "Root Token";
    if (k === "delegation") {
      const idx = typeof node.data?.hop_index === "number" ? node.data.hop_index : node.id.split(":")[1] || 0;
      return `Hop ${idx}`;
    }
    if (k === "agent") return "Agent";
    if (k === "decision") return "Decision";
    if (k === "action") {
      const idx = typeof node.data?.index === "number" ? node.data.index : node.id.split(":")[1] || 0;
      return `Action ${idx}`;
    }
    if (k === "receipt") return "Receipt";
    return node.data?.label || node.id;
  };

  if (custodyChain.length === 0) return null;

  return (
    <nav className="flex items-center flex-wrap gap-1 text-[11px] font-mono select-none" aria-label="Custody Breadcrumb Trail">
      {custodyChain.map((node, index) => {
        const isCurrent = node.id === selectedNodeId;
        const isVerified = node.data?.verified ?? true;
        const kind = (node.data?.kind || node.type || "").toLowerCase();

        return (
          <React.Fragment key={node.id}>
            {index > 0 && (
              <ChevronRight className="w-3 h-3 text-slate-600 shrink-0" />
            )}
            <button
              type="button"
              onClick={() => onSelectNode(node.id)}
              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded transition-all cursor-pointer ${
                isCurrent
                  ? "bg-corporate-steel/20 border border-corporate-steel text-corporate-steel-light font-bold"
                  : "bg-obsidian-800 hover:bg-obsidian-700 text-slate-300 border border-obsidian-700 hover:border-obsidian-600"
              }`}
              title={`Inspect ${getNodeLabel(node)} (${node.id})`}
            >
              <span className={isVerified ? "text-corporate-steel-light" : "text-corporate-danger-light"}>
                {getNodeIcon(kind)}
              </span>
              <span>{getNodeLabel(node)}</span>
            </button>
          </React.Fragment>
        );
      })}
    </nav>
  );
};
