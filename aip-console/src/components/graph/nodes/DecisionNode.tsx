"use client";

import React from "react";
import type { NodeProps } from "@xyflow/react";
import { Brain, Scale } from "lucide-react";
import { BaseNodeCard } from "./BaseNodeCard";
import type { AccountabilityFlowNode } from "../types";

export function DecisionNode({ data, selected }: NodeProps<AccountabilityFlowNode>) {
  const actionKindText =
    typeof data.action_kind === "object" && data.action_kind !== null
      ? `${data.action_kind.kind || "Standard"}: ${data.action_kind.action || "Write"}`
      : String(data.action_kind || "Standard");

  return (
    <BaseNodeCard
      id={data.id}
      selected={selected}
      kindLabel="Agent Decision"
      icon={<Brain className="w-4 h-4" />}
      verified={data.verified}
      accentColor="blue"
      layoutDirection={data.layoutDirection}
      hasTargetHandle={true}
      hasSourceHandle={true}
    >
      <div className="space-y-1.5 font-mono">
        <div
          className="text-xs text-slate-100 font-medium line-clamp-2"
          title={data.summary || data.label}
        >
          {data.summary || data.label || "Agent reasoning rationale"}
        </div>

        {/* Action Kind Badge */}
        <div className="flex items-center justify-between text-[10px] bg-obsidian-800 px-2 py-1 rounded border border-obsidian-700">
          <span className="text-slate-400">Action:</span>
          <span className="text-corporate-info-light font-semibold truncate max-w-[170px]" title={actionKindText}>
            {actionKindText}
          </span>
        </div>

        <div className="flex items-center justify-between text-[9px] text-slate-400 pt-0.5">
          <span>Decided: {data.decided_at_iso ? data.decided_at_iso.slice(11, 19) : "N/A"}</span>
          <span className="text-corporate-steel-light flex items-center gap-0.5 font-semibold">
            <Scale className="w-2.5 h-2.5" /> Scope Checked
          </span>
        </div>
      </div>
    </BaseNodeCard>
  );
}
