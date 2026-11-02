"use client";

import React from "react";
import type { NodeProps } from "@xyflow/react";
import { GitBranch, Layers } from "lucide-react";
import { BaseNodeCard } from "./BaseNodeCard";
import type { AccountabilityFlowNode } from "../types";

export function DelegationNode({ data, selected }: NodeProps<AccountabilityFlowNode>) {
  const hopIdx = data.hop_index ?? 0;
  const depth = data.depth ?? hopIdx + 1;
  const attenuation = data.attenuationDelta ?? 0;

  return (
    <BaseNodeCard
      id={data.id}
      selected={selected}
      kindLabel={`Delegation Hop #${hopIdx}`}
      icon={<GitBranch className="w-4 h-4" />}
      verified={data.verified}
      accentColor="indigo"
      layoutDirection={data.layoutDirection}
      hasTargetHandle={true}
      hasSourceHandle={true}
    >
      <div className="space-y-1.5 font-mono">
        <div className="flex items-center justify-between text-[10px]">
          <span className="text-slate-400">Depth:</span>
          <span className="text-corporate-steel-light bg-obsidian-800 px-1.5 py-0.5 rounded border border-obsidian-700">
            {depth} / 8 Max
          </span>
        </div>

        {/* Attenuation Indicator */}
        <div className="bg-obsidian-800 p-1.5 rounded border border-obsidian-700 text-[10px]">
          <div className="text-slate-400 text-[9px] mb-0.5">Lattice Attenuation:</div>
          <div className="text-corporate-steel-light font-semibold flex items-center gap-1">
            <Layers className="w-3 h-3 text-corporate-info-light" />
            {attenuation < 0
              ? `Scope narrowed: ${attenuation} verbs`
              : "Identical scope (⊆)"}
          </div>
        </div>

        <div className="text-[9px] text-slate-400 truncate pt-0.5" title={`${data.issuer_id} → ${data.grantee_id}`}>
          {data.issuer_id || "Issuer"} → {data.grantee_id || "Grantee"}
        </div>
      </div>
    </BaseNodeCard>
  );
}
