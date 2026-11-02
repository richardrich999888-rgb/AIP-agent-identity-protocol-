"use client";

import React from "react";
import type { NodeProps } from "@xyflow/react";
import { Zap } from "lucide-react";
import { BaseNodeCard } from "./BaseNodeCard";
import type { AccountabilityFlowNode } from "../types";

export function ActionNode({ data, selected }: NodeProps<AccountabilityFlowNode>) {
  const index = data.index ?? parseInt(data.id.split(":")[1] || "0", 10);

  return (
    <BaseNodeCard
      id={data.id}
      selected={selected}
      kindLabel={`Action Attestation [${index}]`}
      icon={<Zap className="w-4 h-4" />}
      verified={data.verified}
      accentColor="cyan"
      layoutDirection={data.layoutDirection}
      hasTargetHandle={true}
      hasSourceHandle={true}
      className="!w-[280px]"
    >
      <div className="space-y-1 font-mono">
        <div
          className="text-xs font-semibold text-slate-200 truncate"
          title={data.description || data.label || data.action_id}
        >
          {data.description || data.label || data.action_id || "Discrete Action"}
        </div>

        <div className="bg-obsidian-800 px-2 py-1 rounded border border-obsidian-700 flex items-center justify-between text-[10px]">
          <span className="text-slate-400">Payload Hash:</span>
          <span className="text-corporate-steel-light truncate max-w-[120px]" title={data.payload_hash}>
            {data.payload_hash ? `${data.payload_hash.slice(0, 8)}...` : "N/A"}
          </span>
        </div>

        <div className="text-[9px] text-slate-400 flex items-center justify-between pt-0.5">
          <span className="truncate max-w-[150px]" title={data.action_id}>ID: {data.action_id || data.id}</span>
          <span className="text-corporate-accent-light font-semibold">ATTESTED</span>
        </div>
      </div>
    </BaseNodeCard>
  );
}
