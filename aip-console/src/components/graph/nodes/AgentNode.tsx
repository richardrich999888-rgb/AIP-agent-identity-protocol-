"use client";

import React from "react";
import type { NodeProps } from "@xyflow/react";
import { Bot, Cpu } from "lucide-react";
import { BaseNodeCard } from "./BaseNodeCard";
import type { AccountabilityFlowNode } from "../types";

export function AgentNode({ data, selected }: NodeProps<AccountabilityFlowNode>) {
  return (
    <BaseNodeCard
      id={data.id}
      selected={selected}
      kindLabel="Executing Agent"
      icon={<Bot className="w-4 h-4" />}
      verified={data.verified}
      accentColor="amber"
      layoutDirection={data.layoutDirection}
      hasTargetHandle={true}
      hasSourceHandle={true}
    >
      <div className="space-y-1.5 font-mono">
        <div
          className="text-xs font-bold text-corporate-warning-light truncate"
          title={data.aip_id || data.id}
        >
          {data.aip_id || data.id}
        </div>

        {/* Ephemeral Key Fingerprint */}
        <div className="bg-obsidian-800 p-1.5 rounded border border-obsidian-700 text-[10px]">
          <div className="text-slate-400 text-[9px]">Key Fingerprint (Ed25519):</div>
          <div className="text-slate-200 truncate" title={data.public_key_hex || data.public_key}>
            {data.fingerprint || (data.public_key ? `${data.public_key.slice(0, 8)}...${data.public_key.slice(-8)}` : "N/A")}
          </div>
        </div>

        {/* Provenance Triple */}
        <div className="flex items-center justify-between text-[9px] text-slate-400 pt-0.5">
          <span className="flex items-center gap-1 truncate max-w-[170px]" title={data.provenance?.model || "Verified Model"}>
            <Cpu className="w-2.5 h-2.5 text-corporate-warning-light shrink-0" />
            <span className="truncate">{data.provenance?.model || data.provenance?.model_hash || "Verified Model"}</span>
          </span>
          <span className="text-corporate-accent-light font-semibold">BOUND</span>
        </div>
      </div>
    </BaseNodeCard>
  );
}
