"use client";

import React from "react";
import type { NodeProps } from "@xyflow/react";
import { ShieldCheck, Key } from "lucide-react";
import { BaseNodeCard } from "./BaseNodeCard";
import type { AccountabilityFlowNode } from "../types";

export function PrincipalNode({ data, selected }: NodeProps<AccountabilityFlowNode>) {
  return (
    <BaseNodeCard
      id={data.id}
      selected={selected}
      kindLabel="Principal (Root)"
      icon={<ShieldCheck className="w-4 h-4" />}
      verified={data.verified}
      accentColor="cyan"
      layoutDirection={data.layoutDirection}
      hasTargetHandle={false} // Root principal has no incoming parent
      hasSourceHandle={true}
    >
      <div className="space-y-1.5 font-mono">
        <div
          className="text-xs font-bold text-slate-100 truncate"
          title={data.display_role || data.label}
        >
          {data.display_role || data.label || "Organizational Principal"}
        </div>
        <div
          className="text-[11px] text-slate-400 bg-obsidian-800 px-2 py-1 rounded border border-obsidian-700 truncate"
          title={data.principal_id || data.id}
        >
          {data.principal_id || data.id}
        </div>
        <div className="flex items-center justify-between pt-1">
          <span className="inline-flex items-center gap-1 text-[10px] text-corporate-steel-light bg-cyan-500/10 border border-cyan-500/30 px-1.5 py-0.5 rounded font-semibold">
            <Key className="w-2.5 h-2.5" /> TRUST ANCHOR
          </span>
          <span className="text-[9px] text-slate-500">ED25519</span>
        </div>
      </div>
    </BaseNodeCard>
  );
}
