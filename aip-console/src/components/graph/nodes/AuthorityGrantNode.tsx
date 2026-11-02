"use client";

import React from "react";
import type { NodeProps } from "@xyflow/react";
import { KeyRound, Clock, ShieldAlert } from "lucide-react";
import { BaseNodeCard } from "./BaseNodeCard";
import type { AccountabilityFlowNode } from "../types";

export function AuthorityGrantNode({ data, selected }: NodeProps<AccountabilityFlowNode>) {
  const allowedCount = data.scope?.allowed?.length ?? 0;
  const isPerpetual = !data.expires_at;

  return (
    <BaseNodeCard
      id={data.id}
      selected={selected}
      kindLabel="Authority Grant (Root Token)"
      icon={<KeyRound className="w-4 h-4" />}
      verified={data.verified}
      accentColor="indigo"
      layoutDirection={data.layoutDirection}
      hasTargetHandle={true}
      hasSourceHandle={true}
    >
      <div className="space-y-1.5 font-mono">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-400">JTI:</span>
          <span className="text-corporate-steel-light font-bold truncate max-w-[170px]" title={data.jti}>
            {data.jti ? data.jti.slice(0, 12) + "..." : "N/A"}
          </span>
        </div>

        {/* Scope Matrix Summary */}
        <div className="bg-obsidian-800 p-1.5 rounded border border-obsidian-700 flex items-center justify-between text-[10px]">
          <span className="text-slate-400">Scope:</span>
          <span className="text-corporate-accent-light font-semibold">
            {allowedCount} Allowed {data.scope?.denied?.length ? `| ${data.scope.denied.length} Denied` : ""}
          </span>
        </div>

        {/* Expiration & Revocation Status */}
        <div className="flex items-center justify-between pt-1 text-[10px]">
          <div className="flex items-center gap-1 text-slate-400">
            <Clock className="w-3 h-3 text-slate-500" />
            <span>{isPerpetual ? "Perpetual" : "Timed Window"}</span>
          </div>
          {data.isRevoked ? (
            <span className="inline-flex items-center gap-1 text-corporate-danger-light bg-red-500/20 border border-red-500/30 px-1 py-0.5 rounded font-bold">
              <ShieldAlert className="w-2.5 h-2.5" /> REVOKED
            </span>
          ) : (
            <span className="text-corporate-accent-light text-[9px] bg-emerald-500/10 px-1 py-0.5 rounded">CLEAR</span>
          )}
        </div>
      </div>
    </BaseNodeCard>
  );
}
