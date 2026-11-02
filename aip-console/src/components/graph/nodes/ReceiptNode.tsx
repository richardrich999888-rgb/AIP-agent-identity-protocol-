"use client";

import React from "react";
import type { NodeProps } from "@xyflow/react";
import { Receipt, FileCheck2 } from "lucide-react";
import { BaseNodeCard } from "./BaseNodeCard";
import type { AccountabilityFlowNode } from "../types";

export function ReceiptNode({ data, selected }: NodeProps<AccountabilityFlowNode>) {
  return (
    <BaseNodeCard
      id={data.id}
      selected={selected}
      kindLabel="Countersigned Receipt (L3)"
      icon={<Receipt className="w-4 h-4" />}
      verified={data.verified}
      accentColor="green"
      layoutDirection={data.layoutDirection}
      hasTargetHandle={true}
      hasSourceHandle={false} // Terminal sink has no outgoing children
    >
      <div className="space-y-1.5 font-mono">
        <div
          className="text-xs font-bold text-slate-100 truncate"
          title={data.receipt_id || data.id}
        >
          {data.receipt_id || data.id || "External Receipt"}
        </div>

        <div className="bg-obsidian-800 p-1.5 rounded border border-obsidian-700 text-[10px] space-y-0.5">
          <div className="text-slate-400 truncate" title={data.receipt_system}>
            System: {data.receipt_system || "Counterparty Gateway"}
          </div>
          <div className="text-slate-400 truncate" title={data.receipt_hash}>
            Hash: {data.receipt_hash ? `${data.receipt_hash.slice(0, 12)}...` : "N/A"}
          </div>
        </div>

        <div className="flex items-center justify-between pt-1">
          {data.countersigned ? (
            <span className="inline-flex items-center gap-1 text-[10px] text-corporate-accent-light bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 rounded font-bold">
              <FileCheck2 className="w-3 h-3" /> COUNTERSIGNED
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-[10px] text-slate-400 bg-slate-800 border border-slate-700 px-1.5 py-0.5 rounded">
              HASH-ONLY
            </span>
          )}
          <span className="text-[9px] text-slate-500">Bilateral Proof</span>
        </div>
      </div>
    </BaseNodeCard>
  );
}
