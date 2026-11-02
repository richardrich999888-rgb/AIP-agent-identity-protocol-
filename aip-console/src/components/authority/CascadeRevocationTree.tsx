"use client";

import React, { useMemo, useState } from "react";
import {
  DelegationTreeNode,
  RevocationEntry,
  TokenStatus,
} from "./types";
import {
  computeCascadeRevocations,
  SAMPLE_DELEGATION_TREES,
} from "./revocationCascade";
import {
  ShieldAlert,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  ChevronRight,
  Ban,
  User,
  Key,
} from "lucide-react";

export interface CascadeRevocationTreeProps {
  nodes: DelegationTreeNode[];
  revocations: RevocationEntry[];
  onRevoke: (jti: string) => void;
  onRestore: (jti: string) => void;
  onReset: () => void;
  onTopologyChange?: (topologyKey: string) => void;
  currentTopology?: string;
  className?: string;
}

export const CascadeRevocationTree: React.FC<CascadeRevocationTreeProps> = ({
  nodes,
  revocations,
  onRevoke,
  onRestore,
  onReset,
  onTopologyChange,
  currentTopology = "multi_branch",
  className = "",
}) => {
  // Map of revoked JTIs to their revocation entries
  const revocationMap = useMemo(() => {
    const map = new Map<string, RevocationEntry>();
    revocations.forEach((r) => map.set(r.jti, r));
    return map;
  }, [revocations]);

  // Derive statuses for all nodes
  const processedNodes = useMemo(() => {
    return nodes.map((node) => {
      const revEntry = revocationMap.get(node.jti);
      let status: TokenStatus = "VALID";

      if (revEntry) {
        status = revEntry.reason === "AdminRevocation" ? "CASCADE_REVOKED" : "REVOKED";
      } else if (node.expires_at && node.expires_at < Date.now()) {
        status = "EXPIRED";
      }

      return {
        ...node,
        status,
        revocationReason: revEntry?.reason,
        revoked_at: revEntry?.revoked_at,
        revoked_by: revEntry?.revoked_by,
      };
    });
  }, [nodes, revocationMap]);

  return (
    <div
      className={`rounded-md border border-slate-800 bg-[#0E131F] p-4 sm:p-6 font-mono text-xs shadow-2xl space-y-6 ${className}`}
    >
      {/* Header and Topology Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <h2 className="text-base font-bold text-slate-100 uppercase tracking-wide">
              Cascade Revocation Tree
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-red-950/70 border border-red-800/60 text-red-300">
              Feature F16 • Recursive BFS
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Interactive tree visualization of delegated tokens. Revoking any token recursively invalidates all downstream sub-agent tokens via pure BFS cascade matching AIP specification.
          </p>
        </div>

        {/* Topology Selector & Reset Button */}
        <div className="flex flex-wrap items-center gap-2">
          {onTopologyChange && (
            <select
              value={currentTopology}
              onChange={(e) => onTopologyChange(e.target.value)}
              className="bg-[#080B11] border border-slate-750 text-slate-200 rounded-md px-2.5 py-1.5 text-xs font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="active_packet">Active Packet Hierarchy</option>
              <option value="multi_branch">Multi-Branch Organization (5 Nodes)</option>
              <option value="enterprise_loan">Enterprise Loan Approval</option>
              <option value="wide_tree">Wide Fanout (10 Children)</option>
              <option value="deep_chain">Deep 4-Hop Linear Chain</option>
            </select>
          )}

          <button
            type="button"
            onClick={onReset}
            className="px-3 py-1.5 rounded-md text-xs bg-slate-850 hover:bg-slate-800 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Reset Revocations</span>
          </button>
        </div>
      </div>

      {/* ── Tree Nodes List ────────────────────────────────────────────────── */}
      <div className="space-y-3">
        {processedNodes.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            No delegation nodes present in current authority structure.
          </div>
        ) : (
          processedNodes.map((node) => {
            const isRevoked = node.status === "REVOKED";
            const isCascadeRevoked = node.status === "CASCADE_REVOKED";
            const isAnyRevoked = isRevoked || isCascadeRevoked;

            // Indentation based on depth
            const indentPixels = Math.min(node.depth * 28, 140);

            return (
              <div
                key={node.jti}
                style={{ marginLeft: `${indentPixels}px` }}
                className={`p-4 rounded-md border transition-all duration-200 relative ${
                  isRevoked
                    ? "bg-[#C62828]/10 border-[#C62828] ring-1 ring-[#C62828]/40"
                    : isCascadeRevoked
                    ? "bg-[#C62828]/5 border-[#C62828]/60"
                    : "bg-[#080B11] border-slate-800 hover:border-slate-700"
                }`}
              >
                {/* Node Connector Tag for Children */}
                {node.depth > 0 && (
                  <div className="absolute -left-5 top-1/2 -translate-y-1/2 flex items-center text-slate-650">
                    <span className="text-slate-600 font-bold select-none">└─</span>
                  </div>
                )}

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  {/* Left: Role, Type, Status, JTI */}
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${
                          node.type === "root"
                            ? "bg-cyan-950/60 text-cyan-300 border-cyan-800/60"
                            : node.type === "intermediate"
                            ? "bg-indigo-950/60 text-indigo-300 border-indigo-800/60"
                            : "bg-emerald-950/60 text-emerald-300 border-emerald-800/60"
                        }`}
                      >
                        {node.type} • Depth {node.depth}
                      </span>

                      <span
                        className={`font-bold text-xs ${
                          isAnyRevoked
                            ? "text-slate-400 line-through decoration-[#C62828] decoration-2"
                            : "text-slate-100"
                        }`}
                      >
                        {node.role}
                      </span>

                      {/* Status Badges */}
                      {isRevoked ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-[#C62828] text-white">
                          <Ban className="w-3 h-3" />
                          REVOKED (PRIMARY)
                        </span>
                      ) : isCascadeRevoked ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-[#C62828]/20 text-[#EF5350] border border-[#C62828]/50">
                          <ShieldAlert className="w-3 h-3" />
                          CASCADE REVOKED
                        </span>
                      ) : node.status === "EXPIRED" ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-500/50">
                          <Clock className="w-3 h-3" />
                          EXPIRED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-500/50">
                          <CheckCircle2 className="w-3 h-3" />
                          VALID
                        </span>
                      )}
                    </div>

                    {/* JTI and Grantee Info */}
                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400 font-mono">
                      <span>
                        JTI:{" "}
                        <code
                          className={`${
                            isAnyRevoked
                              ? "text-slate-500 line-through decoration-[#C62828]"
                              : "text-cyan-400"
                          }`}
                        >
                          {node.jti}
                        </code>
                      </span>
                      <span>•</span>
                      <span>
                        Grantee:{" "}
                        <span
                          className={`${
                            isAnyRevoked
                              ? "text-slate-500 line-through decoration-[#C62828]"
                              : "text-slate-300"
                          }`}
                        >
                          {node.grantee_id}
                        </span>
                      </span>
                      {node.parent_jti && (
                        <>
                          <span>•</span>
                          <span className="text-slate-500">
                            Parent: <code>{node.parent_jti}</code>
                          </span>
                        </>
                      )}
                    </div>

                    {/* Revocation Metadata if Revoked */}
                    {isAnyRevoked && (
                      <div className="mt-1 text-[10px] text-red-300/90 font-mono flex items-center gap-2">
                        <span>Reason: <strong>{node.revocationReason}</strong></span>
                        <span>•</span>
                        <span>By: {node.revoked_by}</span>
                        {node.revoked_at && (
                          <>
                            <span>•</span>
                            <span>{new Date(node.revoked_at).toLocaleTimeString()}</span>
                          </>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Right: Revoke / Restore Action Button */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    {isRevoked ? (
                      <button
                        type="button"
                        onClick={() => onRestore(node.jti)}
                        className="px-3 py-1.5 rounded-md text-xs font-bold bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-emerald-500/40 transition-colors"
                      >
                        Restore Token
                      </button>
                    ) : isCascadeRevoked ? (
                      <span className="text-[11px] text-red-400 italic font-sans pr-2">
                        Cascaded from parent
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onRevoke(node.jti)}
                        className="px-3 py-1.5 rounded-md text-xs font-bold bg-slate-850 hover:bg-[#C62828] hover:text-white text-red-400 border border-red-500/40 transition-all"
                      >
                        Revoke Token
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
