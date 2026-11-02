"use client";

import React, { useState } from "react";
import { RevocationEntry, RevocationImpact } from "./types";
import {
  ShieldAlert,
  Flame,
  Download,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Copy,
  Check,
  Send,
} from "lucide-react";

export interface RevocationImpactSummaryProps {
  impact: RevocationImpact;
  revocations: RevocationEntry[];
  onApplyToVerifier?: () => void;
  isApplied?: boolean;
  className?: string;
}

export const RevocationImpactSummary: React.FC<RevocationImpactSummaryProps> = ({
  impact,
  revocations,
  onApplyToVerifier,
  isApplied = false,
  className = "",
}) => {
  const [copied, setCopied] = useState(false);

  const exportCrlJson = () => {
    const blob = new Blob([JSON.stringify(revocations, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `crl-revocations-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyCrl = () => {
    navigator.clipboard.writeText(JSON.stringify(revocations, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`rounded-md border border-slate-800 bg-[#0E131F] p-4 sm:p-6 font-mono text-xs shadow-2xl space-y-6 ${className}`}
    >
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Flame className="w-5 h-5 text-red-400" />
            <h2 className="text-base font-bold text-slate-100 uppercase tracking-wide">
              Revocation Impact & Verifier Synchronization
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-red-950/70 border border-red-800/60 text-red-300">
              Rule 9 Sync
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Metrics ledger and CRL registry of invalidated authority delegation tokens. Synchronize with verifier context to trigger engine Rule 9 failure.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {onApplyToVerifier && (
            <button
              type="button"
              onClick={onApplyToVerifier}
              disabled={revocations.length === 0}
              className={`px-3 py-1.5 rounded-md text-xs font-bold flex items-center gap-1.5 transition-all ${
                isApplied
                  ? "bg-emerald-500 text-obsidian-950 border border-emerald-400"
                  : "bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-obsidian-950"
              }`}
            >
              {isApplied ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Synchronized to Verifier</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Apply Revocations to Verifier</span>
                </>
              )}
            </button>
          )}

          <button
            type="button"
            onClick={exportCrlJson}
            disabled={revocations.length === 0}
            className="px-3 py-1.5 rounded-md text-xs bg-slate-850 hover:bg-slate-800 disabled:opacity-40 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CRL</span>
          </button>
        </div>
      </div>

      {/* ── Key Metrics Cards ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {/* Total Revoked */}
        <div className="p-3.5 rounded-md border border-red-500/40 bg-red-950/20 space-y-1">
          <span className="text-[10px] text-red-400 font-bold uppercase tracking-wider">
            Total Revoked
          </span>
          <div className="text-xl font-bold text-red-300 font-mono">
            {impact.totalRevoked}
          </div>
          <p className="text-[10px] text-red-400/80 font-sans">Invalidated tokens</p>
        </div>

        {/* Primary Revocations */}
        <div className="p-3.5 rounded-md border border-slate-800 bg-[#080B11] space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
            Direct Compromise
          </span>
          <div className="text-xl font-bold text-slate-200 font-mono">
            {impact.primaryRevocations}
          </div>
          <p className="text-[10px] text-slate-500 font-sans">Primary trigger points</p>
        </div>

        {/* Cascaded */}
        <div className="p-3.5 rounded-md border border-slate-800 bg-[#080B11] space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
            Downstream Cascades
          </span>
          <div className="text-xl font-bold text-slate-200 font-mono">
            {impact.cascadedRevocations}
          </div>
          <p className="text-[10px] text-slate-500 font-sans">Subtree invalidations</p>
        </div>

        {/* Cut-off Agents */}
        <div className="p-3.5 rounded-md border border-slate-800 bg-[#080B11] space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
            Affected Agents
          </span>
          <div className="text-xl font-bold text-slate-200 font-mono">
            {impact.affectedAgents.length}
          </div>
          <p className="text-[10px] text-slate-500 font-sans">Grantees disabled</p>
        </div>

        {/* Broken Delegations */}
        <div className="p-3.5 rounded-md border border-slate-800 bg-[#080B11] space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
            Broken Handoffs
          </span>
          <div className="text-xl font-bold text-slate-200 font-mono">
            {impact.brokenDelegations}
          </div>
          <p className="text-[10px] text-slate-500 font-sans">Interrupted chains</p>
        </div>
      </div>

      {/* ── Engine Impact Notice ───────────────────────────────────────────── */}
      <div className="p-3.5 rounded-md border border-slate-800 bg-[#080B11] text-xs font-mono flex items-start gap-3">
        <ShieldAlert className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="font-sans leading-relaxed">
          <strong className="text-slate-200">Engine Rule 9 (REVOCATION) Contract:</strong>{" "}
          <span className="text-slate-400">
            When revocations are applied to the active verifier context, both <code className="text-cyan-300">revoked_jtis</code> and <code className="text-cyan-300">revoked_token_ids</code> are updated. The compiled WebAssembly engine evaluates Rule 9. If any JTI in the root authority or delegation chain matches, Rule 9 fails (<code className="text-red-300">&quot;revoked tokens in chain: ...&quot;</code>), marking <code className="text-red-300">overall_valid = false</code> and downgrading the Trust Floor to <code className="text-amber-300">AGENT_SIGNED</code> or <code className="text-slate-400">UNVERIFIED</code>.
          </span>
        </div>
      </div>

      {/* ── Revocation CRL Table ───────────────────────────────────────────── */}
      <div className="rounded-md border border-slate-800 bg-[#080B11] overflow-hidden">
        <div className="px-4 py-2.5 bg-[#0E131F] border-b border-slate-800 flex items-center justify-between">
          <span className="font-bold text-slate-200 text-xs uppercase tracking-wider">
            Revocation Certificate List (CRL Log)
          </span>

          <button
            type="button"
            onClick={copyCrl}
            disabled={revocations.length === 0}
            className="text-[11px] text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copy CRL JSON</span>
              </>
            )}
          </button>
        </div>

        <div className="max-h-48 overflow-y-auto divide-y divide-slate-850">
          {revocations.length === 0 ? (
            <div className="p-6 text-center text-slate-500 text-xs">
              CRL is currently empty. No tokens revoked.
            </div>
          ) : (
            revocations.map((entry, idx) => (
              <div
                key={idx}
                className="px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-[11px] hover:bg-slate-900/40"
              >
                <div className="flex items-center gap-3">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                  <code className="text-cyan-300 font-bold">{entry.jti}</code>
                  <span className="text-slate-400 font-sans">
                    Reason: <strong>{entry.reason}</strong>
                  </span>
                </div>

                <div className="flex items-center gap-3 text-slate-500">
                  <span>Revoked by: {entry.revoked_by}</span>
                  <span>•</span>
                  <span>{new Date(entry.revoked_at).toLocaleTimeString()}</span>
                  <span>•</span>
                  <span className="text-emerald-400 font-bold">cascade: true</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
