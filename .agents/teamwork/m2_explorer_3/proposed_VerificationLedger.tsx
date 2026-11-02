"use client";

/**
 * VerificationLedger: 14-Rule Verification Ledger UI for AIP Console
 * Target: aip-console/src/components/ingestion/VerificationLedger.tsx
 *
 * STRICT CONSTRAINT: ZERO verification logic in JavaScript/TypeScript.
 * All rule evaluations, pass/fail states, and detail strings are received
 * directly from the WebAssembly verification engine report (aip-wasm).
 */

import React, { useState, useMemo } from "react";
import {
  VerificationReport,
  RuleResult,
  RuleIdentifier,
  AIP_RULES_REGISTRY,
  RuleLayer,
} from "@/types/verification";
import {
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  Flame,
  Copy,
  Check,
  Shield,
  Layers,
  Filter,
  Download,
  AlertTriangle,
  Info,
  ExternalLink,
} from "lucide-react";

export interface VerificationLedgerProps {
  report: VerificationReport | null;
  className?: string;
  onRuleSelect?: (rule: RuleIdentifier) => void;
}

type FilterStatus = "all" | "failed" | "passed";
type FilterLayer = "all" | RuleLayer;

export const VerificationLedger: React.FC<VerificationLedgerProps> = ({
  report,
  className = "",
  onRuleSelect,
}) => {
  // Expansion state for accordion rows
  const [expandedRules, setExpandedRules] = useState<Record<string, boolean>>({});
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<FilterStatus>("all");
  const [layerFilter, setLayerFilter] = useState<FilterLayer>("all");

  const toggleRule = (ruleKey: string) => {
    setExpandedRules((prev) => ({
      ...prev,
      [ruleKey]: !prev[ruleKey],
    }));
  };

  const expandAll = () => {
    if (!report) return;
    const allExpanded: Record<string, boolean> = {};
    report.checks.forEach((c) => {
      allExpanded[c.rule] = true;
    });
    setExpandedRules(allExpanded);
  };

  const collapseAll = () => {
    setExpandedRules({});
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const exportReportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `verification-report-${report.packet_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Derive counts directly from report (Pure projection, zero verification)
  const stats = useMemo(() => {
    if (!report || !report.checks) {
      return { total: 0, passed: 0, failed: 0, passRate: 0 };
    }
    const total = report.checks.length;
    const passed = report.checks.filter((c) => c.pass).length;
    const failed = total - passed;
    const passRate = total > 0 ? Math.round((passed / total) * 100) : 0;
    return { total, passed, failed, passRate };
  }, [report]);

  // Filtered checks list
  const filteredChecks = useMemo(() => {
    if (!report || !report.checks) return [];
    return report.checks.filter((check) => {
      const meta = AIP_RULES_REGISTRY[check.rule as RuleIdentifier];
      const matchesStatus =
        statusFilter === "all"
          ? true
          : statusFilter === "failed"
          ? !check.pass
          : check.pass;
      const matchesLayer =
        layerFilter === "all" ? true : meta?.layer === layerFilter;
      return matchesStatus && matchesLayer;
    });
  }, [report, statusFilter, layerFilter]);

  // Empty state when no report is available
  if (!report) {
    return (
      <div
        className={`rounded-xl border border-dashed border-slate-800 bg-[#0E131F]/50 p-8 text-center ${className}`}
      >
        <Shield className="w-10 h-10 text-slate-600 mx-auto mb-3" />
        <h3 className="text-sm font-semibold text-slate-300">
          Awaiting Evidence Verification
        </h3>
        <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
          Load an EvidencePacket (.json) or audit export (.zip) to run the 14-rule
          WASM verification engine and populate the ledger.
        </p>
      </div>
    );
  }

  return (
    <div
      className={`rounded-xl border border-slate-800 bg-[#0E131F] overflow-hidden shadow-2xl ${className}`}
    >
      {/* ── Ledger Header & Global Metrics ─────────────────────────────────── */}
      <div className="p-4 sm:p-5 border-b border-slate-800 bg-[#080B11]/80">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#00E5FF]" />
              <h2 className="text-base font-bold text-slate-100 tracking-wide flex items-center gap-2">
                14-Rule Verification Ledger
                <span className="text-xs font-mono font-normal text-cyan-400 bg-cyan-950/60 border border-cyan-800/50 px-2 py-0.5 rounded">
                  aip-protocol v1
                </span>
              </h2>
            </div>
            <div className="flex flex-wrap items-center gap-3 mt-1.5 text-xs text-slate-400 font-mono">
              <span>
                Packet ID:{" "}
                <button
                  onClick={() => copyToClipboard(report.packet_id)}
                  className="text-slate-300 hover:text-cyan-400 inline-flex items-center gap-1 transition-colors"
                  title="Click to copy Packet ID"
                >
                  {report.packet_id.slice(0, 16)}...
                  {copiedText === report.packet_id ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3 text-slate-500" />
                  )}
                </button>
              </span>
              <span>•</span>
              <span>
                Acting Agent:{" "}
                <span className="text-slate-300">
                  {report.agent_id ? report.agent_id.slice(0, 12) + "..." : "Unknown"}
                </span>
              </span>
              <span>•</span>
              <span>
                Verified:{" "}
                <span className="text-slate-300">
                  {new Date(report.verified_at).toLocaleTimeString()}
                </span>
              </span>
            </div>
          </div>

          {/* Overall Pass/Fail Badge + Export Button */}
          <div className="flex items-center gap-2">
            <button
              onClick={exportReportJson}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-mono text-slate-300 bg-slate-800/80 hover:bg-slate-700 border border-slate-700 transition-colors"
              title="Export complete VerificationReport as JSON"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Report JSON</span>
            </button>

            <div
              className={`px-3 py-1.5 rounded-lg border font-mono text-xs font-bold flex items-center gap-2 ${
                report.overall_valid || report.valid
                  ? "bg-emerald-950/40 border-emerald-500/50 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.15)]"
                  : report.tamper_evidence || report.tampered
                  ? "bg-red-950/50 border-red-500/60 text-red-300 shadow-[0_0_15px_rgba(239,68,68,0.2)] animate-pulse"
                  : "bg-amber-950/40 border-amber-500/50 text-amber-300"
              }`}
            >
              {report.overall_valid || report.valid ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>ALL 14 RULES PASSED</span>
                </>
              ) : report.tamper_evidence || report.tampered ? (
                <>
                  <Flame className="w-4 h-4 text-red-400 animate-bounce" />
                  <span>TAMPER DETECTED ({stats.failed} FAILING)</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>VERIFICATION FAILED ({stats.failed} FAILING)</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* ── Quick Filter and Layer Selector Bar ──────────────────────────── */}
        <div className="mt-4 pt-3 border-t border-slate-800/70 flex flex-wrap items-center justify-between gap-3">
          {/* Status Filter Tabs */}
          <div className="flex items-center gap-1 bg-[#080B11] p-1 rounded-lg border border-slate-800 text-xs font-mono">
            <button
              onClick={() => setStatusFilter("all")}
              className={`px-2.5 py-1 rounded transition-colors ${
                statusFilter === "all"
                  ? "bg-cyan-500/20 text-cyan-300 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              All Rules ({stats.total})
            </button>
            <button
              onClick={() => setStatusFilter("failed")}
              className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                statusFilter === "failed"
                  ? "bg-red-500/20 text-red-300 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  stats.failed > 0 ? "bg-red-400 animate-ping" : "bg-slate-600"
                }`}
              />
              Failed ({stats.failed})
            </button>
            <button
              onClick={() => setStatusFilter("passed")}
              className={`px-2.5 py-1 rounded transition-colors ${
                statusFilter === "passed"
                  ? "bg-emerald-500/20 text-emerald-300 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Passed ({stats.passed})
            </button>
          </div>

          {/* Layer Filter Tabs */}
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <span className="text-slate-500 hidden sm:inline">Layer:</span>
            {(["all", "INTEGRITY", "AUTHORITY", "VALIDITY", "BILATERAL"] as const).map(
              (layer) => (
                <button
                  key={layer}
                  onClick={() => setLayerFilter(layer)}
                  className={`px-2 py-1 rounded border text-[11px] transition-colors ${
                    layerFilter === layer
                      ? "bg-slate-800 text-cyan-300 border-cyan-500/40 font-bold"
                      : "bg-transparent text-slate-400 border-slate-800 hover:text-slate-300"
                  }`}
                >
                  {layer === "all" ? "All Layers" : layer}
                </button>
              )
            )}
          </div>

          {/* Expand/Collapse All */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <button
              onClick={expandAll}
              className="text-slate-400 hover:text-cyan-400 transition-colors"
            >
              Expand All
            </button>
            <span className="text-slate-600">|</span>
            <button
              onClick={collapseAll}
              className="text-slate-400 hover:text-cyan-400 transition-colors"
            >
              Collapse All
            </button>
          </div>
        </div>
      </div>

      {/* ── 14-Rule Ledger List ────────────────────────────────────────────── */}
      <div className="divide-y divide-slate-800/80">
        {filteredChecks.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs font-mono">
            No verification rules match the selected filter criteria.
          </div>
        ) : (
          filteredChecks.map((check) => {
            const ruleKey = check.rule as RuleIdentifier;
            const meta = AIP_RULES_REGISTRY[ruleKey] ?? {
              index: 0,
              identifier: ruleKey,
              name: ruleKey,
              summary: "AIP verification rule",
              layer: "INTEGRITY",
              layerName: "Engine Rule",
              specSection: "AIP_SPEC.md",
              isTamperCritical: false,
            };

            const isExpanded = !!expandedRules[ruleKey];
            const isFailing = !check.pass;
            const isTamperViolated = isFailing && report.tamper_evidence && meta.isTamperCritical;

            return (
              <div
                key={ruleKey}
                className={`transition-colors ${
                  isFailing
                    ? isTamperViolated
                      ? "bg-red-950/20 hover:bg-red-950/30"
                      : "bg-amber-950/15 hover:bg-amber-950/25"
                    : isExpanded
                    ? "bg-[#161F31]/30"
                    : "hover:bg-slate-900/40"
                }`}
              >
                {/* ── Rule Summary Row ── */}
                <div
                  onClick={() => {
                    toggleRule(ruleKey);
                    onRuleSelect?.(ruleKey);
                  }}
                  className="p-3.5 sm:px-5 flex items-center justify-between gap-3 cursor-pointer select-none"
                >
                  {/* Left: Rule Number, Icon, Name, and Summary */}
                  <div className="flex items-center gap-3 min-w-0">
                    {/* Pass/Fail Icon */}
                    <div className="flex-shrink-0">
                      {check.pass ? (
                        <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                      ) : isTamperViolated ? (
                        <Flame className="w-5 h-5 text-red-400 animate-pulse" />
                      ) : (
                        <XCircle className="w-5 h-5 text-red-400" />
                      )}
                    </div>

                    {/* Rule Index & Name */}
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[11px] font-mono text-slate-500 font-semibold">
                          #{String(meta.index).padStart(2, "0")}
                        </span>
                        <span className="font-mono text-xs font-bold text-slate-200 tracking-tight">
                          {ruleKey}
                        </span>
                        <span className="text-xs text-slate-400 hidden md:inline">
                          — {meta.name}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 hidden lg:inline">
                          {meta.layer}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 truncate mt-0.5">
                        {meta.summary}
                      </p>
                    </div>
                  </div>

                  {/* Right: Badges and Chevron */}
                  <div className="flex items-center gap-2.5 flex-shrink-0">
                    {isTamperViolated && (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse">
                        <Flame className="w-3 h-3" />
                        TAMPER
                      </span>
                    )}

                    <span
                      className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border ${
                        check.pass
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                          : "bg-red-500/10 text-red-400 border-red-500/30"
                      }`}
                    >
                      {check.pass ? "PASS" : "FAIL"}
                    </span>

                    <div className="text-slate-500 hover:text-slate-300">
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </div>
                  </div>
                </div>

                {/* ── Expanded Rule Details Panel ── */}
                {isExpanded && (
                  <div className="px-5 pb-4 pt-1 bg-[#080B11]/70 border-t border-slate-800/60 font-mono text-xs">
                    {/* Verbatim Engine Detail */}
                    <div className="mt-2 p-3 rounded-lg bg-[#0E131F] border border-slate-800">
                      <div className="flex items-center justify-between text-slate-400 text-[11px] mb-1.5 pb-1 border-b border-slate-800/80">
                        <span className="flex items-center gap-1 text-cyan-400 font-semibold">
                          <Info className="w-3.5 h-3.5" />
                          Rust Engine Verification Detail:
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(check.detail);
                          }}
                          className="hover:text-slate-200 inline-flex items-center gap-1 text-[10px] transition-colors"
                        >
                          {copiedText === check.detail ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              Copy Detail
                            </>
                          )}
                        </button>
                      </div>
                      <p
                        className={`leading-relaxed break-all font-mono select-text ${
                          check.pass ? "text-slate-300" : "text-red-300 font-medium"
                        }`}
                      >
                        {check.detail}
                      </p>
                    </div>

                    {/* Metadata & Spec Reference */}
                    <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-400">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500">Classification:</span>
                        <span className="text-slate-300">{meta.layerName}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500">Normative Specification:</span>
                        <span className="text-cyan-400 underline underline-offset-2 flex items-center gap-1">
                          {meta.specSection}
                          <ExternalLink className="w-3 h-3" />
                        </span>
                      </div>
                    </div>

                    {/* Tamper Evidence Banner (if rule is violated and tamper flag is set) */}
                    {isTamperViolated && (
                      <div className="mt-3 p-2.5 rounded bg-red-950/40 border border-red-500/50 text-red-300 text-xs flex items-start gap-2">
                        <Flame className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <strong>Cryptographic Violation:</strong> This check proves
                          adversarial or in-transit modification. The sealed payload does
                          not match the cryptographic signature or hash commitments.
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* ── Ledger Footer Summary ──────────────────────────────────────────── */}
      <div className="p-3.5 px-5 bg-[#080B11] border-t border-slate-800 flex flex-wrap items-center justify-between text-xs font-mono text-slate-500">
        <div>
          Engine Pass Rate:{" "}
          <span
            className={
              stats.passRate === 100
                ? "text-emerald-400 font-bold"
                : stats.passRate > 50
                ? "text-amber-400 font-bold"
                : "text-red-400 font-bold"
            }
          >
            {stats.passed}/{stats.total} ({stats.passRate}%)
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span>Non-short-circuiting evaluation</span>
          <span>•</span>
          <span className="text-cyan-400">Zero JS Verification Logic</span>
        </div>
      </div>
    </div>
  );
};

export default VerificationLedger;
