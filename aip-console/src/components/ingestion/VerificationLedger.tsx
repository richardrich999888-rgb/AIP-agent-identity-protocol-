"use client";

/**
 * VerificationLedger: 14-rule verification ledger.
 *
 * STRICT CONSTRAINT: ZERO verification logic in JavaScript/TypeScript.
 * All rule evaluations, pass/fail states, and detail strings are received
 * directly from the WebAssembly verification engine report (aip-wasm).
 */

import React, { useState, useMemo } from "react";
import {
  VerificationReport,
  RuleIdentifier,
  AIP_RULES_REGISTRY,
  RuleLayer,
} from "@/types/verification";
import { CheckCircle2, XCircle, ChevronDown, Copy, Check, Download, AlertTriangle, ShieldAlert } from "lucide-react";
import { btn, badge, panel, panelHeader, panelTitle, focusRing } from "@/components/ui/styles";

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


  const isValid = Boolean(report?.overall_valid || report?.valid);
  const isTampered = Boolean(report?.tamper_evidence || report?.tampered);

  // Empty state when no report is available
  if (!report) {
    return (
      <section className={`${panel} px-6 py-10 text-center ${className}`}>
        <h2 className={panelTitle}>Verification ledger</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
          Load an EvidencePacket (.json) or audit export (.zip). The 14 verification rules and their engine
          output will appear here.
        </p>
      </section>
    );
  }

  const segment = (active: boolean) =>
    `h-7 px-2.5 rounded text-xs font-medium transition-colors duration-150 ${focusRing} ${
      active ? "bg-obsidian-800 text-slate-100" : "text-slate-400 hover:text-slate-200"
    }`;

  return (
    <section className={`${panel} overflow-hidden ${className}`} aria-labelledby="ledger-heading">
      {/* Header */}
      <div className={panelHeader}>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h2 id="ledger-heading" className={panelTitle}>
              Verification ledger
            </h2>
            <span className={badge.neutral}>aip-protocol v1</span>
          </div>
          <dl className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
            <div className="flex items-center gap-1.5">
              <dt>Packet</dt>
              <dd>
                <button
                  type="button"
                  onClick={() => copyToClipboard(report.packet_id || "")}
                  className={`inline-flex items-center gap-1 rounded font-mono text-slate-200 hover:text-slate-100 ${focusRing}`}
                  title="Copy packet ID"
                >
                  {(report.packet_id || "unknown").slice(0, 16)}...
                  {copiedText === report.packet_id ? (
                    <Check className="w-3 h-3 text-corporate-accent-light" aria-label="Copied" />
                  ) : (
                    <Copy className="w-3 h-3 text-slate-500" aria-hidden />
                  )}
                </button>
              </dd>
            </div>
            <div className="flex items-center gap-1.5">
              <dt>Agent</dt>
              <dd className="font-mono text-slate-200">
                {report.agent_id ? report.agent_id.slice(0, 12) + "..." : "unknown"}
              </dd>
            </div>
            <div className="flex items-center gap-1.5">
              <dt>Verified</dt>
              <dd className="text-slate-200 tabular-nums">
                {new Date(report.verified_at || Date.now()).toLocaleTimeString()}
              </dd>
            </div>
          </dl>
        </div>

        <div className="flex items-center gap-2">
          <span className={isValid ? badge.success : isTampered ? badge.danger : badge.warning}>
            {isValid ? (
              <CheckCircle2 className="w-3 h-3" aria-hidden />
            ) : isTampered ? (
              <ShieldAlert className="w-3 h-3" aria-hidden />
            ) : (
              <AlertTriangle className="w-3 h-3" aria-hidden />
            )}
            {isValid
              ? `All ${stats.total} rules passed`
              : isTampered
              ? `Tamper detected, ${stats.failed} failing`
              : `Verification failed, ${stats.failed} failing`}
          </span>
          <button type="button" onClick={exportReportJson} className={btn.secondary} title="Download the VerificationReport as JSON">
            <Download className="w-3.5 h-3.5" aria-hidden />
            Export report
          </button>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-b border-obsidian-700 bg-obsidian-950/40">
        <div className="flex flex-wrap items-center gap-3">
          <div role="group" aria-label="Filter by result" className="inline-flex rounded-md border border-obsidian-700 p-0.5">
            <button type="button" aria-pressed={statusFilter === "all"} onClick={() => setStatusFilter("all")} className={segment(statusFilter === "all")}>
              All <span className="tabular-nums text-slate-500">{stats.total}</span>
            </button>
            <button type="button" aria-pressed={statusFilter === "failed"} onClick={() => setStatusFilter("failed")} className={segment(statusFilter === "failed")}>
              Failed{" "}
              <span className={`tabular-nums ${stats.failed > 0 ? "text-corporate-danger-light" : "text-slate-500"}`}>
                {stats.failed}
              </span>
            </button>
            <button type="button" aria-pressed={statusFilter === "passed"} onClick={() => setStatusFilter("passed")} className={segment(statusFilter === "passed")}>
              Passed <span className="tabular-nums text-slate-500">{stats.passed}</span>
            </button>
          </div>

          <div role="group" aria-label="Filter by layer" className="inline-flex flex-wrap rounded-md border border-obsidian-700 p-0.5">
            {(["all", "INTEGRITY", "AUTHORITY", "VALIDITY", "BILATERAL"] as const).map((layer) => (
              <button
                key={layer}
                type="button"
                aria-pressed={layerFilter === layer}
                onClick={() => setLayerFilter(layer)}
                className={`${segment(layerFilter === layer)} capitalize`}
              >
                {layer === "all" ? "All layers" : layer.toLowerCase()}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button type="button" onClick={expandAll} className={`${btn.ghost} h-7 text-xs`}>
            Expand all
          </button>
          <button type="button" onClick={collapseAll} className={`${btn.ghost} h-7 text-xs`}>
            Collapse all
          </button>
        </div>
      </div>

      {/* Rules */}
      <ul className="divide-y divide-obsidian-700">
        {filteredChecks.length === 0 ? (
          <li className="px-4 py-8 text-center text-xs text-slate-400">No rules match these filters.</li>
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
            const isTamperViolated = isFailing && isTampered && meta.isTamperCritical;
            const detailId = `rule-detail-${ruleKey}`;

            return (
              <li key={ruleKey} className={isFailing ? "bg-corporate-danger/[0.06]" : ""}>
                <button
                  type="button"
                  aria-expanded={isExpanded}
                  aria-controls={detailId}
                  onClick={() => {
                    toggleRule(ruleKey);
                    onRuleSelect?.(ruleKey);
                  }}
                  className={`w-full grid grid-cols-[auto_1fr_auto] items-center gap-3 px-4 py-3 text-left transition-colors duration-150 hover:bg-obsidian-850 ${focusRing}`}
                >
                  {check.pass ? (
                    <CheckCircle2 className="w-4 h-4 text-corporate-accent-light" aria-label="Passed" />
                  ) : (
                    <XCircle className="w-4 h-4 text-corporate-danger-light" aria-label="Failed" />
                  )}

                  <div className="min-w-0">
                    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                      <span className="font-mono text-xs text-slate-500 tabular-nums">
                        {String(meta.index).padStart(2, "0")}
                      </span>
                      <span className="font-mono text-[13px] font-medium text-slate-100">{ruleKey}</span>
                      <span className="text-[13px] text-slate-400 hidden md:inline">{meta.name}</span>
                    </div>
                    <p className="text-xs text-slate-500 truncate mt-0.5">{meta.summary}</p>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className={`${badge.neutral} hidden lg:inline-flex capitalize`}>{meta.layer.toLowerCase()}</span>
                    {isTamperViolated && <span className={badge.danger}>Tamper</span>}
                    <span className={check.pass ? badge.success : badge.danger}>{check.pass ? "Pass" : "Fail"}</span>
                    <ChevronDown
                      className={`w-4 h-4 text-slate-500 transition-transform duration-150 ${isExpanded ? "rotate-180" : ""}`}
                      aria-hidden
                    />
                  </div>
                </button>

                {isExpanded && (
                  <div id={detailId} className="px-4 pb-4 pl-11 space-y-3">
                    <div className="rounded-md border border-obsidian-700 bg-obsidian-950">
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-obsidian-700">
                        <span className="text-xs text-slate-400">Engine output</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(check.detail)}
                          className={`${btn.ghost} h-6 px-1.5 text-xs`}
                        >
                          {copiedText === check.detail ? (
                            <>
                              <Check className="w-3 h-3 text-corporate-accent-light" aria-hidden />
                              Copied
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" aria-hidden />
                              Copy
                            </>
                          )}
                        </button>
                      </div>
                      <p
                        className={`px-3 py-2.5 font-mono text-xs leading-relaxed break-all select-text ${
                          check.pass ? "text-slate-300" : "text-corporate-danger-light"
                        }`}
                      >
                        {check.detail}
                      </p>
                    </div>

                    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                      <div className="flex gap-2">
                        <dt className="text-slate-500">Classification</dt>
                        <dd className="text-slate-300">{meta.layerName}</dd>
                      </div>
                      <div className="flex gap-2">
                        <dt className="text-slate-500">Specification</dt>
                        <dd className="font-mono text-slate-300">{meta.specSection}</dd>
                      </div>
                    </dl>

                    {isTamperViolated && (
                      <p className="flex items-start gap-2 text-xs text-slate-300">
                        <ShieldAlert className="w-4 h-4 text-corporate-danger-light shrink-0" aria-hidden />
                        <span>
                          This rule proves modification after sealing: the payload no longer matches its signature or
                          hash commitments.
                        </span>
                      </p>
                    )}
                  </div>
                )}
              </li>
            );
          })
        )}
      </ul>

      {/* Footer */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border-t border-obsidian-700 text-xs text-slate-500">
        <span>
          <span className={`tabular-nums font-medium ${stats.passRate === 100 ? "text-corporate-accent-light" : "text-corporate-danger-light"}`}>
            {stats.passed} of {stats.total}
          </span>{" "}
          rules passed ({stats.passRate}%)
        </span>
        <span>All rules evaluated, no short-circuiting. Verification logic runs only in WebAssembly.</span>
      </div>
    </section>
  );
};

export default VerificationLedger;
