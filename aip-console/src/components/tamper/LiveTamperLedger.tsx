"use client";

import React, { useMemo, useState } from "react";
import type { VerificationReport, RuleIdentifier } from "@/types/verification";
import { VerificationLedger } from "@/components/ingestion/VerificationLedger";
import { TrustFloorBadge } from "@/components/ingestion/TrustFloorBadge";
import {
  Flame,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  RotateCcw,
} from "lucide-react";

export interface LiveTamperLedgerProps {
  report: VerificationReport | null;
  engineError?: string | null;
  className?: string;
  onRuleSelect?: (rule: RuleIdentifier) => void;
  onReset?: () => void;
}

export const LiveTamperLedger: React.FC<LiveTamperLedgerProps> = ({
  report,
  engineError,
  className = "",
  onRuleSelect,
  onReset,
}) => {
  const [copiedError, setCopiedError] = useState(false);

  const copyError = () => {
    if (!engineError) return;
    navigator.clipboard.writeText(engineError);
    setCopiedError(true);
    setTimeout(() => setCopiedError(false), 2000);
  };

  const stats = useMemo(() => {
    if (!report || !report.checks) {
      return { total: 0, passed: 0, failed: 0, failingRules: [] as string[] };
    }
    const total = report.checks.length;
    const passed = report.checks.filter((c) => c.pass).length;
    const failed = total - passed;
    const failingRules = report.checks.filter((c) => !c.pass).map((c) => c.rule);
    return { total, passed, failed, failingRules };
  }, [report]);

  const isTampered = Boolean(report?.tamper_evidence || (report as any)?.tampered);
  const isValid = Boolean(report?.overall_valid || (report as any)?.valid);

  return (
    <div className={`space-y-4 ${className}`}>
      {/* ── Engine Deserialization Error Alert Banner ─────────────────────── */}
      {engineError && (
        <div className="p-4 rounded-md border border-red-500/50 bg-red-950/30 text-red-200 font-mono text-xs shadow-md space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-red-900/60 pb-3">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm text-red-100 tracking-wide">
                    Engine Deserialization Error
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-red-900/60 text-red-200 border border-red-700/60 font-bold uppercase">
                    Wire-Format Rejection
                  </span>
                </div>
                <p className="text-[11px] text-red-300/80 mt-0.5 font-sans">
                  The WebAssembly verification engine rejected this payload prior to rule evaluation.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-end sm:self-auto">
              <button
                type="button"
                onClick={copyError}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-red-900/40 hover:bg-red-900/70 border border-red-700/60 text-red-200 text-[11px] transition-colors"
                title="Copy raw engine error string"
              >
                {copiedError ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy Error</span>
                  </>
                )}
              </button>

              {onReset && (
                <button
                  type="button"
                  onClick={onReset}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-[11px] transition-colors"
                  title="Revert payload to baseline honest packet"
                >
                  <RotateCcw className="w-3 h-3 text-cyan-400" />
                  <span>Revert to Pristine</span>
                </button>
              )}
            </div>
          </div>

          {/* Verbatim Serde / Engine Error Message */}
          <div className="p-3 rounded bg-black/60 border border-red-900/60 font-mono text-[11px] text-red-300 break-all select-text leading-relaxed">
            <span className="text-slate-500 select-none">$ wasm_engine: </span>
            {engineError}
          </div>

          {/* Diagnostic guidance */}
          <div className="text-[11px] text-slate-400 font-sans leading-relaxed">
            <strong className="text-slate-300 font-mono">Note:</strong> All verification rules run inside the compiled WebAssembly verifier. When packet fields violate binary wire-format types (e.g., passing string literals for numeric byte arrays <code className="text-red-300 font-mono">[u8; 32]</code> or <code className="text-red-300 font-mono">[u8; 64]</code>, or invalid enum representations), Rust Serde aborts evaluation immediately.
          </div>
        </div>
      )}

      {/* ── Suspended Ledger Fallback Card ────────────────────────────────── */}
      {engineError && !report && (
        <div className="rounded-md border border-dashed border-red-900/50 bg-[#0E131F]/40 p-6 text-center font-mono">
          <ShieldAlert className="w-8 h-8 text-red-500/70 mx-auto mb-2" />
          <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wide">
            14 Engine Verification Checks Suspended
          </h4>
          <p className="text-[11px] text-slate-400 mt-1 max-w-md mx-auto font-sans">
            Payload deserialization failed. Resolve wire-format schema issues above or revert to a pristine baseline packet to resume automated 14-rule cryptographic evaluation.
          </p>
        </div>
      )}

      {/* ── Active Verification Report View (Rendered when engine succeeds) ── */}
      {!engineError && (
        <>
          {/* Dynamic Status Notification Banner */}
          {report && (
            <div
              className={`p-4 rounded-md border flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono text-xs transition-all ${
                isValid
                  ? "bg-emerald-950/30 border-emerald-500/50 text-emerald-200"
                  : isTampered
                  ? "bg-red-950/40 border-red-500/60 text-red-200"
                  : "bg-amber-950/30 border-amber-500/50 text-amber-200"
              }`}
            >
              <div className="flex items-center gap-3">
                {isValid ? (
                  <CheckCircle2 className="w-6 h-6 text-emerald-400 flex-shrink-0" />
                ) : isTampered ? (
                  <Flame className="w-6 h-6 text-red-400 flex-shrink-0" />
                ) : (
                  <AlertTriangle className="w-6 h-6 text-amber-400 flex-shrink-0" />
                )}

                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm tracking-wide">
                      {isValid
                        ? "PRISTINE & VERIFIED: ALL 14 RULES PASS"
                        : isTampered
                        ? "CRYPTOGRAPHIC TAMPER DETECTED"
                        : "VERIFICATION FAILED (POLICY GAP)"}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-black/40 border border-current font-bold">
                      {stats.failed} FAILING RULES
                    </span>
                  </div>
                  <p className="text-[11px] opacity-80 mt-0.5 font-sans">
                    {isValid
                      ? "Every cryptographic signature, canonical hash, and authority delegation hop verified cleanly via WebAssembly."
                      : isTampered
                      ? "Sealed payload, canonical hash, or cryptographic signature modified after sealing. Mathematical non-repudiation enforced."
                      : "Administrative or policy configuration requirement not met (e.g. untrusted root key or revoked credential)."}
                  </p>
                </div>
              </div>

              {/* Quick failing rules chips */}
              {stats.failed > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 justify-end">
                  {stats.failingRules.map((rule) => (
                    <span
                      key={rule}
                      className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-900/60 text-red-200 border border-red-700/60"
                    >
                      {rule}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Trust Floor Progression Ladder Badge */}
          {report && (
            <TrustFloorBadge
              derivedFloor={report.derived_trust_floor || (report as any).trust_floor}
              claimedFloor={report.claimed_trust_floor}
              tamperEvidence={isTampered}
              variant="ladder"
            />
          )}

          {/* Embedded 14-Rule Verification Ledger */}
          <VerificationLedger report={report} onRuleSelect={onRuleSelect} />
        </>
      )}
    </div>
  );
};
