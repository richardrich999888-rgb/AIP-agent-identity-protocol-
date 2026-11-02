"use client";

import React, { useState } from "react";
import {
  Hash,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Zap,
  ShieldAlert,
  Code,
} from "lucide-react";

export interface SmartHashToggleProps {
  autoRecalculate: boolean;
  onToggle: (enabled: boolean) => void;
  storedHash: string | number[];
  recomputedHash: string;
  canonicalBytesHex?: string;
  onRecomputeManual?: () => void;
  className?: string;
}

export const SmartHashToggle: React.FC<SmartHashToggleProps> = ({
  autoRecalculate,
  onToggle,
  storedHash,
  recomputedHash,
  canonicalBytesHex,
  onRecomputeManual,
  className = "",
}) => {
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showCanonicalBytes, setShowCanonicalBytes] = useState(false);

  // Normalize storedHash to string whether passed as number[] or string
  const normalizedStoredHash = Array.isArray(storedHash)
    ? storedHash.map((b) => Number(b).toString(16).padStart(2, "0")).join("")
    : (typeof storedHash === "string" ? storedHash : "");

  const isHashMatch =
    Boolean(normalizedStoredHash) &&
    Boolean(recomputedHash) &&
    normalizedStoredHash.toLowerCase() === recomputedHash.toLowerCase();

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <div
      className={`rounded-md border border-slate-800 bg-[#0E131F] p-4 sm:p-5 font-mono shadow-xl ${className}`}
    >
      {/* Header and Toggle Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <Hash className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Smart Hash Recalculation Engine
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/60 text-cyan-300">
              Feature F12
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Demonstrates cryptographic non-repudiation: fixing the hash satisfies Rule 3 (CANONICAL_HASH) but breaks Rule 4 (AGENT_SIGNATURE).
          </p>
        </div>

        {/* Toggle Switch */}
        <div className="flex items-center gap-3">
          <label className="relative inline-flex items-center cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoRecalculate}
              onChange={(e) => onToggle(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-sm after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
            <span className="ml-2.5 text-xs font-bold text-slate-200">
              {autoRecalculate ? (
                <span className="text-cyan-400 flex items-center gap-1">
                  <Zap className="w-3.5 h-3.5" />
                  Smart Mode (Auto-Recompute)
                </span>
              ) : (
                <span className="text-slate-400">Naive Mode (Preserve Stored)</span>
              )}
            </span>
          </label>

          {onRecomputeManual && (
            <button
              type="button"
              onClick={onRecomputeManual}
              className="px-2.5 py-1 rounded bg-slate-850 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs flex items-center gap-1.5 transition-colors"
              title="Manually trigger WASM recompute_packet_hash"
            >
              <RefreshCw className="w-3 h-3 text-cyan-400" />
              <span>Recompute</span>
            </button>
          )}
        </div>
      </div>

      {/* Mode Callout Banner */}
      <div
        className={`mt-3.5 p-3 rounded-md border text-xs leading-relaxed transition-all ${
          autoRecalculate
            ? "bg-cyan-950/30 border-cyan-500/40 text-cyan-200"
            : "bg-amber-950/20 border-amber-500/30 text-amber-200"
        }`}
      >
        <div className="flex items-start gap-2.5 font-sans">
          {autoRecalculate ? (
            <Zap className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
          ) : (
            <ShieldAlert className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
          )}
          <div>
            <strong>
              {autoRecalculate
                ? "Smart Attacker Mode Active:"
                : "Naive Attacker Mode Active:"}
            </strong>{" "}
            {autoRecalculate ? (
              <span>
                WASM <code className="text-cyan-300 font-mono">recompute_packet_hash</code> recalculates the SHA-256 digest over the canonical serialization and updates <code className="text-cyan-300 font-mono">packet.packet_hash</code>. Rule 3 (<code className="text-cyan-300 font-mono">CANONICAL_HASH</code>) will <strong>PASS</strong>, but Rule 4 (<code className="text-cyan-300 font-mono">AGENT_SIGNATURE</code>) will <strong>FAIL</strong> because the agent&apos;s cryptographic signature was sealed over the original content. Non-repudiation is preserved.
              </span>
            ) : (
              <span>
                The original <code className="text-amber-300 font-mono">packet.packet_hash</code> is retained untouched. Modifying any decision, action, or agent field will immediately trigger Rule 3 (<code className="text-amber-300 font-mono">CANONICAL_HASH</code>) failure and flag <code className="text-amber-300 font-mono">tamper_evidence = true</code>.
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Hashes Comparison Grid */}
      <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
        {/* Stored Hash Card */}
        <div className="p-3 rounded-md bg-[#080B11] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="text-[11px] font-semibold text-slate-300">
              Stored Packet Hash (<code className="text-slate-400">packet.packet_hash</code>):
            </span>
            <button
              type="button"
              onClick={() => copyToClipboard(normalizedStoredHash, "stored")}
              className="text-slate-500 hover:text-cyan-400 inline-flex items-center gap-1 text-[10px] transition-colors"
            >
              {copiedField === "stored" ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>
          <div className="break-all text-slate-300 bg-[#0E131F] p-2 rounded border border-slate-850 select-text">
            {normalizedStoredHash || <span className="text-slate-600">None</span>}
          </div>
        </div>

        {/* Recomputed Hash Card */}
        <div className="p-3 rounded-md bg-[#080B11] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold text-cyan-300">
                WASM Recomputed Hash (SHA-256):
              </span>
              <span
                className={`inline-flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.2 rounded border ${
                  isHashMatch
                    ? "bg-emerald-950/60 border-emerald-500/50 text-emerald-300"
                    : "bg-red-950/60 border-red-500/50 text-red-300"
                }`}
              >
                {isHashMatch ? (
                  <>
                    <CheckCircle2 className="w-2.5 h-2.5 text-emerald-400" />
                    MATCH
                  </>
                ) : (
                  <>
                    <XCircle className="w-2.5 h-2.5 text-red-400" />
                    MISMATCH
                  </>
                )}
              </span>
            </div>
            <button
              type="button"
              onClick={() => copyToClipboard(recomputedHash, "recomputed")}
              className="text-slate-500 hover:text-cyan-400 inline-flex items-center gap-1 text-[10px] transition-colors"
            >
              {copiedField === "recomputed" ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>
          <div
            className={`break-all p-2 rounded border select-text transition-colors ${
              isHashMatch
                ? "text-emerald-300 bg-emerald-950/20 border-emerald-900/60"
                : "text-red-300 bg-red-950/20 border-red-900/60"
            }`}
          >
            {recomputedHash || <span className="text-slate-600">Calculating...</span>}
          </div>
        </div>
      </div>

      {/* Optional Canonical Bytes Hex Collapsible */}
      {canonicalBytesHex && (
        <div className="mt-3">
          <button
            type="button"
            onClick={() => setShowCanonicalBytes(!showCanonicalBytes)}
            className="text-[11px] text-slate-500 hover:text-cyan-400 flex items-center gap-1.5 transition-colors"
          >
            <Code className="w-3 h-3" />
            <span>
              {showCanonicalBytes
                ? "Hide Canonical Serialization Bytes"
                : "Inspect Canonical Serialization Bytes (WASM get_canonical_bytes_hex)"}
            </span>
          </button>
          {showCanonicalBytes && (
            <div className="mt-2 p-2.5 rounded bg-[#080B11] border border-slate-800 text-[10px] text-slate-400 break-all select-text max-h-24 overflow-y-auto">
              {canonicalBytesHex}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
