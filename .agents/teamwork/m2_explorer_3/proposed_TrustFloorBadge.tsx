"use client";

/**
 * TrustFloorBadge: Visual progression ladder and badge for AIP Trust Floors.
 * Target: aip-console/src/components/ingestion/TrustFloorBadge.tsx
 *
 * STRICT CONSTRAINT: ZERO verification logic.
 * All floor states and tamper flags are received directly from the WASM VerificationReport.
 */

import React from "react";
import {
  TrustFloor,
  TRUST_FLOOR_ORDER,
  TRUST_FLOOR_META,
} from "@/types/verification";
import {
  ShieldAlert,
  ShieldCheck,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowRight,
} from "lucide-react";

export interface TrustFloorBadgeProps {
  derivedFloor: TrustFloor;
  claimedFloor?: TrustFloor;
  tamperEvidence?: boolean;
  variant?: "ladder" | "compact" | "banner";
  className?: string;
}

const ORDERED_FLOORS: TrustFloor[] = [
  "UNVERIFIED",
  "AGENT_SIGNED",
  "AUTHORITY_BOUND",
  "COUNTERPARTY_SIGNED",
];

export const TrustFloorBadge: React.FC<TrustFloorBadgeProps> = ({
  derivedFloor,
  claimedFloor,
  tamperEvidence = false,
  variant = "compact",
  className = "",
}) => {
  const derivedLevel = TRUST_FLOOR_ORDER[derivedFloor] ?? 0;
  const claimedLevel = claimedFloor ? TRUST_FLOOR_ORDER[claimedFloor] ?? 0 : derivedLevel;
  const isDowngraded = claimedFloor && derivedLevel < claimedLevel;
  const currentMeta = TRUST_FLOOR_META[derivedFloor] ?? TRUST_FLOOR_META.UNVERIFIED;

  // ── 1. Compact Pill Mode ───────────────────────────────────────────────────
  if (variant === "compact") {
    return (
      <div
        className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-xs font-mono font-medium border transition-colors ${currentMeta.badgeClass} ${className}`}
        title={`Derived: ${derivedFloor}${claimedFloor ? ` | Claimed: ${claimedFloor}` : ""}${tamperEvidence ? " (TAMPERED)" : ""}`}
      >
        {tamperEvidence ? (
          <Flame className="w-3.5 h-3.5 text-red-400 animate-pulse" />
        ) : isDowngraded ? (
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
        ) : derivedLevel > 0 ? (
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
        ) : (
          <Shield className="w-3.5 h-3.5 text-slate-400" />
        )}

        <span className="tracking-wide">
          [L{currentMeta.level}] {currentMeta.label}
        </span>

        {isDowngraded && (
          <span className="text-[10px] uppercase font-sans tracking-tight px-1 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
            Downgraded
          </span>
        )}
      </div>
    );
  }

  // ── 2. Top Banner Alert Mode ──────────────────────────────────────────────
  if (variant === "banner") {
    return (
      <div
        className={`p-3 rounded-lg border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
          tamperEvidence
            ? "bg-red-950/40 border-red-500/50 text-red-200"
            : isDowngraded
            ? "bg-amber-950/30 border-amber-500/50 text-amber-200"
            : "bg-slate-900/60 border-slate-800 text-slate-200"
        } ${className}`}
      >
        <div className="flex items-center gap-3">
          <div
            className={`p-2 rounded-md ${
              tamperEvidence
                ? "bg-red-500/20 text-red-400"
                : isDowngraded
                ? "bg-amber-500/20 text-amber-400"
                : "bg-cyan-500/20 text-cyan-400"
            }`}
          >
            {tamperEvidence ? (
              <Flame className="w-5 h-5 animate-pulse" />
            ) : isDowngraded ? (
              <AlertTriangle className="w-5 h-5" />
            ) : (
              <ShieldCheck className="w-5 h-5" />
            )}
          </div>
          <div>
            <div className="text-sm font-semibold flex items-center gap-2">
              <span>Trust Assurance Level:</span>
              <span className="font-mono text-cyan-300">
                Level {currentMeta.level} — {currentMeta.label}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              {currentMeta.description}
            </p>
          </div>
        </div>

        {claimedFloor && (
          <div className="flex items-center gap-2 text-xs font-mono bg-black/40 px-3 py-1.5 rounded-md border border-slate-800">
            <span className="text-slate-400">Claimed:</span>
            <span className="text-slate-200 font-semibold">{claimedFloor}</span>
            <ArrowRight className="w-3 h-3 text-slate-500" />
            <span className="text-slate-400">Derived:</span>
            <span
              className={
                isDowngraded ? "text-amber-400 font-bold" : "text-emerald-400 font-bold"
              }
            >
              {derivedFloor}
            </span>
          </div>
        )}
      </div>
    );
  }

  // ── 3. Full Stepped Progression Ladder Mode (Default) ─────────────────────
  return (
    <div
      className={`rounded-xl border border-slate-800 bg-[#0E131F]/90 p-4 sm:p-5 backdrop-blur-sm ${className}`}
    >
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Trust Floor Progression Ladder
          </span>
        </div>

        <div className="flex items-center gap-2">
          {tamperEvidence && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse">
              <Flame className="w-3 h-3" />
              TAMPER EVIDENT
            </span>
          )}

          {isDowngraded && !tamperEvidence && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40">
              <AlertTriangle className="w-3 h-3" />
              CLAIM INFLATED (DOWNGRADED)
            </span>
          )}

          {!isDowngraded && !tamperEvidence && derivedLevel >= 2 && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <CheckCircle2 className="w-3 h-3" />
              CLAIM VERIFIED
            </span>
          )}
        </div>
      </div>

      {/* Stepped horizontal rail */}
      <div className="relative py-2">
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 sm:gap-2 relative z-10">
          {ORDERED_FLOORS.map((floor, idx) => {
            const meta = TRUST_FLOOR_META[floor];
            const isDerivedOrBelow = idx <= derivedLevel;
            const isCurrentDerived = idx === derivedLevel;
            const isClaimedMarker = claimedFloor && floor === claimedFloor;
            const isAboveDerived = idx > derivedLevel;

            return (
              <div
                key={floor}
                className={`relative rounded-lg p-3 transition-all border ${
                  isCurrentDerived
                    ? `${meta.borderClass} ${meta.bgClass} shadow-[0_0_15px_rgba(0,229,255,0.15)] ring-1 ring-cyan-500/30`
                    : isDerivedOrBelow
                    ? "border-slate-700/60 bg-slate-900/40 text-slate-300"
                    : "border-slate-800/50 bg-[#080B11]/50 text-slate-600 opacity-60"
                }`}
              >
                {/* Step indicator header */}
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-mono font-bold ${
                        isCurrentDerived
                          ? "bg-cyan-500 text-black font-extrabold"
                          : isDerivedOrBelow
                          ? "bg-slate-700 text-slate-200"
                          : "bg-slate-800 text-slate-500"
                      }`}
                    >
                      {idx}
                    </span>
                    <span className="text-[11px] font-mono font-semibold tracking-tight text-slate-300">
                      {meta.label}
                    </span>
                  </div>

                  {isCurrentDerived && (
                    <span className="text-[9px] uppercase tracking-wider font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-400/20 text-cyan-300 border border-cyan-400/30">
                      Current
                    </span>
                  )}
                </div>

                {/* Description */}
                <p className="text-[10px] leading-relaxed text-slate-400 min-h-[2.5rem]">
                  {meta.description}
                </p>

                {/* Claimed vs Derived Markers */}
                <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono">
                  {isClaimedMarker && (
                    <span className="text-amber-300/90 font-medium">
                      ★ Producer Claim
                    </span>
                  )}
                  {isCurrentDerived && (
                    <span className="text-cyan-400 font-semibold ml-auto">
                      ✓ Engine Derived
                    </span>
                  )}
                  {!isClaimedMarker && !isCurrentDerived && (
                    <span className="text-slate-600">
                      {isDerivedOrBelow ? "Supported" : "Unreached"}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Downgrade alert footer explanation */}
      {isDowngraded && (
        <div className="mt-3 p-2.5 rounded bg-amber-950/20 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
          <span>
            <strong>Assurance Downgrade:</strong> Packet producer claimed{" "}
            <code className="font-mono text-amber-200">[{claimedFloor}]</code>, but
            engine rules only verify up to{" "}
            <code className="font-mono text-cyan-300">[{derivedFloor}]</code>.
          </span>
        </div>
      )}

      {tamperEvidence && (
        <div className="mt-3 p-2.5 rounded bg-red-950/30 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
          <Flame className="w-4 h-4 text-red-400 flex-shrink-0 animate-pulse" />
          <span>
            <strong>Cryptographic Tamper Alert:</strong> One or more integrity rules failed
            positive verification. This packet has been modified after sealing or
            contains forged signatures.
          </span>
        </div>
      )}
    </div>
  );
};

export default TrustFloorBadge;
