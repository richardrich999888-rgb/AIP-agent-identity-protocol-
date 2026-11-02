"use client";

/**
 * TrustFloorBadge: trust floor badge, banner and progression ladder.
 *
 * STRICT CONSTRAINT: ZERO verification logic.
 * All floor states and tamper flags are received directly from the WASM VerificationReport.
 */

import React from "react";
import { TrustFloor, TRUST_FLOOR_ORDER, TRUST_FLOOR_META } from "@/types/verification";
import { ShieldCheck, Shield, CheckCircle2, AlertTriangle, ShieldAlert, ArrowRight, Flag } from "lucide-react";
import { badge, panel, panelHeader, panelTitle } from "@/components/ui/styles";

export interface TrustFloorBadgeProps {
  derivedFloor: TrustFloor;
  claimedFloor?: TrustFloor;
  tamperEvidence?: boolean;
  variant?: "ladder" | "compact" | "banner";
  className?: string;
}

const ORDERED_FLOORS: TrustFloor[] = ["UNVERIFIED", "AGENT_SIGNED", "AUTHORITY_BOUND", "COUNTERPARTY_SIGNED"];

const FLOOR_LABEL: Record<TrustFloor, string> = {
  UNVERIFIED: "Unverified",
  AGENT_SIGNED: "Agent signed",
  AUTHORITY_BOUND: "Authority bound",
  COUNTERPARTY_SIGNED: "Counterparty signed",
};

export const TrustFloorBadge: React.FC<TrustFloorBadgeProps> = ({
  derivedFloor,
  claimedFloor,
  tamperEvidence = false,
  variant = "compact",
  className = "",
}) => {
  const derivedLevel = TRUST_FLOOR_ORDER[derivedFloor] ?? 0;
  const claimedLevel = claimedFloor ? TRUST_FLOOR_ORDER[claimedFloor] ?? 0 : derivedLevel;
  const isDowngraded = Boolean(claimedFloor) && derivedLevel < claimedLevel;
  const currentMeta = TRUST_FLOOR_META[derivedFloor] ?? TRUST_FLOOR_META.UNVERIFIED;

  const stateBadge = tamperEvidence
    ? badge.danger
    : isDowngraded
    ? badge.warning
    : derivedLevel >= 2
    ? badge.success
    : derivedLevel === 1
    ? badge.warning
    : badge.neutral;

  // ── 1. Compact badge ──────────────────────────────────────────────────────
  if (variant === "compact") {
    return (
      <span
        className={`${stateBadge} ${className}`}
        title={`Derived: ${derivedFloor}${claimedFloor ? ` | Claimed: ${claimedFloor}` : ""}${tamperEvidence ? " (tampered)" : ""}`}
      >
        {tamperEvidence ? (
          <ShieldAlert className="w-3 h-3" aria-hidden />
        ) : isDowngraded ? (
          <AlertTriangle className="w-3 h-3" aria-hidden />
        ) : derivedLevel > 0 ? (
          <ShieldCheck className="w-3 h-3" aria-hidden />
        ) : (
          <Shield className="w-3 h-3" aria-hidden />
        )}
        Level {currentMeta.level} · {FLOOR_LABEL[derivedFloor]}
        {isDowngraded && <span className="ml-1 opacity-80">(downgraded)</span>}
      </span>
    );
  }

  // ── 2. Banner ─────────────────────────────────────────────────────────────
  if (variant === "banner") {
    const tone = tamperEvidence
      ? "border-corporate-danger/40 bg-corporate-danger/10"
      : isDowngraded
      ? "border-corporate-warning/40 bg-corporate-warning/10"
      : "border-obsidian-700 bg-obsidian-900";
    const Icon = tamperEvidence ? ShieldAlert : isDowngraded ? AlertTriangle : ShieldCheck;
    const iconTone = tamperEvidence
      ? "text-corporate-danger-light"
      : isDowngraded
      ? "text-corporate-warning-light"
      : "text-corporate-steel-light";

    return (
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-md border p-3 ${tone} ${className}`}>
        <div className="flex items-start gap-2.5">
          <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${iconTone}`} aria-hidden />
          <div>
            <p className="text-[13px] font-medium text-slate-100">
              Trust floor: level {currentMeta.level}, {FLOOR_LABEL[derivedFloor].toLowerCase()}
            </p>
            <p className="text-xs text-slate-400 mt-0.5">{currentMeta.description}</p>
          </div>
        </div>

        {claimedFloor && (
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>claimed</span>
            <span className="text-slate-200">{claimedFloor}</span>
            <ArrowRight className="w-3 h-3 text-slate-500" aria-hidden />
            <span>derived</span>
            <span className={isDowngraded ? "text-corporate-warning-light" : "text-corporate-accent-light"}>
              {derivedFloor}
            </span>
          </div>
        )}
      </div>
    );
  }

  // ── 3. Progression ladder (default) ──────────────────────────────────────
  return (
    <section className={`${panel} ${className}`} aria-labelledby="trust-floor-heading">
      <div className={panelHeader}>
        <div>
          <h2 id="trust-floor-heading" className={panelTitle}>
            Trust floor
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Level the verifier could prove, compared with the level the producer claimed.
          </p>
        </div>

        {tamperEvidence ? (
          <span className={badge.danger}>
            <ShieldAlert className="w-3 h-3" aria-hidden />
            Tamper evident
          </span>
        ) : isDowngraded ? (
          <span className={badge.warning}>
            <AlertTriangle className="w-3 h-3" aria-hidden />
            Claim inflated, downgraded
          </span>
        ) : derivedLevel >= 2 ? (
          <span className={badge.success}>
            <CheckCircle2 className="w-3 h-3" aria-hidden />
            Claim verified
          </span>
        ) : null}
      </div>

      <ol className="grid grid-cols-1 sm:grid-cols-4 gap-px bg-obsidian-700">
        {ORDERED_FLOORS.map((floor, idx) => {
          const meta = TRUST_FLOOR_META[floor];
          const reached = idx <= derivedLevel;
          const isCurrent = idx === derivedLevel;
          const isClaimed = claimedFloor === floor;

          return (
            <li
              key={floor}
              aria-current={isCurrent ? "step" : undefined}
              className={`relative bg-obsidian-900 px-4 pt-4 pb-3 ${isCurrent ? "bg-obsidian-850" : ""}`}
            >
              <span
                aria-hidden
                className={`absolute inset-x-0 top-0 h-0.5 ${
                  isCurrent
                    ? tamperEvidence
                      ? "bg-corporate-danger-light"
                      : "bg-corporate-steel-light"
                    : reached
                    ? "bg-corporate-steel"
                    : "bg-transparent"
                }`}
              />
              <div className="flex items-baseline justify-between gap-2">
                <span className={`text-xs ${reached ? "text-slate-400" : "text-slate-600"}`}>Level {idx}</span>
                <span className="font-mono text-[11px] text-slate-500">{meta.label}</span>
              </div>
              <p className={`mt-1 text-[13px] font-semibold ${reached ? "text-slate-100" : "text-slate-500"}`}>
                {FLOOR_LABEL[floor]}
              </p>
              <p className={`mt-1 text-xs leading-relaxed ${reached ? "text-slate-400" : "text-slate-600"}`}>
                {meta.description}
              </p>

              {(isCurrent || isClaimed) && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {isCurrent && (
                    <span className={tamperEvidence ? badge.danger : badge.neutral}>
                      <ShieldCheck className="w-3 h-3" aria-hidden />
                      Derived by verifier
                    </span>
                  )}
                  {isClaimed && (
                    <span className={isDowngraded ? badge.warning : badge.neutral}>
                      <Flag className="w-3 h-3" aria-hidden />
                      Producer claim
                    </span>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ol>

      {(isDowngraded || tamperEvidence) && (
        <div className="border-t border-obsidian-700 px-4 py-3 space-y-2">
          {isDowngraded && (
            <p className="flex items-start gap-2 text-xs text-slate-300">
              <AlertTriangle className="w-4 h-4 text-corporate-warning-light shrink-0" aria-hidden />
              <span>
                The producer claimed <code className="font-mono text-slate-100">{claimedFloor}</code>, but the
                verifier could only prove <code className="font-mono text-slate-100">{derivedFloor}</code>.
              </span>
            </p>
          )}
          {tamperEvidence && (
            <p className="flex items-start gap-2 text-xs text-slate-300">
              <ShieldAlert className="w-4 h-4 text-corporate-danger-light shrink-0" aria-hidden />
              <span>
                One or more integrity rules failed. The packet was modified after sealing or carries a forged
                signature.
              </span>
            </p>
          )}
        </div>
      )}
    </section>
  );
};

export default TrustFloorBadge;
