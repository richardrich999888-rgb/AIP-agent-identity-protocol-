"use client";

import React, { useState, useMemo, useEffect, useCallback } from "react";
import {
  ActionVerb,
  CapabilityScope,
  StandardScopePreset,
  LatticeMeetResult,
} from "./types";
import { PRESET_SCOPES } from "./presetScopes";
import {
  STANDARD_ACTIONS,
  verbEquals,
  hasVerb,
  actionToString,
  stringToAction,
  scopeToWasmJson,
  wasmJsonToMeetResult,
  meetCapabilityScopesPure,
  isScopeSubset,
  scopePermitsAction,
} from "./scopeNormalization";
import { useAipVerifier } from "@/lib/wasm/useAipVerifier";
import {
  Layers,
  ArrowRightLeft,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Search,
  Filter,
} from "lucide-react";

export interface LatticeAttenuationPreviewProps {
  initialParent?: CapabilityScope;
  initialChild?: CapabilityScope;
  className?: string;
}

export const LatticeAttenuationPreview: React.FC<LatticeAttenuationPreviewProps> = ({
  initialParent,
  initialChild,
  className = "",
}) => {
  const verifier = useAipVerifier();

  // Parent and Child Presets / Scopes
  const [parentPreset, setParentPreset] = useState<StandardScopePreset | "CUSTOM">("ADMIN");
  const [childPreset, setChildPreset] = useState<StandardScopePreset | "CUSTOM">("ORCHESTRATOR");

  const [parentScope, setParentScope] = useState<CapabilityScope>(
    initialParent || PRESET_SCOPES.ADMIN.scope
  );
  const [childScope, setChildScope] = useState<CapabilityScope>(
    initialChild || PRESET_SCOPES.ORCHESTRATOR.scope
  );

  // Permission test probe state
  const [probeAction, setProbeAction] = useState("Execute");
  const [probeResult, setProbeResult] = useState<{
    permitted: boolean;
    reason: string;
  } | null>(null);

  // Update scope when preset changes
  const handleSelectParentPreset = (presetKey: StandardScopePreset) => {
    setParentPreset(presetKey);
    setParentScope(PRESET_SCOPES[presetKey].scope);
  };

  const handleSelectChildPreset = (presetKey: StandardScopePreset) => {
    setChildPreset(presetKey);
    setChildScope(PRESET_SCOPES[presetKey].scope);
  };

  // Swap parent and child
  const handleSwap = () => {
    const tempP = parentScope;
    const tempPPreset = parentPreset;
    setParentScope(childScope);
    setParentPreset(childPreset);
    setChildScope(tempP);
    setChildPreset(tempPPreset);
  };

  // Compute meet result via WASM or Pure fallback
  const meetResult: LatticeMeetResult = useMemo(() => {
    let wasmResult: { scope: CapabilityScope | null; isBottom: boolean } | null = null;

    if (verifier.isReady) {
      try {
        const pJson = scopeToWasmJson(parentScope);
        const cJson = scopeToWasmJson(childScope);
        const rawWasmMeet = verifier.meetScopes(pJson, cJson);
        wasmResult = wasmJsonToMeetResult(rawWasmMeet);
      } catch (err) {
        console.warn("WASM meet error, using reference oracle:", err);
      }
    }

    // Reference oracle meet
    const refMeet = meetCapabilityScopesPure(parentScope, childScope);
    const effectiveScope = wasmResult ? wasmResult.scope : refMeet;
    const isBottom = wasmResult ? wasmResult.isBottom : refMeet === null;

    const allowed = effectiveScope ? effectiveScope.allowed : [];
    const denied = effectiveScope ? effectiveScope.denied : [...parentScope.denied, ...childScope.denied];

    // Partition 1: Retained by Parent = parent.allowed \ effective.allowed
    const retainedByParent = parentScope.allowed.filter(
      (pa) => !hasVerb(allowed, pa) && !hasVerb(parentScope.denied, pa)
    );

    // Partition 2: Attenuated Grant = effective.allowed
    const attenuatedGrant = allowed;

    // Partition 3: Escalation Attempts = child.allowed \ (parent.allowed \ parent.denied)
    const pAllowedWithoutDenied = parentScope.allowed.filter(
      (pa) => !hasVerb(parentScope.denied, pa)
    );
    // If parent has Admin, it implicitly allows all standard verbs unless denied
    const parentHasAdmin = parentScope.allowed.some(
      (a) => a.kind === "Standard" && a.action === "Admin"
    );

    const escalationAttempts = childScope.allowed.filter((ca) => {
      if (hasVerb(parentScope.denied, ca)) return true;
      if (ca.kind === "Standard" && parentHasAdmin) {
        return false;
      }
      return !hasVerb(pAllowedWithoutDenied, ca);
    });

    // Partition 4: Cumulative Denials = parent.denied ∪ child.denied
    const cumulativeDenials = denied;

    const isSubset = isScopeSubset(parentScope, childScope);

    return {
      scope: effectiveScope,
      isBottom,
      allowed,
      denied,
      retainedByParent,
      attenuatedGrant,
      escalationAttempts,
      cumulativeDenials,
      isSubset,
    };
  }, [parentScope, childScope, verifier]);

  // Execute permission probe query
  const runProbe = useCallback(() => {
    const trimmed = probeAction.trim();
    if (!trimmed) {
      setProbeResult(null);
      return;
    }

    const verb = stringToAction(trimmed);
    const targetScope = meetResult.scope || { allowed: [], denied: meetResult.cumulativeDenials };

    let isPermitted = false;
    let reason = "";

    // 1. WASM Query if ready
    if (verifier.isReady) {
      try {
        const sJson = scopeToWasmJson(targetScope);
        const aJson = JSON.stringify(actionToString(verb));
        isPermitted = verifier.checkScope(sJson, aJson);
      } catch {
        isPermitted = scopePermitsAction(targetScope, verb);
      }
    } else {
      isPermitted = scopePermitsAction(targetScope, verb);
    }

    if (isPermitted) {
      reason = "Directly granted in effective attenuated scope (P ⊓ C).";
    } else if (hasVerb(targetScope.denied, verb)) {
      reason = "Explicitly blocked by cumulative denial set (P.denied ∪ C.denied).";
    } else if (hasVerb(meetResult.escalationAttempts, verb)) {
      reason = "Blocked: child requested permission exceeding parent authority (NM-A1 escalation prevention).";
    } else if (meetResult.isBottom) {
      reason = "Blocked: capability intersection is bottom (⊥), granting zero permissions.";
    } else {
      reason = "Prohibited: default-closed security policy.";
    }

    setProbeResult({ permitted: isPermitted, reason });
  }, [probeAction, meetResult, verifier]);

  // Run probe initially and when meetResult changes
  useEffect(() => {
    runProbe();
  }, [runProbe]);

  return (
    <div
      data-testid="lattice-preview-container"
      className={`rounded-md border border-slate-800 bg-[#0E131F] p-4 sm:p-6 font-mono text-xs shadow-2xl space-y-6 ${className}`}
    >
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-100 uppercase tracking-wide">
              Capability Lattice Attenuation Preview
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/60 text-cyan-300">
              Meet Operator (⊓) • Feature F15
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Simulates mathematical capability attenuation between Parent Grantor Scope (P) and Requested Child Scope (C) in compiled WebAssembly.
          </p>
        </div>

        <button
          type="button"
          onClick={handleSwap}
          className="px-3 py-1.5 rounded-md border border-slate-700 bg-[#080B11] hover:bg-slate-800 text-slate-300 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
          title="Swap Parent and Child scopes to test reverse monotonicity"
        >
          <ArrowRightLeft className="w-3.5 h-3.5 text-cyan-400" />
          <span>Swap Parent / Child</span>
        </button>
      </div>

      {/* ── Dual Scope Comparator Controls ─────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Parent Grantor Scope Panel */}
        <div className="p-4 rounded-md border border-slate-800 bg-[#080B11] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              Parent Grantor Scope (P)
            </span>
            <span className="text-[10px] text-slate-500 font-mono">
              {parentScope.allowed.length} allowed, {parentScope.denied.length} denied
            </span>
          </div>

          {/* Preset Selector */}
          <div className="flex flex-wrap gap-1">
            <select
              data-testid="parent-scope-selector"
              value={parentPreset}
              onChange={(e) => {
                const val = e.target.value as StandardScopePreset;
                handleSelectParentPreset(val);
              }}
              className="w-full bg-[#0E131F] border border-slate-800 rounded-md p-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ADMIN">ADMIN (System Administrator)</option>
              <option value="ORCHESTRATOR">ORCHESTRATOR (Task Orchestrator)</option>
              <option value="AUDITOR">AUDITOR (AUDIT_READER)</option>
              <option value="WORKER">WORKER (SUBMITTER)</option>
              <option value="READ_ONLY">READ_ONLY (Observer)</option>
            </select>
          </div>

          {/* Allowed Verbs Badges */}
          <div className="space-y-1.5 pt-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider">Granted Capabilities:</span>
            <div className="flex flex-wrap gap-1">
              {parentScope.allowed.map((a, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/60"
                >
                  {actionToString(a)}
                </span>
              ))}
              {parentScope.allowed.length === 0 && (
                <span className="text-slate-600 text-[11px] italic">None (Empty Scope)</span>
              )}
            </div>
          </div>

          {/* Denied Verbs */}
          {parentScope.denied.length > 0 && (
            <div className="space-y-1 pt-1">
              <span className="text-[10px] text-red-400 uppercase tracking-wider">Explicitly Denied:</span>
              <div className="flex flex-wrap gap-1">
                {parentScope.denied.map((d, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded text-[11px] font-mono bg-red-950/50 text-red-300 border border-red-800/60"
                  >
                    {actionToString(d)}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Child Grantee Scope Panel */}
        <div className="p-4 rounded-md border border-slate-800 bg-[#080B11] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-indigo-300 uppercase tracking-wider flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-indigo-400" />
              Requested Child Scope (C)
            </span>
            <span className="text-[10px] text-slate-500 font-mono">
              {childScope.allowed.length} requested, {childScope.denied.length} denied
            </span>
          </div>

          {/* Preset Selector */}
          <div className="flex flex-wrap gap-1">
            <select
              data-testid="child-scope-selector"
              value={childPreset}
              onChange={(e) => {
                const val = e.target.value as StandardScopePreset;
                handleSelectChildPreset(val);
              }}
              className="w-full bg-[#0E131F] border border-slate-800 rounded-md p-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
            >
              <option value="ADMIN">ADMIN (Greedy Child - Tests Escalation)</option>
              <option value="ORCHESTRATOR">ORCHESTRATOR (Task Orchestrator)</option>
              <option value="AUDITOR">AUDITOR (AUDIT_READER)</option>
              <option value="WORKER">WORKER (SUBMITTER)</option>
              <option value="READ_ONLY">READ_ONLY (Observer)</option>
            </select>
          </div>

          {/* Allowed Verbs Badges */}
          <div className="space-y-1.5 pt-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider">Requested Capabilities:</span>
            <div className="flex flex-wrap gap-1">
              {childScope.allowed.map((a, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[11px] font-mono bg-indigo-950/60 text-indigo-300 border border-indigo-800/60"
                >
                  {actionToString(a)}
                </span>
              ))}
              {childScope.allowed.length === 0 && (
                <span className="text-slate-600 text-[11px] italic">None (Empty Scope)</span>
              )}
            </div>
          </div>

          {/* Denied Verbs */}
          {childScope.denied.length > 0 && (
            <div className="space-y-1 pt-1">
              <span className="text-[10px] text-red-400 uppercase tracking-wider">Explicitly Denied:</span>
              <div className="flex flex-wrap gap-1">
                {childScope.denied.map((d, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded text-[11px] font-mono bg-red-950/50 text-red-300 border border-red-800/60"
                  >
                    {actionToString(d)}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Status Banners (Bottom ⊥ / Escalation Warning / Valid Monotonic) ── */}
      {meetResult.isBottom ? (
        <div
          data-testid="bottom-conflict-banner"
          className="p-4 rounded-md border border-red-500/60 bg-red-950/40 text-red-200 flex items-start gap-3"
        >
          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div className="space-y-1 font-sans">
            <h4 className="font-bold text-xs uppercase tracking-wide text-red-300 font-mono">
              LATTICE BOTTOM CONFLICT (⊥): ZERO CAPABILITIES GRANTED
            </h4>
            <p className="text-xs leading-relaxed opacity-90">
              Parent and Child capability scopes are disjoint or mutually contradictory. The meet operator evaluates to bottom (⊥). A delegated agent with this scope cannot perform any authorized action and will fail Rule 8 (SCOPE_AUTHORITY).
            </p>
          </div>
        </div>
      ) : meetResult.escalationAttempts.length > 0 ? (
        <div
          data-testid="escalation-warning-banner"
          className="p-4 rounded-md border border-amber-500/60 bg-amber-950/40 text-amber-200 flex items-start gap-3"
        >
          <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
          <div className="space-y-1 font-sans">
            <h4 className="font-bold text-xs uppercase tracking-wide text-amber-300 font-mono">
              SCOPE ESCALATION BLOCKED (NM-A1 ENFORCEMENT)
            </h4>
            <p className="text-xs leading-relaxed opacity-90">
              Child requested permissions exceeding Parent authority:{" "}
              <strong className="text-amber-100 font-mono">
                [ {meetResult.escalationAttempts.map(actionToString).join(", ")} ]
              </strong>
              . In accordance with AIP Novel Mechanism NM-A1, these actions have been stripped from the effective grant. Authority expansion is mathematically prevented.
            </p>
          </div>
        </div>
      ) : (
        <div
          data-testid="valid-attenuation-banner"
          className="p-4 rounded-md border border-emerald-500/60 bg-emerald-950/40 text-emerald-200 flex items-start gap-3"
        >
          <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
          <div className="space-y-1 font-sans">
            <h4 className="font-bold text-xs uppercase tracking-wide text-emerald-300 font-mono">
              ✓ VALID MONOTONIC ATTENUATION (C ⊆ P)
            </h4>
            <p className="text-xs leading-relaxed opacity-90">
              Requested child scope strictly attenuates parent authority. Monotonicity invariant satisfied. Safe for cryptographic delegation token issuance.
            </p>
          </div>
        </div>
      )}

      {/* ── 4-Partition Venn / Lattice Attenuation Diagram ────────────────── */}
      <div className="p-5 rounded-md border border-slate-800 bg-[#080B11] space-y-4">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <span>Attenuated Capability Partitions</span>
          <span className="text-[10px] text-slate-500 font-normal">
            (P ⊓ C = Allowed(C) ∩ [Allowed(P) \ Denied(P)])
          </span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {/* Partition 1: Retained by Parent */}
          <div className="p-3.5 rounded-md border border-slate-800 bg-[#0E131F] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                1. Retained by Parent
              </span>
              <span className="text-[10px] text-slate-500">P \ (P ⊓ C)</span>
            </div>
            <p className="text-[10px] text-slate-500 font-sans">
              Held by parent but not delegated downstream.
            </p>
            <div className="flex flex-wrap gap-1 pt-1">
              {meetResult.retainedByParent.map((a, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-850 text-slate-400 border border-slate-750"
                >
                  {actionToString(a)}
                </span>
              ))}
              {meetResult.retainedByParent.length === 0 && (
                <span className="text-slate-600 text-[10px] italic">None</span>
              )}
            </div>
          </div>

          {/* Partition 2: Attenuated Grant */}
          <div className="p-3.5 rounded-md border border-emerald-500/40 bg-emerald-950/20 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-emerald-300 uppercase tracking-wider">
                2. Attenuated Grant
              </span>
              <span className="text-[10px] text-emerald-400 font-bold">P ⊓ C</span>
            </div>
            <p className="text-[10px] text-emerald-400/80 font-sans">
              Legitimate, verified capabilities granted to child.
            </p>
            <div className="flex flex-wrap gap-1 pt-1">
              {meetResult.attenuatedGrant.map((a, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/70 text-emerald-300 border border-emerald-500/50"
                >
                  {actionToString(a)}
                </span>
              ))}
              {meetResult.attenuatedGrant.length === 0 && (
                <span className="text-red-400 text-[10px] font-bold italic">
                  Bottom (⊥) - Zero Granted
                </span>
              )}
            </div>
          </div>

          {/* Partition 3: Escalation Attempts */}
          <div className="p-3.5 rounded-md border border-red-500/40 bg-red-950/20 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-red-300 uppercase tracking-wider">
                3. Escalation Blocked
              </span>
              <span className="text-[10px] text-red-400 font-bold">C \ P</span>
            </div>
            <p className="text-[10px] text-red-400/80 font-sans">
              Requested permissions stripped by meet operator.
            </p>
            <div className="flex flex-wrap gap-1 pt-1">
              {meetResult.escalationAttempts.map((a, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[10px] font-mono line-through decoration-red-500 decoration-2 bg-red-950/70 text-red-300 border border-red-500/50"
                >
                  {actionToString(a)}
                </span>
              ))}
              {meetResult.escalationAttempts.length === 0 && (
                <span className="text-emerald-400 text-[10px] italic">0 Escalations</span>
              )}
            </div>
          </div>

          {/* Partition 4: Cumulative Denials */}
          <div className="p-3.5 rounded-md border border-amber-500/40 bg-amber-950/20 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-amber-300 uppercase tracking-wider">
                4. Cumulative Denials
              </span>
              <span className="text-[10px] text-amber-400 font-bold">P.denied ∪ C.denied</span>
            </div>
            <p className="text-[10px] text-amber-400/80 font-sans">
              Monotonically preserved explicit prohibitions.
            </p>
            <div className="flex flex-wrap gap-1 pt-1">
              {meetResult.cumulativeDenials.map((d, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950/70 text-amber-300 border border-amber-500/50"
                >
                  {actionToString(d)}
                </span>
              ))}
              {meetResult.cumulativeDenials.length === 0 && (
                <span className="text-slate-600 text-[10px] italic">None</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Real-Time Permission Testing Probe ────────────────────────────── */}
      <div className="p-4 rounded-md border border-slate-800 bg-[#080B11] space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
            <Search className="w-3.5 h-3.5 text-cyan-400" />
            Interactive Permission Probe Sandbox
          </h3>
          <span className="text-[10px] text-slate-500 font-normal">
            Calls WASM check_scope_permits
          </span>
        </div>

        <div className="flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            data-testid="test-action-input"
            value={probeAction}
            onChange={(e) => setProbeAction(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") runProbe();
            }}
            placeholder="Type action verb to probe (e.g. Execute, loan:approve, Admin)..."
            className="flex-1 bg-[#0E131F] border border-slate-850 rounded-md px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          />

          <button
            type="button"
            data-testid="test-action-btn"
            onClick={runProbe}
            className="px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-obsidian-950 font-bold transition-colors whitespace-nowrap"
          >
            Probe Permission
          </button>
        </div>

        {/* Quick action chips for probe */}
        <div className="flex flex-wrap items-center gap-1 pt-1">
          <span className="text-[10px] text-slate-500 mr-1">Quick Probe:</span>
          {["Read", "Write", "Admin", "Execute", "loan:approve", "wire:transfer"].map(
            (act) => (
              <button
                key={act}
                type="button"
                onClick={() => {
                  setProbeAction(act);
                }}
                className="px-2 py-0.5 rounded bg-slate-850 hover:bg-slate-800 border border-slate-750 text-slate-300 text-[10px] transition-colors"
              >
                {act}
              </button>
            )
          )}
        </div>

        {/* Probe Result Display */}
        {probeResult && (
          <div
            className={`mt-2 p-3 rounded-md border text-xs font-mono flex items-center justify-between gap-4 ${
              probeResult.permitted
                ? "bg-emerald-950/30 border-emerald-500/50 text-emerald-200"
                : "bg-red-950/30 border-red-500/50 text-red-200"
            }`}
          >
            <div className="flex items-center gap-2.5">
              {probeResult.permitted ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              ) : (
                <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
              )}
              <span className="font-sans text-[11px]">{probeResult.reason}</span>
            </div>

            <span
              data-testid="test-action-result"
              className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${
                probeResult.permitted
                  ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                  : "bg-red-500/20 text-red-300 border-red-500/40"
              }`}
            >
              {probeResult.permitted ? "PERMITTED" : "PROHIBITED"}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
