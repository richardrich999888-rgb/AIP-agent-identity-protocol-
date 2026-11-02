"use client";

import React, { useState, useMemo, useCallback } from "react";
import {
  ActionVerb,
  CapabilityScope,
  StandardActionName,
  StandardScopePreset,
  MatrixScopeState,
} from "./types";
import { PRESET_SCOPES } from "./presetScopes";
import {
  STANDARD_ACTIONS,
  verbEquals,
  hasVerb,
  scopePermitsAction,
} from "./scopeNormalization";
import {
  ShieldCheck,
  Plus,
  Trash2,
  CheckCircle2,
  XCircle,
  Sparkles,
  Search,
  Check,
  AlertCircle,
  Key,
  FolderGit2,
} from "lucide-react";

export interface ScopeMatrixEditorProps {
  value?: CapabilityScope;
  onChange?: (scope: CapabilityScope) => void;
  className?: string;
}

const ACTION_OPCODES: Record<StandardActionName, { code: string; desc: string }> = {
  Read: { code: "0x01", desc: "Inspect evidence packets, audit logs, and verified DAG state" },
  Write: { code: "0x02", desc: "Submit evidence records, sign decisions, and attest operations" },
  Delete: { code: "0x03", desc: "Invalidate or expunge stored evidence records" },
  Admin: { code: "0x04", desc: "Manage KMS credentials, revoke tokens, reconfigure trust anchors" },
  Execute: { code: "0x05", desc: "Trigger autonomous AI tool execution and workflow actions" },
  Delegate: { code: "0x06", desc: "Issue child delegation tokens and transfer authority to sub-agents" },
};

const ENTERPRISE_CHIPS = [
  "loan:approve",
  "credit:underwrite",
  "wire:transfer",
  "ledger/treasury:transfer-wire_v2",
  "audit:export",
];

export const ScopeMatrixEditor: React.FC<ScopeMatrixEditorProps> = ({
  value,
  onChange,
  className = "",
}) => {
  // Active internal scope state
  const [internalScope, setInternalScope] = useState<CapabilityScope>(
    value || PRESET_SCOPES.ADMIN.scope
  );

  // Constraints and resource patterns
  const [constraints, setConstraints] = useState<Record<string, string>>({
    environment: "production",
    max_amount: "5000000",
  });
  const [newConstraintKey, setNewConstraintKey] = useState("");
  const [newConstraintVal, setNewConstraintVal] = useState("");

  const [resourcePatterns, setResourcePatterns] = useState<string[]>([
    "treasury/transfers/*",
    "vault:acme:**",
  ]);
  const [newPattern, setNewPattern] = useState("");

  // Resource tester state
  const [testPath, setTestPath] = useState("treasury/transfers/batch_99");

  // Custom action input
  const [customActionInput, setCustomActionInput] = useState("");
  const [customActionError, setCustomActionError] = useState<string | null>(null);

  // Active preset tracking
  const [activePreset, setActivePreset] = useState<StandardScopePreset | null>("ADMIN");

  // Keep internal state synced if parent value changes
  React.useEffect(() => {
    if (value) {
      setInternalScope(value);
    }
  }, [value]);

  const updateScope = useCallback(
    (updater: (prev: CapabilityScope) => CapabilityScope) => {
      setInternalScope((prev) => {
        const next = updater(prev);
        onChange?.(next);
        return next;
      });
      setActivePreset(null);
    },
    [onChange]
  );

  // Apply Preset
  const handleSelectPreset = (presetKey: StandardScopePreset) => {
    const preset = PRESET_SCOPES[presetKey];
    if (!preset) return;
    setActivePreset(presetKey);
    setInternalScope(preset.scope);
    if (preset.constraints) setConstraints(preset.constraints);
    if (preset.resource_patterns) setResourcePatterns(preset.resource_patterns);
    onChange?.(preset.scope);
  };

  // Toggle Standard Action
  const toggleStandardAction = (action: StandardActionName, targetState: "allow" | "deny" | "unset") => {
    const verb: ActionVerb = { kind: "Standard", action };
    updateScope((prev) => {
      let allowed = prev.allowed.filter((a) => !verbEquals(a, verb));
      let denied = prev.denied.filter((d) => !verbEquals(d, verb));

      if (targetState === "allow") {
        allowed.push(verb);
      } else if (targetState === "deny") {
        denied.push(verb);
      }
      // unset means removed from both

      return { allowed, denied };
    });
  };

  // Custom Action Validation & Adding
  const handleAddCustomAction = () => {
    const trimmed = customActionInput.trim();
    if (!trimmed) return;

    // Validate regex ^[a-zA-Z0-9_\-\:\.\/]+$
    const validRegex = /^[a-zA-Z0-9_\-:\.\/]+$/;
    if (!validRegex.test(trimmed)) {
      setCustomActionError("Invalid characters. Allowed: alphanumeric, _, -, :, ., /");
      return;
    }

    const verb: ActionVerb = { kind: "Custom", name: trimmed };

    // Prevent duplicate
    if (hasVerb(internalScope.allowed, verb) || hasVerb(internalScope.denied, verb)) {
      setCustomActionError(`Action '${trimmed}' is already in matrix.`);
      return;
    }

    setCustomActionError(null);
    updateScope((prev) => ({
      allowed: [...prev.allowed, verb],
      denied: prev.denied,
    }));
    setCustomActionInput("");
  };

  const handleToggleCustomAction = (verb: ActionVerb, targetState: "allow" | "deny") => {
    updateScope((prev) => {
      let allowed = prev.allowed.filter((a) => !verbEquals(a, verb));
      let denied = prev.denied.filter((d) => !verbEquals(d, verb));

      if (targetState === "allow") {
        allowed.push(verb);
      } else {
        denied.push(verb);
      }

      return { allowed, denied };
    });
  };

  const handleRemoveCustomAction = (verb: ActionVerb) => {
    updateScope((prev) => ({
      allowed: prev.allowed.filter((a) => !verbEquals(a, verb)),
      denied: prev.denied.filter((d) => !verbEquals(d, verb)),
    }));
  };

  // Constraints Handlers
  const handleAddConstraint = () => {
    if (!newConstraintKey.trim()) return;
    setConstraints((prev) => ({
      ...prev,
      [newConstraintKey.trim()]: newConstraintVal.trim(),
    }));
    setNewConstraintKey("");
    setNewConstraintVal("");
  };

  const handleRemoveConstraint = (key: string) => {
    setConstraints((prev) => {
      const next = { ...prev };
      delete next[key];
      return next;
    });
  };

  // Resource Pattern Handlers
  const handleAddPattern = () => {
    if (!newPattern.trim()) return;
    setResourcePatterns((prev) => Array.from(new Set([...prev, newPattern.trim()])));
    setNewPattern("");
  };

  const handleRemovePattern = (pat: string) => {
    setResourcePatterns((prev) => prev.filter((p) => p !== pat));
  };

  // Path matcher
  const isPathMatched = useMemo(() => {
    if (!testPath) return false;
    return resourcePatterns.some((pattern) => {
      if (pattern === "*") return true;
      if (pattern.endsWith("/**") || pattern.endsWith(":**")) {
        const prefix = pattern.slice(0, -3);
        return testPath.startsWith(prefix);
      }
      if (pattern.endsWith("/*")) {
        const prefix = pattern.slice(0, -2);
        return testPath.startsWith(prefix);
      }
      return testPath === pattern;
    });
  }, [testPath, resourcePatterns]);

  // Extract all custom verbs
  const customVerbs = useMemo(() => {
    const list: { verb: { kind: "Custom"; name: string }; isAllowed: boolean; isDenied: boolean }[] = [];
    const seen = new Set<string>();

    internalScope.allowed.forEach((v) => {
      if (v.kind === "Custom" && !seen.has(v.name)) {
        seen.add(v.name);
        list.push({
          verb: v,
          isAllowed: true,
          isDenied: hasVerb(internalScope.denied, v),
        });
      }
    });

    internalScope.denied.forEach((v) => {
      if (v.kind === "Custom" && !seen.has(v.name)) {
        seen.add(v.name);
        list.push({
          verb: v,
          isAllowed: false,
          isDenied: true,
        });
      }
    });

    return list;
  }, [internalScope]);

  return (
    <div
      data-testid="scope-matrix-editor"
      className={`rounded-md border border-slate-800 bg-[#0E131F] p-4 sm:p-6 font-mono text-xs shadow-2xl space-y-6 ${className}`}
    >
      {/* Header with Title and Presets */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-100 uppercase tracking-wide">
              Visual Scope Matrix Editor
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/60 text-cyan-300">
              Feature F14
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Author and inspect CapabilityScope structures: standard actions with Admin inheritance, custom action verbs, security constraints, and resource pattern access policies.
          </p>
        </div>

        {/* Scope Preset Buttons */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-slate-500 text-[11px] mr-1">Presets:</span>
          {(["ADMIN", "ORCHESTRATOR", "AUDITOR", "WORKER", "READ_ONLY"] as const).map(
            (presetKey) => {
              const isSelected = activePreset === presetKey;
              return (
                <button
                  key={presetKey}
                  type="button"
                  data-testid={`preset-select-${presetKey}`}
                  onClick={() => handleSelectPreset(presetKey)}
                  className={`px-2.5 py-1.5 rounded-md border text-[11px] font-bold transition-all ${
                    isSelected
                      ? "bg-cyan-500 text-obsidian-950 border-cyan-400"
                      : "bg-[#080B11] text-slate-300 border-slate-700 hover:border-slate-500 hover:text-white"
                  }`}
                >
                  {presetKey}
                </button>
              );
            }
          )}
        </div>
      </div>

      {/* ── 1. Standard Actions Matrix Table ──────────────────────────────── */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <span>Standard Action Verbs</span>
            <span className="text-[10px] text-slate-500 font-normal">
              (6 normative protocol actions with Admin inheritance)
            </span>
          </h3>
        </div>

        <div className="rounded-md border border-slate-800 bg-[#080B11] overflow-hidden">
          <div className="grid grid-cols-12 gap-2 px-4 py-2.5 bg-[#0E131F] border-b border-slate-800 text-slate-400 font-semibold text-[11px]">
            <div className="col-span-1">OPCODE</div>
            <div className="col-span-3">ACTION VERB</div>
            <div className="col-span-4">3-STATE TOGGLE</div>
            <div className="col-span-4 text-right">EFFECTIVE PERMISSION STATUS</div>
          </div>

          <div className="divide-y divide-slate-850">
            {STANDARD_ACTIONS.map((action) => {
              const verb: ActionVerb = { kind: "Standard", action };
              const meta = ACTION_OPCODES[action];

              const isDirectlyAllowed = hasVerb(internalScope.allowed, verb);
              const isExplicitlyDenied = hasVerb(internalScope.denied, verb);
              const hasAdmin = internalScope.allowed.some(
                (a) => a.kind === "Standard" && a.action === "Admin"
              );
              const isInherited = hasAdmin && !isDirectlyAllowed && !isExplicitlyDenied;
              const isPermitted = scopePermitsAction(internalScope, verb);

              return (
                <div
                  key={action}
                  data-testid={`standard-action-row-${action}`}
                  className="grid grid-cols-12 gap-2 px-4 py-3 items-center hover:bg-slate-900/40 transition-colors"
                >
                  {/* Opcode */}
                  <div className="col-span-1 font-mono text-cyan-400 font-bold text-[11px]">
                    {meta.code}
                  </div>

                  {/* Name and description */}
                  <div className="col-span-3">
                    <div className="font-bold text-slate-200 font-mono text-xs">{action}</div>
                    <div className="text-[10px] text-slate-500 font-sans truncate">{meta.desc}</div>
                  </div>

                  {/* 3-State Toggle Controls */}
                  <div className="col-span-4 flex items-center gap-1.5">
                    <button
                      type="button"
                      data-testid={`toggle-allow-${action}`}
                      onClick={() =>
                        toggleStandardAction(
                          action,
                          isDirectlyAllowed ? "unset" : "allow"
                        )
                      }
                      className={`px-2.5 py-1 rounded text-[11px] font-bold border transition-all ${
                        isDirectlyAllowed
                          ? "bg-emerald-500 text-obsidian-950 border-emerald-400"
                          : "bg-slate-850 text-slate-400 border-slate-700 hover:text-emerald-400"
                      }`}
                    >
                      ALLOW
                    </button>

                    <button
                      type="button"
                      data-testid={`toggle-deny-${action}`}
                      onClick={() =>
                        toggleStandardAction(
                          action,
                          isExplicitlyDenied ? "unset" : "deny"
                        )
                      }
                      className={`px-2.5 py-1 rounded text-[11px] font-bold border transition-all ${
                        isExplicitlyDenied
                          ? "bg-red-500 text-obsidian-950 border-red-400"
                          : "bg-slate-850 text-slate-400 border-slate-700 hover:text-red-400"
                      }`}
                    >
                      DENY
                    </button>

                    <button
                      type="button"
                      onClick={() => toggleStandardAction(action, "unset")}
                      className={`px-2 py-1 rounded text-[10px] border transition-colors ${
                        !isDirectlyAllowed && !isExplicitlyDenied
                          ? "bg-slate-750 text-slate-200 border-slate-600 font-bold"
                          : "bg-transparent text-slate-500 border-transparent hover:text-slate-300"
                      }`}
                    >
                      UNSET
                    </button>
                  </div>

                  {/* Effective Status Badge */}
                  <div className="col-span-4 flex items-center justify-end">
                    {isExplicitlyDenied ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-bold bg-red-950/60 text-red-300 border border-red-500/50">
                        <XCircle className="w-3 h-3 text-red-400" />
                        Explicitly Denied (F14.B1)
                      </span>
                    ) : isDirectlyAllowed ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-bold bg-emerald-950/60 text-emerald-300 border border-emerald-500/50">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        Directly Allowed
                      </span>
                    ) : isInherited ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-bold bg-indigo-950/60 text-indigo-300 border border-indigo-500/50">
                        <Sparkles className="w-3 h-3 text-indigo-400" />
                        Inherited from Admin (F14.B5)
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] bg-slate-850 text-slate-400 border border-slate-700">
                        Prohibited (Default Closed)
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── 2. Custom Enterprise Actions Manager ───────────────────────────── */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <span>Custom Enterprise Action Verbs</span>
            <span className="text-[10px] text-slate-500 font-normal">
              (Regex validated ^[a-zA-Z0-9_\-\:\.\/]+$, strict case sensitive)
            </span>
          </h3>
        </div>

        {/* Input Bar and Quick Chips */}
        <div className="p-4 rounded-md border border-slate-800 bg-[#080B11] space-y-3">
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="flex-1 relative">
              <input
                type="text"
                data-testid="custom-action-input"
                value={customActionInput}
                onChange={(e) => {
                  setCustomActionInput(e.target.value);
                  setCustomActionError(null);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAddCustomAction();
                }}
                placeholder="Enter custom action verb (e.g. loan:approve, ledger/treasury:transfer-wire_v2)..."
                className="w-full bg-[#0E131F] border border-slate-850 rounded-md px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
            </div>

            <button
              type="button"
              data-testid="add-custom-action-btn"
              onClick={handleAddCustomAction}
              className="px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-obsidian-950 font-bold flex items-center justify-center gap-1.5 transition-colors whitespace-nowrap"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Custom Verb</span>
            </button>
          </div>

          {customActionError && (
            <div className="flex items-center gap-1.5 text-red-400 text-[11px]">
              <AlertCircle className="w-3.5 h-3.5" />
              <span>{customActionError}</span>
            </div>
          )}

          {/* Quick Enterprise Domain Presets */}
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            <span className="text-[10px] text-slate-500 mr-1">Quick Add:</span>
            {ENTERPRISE_CHIPS.map((chip) => (
              <button
                key={chip}
                type="button"
                onClick={() => {
                  setCustomActionInput(chip);
                  setCustomActionError(null);
                }}
                className="px-2 py-0.5 rounded bg-slate-850 hover:bg-slate-800 border border-slate-750 text-slate-300 text-[10px] transition-colors"
              >
                +{chip}
              </button>
            ))}
          </div>

          {/* Rendered Custom Action Items */}
          <div className="mt-3 divide-y divide-slate-850 border-t border-slate-800/80 pt-2">
            {customVerbs.length === 0 ? (
              <div className="py-4 text-center text-slate-500 text-[11px]">
                No custom enterprise actions configured in this capability scope.
              </div>
            ) : (
              customVerbs.map(({ verb, isAllowed, isDenied }) => (
                <div
                  key={verb.name}
                  data-testid={`custom-action-item-${verb.name}`}
                  className="py-2.5 flex items-center justify-between gap-3"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    <span className="font-mono text-xs font-bold text-slate-200 truncate">
                      {verb.name}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        handleToggleCustomAction(verb, isAllowed ? "deny" : "allow")
                      }
                      className={`px-2.5 py-0.5 rounded text-[10px] font-bold border transition-colors ${
                        isAllowed
                          ? "bg-emerald-950/60 text-emerald-300 border-emerald-500/50"
                          : "bg-red-950/60 text-red-300 border-red-500/50"
                      }`}
                    >
                      {isAllowed ? "ALLOWED" : "DENIED"}
                    </button>

                    <button
                      type="button"
                      onClick={() => handleRemoveCustomAction(verb)}
                      className="p-1 rounded text-slate-500 hover:text-red-400 hover:bg-red-950/40 transition-colors"
                      title="Remove custom action verb"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── 3. Security Constraints & Resource Patterns Grid ──────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Security Constraints Key-Value Editor */}
        <div className="p-4 rounded-md border border-slate-800 bg-[#080B11] space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-cyan-400" />
              Security Policy Constraints
            </h3>
            <span className="text-[10px] text-slate-500 font-normal">
              ({Object.keys(constraints).length} active)
            </span>
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              data-testid="constraint-key-input"
              value={newConstraintKey}
              onChange={(e) => setNewConstraintKey(e.target.value)}
              placeholder="Key (e.g. max_amount)"
              className="flex-1 bg-[#0E131F] border border-slate-850 rounded-md px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            />
            <input
              type="text"
              data-testid="constraint-val-input"
              value={newConstraintVal}
              onChange={(e) => setNewConstraintVal(e.target.value)}
              placeholder="Value (e.g. 5000000)"
              className="flex-1 bg-[#0E131F] border border-slate-850 rounded-md px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            />
            <button
              type="button"
              onClick={handleAddConstraint}
              className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold"
            >
              Add
            </button>
          </div>

          <div className="divide-y divide-slate-850 max-h-36 overflow-y-auto pr-1">
            {Object.entries(constraints).map(([k, v]) => (
              <div key={k} className="py-2 flex items-center justify-between text-xs">
                <span className="text-cyan-300 font-mono">{k}:</span>
                <div className="flex items-center gap-2">
                  <span className="text-slate-300 font-mono">{v}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveConstraint(k)}
                    className="text-slate-500 hover:text-red-400"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Resource Patterns Manager */}
        <div className="p-4 rounded-md border border-slate-800 bg-[#080B11] space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
              Resource Path Patterns (Globs)
            </h3>
            <span className="text-[10px] text-slate-500 font-normal">
              ({resourcePatterns.length} patterns)
            </span>
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              data-testid="resource-pattern-input"
              value={newPattern}
              onChange={(e) => setNewPattern(e.target.value)}
              placeholder="Resource pattern (e.g. treasury/transfers/*)"
              className="flex-1 bg-[#0E131F] border border-slate-850 rounded-md px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            />
            <button
              type="button"
              onClick={handleAddPattern}
              className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold"
            >
              Add
            </button>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {resourcePatterns.map((pat) => (
              <span
                key={pat}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#0E131F] border border-slate-800 text-slate-300 text-[11px]"
              >
                <span>{pat}</span>
                <button
                  type="button"
                  onClick={() => handleRemovePattern(pat)}
                  className="text-slate-500 hover:text-red-400"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>

          {/* Interactive Resource Tester */}
          <div className="pt-2 border-t border-slate-850">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] text-slate-400">Interactive Path Tester:</span>
              <span
                className={`text-[10px] font-bold px-2 py-0.2 rounded border ${
                  isPathMatched
                    ? "bg-emerald-950/60 text-emerald-300 border-emerald-500/50"
                    : "bg-red-950/60 text-red-300 border-red-500/50"
                }`}
              >
                {isPathMatched ? "MATCHED (Allowed)" : "UNMATCHED (Prohibited)"}
              </span>
            </div>
            <input
              type="text"
              value={testPath}
              onChange={(e) => setTestPath(e.target.value)}
              placeholder="Enter test resource path..."
              className="w-full bg-[#0E131F] border border-slate-850 rounded-md px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      </div>
    </div>
  );
};
