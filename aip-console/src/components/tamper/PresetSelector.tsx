"use client";

import React, { useState } from "react";
import { ATTACK_PRESETS, AttackPreset } from "./attackPresets";
import { RuleLayer } from "@/types/verification";
import { ShieldAlert, Zap, Filter, Check, Flame } from "lucide-react";

export interface PresetSelectorProps {
  activePresetId: string | null;
  onSelectPreset: (preset: AttackPreset) => void;
  onClearPreset: () => void;
  className?: string;
}

export const PresetSelector: React.FC<PresetSelectorProps> = ({
  activePresetId,
  onSelectPreset,
  onClearPreset,
  className = "",
}) => {
  const [selectedLayer, setSelectedLayer] = useState<"ALL" | RuleLayer>("ALL");

  const filteredPresets = ATTACK_PRESETS.filter((p) => {
    if (selectedLayer === "ALL") return true;
    return p.category === selectedLayer;
  });

  return (
    <div
      className={`rounded-md border border-slate-800 bg-[#0E131F] p-4 sm:p-5 font-mono shadow-xl ${className}`}
    >
      {/* Header and Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              14 Attack Vector Presets
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-red-950/70 border border-red-800/60 text-red-300">
              1:1 Rule Mapping (F11)
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Select an adversarial preset to simulate targeted cryptographic attack scenarios against the 14 engine verification rules.
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1 text-[11px]">
          {(["ALL", "INTEGRITY", "AUTHORITY", "VALIDITY", "BILATERAL"] as const).map(
            (layer) => (
              <button
                key={layer}
                type="button"
                onClick={() => setSelectedLayer(layer)}
                className={`px-2.5 py-1 rounded border transition-colors ${
                  selectedLayer === layer
                    ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/50 font-bold"
                    : "bg-slate-850 text-slate-400 border-slate-700 hover:text-slate-200"
                }`}
              >
                {layer === "ALL" ? "All (14)" : layer}
              </button>
            )
          )}

          {activePresetId && (
            <button
              type="button"
              onClick={onClearPreset}
              className="px-2.5 py-1 rounded bg-red-950/50 hover:bg-red-900/60 border border-red-800/60 text-red-300 font-bold ml-1 transition-colors"
            >
              Clear Preset
            </button>
          )}
        </div>
      </div>

      {/* Preset Cards Grid */}
      <div className="mt-3.5 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2.5 max-h-[360px] overflow-y-auto pr-1">
        {filteredPresets.map((preset) => {
          const isActive = activePresetId === preset.id;

          return (
            <div
              key={preset.id}
              onClick={() => onSelectPreset(preset)}
              className={`p-3 rounded-md border text-left cursor-pointer transition-all select-none ${
                isActive
                  ? "bg-red-950/40 border-red-500/70 ring-1 ring-red-500/50"
                  : "bg-[#080B11] border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="text-[10px] text-slate-500 font-bold">
                    #{String(preset.index).padStart(2, "0")}
                  </span>
                  <span
                    className={`text-xs font-bold truncate ${
                      isActive ? "text-red-300 font-mono" : "text-slate-200 font-mono"
                    }`}
                  >
                    {preset.name}
                  </span>
                </div>

                <span
                  className={`text-[9px] font-mono px-1.5 py-0.5 rounded border flex-shrink-0 ${
                    isActive
                      ? "bg-red-500/20 text-red-300 border-red-500/50 font-bold"
                      : "bg-slate-800 text-slate-400 border-slate-700"
                  }`}
                >
                  {preset.targetRule}
                </span>
              </div>

              <p className="text-[11px] text-slate-400 font-sans line-clamp-2 leading-relaxed">
                {preset.description}
              </p>

              <div className="mt-2 pt-1.5 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500">
                <span className="text-slate-400 uppercase tracking-wider">{preset.category}</span>
                {isActive && (
                  <span className="text-red-400 font-bold flex items-center gap-1">
                    <Check className="w-3 h-3" />
                    ACTIVE
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
