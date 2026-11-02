"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { useConsole } from "@/lib/context/ConsoleContext";
import { useEvidence } from "@/lib/wasm/EvidenceContext";
import { useAipVerifier } from "@/lib/wasm/useAipVerifier";
import type { VerificationReport, RuleIdentifier } from "@/types/verification";

import { PresetSelector } from "./PresetSelector";
import { SmartHashToggle } from "./SmartHashToggle";
import { FieldTamperPanel } from "./FieldTamperPanel";
import { JsonPayloadEditor } from "./JsonPayloadEditor";
import { JsonDiffViewer } from "./JsonDiffViewer";
import { LiveTamperLedger } from "./LiveTamperLedger";
import { AttackPreset } from "./attackPresets";

import {
  ShieldAlert,
  RotateCcw,
  Download,
  Eye,
  Code2,
  Sliders,
  Flame,
  CheckCircle2,
  Activity,
} from "lucide-react";

export interface TamperSimulatorProps {
  className?: string;
}

/**
 * Convert 64-character hexadecimal string to an array of 32 bytes for Rust serde [u8; 32] wire compatibility.
 */
function hexToBytes(hex: string): number[] {
  const cleanHex = hex.trim().replace(/^0x/i, "");
  const bytes: number[] = [];
  for (let c = 0; c < cleanHex.length; c += 2) {
    bytes.push(parseInt(cleanHex.substring(c, c + 2), 16));
  }
  return bytes;
}

/**
 * Convert a byte array ([u8; 32]) or hex string to normalized 64-char lowercase hex string for display.
 */
function bytesToHex(bytes: number[]): string {
  return bytes.map((b) => Number(b).toString(16).padStart(2, "0")).join("");
}

/**
 * Value equality check for byte arrays or strings to prevent React infinite re-render loops.
 */
function areByteArraysEqual(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
  return a === b;
}

export const TamperSimulator: React.FC<TamperSimulatorProps> = ({ className = "" }) => {
  const { loadedPacket, rawPacketJson } = useConsole();
  const { evidence, contextJson } = useEvidence();
  const verifier = useAipVerifier();

  // Baseline original pristine packet JSON
  const [baselineJson, setBaselineJson] = useState<string>("");

  // Working mutated packet state
  const [mutatedPacket, setMutatedPacket] = useState<any>(null);
  const [mutatedJson, setMutatedJson] = useState<string>("");

  // Hash recomputation state (F12)
  const [autoRecalculate, setAutoRecalculate] = useState<boolean>(false);
  const [recomputedHash, setRecomputedHash] = useState<string>("");
  const [canonicalBytesHex, setCanonicalBytesHex] = useState<string>("");

  // Active preset
  const [activePresetId, setActivePresetId] = useState<string | null>(null);

  // View mode tab: "visual" | "json" | "diff"
  const [viewMode, setViewMode] = useState<"visual" | "json" | "diff">("visual");

  // Live report from WASM verify_evidence_packet (zero JS verification)
  const [liveReport, setLiveReport] = useState<VerificationReport | null>(null);
  const [engineError, setEngineError] = useState<string | null>(null);

  // Initialize baseline when evidence is loaded
  useEffect(() => {
    if (evidence?.packetJson && (!baselineJson || !mutatedPacket)) {
      setBaselineJson(evidence.packetJson);
      try {
        const parsed = JSON.parse(evidence.packetJson);
        setMutatedPacket(parsed);
        setMutatedJson(evidence.packetJson);
      } catch (err) {
        console.warn("Failed to parse evidence packet:", err);
      }
    } else if (!evidence?.packetJson && !mutatedPacket && verifier.isReady) {
      // Default to honest counterparty sample from WASM
      try {
        const sample = verifier.getSample("honest_counterparty");
        if (sample) {
          setBaselineJson(sample);
          setMutatedPacket(JSON.parse(sample));
          setMutatedJson(sample);
        }
      } catch (err) {
        console.warn("Failed to load default sample:", err);
      }
    }
  }, [evidence?.packetJson, baselineJson, mutatedPacket, verifier]);

  // Re-verify reactive effect
  useEffect(() => {
    if (!verifier.isReady || !mutatedJson) return;

    try {
      let currentJson = mutatedJson;
      let currentObj = mutatedPacket;

      // Handle Smart Hash Recalculation (Feature F12)
      if (autoRecalculate && currentObj) {
        try {
          const freshHash = verifier.recomputeHash(currentJson);
          const targetHash = Array.isArray(currentObj.packet_hash)
            ? hexToBytes(freshHash)
            : freshHash;

          if (!areByteArraysEqual(currentObj.packet_hash, targetHash)) {
            currentObj = { ...currentObj, packet_hash: targetHash };
            currentJson = JSON.stringify(currentObj, null, 2);
            setMutatedPacket(currentObj);
            setMutatedJson(currentJson);
          }
        } catch (hashErr) {
          console.warn("Failed to recompute hash:", hashErr);
        }
      }

      // Recompute hash for comparison display
      try {
        const compHash = verifier.recomputeHash(currentJson);
        setRecomputedHash(compHash);
      } catch {
        setRecomputedHash("");
      }

      // Get canonical bytes hex
      try {
        const cBytes = verifier.getCanonicalBytesHex(currentJson);
        setCanonicalBytesHex(cBytes);
      } catch {
        setCanonicalBytesHex("");
      }

      // Zero-JS verification: delegate 100% to Rust WebAssembly
      const activeCtx = contextJson || "{}";
      const rep = verifier.verifyPacket(currentJson, activeCtx);
      setLiveReport(rep);
      setEngineError(null);
    } catch (err: unknown) {
      const msg = typeof err === "string" ? err : err instanceof Error ? err.message : String(err);
      console.error("Verification execution error:", err);
      setLiveReport(null);
      setEngineError(msg);
    }
  }, [mutatedJson, autoRecalculate, contextJson, verifier]);

  // Handle Preset Selection
  const handleSelectPreset = useCallback(
    (preset: AttackPreset) => {
      if (!baselineJson) return;
      try {
        const baseObj = JSON.parse(baselineJson);
        const { packet: mutated, context: mutatedCtx } = preset.mutate(baseObj, {});
        setActivePresetId(preset.id);
        const newJson = JSON.stringify(mutated, null, 2);
        setMutatedPacket(mutated);
        setMutatedJson(newJson);
      } catch (err) {
        console.error("Failed to apply preset:", err);
      }
    },
    [baselineJson]
  );

  // Clear Preset / Revert to baseline
  const handleResetToBaseline = useCallback(() => {
    if (!baselineJson) return;
    try {
      const parsed = JSON.parse(baselineJson);
      setMutatedPacket(parsed);
      setMutatedJson(baselineJson);
      setActivePresetId(null);
      setEngineError(null);
    } catch (err) {
      console.error("Failed to reset baseline:", err);
    }
  }, [baselineJson]);

  // Handle manual visual mutation
  const handleVisualChange = useCallback((updatedPacket: any) => {
    setMutatedPacket(updatedPacket);
    setMutatedJson(JSON.stringify(updatedPacket, null, 2));
    setActivePresetId(null); // Custom mutation overrides preset
  }, []);

  // Handle manual raw JSON edit
  const handleRawJsonChange = useCallback((newJsonStr: string) => {
    setMutatedJson(newJsonStr);
    try {
      const parsed = JSON.parse(newJsonStr);
      setMutatedPacket(parsed);
    } catch {
      // Keep string until valid
    }
    setActivePresetId(null);
  }, []);

  // Export tampered JSON
  const handleExportTamperedJson = () => {
    if (!mutatedJson) return;
    const blob = new Blob([mutatedJson], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `tampered-evidence-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const storedHash = React.useMemo(() => {
    if (!mutatedPacket?.packet_hash) return "";
    if (Array.isArray(mutatedPacket.packet_hash)) {
      return bytesToHex(mutatedPacket.packet_hash);
    }
    return String(mutatedPacket.packet_hash);
  }, [mutatedPacket?.packet_hash]);

  return (
    <div className={`space-y-6 font-mono ${className}`}>
      {/* ── Top Simulator Toolbar ────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-md border border-slate-800 bg-[#080B11] shadow-xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-md bg-red-950/60 border border-red-500/50 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              Adversarial Tamper Simulator
              <span className="text-xs px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-300">
                NM-A3 Non-Repudiation
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5 font-sans">
              Mutate EvidencePacket fields, recompute hashes via WASM, and observe real-time cryptographic failure ledgers.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleResetToBaseline}
            className="px-3 py-1.5 rounded-md text-xs font-mono bg-slate-850 hover:bg-slate-800 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors"
            title="Revert all mutations to baseline honest packet"
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Revert to Pristine</span>
          </button>

          <button
            type="button"
            onClick={handleExportTamperedJson}
            className="px-3 py-1.5 rounded-md text-xs font-mono bg-slate-850 hover:bg-slate-800 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors"
            title="Download mutated evidence JSON for offline auditing"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export Tampered JSON</span>
          </button>
        </div>
      </div>

      {/* ── Preset Selector (14 Attack Vectors) ───────────────────────────── */}
      <PresetSelector
        activePresetId={activePresetId}
        onSelectPreset={handleSelectPreset}
        onClearPreset={handleResetToBaseline}
      />

      {/* ── Smart Hash Recalculation Toggle (Feature F12) ─────────────────── */}
      <SmartHashToggle
        autoRecalculate={autoRecalculate}
        onToggle={setAutoRecalculate}
        storedHash={storedHash}
        recomputedHash={recomputedHash}
        canonicalBytesHex={canonicalBytesHex}
        onRecomputeManual={() => {
          if (!mutatedPacket || !verifier.isReady) return;
          try {
            const h = verifier.recomputeHash(mutatedJson);
            const targetHash = Array.isArray(mutatedPacket.packet_hash)
              ? hexToBytes(h)
              : h;
            const updated = { ...mutatedPacket, packet_hash: targetHash };
            setMutatedPacket(updated);
            setMutatedJson(JSON.stringify(updated, null, 2));
          } catch (err) {
            console.error("Failed to manually recompute hash:", err);
          }
        }}
      />

      {/* ── Mutation View Switcher (Visual vs Raw vs Diff) ────────────────── */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setViewMode("visual")}
              className={`px-3 py-1.5 rounded-md text-xs font-mono flex items-center gap-1.5 transition-colors ${
                viewMode === "visual"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-bold"
                  : "bg-slate-850 text-slate-400 border border-slate-700 hover:text-slate-200"
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Structured Field Editor</span>
            </button>

            <button
              type="button"
              onClick={() => setViewMode("diff")}
              className={`px-3 py-1.5 rounded-md text-xs font-mono flex items-center gap-1.5 transition-colors ${
                viewMode === "diff"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-bold"
                  : "bg-slate-850 text-slate-400 border border-slate-700 hover:text-slate-200"
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Visual Payload Diff</span>
            </button>

            <button
              type="button"
              onClick={() => setViewMode("json")}
              className={`px-3 py-1.5 rounded-md text-xs font-mono flex items-center gap-1.5 transition-colors ${
                viewMode === "json"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-bold"
                  : "bg-slate-850 text-slate-400 border border-slate-700 hover:text-slate-200"
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Raw JSON Editor</span>
            </button>
          </div>

          <span className="text-[11px] text-slate-500">
            {activePresetId ? (
              <span className="text-red-400 font-bold flex items-center gap-1">
                <Flame className="w-3 h-3" />
                Active Vector: {activePresetId}
              </span>
            ) : (
              <span>Manual Custom Mutations</span>
            )}
          </span>
        </div>

        {/* View Mode Panes */}
        {viewMode === "visual" && (
          <FieldTamperPanel packet={mutatedPacket} onChange={handleVisualChange} />
        )}

        {viewMode === "diff" && (
          <JsonDiffViewer
            originalJson={baselineJson}
            mutatedJson={mutatedJson}
          />
        )}

        {viewMode === "json" && (
          <JsonPayloadEditor
            jsonString={mutatedJson}
            onChange={handleRawJsonChange}
            onReset={handleResetToBaseline}
          />
        )}
      </div>

      {/* ── Instant Live Verification Ledger (Feature F13) ────────────────── */}
      <div className="pt-2">
        <div className="mb-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 uppercase tracking-wider">
            <Activity className="w-4 h-4 text-cyan-400" />
            Live Verification Feedback Ledger
          </h3>
          <p className="text-xs text-slate-400 mt-0.5 font-sans">
            Instant evaluation from compiled WebAssembly engine with ZERO client-side verification logic.
          </p>
        </div>

        <LiveTamperLedger
          report={liveReport}
          engineError={engineError}
          onReset={handleResetToBaseline}
        />
      </div>
    </div>
  );
};
