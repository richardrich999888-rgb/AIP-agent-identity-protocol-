"use client";

import React, { useState, useRef, useCallback, DragEvent, ChangeEvent, KeyboardEvent } from "react";
import { Upload, Archive, AlertTriangle, Loader2, X, FileCode, ChevronDown, RefreshCw } from "lucide-react";
import { useEvidence } from "@/lib/wasm/EvidenceContext";
import { useAipVerifier } from "@/lib/wasm/useAipVerifier";
import { SAMPLE_FIXTURES } from "@/lib/wasm/fixtures";
import { btn, badge, panel, panelHeader, panelTitle, focusRing } from "@/components/ui/styles";

export interface DropzoneProps {
  onPacketLoaded?: (packetJson: string) => void;
}

type CategoryFilter = "all" | "valid" | "adversarial" | "bundle";

const QUICK_FIXTURES = [
  { id: "honest_counterparty", label: "Honest payment", desc: "Valid, level 3" },
  { id: "authority_bound", label: "Cloud scaling", desc: "Valid, level 2" },
  { id: "tampered_summary", label: "Tampered summary", desc: "Adversarial" },
  { id: "revoked_token", label: "Revoked token", desc: "Revocation" },
  { id: "audit_bundle_valid", label: "Audit ZIP", desc: "Conforming bundle" },
];

const categoryBadge = (category: string) =>
  category === "valid"
    ? badge.success
    : category === "adversarial"
    ? badge.danger
    : category === "bundle"
    ? badge.info
    : badge.warning;

export function Dropzone({ onPacketLoaded }: DropzoneProps = {}) {
  const { isReady, isLoading: isWasmLoading } = useAipVerifier();
  const { evidence, report, bundleResult, isVerifying, error, loadPacket, loadBundle, loadFixture, clearEvidence } =
    useEvidence();

  const [isDragActive, setIsDragActive] = useState(false);
  const [category, setCategory] = useState<CategoryFilter>("all");
  const [showCatalog, setShowCatalog] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const busy = isVerifying || isWasmLoading;

  const handleFiles = useCallback(
    async (files: FileList | null) => {
      if (!files || files.length === 0) return;
      const file = files[0];
      const isZip = file.name.endsWith(".zip");
      const isJson = file.name.endsWith(".json");

      if (!isZip && !isJson) {
        setFileError(`"${file.name}" is not supported. Use a .json EvidencePacket or a .zip audit bundle.`);
        return;
      }
      setFileError(null);

      const reader = new FileReader();
      if (isZip) {
        reader.onload = async (e) => {
          const buffer = e.target?.result as ArrayBuffer;
          await loadBundle(new Uint8Array(buffer), file.name);
        };
        reader.readAsArrayBuffer(file);
      } else {
        reader.onload = async (e) => {
          const text = e.target?.result as string;
          await loadPacket(text, file.name);
          onPacketLoaded?.(text);
        };
        reader.readAsText(file);
      }
    },
    [loadBundle, loadPacket, onPacketLoaded]
  );

  const openPicker = () => {
    if (!busy) fileInputRef.current?.click();
  };

  const dropHandlers = {
    onDragOver: (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragActive(true);
    },
    onDragLeave: (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragActive(false);
    },
    onDrop: (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragActive(false);
      handleFiles(e.dataTransfer.files);
    },
  };

  const onPickerKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openPicker();
    }
  };

  const onFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    handleFiles(e.target.files);
    e.target.value = "";
  };

  const loadSample = (id: string) => {
    setFileError(null);
    loadFixture(id);
  };

  const catalog = SAMPLE_FIXTURES.filter((f) => category === "all" || f.category === category);
  const isValid = report ? Boolean(report.overall_valid || report.valid) : undefined;
  const shownError = fileError ?? error;

  return (
    <section className={panel} aria-labelledby="evidence-heading">
      <input
        ref={fileInputRef}
        type="file"
        accept=".json,.zip,application/json,application/zip"
        className="hidden"
        onChange={onFileInputChange}
      />

      <div className={panelHeader}>
        <div>
          <h2 id="evidence-heading" className={panelTitle}>
            Evidence
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">Files are verified in this browser and never uploaded.</p>
        </div>
        {evidence && (
          <div className="flex items-center gap-2">
            <button type="button" onClick={openPicker} disabled={busy} className={btn.secondary}>
              <RefreshCw className="w-3.5 h-3.5" aria-hidden />
              Replace file
            </button>
            <button type="button" onClick={clearEvidence} className={btn.danger}>
              <X className="w-3.5 h-3.5" aria-hidden />
              Clear
            </button>
          </div>
        )}
      </div>

      <div className="p-4">
        {evidence ? (
          /* Loaded: compact summary row, still a drop target for replacement */
          <div
            {...dropHandlers}
            className={`flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border px-3 py-2.5 transition-colors duration-150 ${
              isDragActive ? "border-corporate-steel-light bg-corporate-steel/10" : "border-obsidian-700 bg-obsidian-950"
            }`}
          >
            <div className="flex items-center gap-2.5 min-w-0">
              {busy ? (
                <Loader2 className="w-4 h-4 text-corporate-steel-light animate-spin shrink-0" aria-hidden />
              ) : evidence.fileType === "zip" ? (
                <Archive className="w-4 h-4 text-slate-400 shrink-0" aria-hidden />
              ) : (
                <FileCode className="w-4 h-4 text-slate-400 shrink-0" aria-hidden />
              )}
              <span className="font-mono text-[13px] text-slate-100 truncate">{evidence.fileName}</span>
              <span className={badge.neutral}>{evidence.fileType.toUpperCase()}</span>
            </div>

            {isVerifying ? (
              <span className="text-xs text-slate-400">Verifying...</span>
            ) : (
              <div className="flex items-center gap-2">
                {report && (
                  <span className={isValid ? badge.success : badge.danger}>
                    {isValid ? `${report.checks?.length ?? 14} of ${report.checks?.length ?? 14} rules passed` : "Verification failed"}
                  </span>
                )}
                {bundleResult && (
                  <span className={bundleResult.overall_pass ? badge.success : badge.danger}>
                    Bundle {bundleResult.overall}
                  </span>
                )}
              </div>
            )}

            <span className="font-mono text-xs text-slate-500 truncate sm:ml-auto">
              {report?.packet_id ? `id ${report.packet_id}` : bundleResult ? `bundle ${bundleResult.bundle_id}` : ""}
            </span>
          </div>
        ) : (
          /* Empty: drop target */
          <div
            {...dropHandlers}
            role="button"
            tabIndex={busy ? -1 : 0}
            aria-disabled={busy}
            onClick={openPicker}
            onKeyDown={onPickerKey}
            className={`flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-4 rounded-md border border-dashed px-6 py-8 text-center sm:text-left cursor-pointer transition-colors duration-150 ${focusRing} ${
              isDragActive
                ? "border-corporate-steel-light bg-corporate-steel/10"
                : "border-obsidian-600 bg-obsidian-950 hover:border-corporate-steel"
            }`}
          >
            {busy ? (
              <Loader2 className="w-5 h-5 text-corporate-steel-light animate-spin shrink-0" aria-hidden />
            ) : (
              <Upload className="w-5 h-5 text-slate-400 shrink-0" aria-hidden />
            )}
            <div>
              <p className="text-sm font-medium text-slate-100">
                {isWasmLoading
                  ? "Loading the WebAssembly verifier..."
                  : isVerifying
                  ? "Verifying evidence..."
                  : "Drop an EvidencePacket or audit bundle, or click to choose a file"}
              </p>
              <p className="text-xs text-slate-400 mt-0.5">.json EvidencePacket v1 · .zip audit bundle</p>
            </div>
          </div>
        )}

        {shownError && (
          <div
            role="alert"
            className="mt-3 flex items-start gap-2.5 rounded-md border border-corporate-danger/40 bg-corporate-danger/10 px-3 py-2.5"
          >
            <AlertTriangle className="w-4 h-4 text-corporate-danger-light shrink-0 mt-0.5" aria-hidden />
            <div className="min-w-0">
              <p className="text-[13px] font-medium text-corporate-danger-light">Could not verify this file</p>
              <p className="text-xs text-slate-300 mt-0.5 font-mono break-words">{shownError}</p>
            </div>
          </div>
        )}
      </div>

      {/* Samples */}
      <div className="border-t border-obsidian-700 px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <span className="text-xs text-slate-400 mr-1">Load a sample</span>
          {QUICK_FIXTURES.map((qf) => (
            <button
              key={qf.id}
              type="button"
              disabled={busy || !isReady}
              onClick={() => loadSample(qf.id)}
              title={qf.desc}
              className={`${btn.secondary} h-7 px-2.5 text-xs`}
            >
              {qf.label}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setShowCatalog(!showCatalog)}
            aria-expanded={showCatalog}
            className={`${btn.link} ml-auto text-xs`}
          >
            {showCatalog ? "Hide catalog" : `All ${SAMPLE_FIXTURES.length} samples`}
            <ChevronDown
              className={`w-3.5 h-3.5 transition-transform duration-150 ${showCatalog ? "rotate-180" : ""}`}
              aria-hidden
            />
          </button>
        </div>

        {showCatalog && (
          <div className="mt-3 space-y-2">
            <div role="tablist" aria-label="Filter samples" className="inline-flex rounded-md border border-obsidian-700 p-0.5">
              {(["all", "valid", "adversarial", "bundle"] as const).map((c) => (
                <button
                  key={c}
                  type="button"
                  role="tab"
                  aria-selected={category === c}
                  onClick={() => setCategory(c)}
                  className={`h-7 px-3 rounded text-xs font-medium capitalize transition-colors duration-150 ${focusRing} ${
                    category === c ? "bg-obsidian-800 text-slate-100" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {c}
                </button>
              ))}
            </div>

            <ul className="divide-y divide-obsidian-700 rounded-md border border-obsidian-700 max-h-80 overflow-y-auto">
              {catalog.map((fx) => (
                <li key={fx.id}>
                  <button
                    type="button"
                    disabled={busy || !isReady}
                    onClick={() => loadSample(fx.id)}
                    className={`w-full flex items-start justify-between gap-4 px-3 py-2.5 text-left transition-colors duration-150 hover:bg-obsidian-850 disabled:opacity-50 ${focusRing}`}
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[13px] font-medium text-slate-100">{fx.title}</span>
                        <span className={`${categoryBadge(fx.category)} capitalize`}>
                          {fx.category.replace(/_/g, " ")}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">{fx.description}</p>
                    </div>
                    <span className="font-mono text-xs text-slate-500 shrink-0 mt-0.5">.{fx.format || "json"}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

export default Dropzone;
