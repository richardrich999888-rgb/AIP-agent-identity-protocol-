"use client";

import React, { useMemo, useState } from "react";
import { computeLineDiff } from "./diffUtils";
import { Copy, Check, Eye, Columns, AlertCircle } from "lucide-react";

export interface JsonDiffViewerProps {
  originalJson: string;
  mutatedJson: string;
  className?: string;
}

export const JsonDiffViewer: React.FC<JsonDiffViewerProps> = ({
  originalJson,
  mutatedJson,
  className = "",
}) => {
  const [copied, setCopied] = useState(false);
  const [onlyChanges, setOnlyChanges] = useState(false);

  const diffSummary = useMemo(() => {
    return computeLineDiff(originalJson, mutatedJson);
  }, [originalJson, mutatedJson]);

  const displayLines = useMemo(() => {
    if (!onlyChanges) return diffSummary.lines;
    // Show only lines with changes plus a window of 2 context lines
    const result: typeof diffSummary.lines = [];
    const changedIndices = new Set<number>();

    diffSummary.lines.forEach((line, idx) => {
      if (line.type !== "unchanged") {
        for (let offset = -2; offset <= 2; offset++) {
          const target = idx + offset;
          if (target >= 0 && target < diffSummary.lines.length) {
            changedIndices.add(target);
          }
        }
      }
    });

    diffSummary.lines.forEach((line, idx) => {
      if (changedIndices.has(idx)) {
        result.push(line);
      }
    });

    return result;
  }, [diffSummary, onlyChanges]);

  const copyDiff = () => {
    const text = diffSummary.lines
      .map((l) => `${l.type === "added" ? "+" : l.type === "deleted" ? "-" : " "} ${l.content}`)
      .join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`rounded-md border border-slate-800 bg-[#080B11] overflow-hidden font-mono text-xs shadow-xl ${className}`}
    >
      {/* Diff Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-[#0E131F] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400" />
          <span className="text-slate-200 font-bold font-mono">Visual Payload Diff</span>
          {diffSummary.hasChanges ? (
            <span className="flex items-center gap-2 text-[11px]">
              <span className="text-emerald-400 bg-emerald-950/60 border border-emerald-800/50 px-2 py-0.5 rounded">
                +{diffSummary.additions} added
              </span>
              <span className="text-red-400 bg-red-950/60 border border-red-800/50 px-2 py-0.5 rounded">
                -{diffSummary.deletions} removed
              </span>
            </span>
          ) : (
            <span className="text-slate-500 text-[11px] bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
              Pristine (No Modifications)
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setOnlyChanges(!onlyChanges)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] border transition-colors ${
              onlyChanges
                ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                : "bg-slate-850 text-slate-400 border-slate-700 hover:text-slate-200"
            }`}
          >
            <Eye className="w-3 h-3" />
            <span>{onlyChanges ? "Showing Changes Only" : "Show All Lines"}</span>
          </button>

          <button
            type="button"
            onClick={copyDiff}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] bg-slate-850 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copy Diff</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Diff Code Container */}
      <div className="max-h-[380px] overflow-y-auto overflow-x-auto divide-y divide-slate-900/60 font-mono text-[11px] leading-5 select-text">
        {!diffSummary.hasChanges ? (
          <div className="p-8 text-center text-slate-500">
            <p>Original baseline packet and current payload are cryptographically identical.</p>
            <p className="text-[10px] text-slate-600 mt-1">Select an attack vector or modify fields below to see line-by-line mutations.</p>
          </div>
        ) : (
          displayLines.map((line, idx) => {
            const isAdded = line.type === "added";
            const isDeleted = line.type === "deleted";

            return (
              <div
                key={idx}
                className={`flex items-start transition-colors ${
                  isAdded
                    ? "bg-emerald-950/30 text-emerald-300 border-l-2 border-emerald-500"
                    : isDeleted
                    ? "bg-red-950/30 text-red-300 border-l-2 border-red-500 line-through decoration-red-500/70"
                    : "text-slate-400 hover:bg-slate-900/40"
                }`}
              >
                {/* Line numbers */}
                <div className="w-10 flex-shrink-0 text-right pr-2 select-none text-slate-600 text-[10px]">
                  {line.originalLineNumber || ""}
                </div>
                <div className="w-10 flex-shrink-0 text-right pr-2 select-none text-slate-600 text-[10px]">
                  {line.mutatedLineNumber || ""}
                </div>

                {/* Diff prefix */}
                <div className="w-5 flex-shrink-0 text-center select-none font-bold">
                  {isAdded ? (
                    <span className="text-emerald-400">+</span>
                  ) : isDeleted ? (
                    <span className="text-red-400">-</span>
                  ) : (
                    <span className="text-slate-600"> </span>
                  )}
                </div>

                {/* Code content */}
                <pre className="flex-1 overflow-x-visible whitespace-pre font-mono py-0.5 pr-4">
                  {line.content}
                </pre>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
