"use client";

import React, { useState, useEffect } from "react";
import {
  Code2,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
} from "lucide-react";

export interface JsonPayloadEditorProps {
  jsonString: string;
  onChange: (newJson: string) => void;
  onReset?: () => void;
  className?: string;
}

export const JsonPayloadEditor: React.FC<JsonPayloadEditorProps> = ({
  jsonString,
  onChange,
  onReset,
  className = "",
}) => {
  const [internalValue, setInternalValue] = useState(jsonString);
  const [copied, setCopied] = useState(false);
  const [syntaxError, setSyntaxError] = useState<string | null>(null);

  useEffect(() => {
    setInternalValue(jsonString);
    try {
      JSON.parse(jsonString);
      setSyntaxError(null);
    } catch (err: any) {
      setSyntaxError(err.message);
    }
  }, [jsonString]);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setInternalValue(val);
    try {
      JSON.parse(val);
      setSyntaxError(null);
      onChange(val);
    } catch (err: any) {
      setSyntaxError(err.message);
    }
  };

  const handleFormat = () => {
    try {
      const parsed = JSON.parse(internalValue);
      const formatted = JSON.stringify(parsed, null, 2);
      setInternalValue(formatted);
      setSyntaxError(null);
      onChange(formatted);
    } catch (err: any) {
      setSyntaxError(err.message);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(internalValue);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`rounded-md border border-slate-800 bg-[#080B11] overflow-hidden font-mono text-xs shadow-xl flex flex-col ${className}`}
    >
      {/* Editor Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-[#0E131F] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Code2 className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-slate-200">Raw JSON Evidence Payload</span>
          <span
            className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded border ${
              syntaxError
                ? "bg-red-950/60 border-red-500/50 text-red-300"
                : "bg-emerald-950/60 border-emerald-500/50 text-emerald-300"
            }`}
          >
            {syntaxError ? (
              <>
                <XCircle className="w-3 h-3 text-red-400" />
                Invalid JSON
              </>
            ) : (
              <>
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                Valid Syntax
              </>
            )}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleFormat}
            disabled={!!syntaxError}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] bg-slate-850 hover:bg-slate-800 disabled:opacity-40 disabled:hover:bg-slate-850 text-slate-300 border border-slate-700 transition-colors"
          >
            <Sparkles className="w-3 h-3 text-cyan-400" />
            <span>Format</span>
          </button>

          <button
            type="button"
            onClick={copyToClipboard}
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
                <span>Copy</span>
              </>
            )}
          </button>

          {onReset && (
            <button
              type="button"
              onClick={onReset}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] bg-red-950/40 hover:bg-red-950/60 text-red-300 border border-red-800/60 transition-colors"
              title="Reset payload to unmodified baseline"
            >
              <RotateCcw className="w-3 h-3 text-red-400" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Syntax Error Banner if Invalid */}
      {syntaxError && (
        <div className="p-2.5 bg-red-950/50 border-b border-red-800/60 text-red-300 text-[11px] flex items-center gap-2">
          <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
          <span className="font-mono truncate">{syntaxError}</span>
        </div>
      )}

      {/* Text Area */}
      <textarea
        value={internalValue}
        onChange={handleChange}
        spellCheck={false}
        rows={16}
        className="w-full flex-1 bg-[#05070A] p-4 text-slate-200 font-mono text-[11px] leading-5 resize-y focus:outline-none focus:ring-1 focus:ring-cyan-500/50 selection:bg-cyan-500/30"
      />
    </div>
  );
};
