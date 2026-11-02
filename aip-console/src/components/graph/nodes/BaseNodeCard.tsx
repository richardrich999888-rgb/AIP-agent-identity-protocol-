"use client";

import React, { ReactNode } from "react";
import { Handle, Position } from "@xyflow/react";
import { CheckCircle2, AlertOctagon } from "lucide-react";
import type { LayoutDirection } from "../types";

export interface BaseNodeCardProps {
  id: string;
  selected?: boolean;
  kindLabel: string;
  icon: ReactNode;
  verified: boolean;
  accentColor: "cyan" | "green" | "amber" | "indigo" | "blue" | "red";
  layoutDirection?: LayoutDirection;
  hasTargetHandle?: boolean;
  hasSourceHandle?: boolean;
  children: ReactNode;
  className?: string;
}

const ACCENT_CLASSES: Record<
  string,
  {
    topStrip: string;
    borderActive: string;
    iconColor: string;
  }
> = {
  cyan: {
    topStrip: "bg-gradient-to-r from-corporate-steel to-corporate-info",
    borderActive: "border-corporate-steel",
    iconColor: "text-corporate-steel-light",
  },
  green: {
    topStrip: "bg-corporate-accent",
    borderActive: "border-corporate-accent",
    iconColor: "text-corporate-accent-light",
  },
  amber: {
    topStrip: "bg-corporate-warning",
    borderActive: "border-corporate-warning shadow-card",
    iconColor: "text-corporate-warning-light",
  },
  indigo: {
    topStrip: "bg-corporate-info",
    borderActive: "border-corporate-info",
    iconColor: "text-corporate-info-light",
  },
  blue: {
    topStrip: "bg-corporate-info",
    borderActive: "border-corporate-info",
    iconColor: "text-corporate-info-light",
  },
  red: {
    topStrip: "bg-corporate-danger",
    borderActive: "border-corporate-danger",
    iconColor: "text-corporate-danger-light",
  },
};

export const BaseNodeCard: React.FC<BaseNodeCardProps> = ({
  selected,
  kindLabel,
  icon,
  verified,
  accentColor,
  layoutDirection = "LR",
  hasTargetHandle = true,
  hasSourceHandle = true,
  children,
  className = "",
}) => {
  const accent = ACCENT_CLASSES[accentColor] || ACCENT_CLASSES.cyan;

  const targetPosition = layoutDirection === "LR" ? Position.Left : Position.Top;
  const sourcePosition = layoutDirection === "LR" ? Position.Right : Position.Bottom;

  return (
    <div
      className={`w-[300px] bg-obsidian-900 border rounded-md overflow-hidden transition-all duration-200 select-none shadow-card cursor-pointer ${
        selected
          ? accent.borderActive + " ring-1 ring-corporate-steel/50"
          : "border-obsidian-700 hover:border-obsidian-600"
      } ${className}`}
    >
      {/* Target (Incoming) Handle */}
      {hasTargetHandle && (
        <Handle
          type="target"
          position={targetPosition}
          className={`!w-3 !h-3 !border-2 hover:!scale-125 transition-transform !bg-obsidian-950 ${
            verified ? "!border-corporate-steel" : "!border-corporate-danger"
          }`}
        />
      )}

      {/* Top Accent Strip */}
      <div className={`h-1 w-full ${verified ? accent.topStrip : "bg-corporate-danger"}`} />

      {/* Node Header Strip */}
      <div className="px-3 py-2 bg-obsidian-850 border-b border-obsidian-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={accent.iconColor}>{icon}</span>
          <span className="text-[10px] font-mono tracking-wider text-slate-300 font-bold uppercase">
            {kindLabel}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          {verified ? (
            <span className="inline-flex items-center gap-1 text-[9px] font-mono text-corporate-accent-light bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 rounded font-semibold">
              <CheckCircle2 className="w-2.5 h-2.5" /> VERIFIED
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-[9px] font-mono text-corporate-danger-light bg-red-500/10 border border-red-500/30 px-1.5 py-0.5 rounded font-semibold">
              <AlertOctagon className="w-2.5 h-2.5" /> UNVERIFIED
            </span>
          )}
        </div>
      </div>

      {/* Node Content Body */}
      <div className="p-3 space-y-2">{children}</div>

      {/* Source (Outgoing) Handle */}
      {hasSourceHandle && (
        <Handle
          type="source"
          position={sourcePosition}
          className={`!w-3 !h-3 !border-2 hover:!scale-125 transition-transform !bg-obsidian-950 ${
            verified ? "!border-corporate-steel" : "!border-corporate-danger"
          }`}
        />
      )}
    </div>
  );
};
