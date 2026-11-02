"use client";

import React, { memo } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  type EdgeProps,
  getSmoothStepPath,
} from "@xyflow/react";
import { AlertTriangle } from "lucide-react";
import type { AccountabilityFlowEdge } from "../types";

export const AccountabilityEdge = memo(function AccountabilityEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}: EdgeProps<AccountabilityFlowEdge>) {
  const verified = data?.verified ?? true;
  const relation = data?.relation ?? "Issues";

  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 16,
  });

  return (
    <>
      {/* Background glow path */}
      <path
        d={edgePath}
        fill="none"
        stroke={verified ? "#607D8B" : "#C62828"}
        strokeWidth={verified ? 6 : 8}
        strokeOpacity={verified ? 0.25 : 0.45}
        className={verified ? "blur-[2px]" : "blur-[4px]"}
      />

      {/* Primary SVG edge line */}
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: verified ? "#607D8B" : "#C62828",
          strokeWidth: selected ? 2.5 : 2,
          strokeDasharray: verified ? "8 4" : "6 4",
          animation: verified
            ? "flowAnimation 1.5s linear infinite"
            : "warningPulse 1.2s ease-in-out infinite",
          transition: "stroke 0.2s, stroke-width 0.2s",
        }}
        markerEnd={verified ? "url(#cyan-arrow)" : "url(#crimson-arrow)"}
      />

      {/* Relation Pill Badge */}
      <EdgeLabelRenderer>
        <div
          style={{
            position: "absolute",
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
          }}
          className={`pointer-events-auto flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono tracking-wider uppercase border transition-all select-none ${
            verified
              ? "bg-obsidian-950/95 border-corporate-steel/40 text-corporate-steel-light hover:border-corporate-steel"
              : "bg-obsidian-950/95 border-corporate-danger/80 text-corporate-danger-light hover:border-corporate-danger"
          }`}
        >
          {verified ? (
            <>
              <span className="w-1.5 h-1.5 rounded-full bg-corporate-steel" />
              <span>{relation}</span>
            </>
          ) : (
            <>
              <AlertTriangle className="w-3 h-3 text-corporate-danger-light" />
              <span className="font-bold">{relation} (TAMPERED)</span>
            </>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
});

export const VerifiedEdge = AccountabilityEdge;
export const BrokenEdge = AccountabilityEdge;
export const TamperedEdge = AccountabilityEdge;
