"use client";

import React from "react";

/**
 * SVG Arrow Marker Definitions and CSS Keyframes for React Flow edges.
 * Mounted once at the canvas root to enable cyan flow and crimson warning pulses.
 */
export function EdgeMarkerDefs() {
  return (
    <svg
      style={{ position: "absolute", top: 0, left: 0, width: 0, height: 0, pointerEvents: "none" }}
      aria-hidden="true"
    >
      <defs>
        {/* Electric Cyan Arrow Marker for Verified Edges */}
        <marker
          id="cyan-arrow"
          viewBox="0 0 12 12"
          refX="10"
          refY="6"
          markerWidth="8"
          markerHeight="8"
          orient="auto-start-reverse"
        >
          <path d="M 0 1 L 12 6 L 0 11 z" fill="#607D8B" />
        </marker>

        {/* Crimson Arrow Marker for Tampered / Unverified Edges */}
        <marker
          id="crimson-arrow"
          viewBox="0 0 12 12"
          refX="10"
          refY="6"
          markerWidth="8"
          markerHeight="8"
          orient="auto-start-reverse"
        >
          <path d="M 0 1 L 12 6 L 0 11 z" fill="#C62828" />
        </marker>

        {/* Keyframe Animations for Edge Flow and Warning Pulse */}
        <style>
          {`
            @keyframes flowAnimation {
              from {
                stroke-dashoffset: 24;
              }
              to {
                stroke-dashoffset: 0;
              }
            }

            @keyframes warningPulse {
              0%, 100% {
                opacity: 0.65;
                stroke-width: 2px;
              }
              50% {
                opacity: 1;
                stroke-width: 3.5px;
                filter: drop-shadow(0 0 8px #C62828);
              }
            }
          `}
        </style>
      </defs>
    </svg>
  );
}
