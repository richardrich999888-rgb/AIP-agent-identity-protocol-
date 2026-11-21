"use client";

import { useId } from "react";
import "./visual.css";

export interface OrbitalSensor {
  id: string;
  name: string;
  state: string;
  group?: string;
}
interface Props {
  sensors: OrbitalSensor[];
  onSelect?: (id: string) => void;
  className?: string;
}

export function OrbitalSensors({ sensors, onSelect, className = "" }: Props) {
  const prefix = useId().replace(/:/g, "");
  const sorted = [...sensors].sort(
    (a, b) =>
      (a.group ?? "").localeCompare(b.group ?? "") || a.id.localeCompare(b.id),
  );
  const keys = [...new Set(sorted.map((s) => s.group ?? ""))];
  const center = { x: 145, y: 111 };
  const placed = sorted.map((s) => {
    const key = s.group ?? "";
    const inGroup = sorted.filter((n) => (n.group ?? "") === key);
    const ix = inGroup.findIndex((n) => n.id === s.id);
    const groupIndex = keys.indexOf(key);
    const angle =
      ((-120 + (groupIndex * 360) / Math.max(1, keys.length) + (ix % 3) * 10) *
        Math.PI) /
      180;
    const r =
      inGroup.length === 1
        ? 73
        : 52 + (46 * ix) / Math.max(1, inGroup.length - 1);
    return {
      s,
      x: center.x + Math.cos(angle) * r,
      y: center.y + Math.sin(angle) * r * 0.79,
    };
  });
  return (
    <svg
      className={"vorb " + className}
      viewBox="0 0 290 205"
      role={onSelect ? "group" : "img"}
      aria-labelledby={prefix + "-title " + prefix + "-desc"}
    >
      <title id={prefix + "-title"}>Sensor coverage schematic</title>
      <desc id={prefix + "-desc"}>
        Each point represents one sensor. Position groups sensors by ownership.
        The rings are diagram guides.
      </desc>
      <defs>
        <radialGradient id={prefix + "-field"}>
          <stop stopColor="#8854f4" stopOpacity=".23" />
          <stop offset=".72" stopColor="#8d57f1" stopOpacity=".09" />
          <stop offset="1" stopColor="#8d57f1" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={prefix + "-line"} x1="0" y1="1" x2="1" y2="0">
          <stop stopColor="#7753c9" stopOpacity=".23" />
          <stop offset=".64" stopColor="#ad82ff" stopOpacity=".8" />
          <stop offset="1" stopColor="#e0a8fa" />
        </linearGradient>
        <pattern
          id={prefix + "-grid"}
          width="15"
          height="15"
          patternUnits="userSpaceOnUse"
        >
          <circle cx="1" cy="1" r=".63" fill="#b1a0da" opacity=".4" />
        </pattern>
        <radialGradient id={prefix + "-dot"}>
          <stop stopColor="#fff" />
          <stop offset=".5" stopColor="#e4d2ff" />
          <stop offset="1" stopColor="#a888ff" />
        </radialGradient>
        <linearGradient id={prefix + "-sweep"} x1="0" y1="1" x2="1" y2="0">
          <stop stopColor="#b999ff" stopOpacity="0" />
          <stop offset="1" stopColor="#ae7bff" stopOpacity=".37" />
        </linearGradient>
      </defs>
      <rect
        width="290"
        height="205"
        fill={"url(#" + prefix + "-grid)"}
        opacity=".65"
      />
      <ellipse
        cx={center.x}
        cy={center.y}
        rx="142"
        ry="101"
        fill={"url(#" + prefix + "-field)"}
      />
      <g fill="none" stroke="#c3a4ff" opacity=".25">
        {[24, 50, 79, 109, 136].map((r) => (
          <ellipse
            key={r}
            cx={center.x}
            cy={center.y}
            rx={r}
            ry={r * 0.79}
            strokeWidth={r === 109 ? ".85" : ".65"}
          />
        ))}
        <path
          d="M8 111h274M145 12v187M36 51l217 120M45 174 245 49"
          strokeDasharray="3 5"
          strokeWidth=".65"
        />
      </g>
      <g
        fill="#c0a6ed"
        opacity=".65"
        fontFamily="'JetBrains Mono', monospace"
        fontSize="5.3"
        letterSpacing=".7"
        aria-hidden="true"
      >
        <text x="7" y="108">
          −
        </text>
        <text x="281" y="108">
          +
        </text>
      </g>
      <g
        fill="none"
        stroke={"url(#" + prefix + "-line)"}
        strokeWidth="1.15"
        opacity=".9"
      >
        <path d="M144 25A109 86 0 0 1 248 84" />
        <path d="M42 139a109 86 0 0 0 45 45" />
        <path d="M152 49a79 62 0 0 1 67 41" />
      </g>
      {placed.length > 0 && (
        <path
          d="M145 111l46-79a113 90 0 0 1 61 58z"
          fill={"url(#" + prefix + "-sweep)"}
        />
      )}
      {placed.map(({ s, x, y }) => {
        const degraded = /delay|offline|error|down|stale|degrad/i.test(s.state);
        const selectedColor = degraded ? "#ffbc7d" : "#cfb0ff";
        const name =
          s.name + " · " + s.state + (s.group ? " · " + s.group : "");
        return (
          <g
            key={s.id}
            className={onSelect ? "vorb-interactive" : undefined}
            role={onSelect ? "button" : undefined}
            aria-label={onSelect ? name : undefined}
            tabIndex={onSelect ? 0 : undefined}
            onClick={onSelect ? () => onSelect(s.id) : undefined}
            onKeyDown={
              onSelect
                ? (e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelect(s.id);
                    }
                  }
                : undefined
            }
          >
            <title>{name}</title>
            <circle cx={x} cy={y} r="9" fill="transparent" />
            <circle
              cx={x}
              cy={y}
              r="6.5"
              stroke={selectedColor}
              fill={selectedColor}
              fillOpacity=".08"
              strokeOpacity=".38"
              strokeWidth=".7"
            />
            <circle
              cx={x}
              cy={y}
              r="2.7"
              fill={degraded ? selectedColor : "url(#" + prefix + "-dot)"}
            />
          </g>
        );
      })}
      <g stroke="#d4beff" strokeWidth="1.1" opacity=".9">
        <path d="M141 111h8m-4-4v8" />
      </g>
    </svg>
  );
}
