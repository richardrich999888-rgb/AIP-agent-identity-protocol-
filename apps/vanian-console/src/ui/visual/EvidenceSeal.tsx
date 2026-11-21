"use client";
import { useId } from "react";
import "./visual.css";
export type SealState = "unverified" | "verifying" | "verified" | "invalid";
export function EvidenceSeal({
  state,
  size = 66,
}: {
  state: SealState;
  size?: number;
}) {
  const id = useId().replace(/:/g, "");
  const title = {
    unverified: "Signature unchecked",
    verifying: "Checking signature",
    verified: "Signature verified",
    invalid: "Signature invalid",
  }[state];
  const color =
    state === "verified"
      ? "#08785d"
      : state === "invalid"
        ? "#bd3439"
        : "#8355d6";
  return (
    <svg
      className={"vseal vseal--" + state}
      width={size}
      height={size}
      viewBox="0 0 80 80"
      role="img"
      aria-label={title}
    >
      <title>{title}</title>
      <defs>
        <linearGradient id={id + "-fill"} x1="0" y1="0" x2="1" y2="1">
          <stop stopColor={color} stopOpacity=".16" />
          <stop offset="1" stopColor={color} stopOpacity=".035" />
        </linearGradient>
      </defs>
      <circle
        cx="40"
        cy="40"
        r="32"
        stroke={color}
        strokeOpacity=".18"
        fill={"url(#" + id + "-fill)"}
      />
      <circle
        className="vseal-track"
        cx="40"
        cy="40"
        r="28"
        stroke={color}
        strokeWidth="1.35"
        strokeDasharray="30 5 3 5 52 12"
        fill="none"
        opacity=".7"
      />
      <path
        d="m40 21 14 6v10c0 10-6 16-14 20-8-4-14-10-14-20V27z"
        stroke={color}
        fill={"url(#" + id + "-fill)"}
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      {state === "verified" ? (
        <path
          d="m32.8 38.1 4.9 5.4 9.6-11.1"
          stroke={color}
          fill="none"
          strokeWidth="2.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      ) : state === "invalid" ? (
        <path
          d="m35 32 10 11m0-11-10 11"
          stroke={color}
          strokeWidth="2.1"
          strokeLinecap="round"
        />
      ) : (
        <g stroke={color} strokeLinecap="round" strokeWidth="1.55">
          <path d="M34 34h12m-12 4h9m-9 4h6" />
        </g>
      )}
    </svg>
  );
}
