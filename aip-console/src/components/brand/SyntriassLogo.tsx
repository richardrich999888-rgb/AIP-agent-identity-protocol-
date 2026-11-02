import React, { useId } from "react";

export interface SyntriassLogoProps {
  size?: number;
  className?: string;
  glow?: boolean;
  showBackground?: boolean;
}

/**
 * SyntriassLogo: brand icon.
 * Visualizes the Triad of Autonomous Agent Accountability:
 * - Top Vertex (Cyan #607D8B): Cryptographic Identity & Keys (aip-crypto)
 * - Right Vertex (Blue #3F6E9A): Scoped Capability Tokens & Lattice (aip-core)
 * - Left Vertex (Indigo #3F6E9A): Tamper-Evident EvidencePackets (aip-protocol)
 * - Core Keyhole: Cryptographic Verification Engine
 */
export const SyntriassLogo: React.FC<SyntriassLogoProps> = ({
  size = 36,
  className = "",
  glow = true,
  showBackground = true,
}) => {
  const rawId = useId();
  const gradId = `syn-icon-grad-${rawId.replace(/:/g, "")}`;
  const coreGradId = `syn-core-grad-${rawId.replace(/:/g, "")}`;
  const glowId = `syn-glow-${rawId.replace(/:/g, "")}`;

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 36 36"
      width={size}
      height={size}
      fill="none"
      role="img"
      aria-label="Syntriass Brand Logo"
      className={`shrink-0 transition-transform duration-200 hover:scale-105 ${className}`}
    >
      <defs>
        <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#607D8B" />
          <stop offset="50%" stopColor="#3F6E9A" />
          <stop offset="100%" stopColor="#3F6E9A" />
        </linearGradient>

        <linearGradient id={coreGradId} x1="0%" y1="100%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#2E7D32" />
          <stop offset="100%" stopColor="#607D8B" />
        </linearGradient>

        {glow && (
          <filter id={glowId} x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="1.8" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        )}
      </defs>

      {/* Cyber Panel Outer Container */}
      {showBackground && (
        <rect
          width="36"
          height="36"
          rx="8"
          fill="#0E131F"
          stroke="#222F46"
          strokeWidth="1.2"
        />
      )}

      {/* Tripartite Cryptographic Delta Knot */}
      <path
        d="M18 6 L30 27 L6 27 Z"
        stroke={`url(#${gradId})`}
        strokeWidth="2.2"
        strokeLinejoin="round"
        fill="none"
        filter={glow ? `url(#${glowId})` : undefined}
      />

      {/* Inner Interlocking Lattice Core */}
      <polygon
        points="18,12 25,24 11,24"
        fill="#080B11"
        stroke="#222F46"
        strokeWidth="1.2"
      />

      {/* Core Cryptographic Anchor & Keyhole */}
      <circle cx="18" cy="17" r="2.2" fill={`url(#${coreGradId})`} />
      <path
        d="M18 19.2 L18 22.4"
        stroke={`url(#${coreGradId})`}
        strokeWidth="1.8"
        strokeLinecap="round"
      />

      {/* Three Vertex Nodes: Identity, Authority, Accountability */}
      <circle cx="18" cy="6" r="1.8" fill="#607D8B" />
      <circle cx="30" cy="27" r="1.8" fill="#3F6E9A" />
      <circle cx="6" cy="27" r="1.8" fill="#3F6E9A" />
    </svg>
  );
};

export default SyntriassLogo;
