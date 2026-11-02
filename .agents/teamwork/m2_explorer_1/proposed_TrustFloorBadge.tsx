import React from "react";
import { CheckCircle2, Shield, AlertTriangle, HelpCircle } from "lucide-react";
import type { TrustFloor } from "@/lib/types";

export interface TrustFloorBadgeProps {
  floor: TrustFloor;
  tampered?: boolean;
  size?: "sm" | "md" | "lg";
  className?: string;
  showIcon?: boolean;
  showLevel?: boolean;
}

export const TrustFloorBadge: React.FC<TrustFloorBadgeProps> = ({
  floor,
  tampered = false,
  size = "md",
  className = "",
  showIcon = true,
  showLevel = true,
}) => {
  const sizeClasses = {
    sm: "text-[10px] px-2 py-0.5 gap-1",
    md: "text-xs px-2.5 py-1 gap-1.5",
    lg: "text-sm px-3.5 py-1.5 gap-2",
  };

  const iconSizes = {
    sm: "w-3 h-3",
    md: "w-3.5 h-3.5",
    lg: "w-4 h-4",
  };

  if (tampered) {
    return (
      <span
        className={`inline-flex items-center rounded font-mono font-bold uppercase tracking-wider bg-cyber-red/15 text-cyber-red border border-cyber-red/40 shadow-red-glow ${sizeClasses[size]} ${className}`}
      >
        {showIcon && <AlertTriangle className={iconSizes[size]} />}
        <span>TAMPERED</span>
        {showLevel && <span className="opacity-70">(INVALID)</span>}
      </span>
    );
  }

  switch (floor) {
    case "COUNTERPARTY_SIGNED":
      return (
        <span
          className={`inline-flex items-center rounded font-mono font-bold uppercase tracking-wider bg-cyber-green/15 text-cyber-green border border-cyber-green/40 shadow-green-glow ${sizeClasses[size]} ${className}`}
        >
          {showIcon && <CheckCircle2 className={iconSizes[size]} />}
          <span>COUNTERPARTY_SIGNED</span>
          {showLevel && <span className="opacity-80">[L3]</span>}
        </span>
      );

    case "AUTHORITY_BOUND":
      return (
        <span
          className={`inline-flex items-center rounded font-mono font-bold uppercase tracking-wider bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/40 shadow-cyan-glow ${sizeClasses[size]} ${className}`}
        >
          {showIcon && <Shield className={iconSizes[size]} />}
          <span>AUTHORITY_BOUND</span>
          {showLevel && <span className="opacity-80">[L2]</span>}
        </span>
      );

    case "AGENT_SIGNED":
      return (
        <span
          className={`inline-flex items-center rounded font-mono font-bold uppercase tracking-wider bg-cyber-amber/15 text-cyber-amber border border-cyber-amber/40 shadow-amber-glow ${sizeClasses[size]} ${className}`}
        >
          {showIcon && <Shield className={iconSizes[size]} />}
          <span>AGENT_SIGNED</span>
          {showLevel && <span className="opacity-80">[L1]</span>}
        </span>
      );

    case "UNVERIFIED":
    default:
      return (
        <span
          className={`inline-flex items-center rounded font-mono font-bold uppercase tracking-wider bg-cyber-slate/20 text-cyber-slate border border-cyber-slate/40 ${sizeClasses[size]} ${className}`}
        >
          {showIcon && <HelpCircle className={iconSizes[size]} />}
          <span>UNVERIFIED</span>
          {showLevel && <span className="opacity-70">[L0]</span>}
        </span>
      );
  }
};

export default TrustFloorBadge;
