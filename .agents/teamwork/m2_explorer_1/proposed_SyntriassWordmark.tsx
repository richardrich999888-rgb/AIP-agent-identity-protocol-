import React from "react";
import SyntriassLogo from "./SyntriassLogo";

export interface SyntriassWordmarkProps {
  className?: string;
  size?: "sm" | "md" | "lg";
  showSubtitle?: boolean;
  subtitle?: string;
  showBadge?: boolean;
  onClick?: () => void;
}

/**
 * SyntriassWordmark: Enterprise header wordmark with inline vector SVG brandmark,
 * geometric uppercase brand typography, and high-tech monospace descriptor.
 */
export const SyntriassWordmark: React.FC<SyntriassWordmarkProps> = ({
  className = "",
  size = "md",
  showSubtitle = true,
  subtitle = "ACCOUNTABILITY CONSOLE",
  showBadge = true,
  onClick,
}) => {
  const sizeMap = {
    sm: {
      logoSize: 28,
      titleClass: "text-base tracking-[0.14em]",
      subClass: "text-[9px] tracking-[0.18em]",
      badgeClass: "text-[9px] px-1.5 py-0.5",
    },
    md: {
      logoSize: 34,
      titleClass: "text-lg tracking-[0.16em]",
      subClass: "text-[10px] tracking-[0.2em]",
      badgeClass: "text-[10px] px-2 py-0.5",
    },
    lg: {
      logoSize: 42,
      titleClass: "text-2xl tracking-[0.18em]",
      subClass: "text-xs tracking-[0.22em]",
      badgeClass: "text-xs px-2.5 py-1",
    },
  };

  const { logoSize, titleClass, subClass, badgeClass } = sizeMap[size];

  return (
    <div
      onClick={onClick}
      className={`inline-flex items-center gap-3 select-none ${
        onClick ? "cursor-pointer group" : ""
      } ${className}`}
      role="banner"
    >
      <SyntriassLogo size={logoSize} glow={true} />

      <div className="flex flex-col justify-center">
        <div className="flex items-center gap-2">
          <span
            className={`font-sans font-bold text-slate-100 uppercase transition-colors duration-200 group-hover:text-cyber-cyan ${titleClass}`}
          >
            SYNTRIASS
          </span>

          {showBadge && (
            <span
              className={`rounded border border-cyber-cyan/30 bg-cyber-cyan/10 font-mono text-cyber-cyan font-semibold uppercase ${badgeClass}`}
            >
              AEP1
            </span>
          )}
        </div>

        {showSubtitle && (
          <span
            className={`font-mono text-cyber-cyan/85 font-medium uppercase ${subClass}`}
          >
            {subtitle}
          </span>
        )}
      </div>
    </div>
  );
};

export default SyntriassWordmark;
