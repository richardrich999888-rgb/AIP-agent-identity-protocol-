import React from "react";
import SyntriassLogo from "./SyntriassLogo";
import { focusRing } from "@/components/ui/styles";

export interface SyntriassWordmarkProps {
  className?: string;
  subtitle?: string;
  onClick?: () => void;
}

/**
 * SyntriassWordmark: brand mark, company name, product name.
 */
export const SyntriassWordmark: React.FC<SyntriassWordmarkProps> = ({
  className = "",
  subtitle = "Accountability Console",
  onClick,
}) => {
  const content = (
    <>
      <SyntriassLogo size={26} glow={false} />
      <span className="text-[15px] font-semibold tracking-[0.06em] text-slate-100">SYNTRIASS</span>
      <span className="hidden sm:block h-4 w-px bg-obsidian-600" aria-hidden />
      <span className="hidden sm:block text-[13px] text-slate-400">{subtitle}</span>
    </>
  );

  if (!onClick) {
    return <div className={`inline-flex items-center gap-2.5 select-none ${className}`}>{content}</div>;
  }

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="Syntriass Accountability Console home"
      className={`inline-flex items-center gap-2.5 rounded-md select-none ${focusRing} ${className}`}
    >
      {content}
    </button>
  );
};

export default SyntriassWordmark;
