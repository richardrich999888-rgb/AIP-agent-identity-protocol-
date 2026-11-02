/**
 * Shared class vocabulary for console chrome: buttons, badges, panels.
 * One source so the same control looks the same on every screen.
 */

const focusRing =
  "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-corporate-steel-light";

export const btn = {
  secondary: `inline-flex items-center justify-center gap-1.5 h-8 px-3 rounded-md border border-obsidian-600 bg-obsidian-850 text-[13px] font-medium text-slate-200 transition-colors duration-150 hover:bg-obsidian-800 hover:border-corporate-steel disabled:opacity-50 disabled:pointer-events-none ${focusRing}`,
  ghost: `inline-flex items-center justify-center gap-1.5 h-8 px-2.5 rounded-md text-[13px] font-medium text-slate-300 transition-colors duration-150 hover:bg-obsidian-800 hover:text-slate-100 disabled:opacity-50 disabled:pointer-events-none ${focusRing}`,
  danger: `inline-flex items-center justify-center gap-1.5 h-8 px-3 rounded-md border border-obsidian-600 bg-obsidian-850 text-[13px] font-medium text-slate-200 transition-colors duration-150 hover:border-corporate-danger hover:text-corporate-danger-light ${focusRing}`,
  link: `inline-flex items-center gap-1 rounded text-[13px] font-medium text-corporate-steel-light transition-colors duration-150 hover:text-slate-100 ${focusRing}`,
};

const badgeBase = "inline-flex items-center gap-1 h-5 px-1.5 rounded text-[11px] font-medium border whitespace-nowrap";

export const badge = {
  neutral: `${badgeBase} bg-obsidian-800 border-obsidian-600 text-slate-300`,
  success: `${badgeBase} bg-corporate-accent/10 border-corporate-accent/40 text-corporate-accent-light`,
  danger: `${badgeBase} bg-corporate-danger/10 border-corporate-danger/40 text-corporate-danger-light`,
  warning: `${badgeBase} bg-corporate-warning/10 border-corporate-warning/40 text-corporate-warning-light`,
  info: `${badgeBase} bg-corporate-info/10 border-corporate-info/40 text-corporate-info-light`,
};

export const panel = "rounded-md border border-obsidian-700 bg-obsidian-900";
export const panelHeader = "flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-obsidian-700";
export const panelTitle = "text-sm font-semibold text-slate-100";

export { focusRing };
