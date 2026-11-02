"use client";

import React from "react";
import {
  FileCheck,
  Workflow,
  ShieldAlert,
  Layers,
  Database,
  Radio,
} from "lucide-react";
import { usePathname, useRouter } from "next/navigation";
import SyntriassWordmark from "@/components/brand/SyntriassWordmark";
import { useConsole } from "@/lib/context/ConsoleContext";
import { badge, focusRing } from "@/components/ui/styles";
import type { ConsoleTab, TrustFloor } from "@/lib/types";

interface TabItem {
  id: ConsoleTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

const TABS: TabItem[] = [
  { id: "ingestion", label: "Evidence Ingestion & Ledger", icon: FileCheck },
  { id: "graph", label: "Accountability Graph", icon: Workflow },
  { id: "tamper", label: "Tamper Simulator", icon: ShieldAlert },
  { id: "authority", label: "Authority Lattice", icon: Layers },
  { id: "vault", label: "Evidence Vault", icon: Database, badge: "Planned" },
];

const FLOOR_LABEL: Record<TrustFloor, string> = {
  UNVERIFIED: "Unverified",
  AGENT_SIGNED: "Agent signed",
  AUTHORITY_BOUND: "Authority bound",
  COUNTERPARTY_SIGNED: "Counterparty signed",
};

export const ConsoleHeader: React.FC = () => {
  const {
    activeTab,
    setActiveTab,
    isWasmReady,
    isOfflineMode,
    setIsOfflineMode,
    loadedFilename,
    verificationReport,
  } = useConsole();
  const pathname = usePathname();
  const router = useRouter();

  // Tabs live on "/"; from other routes (e.g. /privacy) navigate back first.
  const goToTab = (id: ConsoleTab) => {
    setActiveTab(id);
    if (pathname !== "/") router.push("/");
  };

  const floor = verificationReport?.derived_trust_floor;
  const tampered = verificationReport?.tamper_evidence;
  const floorBadgeClass = tampered
    ? badge.danger
    : floor === "COUNTERPARTY_SIGNED" || floor === "AUTHORITY_BOUND"
    ? badge.success
    : floor === "AGENT_SIGNED"
    ? badge.warning
    : badge.neutral;

  return (
    <header className="sticky top-0 z-50 w-full border-b border-obsidian-700 bg-obsidian-950">
      {/* Tier 1: brand and live engine state */}
      <div className="max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex h-14 items-center justify-between gap-4">
          <SyntriassWordmark onClick={() => goToTab("ingestion")} />

          <div className="flex items-center gap-2 min-w-0">
            {loadedFilename && (
              <div
                className="hidden lg:flex items-center gap-2 min-w-0 h-8 pl-2.5 pr-1.5 rounded-md border border-obsidian-700 bg-obsidian-900"
                title={loadedFilename}
              >
                <span className="font-mono text-xs text-slate-300 truncate max-w-[200px]">
                  {loadedFilename}
                </span>
                {floor && (
                  <span className={floorBadgeClass} title={tampered ? "Tamper evidence detected" : floor}>
                    {tampered ? "Tampered" : FLOOR_LABEL[floor]}
                  </span>
                )}
              </div>
            )}

            <button
              type="button"
              onClick={() => setIsOfflineMode(!isOfflineMode)}
              className={`inline-flex items-center gap-1.5 h-8 px-2.5 rounded-md border text-xs font-medium transition-colors duration-150 ${focusRing} ${
                isOfflineMode
                  ? "border-obsidian-700 text-slate-300 hover:border-corporate-steel"
                  : "border-corporate-info/50 bg-corporate-info/10 text-corporate-info-light"
              }`}
              title="Toggle offline WASM / live REST client mode"
            >
              <Radio className="w-3.5 h-3.5" aria-hidden />
              <span className="hidden sm:inline">{isOfflineMode ? "Offline" : "Live REST"}</span>
            </button>

            <div
              className="inline-flex items-center gap-2 h-8 px-2.5 rounded-md border border-obsidian-700 text-xs text-slate-300"
              title={isWasmReady ? "WebAssembly verifier loaded" : "Loading WebAssembly verifier"}
              role="status"
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  isWasmReady ? "bg-corporate-accent-light" : "bg-corporate-warning-light animate-pulse"
                }`}
                aria-hidden
              />
              <span className="hidden sm:inline">{isWasmReady ? "Verifier ready" : "Verifier loading"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Tier 2: primary navigation */}
      <nav
        aria-label="Console sections"
        className="max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 flex gap-1 overflow-x-auto"
      >
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => goToTab(tab.id)}
              aria-current={isActive ? "page" : undefined}
              className={`relative flex shrink-0 items-center gap-2 h-10 px-3 text-[13px] font-medium whitespace-nowrap transition-colors duration-150 ${focusRing} ${
                isActive ? "text-slate-100" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-corporate-steel-light" : "text-slate-500"}`} />
              <span>{tab.label}</span>
              {tab.badge && <span className={badge.neutral}>{tab.badge}</span>}
              <span
                aria-hidden
                className={`absolute inset-x-2 -bottom-px h-0.5 ${isActive ? "bg-corporate-steel-light" : "bg-transparent"}`}
              />
            </button>
          );
        })}
      </nav>
    </header>
  );
};

export default ConsoleHeader;
