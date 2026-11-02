"use client";

import React from "react";
import {
  FileCheck,
  Workflow,
  ShieldAlert,
  Layers,
  Database,
  Cpu,
  Radio,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import SyntriassWordmark from "@/components/brand/SyntriassWordmark";
import { useConsole } from "@/lib/context/ConsoleContext";
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
  { id: "vault", label: "Evidence Vault", icon: Database },
];

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

  const getFloorBadge = (floor?: TrustFloor, tampered?: boolean) => {
    if (!floor) return null;
    if (tampered) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyber-red/20 text-cyber-red border border-cyber-red/40 animate-pulse">
          <AlertTriangle className="w-3 h-3" />
          TAMPERED
        </span>
      );
    }
    switch (floor) {
      case "COUNTERPARTY_SIGNED":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyber-green/15 text-cyber-green border border-cyber-green/30">
            <CheckCircle2 className="w-3 h-3" />
            COUNTERPARTY_SIGNED
          </span>
        );
      case "AUTHORITY_BOUND":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/30">
            AUTHORITY_BOUND
          </span>
        );
      case "AGENT_SIGNED":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyber-amber/15 text-cyber-amber border border-cyber-amber/30">
            AGENT_SIGNED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyber-slate/20 text-cyber-slate border border-cyber-slate/40">
            UNVERIFIED
          </span>
        );
    }
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-obsidian-700 bg-obsidian-950/90 backdrop-blur-md">
      <div className="max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 items-center justify-between gap-4">
          {/* Brand & Wordmark */}
          <div className="flex items-center gap-4 shrink-0">
            <SyntriassWordmark
              size="md"
              onClick={() => setActiveTab("ingestion")}
            />
          </div>

          {/* Navigation Tabs (R1 to R5) */}
          <nav className="hidden md:flex items-center gap-1 lg:gap-2">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`group relative flex items-center gap-2 px-3 py-2 text-xs lg:text-sm font-medium rounded-md transition-all duration-150 ${
                    isActive
                      ? "text-cyber-cyan bg-obsidian-850 border border-cyber-cyan/40 shadow-cyan-glow"
                      : "text-slate-400 hover:text-slate-100 hover:bg-obsidian-800/60"
                  }`}
                >
                  <Icon
                    className={`w-4 h-4 transition-transform group-hover:scale-110 ${
                      isActive ? "text-cyber-cyan" : "text-slate-400"
                    }`}
                  />
                  <span>{tab.label}</span>
                  {isActive && (
                    <span className="absolute bottom-0 left-2 right-2 h-[2px] bg-cyber-cyan rounded-full" />
                  )}
                </button>
              );
            })}
          </nav>

          {/* Status & Live Indicators */}
          <div className="flex items-center gap-3 shrink-0">
            {/* Loaded Evidence Pill */}
            {loadedFilename && (
              <div className="hidden xl:flex items-center gap-2 px-2.5 py-1 rounded-md bg-obsidian-900 border border-obsidian-700">
                <span className="text-[11px] font-mono text-slate-400 max-w-[120px] truncate">
                  {loadedFilename}
                </span>
                {getFloorBadge(
                  verificationReport?.derived_trust_floor,
                  verificationReport?.tamper_evidence
                )}
              </div>
            )}

            {/* Offline / Connected Toggle */}
            <button
              onClick={() => setIsOfflineMode(!isOfflineMode)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-medium border transition-colors ${
                isOfflineMode
                  ? "bg-obsidian-900 border-obsidian-700 text-slate-300 hover:border-cyber-cyan/50"
                  : "bg-cyber-indigo/15 border-cyber-indigo/40 text-cyber-indigo"
              }`}
              title="Toggle Offline WASM / Live REST client mode"
            >
              <Radio
                className={`w-3.5 h-3.5 ${
                  isOfflineMode ? "text-slate-400" : "text-cyber-indigo animate-pulse"
                }`}
              />
              <span className="hidden sm:inline">
                {isOfflineMode ? "Offline (WASM)" : "Live (REST)"}
              </span>
            </button>

            {/* WASM Engine Status */}
            <div
              className={`flex items-center gap-2 px-2.5 py-1 rounded-md border text-xs font-mono ${
                isWasmReady
                  ? "bg-cyber-green/10 border-cyber-green/30 text-cyber-green"
                  : "bg-cyber-amber/10 border-cyber-amber/30 text-cyber-amber animate-pulse"
              }`}
              title={
                isWasmReady
                  ? "WASM Verification Engine is initialized and ready"
                  : "Initializing WebAssembly engine"
              }
            >
              <Cpu className="w-3.5 h-3.5" />
              <span className="hidden lg:inline">
                {isWasmReady ? "WASM Active" : "WASM Booting"}
              </span>
              <span
                className={`w-2 h-2 rounded-full ${
                  isWasmReady
                    ? "bg-cyber-green shadow-[0_0_8px_#00E676]"
                    : "bg-cyber-amber"
                }`}
              />
            </div>
          </div>
        </div>

        {/* Mobile Sub-Navigation Bar */}
        <div className="flex md:hidden overflow-x-auto py-2 gap-1 border-t border-obsidian-800">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded whitespace-nowrap shrink-0 ${
                  isActive
                    ? "text-cyber-cyan bg-obsidian-850 border border-cyber-cyan/40"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};

export default ConsoleHeader;
