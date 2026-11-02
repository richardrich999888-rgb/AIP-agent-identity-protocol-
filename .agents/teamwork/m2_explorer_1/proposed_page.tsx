"use client";

import React, { useEffect, useState } from "react";
import {
  FileCheck,
  Workflow,
  ShieldAlert,
  Layers,
  Database,
  ArrowRight,
  ShieldCheck,
  Zap,
  Info,
} from "lucide-react";
import { useConsole } from "@/lib/context/ConsoleContext";
import type { FixtureMetadata } from "@/lib/types";

export default function ConsolePage() {
  const {
    activeTab,
    setActiveTab,
    loadedPacket,
    loadedFilename,
    verificationReport,
    loadFixture,
    isWasmReady,
  } = useConsole();

  const [fixtures, setFixtures] = useState<FixtureMetadata[]>([]);

  // Load sample fixtures catalog on mount
  useEffect(() => {
    async function fetchIndex() {
      try {
        const res = await fetch("/fixtures/index.json");
        if (res.ok) {
          const data = await res.json();
          setFixtures(data.fixtures || []);
        }
      } catch (err) {
        console.warn("Could not load /fixtures/index.json catalog:", err);
      }
    }
    fetchIndex();
  }, []);

  return (
    <div className="flex flex-col gap-6 w-full">
      {/* Sample Fixtures Quick-Load Ribbon */}
      <section className="cyber-panel p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-cyber-cyan" />
          <span className="text-xs font-mono font-semibold text-slate-200 uppercase tracking-wider">
            Quick Fixtures:
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => loadFixture("honest_counterparty")}
            className="px-2.5 py-1 text-xs font-mono rounded bg-obsidian-800 hover:bg-obsidian-750 border border-cyber-green/40 text-cyber-green transition-all"
            title="Full valid bilateral payment approval with bank countersignature"
          >
            ✓ Honest Counterparty (Level 3)
          </button>
          <button
            onClick={() => loadFixture("authority_bound")}
            className="px-2.5 py-1 text-xs font-mono rounded bg-obsidian-800 hover:bg-obsidian-750 border border-cyber-cyan/40 text-cyber-cyan transition-all"
            title="Valid cloud infrastructure delegation chain"
          >
            ✓ Authority-Bound (Level 2)
          </button>
          <button
            onClick={() => loadFixture("agent_signed")}
            className="px-2.5 py-1 text-xs font-mono rounded bg-obsidian-800 hover:bg-obsidian-750 border border-cyber-amber/40 text-cyber-amber transition-all"
            title="Agent self-signed task lacking root delegation"
          >
            ! Agent-Signed (Level 1)
          </button>
          <button
            onClick={() => loadFixture("tampered_summary")}
            className="px-2.5 py-1 text-xs font-mono rounded bg-obsidian-800 hover:bg-obsidian-750 border border-cyber-red/40 text-cyber-red transition-all"
            title="Adversarially altered payment amount in decision summary"
          >
            ✕ Tampered Summary (Adversarial)
          </button>
          <button
            onClick={() => loadFixture("scope_escalation")}
            className="px-2.5 py-1 text-xs font-mono rounded bg-obsidian-800 hover:bg-obsidian-750 border border-cyber-red/40 text-cyber-red transition-all"
            title="Unauthorized scope expansion violating attenuation"
          >
            ✕ Scope Escalation
          </button>
        </div>
      </section>

      {/* Main View Display with Container Persistence */}
      <div className="w-full">
        {/* R1: Evidence Ingestion & Verification Ledger */}
        <div className={activeTab === "ingestion" ? "block" : "hidden"}>
          <div id="ingestion-view-mount">
            {/* The Ingestion & Ledger Component mounts here */}
            {/* Fallback scaffold until IngestionView component is mounted */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-5 flex flex-col gap-6">
                <div className="cyber-panel p-6 border-dashed border-obsidian-600 hover:border-cyber-cyan/60 transition-colors cursor-pointer text-center flex flex-col items-center justify-center min-h-[260px]">
                  <FileCheck className="w-12 h-12 text-cyber-cyan mb-3 opacity-80" />
                  <h3 className="text-base font-semibold text-slate-100 mb-1">
                    Ingest Evidence Packet
                  </h3>
                  <p className="text-xs text-slate-400 mb-4 max-w-sm">
                    Drag and drop <code className="text-cyber-cyan font-mono">.json</code> EvidencePacket or <code className="text-cyber-cyan font-mono">.zip</code> audit bundle
                  </p>
                  <span className="text-xs font-mono px-3 py-1.5 rounded bg-obsidian-800 border border-obsidian-700 text-slate-300">
                    Browse File System
                  </span>
                </div>

                <div className="cyber-panel p-4">
                  <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase mb-2">
                    Active Verifier Trust Anchors
                  </h4>
                  <p className="text-xs text-slate-400">
                    Configured with default trusted principal and counterparty verification keys from reference test suite.
                  </p>
                </div>
              </div>

              <div className="lg:col-span-7 cyber-panel p-6">
                <div className="flex items-center justify-between pb-4 border-b border-obsidian-700 mb-4">
                  <div>
                    <h3 className="text-base font-semibold text-slate-100">
                      14-Rule Verification Ledger
                    </h3>
                    <p className="text-xs text-slate-400">
                      Evaluated directly by WebAssembly engine with Zero JavaScript logic.
                    </p>
                  </div>
                  {loadedFilename ? (
                    <span className="text-xs font-mono text-cyber-cyan bg-cyber-cyan/10 px-2 py-1 rounded border border-cyber-cyan/30">
                      Loaded: {loadedFilename}
                    </span>
                  ) : (
                    <span className="text-xs font-mono text-slate-500">
                      No packet loaded
                    </span>
                  )}
                </div>

                {verificationReport ? (
                  <div className="space-y-2">
                    {verificationReport.checks.map((chk, idx) => (
                      <div
                        key={idx}
                        className={`p-3 rounded border text-xs font-mono flex items-start justify-between gap-3 ${
                          chk.pass
                            ? "bg-cyber-green/5 border-cyber-green/20 text-slate-200"
                            : "bg-cyber-red/10 border-cyber-red/30 text-cyber-red"
                        }`}
                      >
                        <div>
                          <span className="font-bold mr-2">
                            {idx + 1}. {chk.rule}
                          </span>
                          <span className="text-slate-400 block mt-0.5">
                            {chk.detail}
                          </span>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded font-bold uppercase shrink-0 ${
                            chk.pass
                              ? "bg-cyber-green/20 text-cyber-green"
                              : "bg-cyber-red/30 text-cyber-red"
                          }`}
                        >
                          {chk.pass ? "PASS" : "FAIL"}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="py-16 text-center text-slate-500 text-xs font-mono">
                    Select a quick fixture above or drop an EvidencePacket to view rule evaluation.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* R2: Accountability Graph DAG Placeholder View */}
        <div className={activeTab === "graph" ? "block" : "hidden"}>
          <div className="cyber-panel p-8 text-center min-h-[480px] flex flex-col items-center justify-center">
            <Workflow className="w-16 h-16 text-cyber-cyan/70 mb-4 animate-pulse" />
            <h3 className="text-xl font-bold text-slate-100 mb-2">
              Interactive Accountability Graph DAG (R2)
            </h3>
            <p className="text-sm text-slate-400 max-w-xl mb-6">
              Visualizes the complete cryptographic delegation chain: Principal → AuthorityGrant → Delegation Hops → Agent → Decision → Action Attestations → Countersigned Receipt using React Flow.
            </p>
            {loadedPacket ? (
              <div className="text-xs font-mono text-slate-300 bg-obsidian-850 p-4 rounded border border-obsidian-700 max-w-lg mb-6">
                <div>Principal: {loadedPacket.root_authority.principal_id}</div>
                <div>Agent: {loadedPacket.agent.aip_id}</div>
                <div>Decision: {loadedPacket.decision.summary}</div>
                <div>Actions: {loadedPacket.actions.length} attestation(s)</div>
              </div>
            ) : (
              <p className="text-xs font-mono text-cyber-amber mb-6">
                Notice: Load a fixture in Ingestion view to populate the DAG visualizer.
              </p>
            )}
            <button
              onClick={() => setActiveTab("ingestion")}
              className="inline-flex items-center gap-2 px-4 py-2 rounded bg-obsidian-800 hover:bg-obsidian-700 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono transition-colors"
            >
              Switch to Ingestion View <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* R3: Adversarial Tamper Simulator Placeholder View */}
        <div className={activeTab === "tamper" ? "block" : "hidden"}>
          <div className="cyber-panel p-8 text-center min-h-[480px] flex flex-col items-center justify-center">
            <ShieldAlert className="w-16 h-16 text-cyber-red/70 mb-4 animate-pulse" />
            <h3 className="text-xl font-bold text-slate-100 mb-2">
              Adversarial Tamper Simulator (R3)
            </h3>
            <p className="text-sm text-slate-400 max-w-xl mb-6">
              Interactive mutation sandbox demonstrating cryptographic tamper detection across 14 attack vectors with smart hash recalculation toggling.
            </p>
            <button
              onClick={() => setActiveTab("ingestion")}
              className="inline-flex items-center gap-2 px-4 py-2 rounded bg-obsidian-800 hover:bg-obsidian-700 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono transition-colors"
            >
              Switch to Ingestion View <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* R4: Authority Lattice Builder Placeholder View */}
        <div className={activeTab === "authority" ? "block" : "hidden"}>
          <div className="cyber-panel p-8 text-center min-h-[480px] flex flex-col items-center justify-center">
            <Layers className="w-16 h-16 text-cyber-indigo/70 mb-4 animate-pulse" />
            <h3 className="text-xl font-bold text-slate-100 mb-2">
              Authority Management & Visual Lattice Builder (R4)
            </h3>
            <p className="text-sm text-slate-400 max-w-xl mb-6">
              Visual scope matrix editor for built-in named scopes (ADMIN, ORCHESTRATOR, AUDIT_READER, SUBMITTER), capability meet operator preview (⊓), and cascade revocation tree traversal.
            </p>
            <button
              onClick={() => setActiveTab("ingestion")}
              className="inline-flex items-center gap-2 px-4 py-2 rounded bg-obsidian-800 hover:bg-obsidian-700 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono transition-colors"
            >
              Switch to Ingestion View <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* R5: Evidence Vault Explorer Placeholder View */}
        <div className={activeTab === "vault" ? "block" : "hidden"}>
          <div className="cyber-panel p-8 text-center min-h-[480px] flex flex-col items-center justify-center">
            <Database className="w-16 h-16 text-cyber-green/70 mb-4 animate-pulse" />
            <h3 className="text-xl font-bold text-slate-100 mb-2">
              Evidence Vault Explorer (R5)
            </h3>
            <p className="text-sm text-slate-400 max-w-xl mb-6">
              Multi-tenant packet repository table, search, filtering, signed ZIP bundle audit export, and live REST / offline mock fallback mode.
            </p>
            <button
              onClick={() => setActiveTab("ingestion")}
              className="inline-flex items-center gap-2 px-4 py-2 rounded bg-obsidian-800 hover:bg-obsidian-700 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono transition-colors"
            >
              Switch to Ingestion View <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
