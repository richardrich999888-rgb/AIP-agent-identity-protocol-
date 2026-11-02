"use client";

import React, { useState, useEffect, useRef } from "react";
import { Database, ArrowRight, Key } from "lucide-react";
import { btn, panel } from "@/components/ui/styles";
import { useConsole } from "@/lib/context/ConsoleContext";
import { useEvidence } from "@/lib/wasm/EvidenceContext";
import { useAipVerifier } from "@/lib/wasm/useAipVerifier";
import { Dropzone } from "@/components/ingestion/Dropzone";
import { VerificationLedger } from "@/components/ingestion/VerificationLedger";
import { TrustFloorBadge } from "@/components/ingestion/TrustFloorBadge";
import { TrustAnchorConfig } from "@/components/ingestion/TrustAnchorConfig";
import { AccountabilityGraph } from "@/components/graph/AccountabilityGraph";
import { TamperSimulator } from "@/components/tamper/TamperSimulator";
import { AuthorityManagement } from "@/components/authority/AuthorityManagement";

export default function ConsolePage() {
  const { activeTab, setActiveTab, loadedPacket } = useConsole();
  const { isReady } = useAipVerifier();
  const {
    evidence,
    report,
    loadFixture,
    updateContext,
    reverify,
  } = useEvidence();

  const [showAnchorModal, setShowAnchorModal] = useState<boolean>(false);
  const hasInitialized = useRef<boolean>(false);

  // Pre-load default honest counterparty sample when WASM engine becomes ready
  useEffect(() => {
    if (isReady && !evidence && !hasInitialized.current) {
      hasInitialized.current = true;
      loadFixture("honest_counterparty").catch((err) => {
        console.warn("Initial sample pre-load note:", err);
      });
    }
  }, [isReady, evidence, loadFixture]);

  const handleContextChange = (newContextJson: string) => {
    updateContext(newContextJson);
    reverify();
  };

  return (
    <div className="flex flex-col gap-6 w-full">
      {/* ── Main Tabbed View Container ── */}
      <div className="w-full">
        {/* Tab 1 (R1): Evidence Ingestion & 14-Rule Verification Ledger */}
        <div className={activeTab === "ingestion" ? "block space-y-4" : "hidden"}>
          {/* View Header with Trust Anchor Toggle */}
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 pb-2">
            <div>
              <h1 className="text-xl font-semibold tracking-tight text-slate-100 text-balance">
                Evidence Ingestion & Verification Ledger
              </h1>
              <p className="text-[13px] text-slate-400 mt-1">
                Verify AIP EvidencePackets and audit bundles locally. All 14 rules run in the WebAssembly verifier.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowAnchorModal(!showAnchorModal)}
                aria-expanded={showAnchorModal}
                className={`${btn.secondary} ${showAnchorModal ? "border-corporate-steel bg-obsidian-800" : ""}`}
              >
                <Key className="w-3.5 h-3.5" aria-hidden />
                {showAnchorModal ? "Hide trust anchors" : "Configure trust anchors"}
              </button>
            </div>
          </div>

          {/* Collapsible Verifier Trust Anchors Panel */}
          {showAnchorModal && (
            <TrustAnchorConfig onContextChange={handleContextChange} />
          )}

          {/* Drag & Drop Ingestion Zone & 10-Fixture Gallery */}
          <Dropzone />

          {/* Trust Floor Progression Ladder Badge */}
          {report && (
            <TrustFloorBadge
              derivedFloor={report.derived_trust_floor || report.trust_floor}
              claimedFloor={report.claimed_trust_floor}
              tamperEvidence={report.tamper_evidence || report.tampered}
              variant="ladder"
            />
          )}

          {/* 14-Rule Verification Ledger */}
          <VerificationLedger report={report} />
        </div>

        {/* Tab 2 (R2): Accountability Graph DAG View */}
        <div className={activeTab === "graph" ? "block space-y-4" : "hidden"}>
          <div className="pb-2">
            <div>
              <h1 className="text-xl font-semibold tracking-tight text-slate-100">
                Accountability Graph
              </h1>
              <p className="text-[13px] text-slate-400 mt-1">
                Chain of custody: Principal → Authority Grant → Delegation → Agent → Decision → Action → Countersigned Receipt.
              </p>
            </div>
          </div>

          <AccountabilityGraph />
        </div>

        {/* Tab 3 (R3): Adversarial Tamper Simulator */}
        <div className={activeTab === "tamper" ? "block space-y-4" : "hidden"}>
          <TamperSimulator />
        </div>

        {/* Tab 4 (R4): Authority Management & Visual Lattice Builder */}
        <div className={activeTab === "authority" ? "block space-y-4" : "hidden"}>
          <AuthorityManagement />
        </div>

        {/* Tab 5 (R5): Evidence Vault (not yet implemented) */}
        <div className={activeTab === "vault" ? "block" : "hidden"}>
          <div className={`${panel} px-6 py-16 text-center flex flex-col items-center`}>
            <Database className="w-6 h-6 text-slate-500 mb-3" aria-hidden />
            <h1 className="text-base font-semibold text-slate-100 mb-1">
              Evidence Vault
            </h1>
            <p className="text-[13px] text-slate-400 max-w-md mb-5">
              Not yet available. Planned: packet repository with search, filtering and signed audit-bundle export.
            </p>
            <button
              type="button"
              onClick={() => setActiveTab("ingestion")}
              className={btn.secondary}
            >
              Go to evidence ingestion <ArrowRight className="w-3.5 h-3.5" aria-hidden />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
