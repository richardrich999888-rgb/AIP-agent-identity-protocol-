# Milestone 2 Integration Blueprint: Ingestion & Verification Ledger

This document details how the four core components of Milestone 2 connect together:
1. `useAipVerifier` (WASM Bridge Provider - Explorer 2)
2. `Dropzone` (Drag-and-Drop Ingestion - Explorer 2)
3. `TrustAnchorConfig` (Verifier Trust Anchors - Explorer 3)
4. `TrustFloorBadge` (Trust Floor Progression Ladder - Explorer 3)
5. `VerificationLedger` (14-Rule Verification Ledger - Explorer 3)

---

## 1. Complete Architecture Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                    Syntriass Console UI (M2)                                       |
|                                                                                                    |
|  +-------------------------------------+  +-----------------------------------------------------+  |
|  |           Dropzone.tsx              |  |                TrustAnchorConfig.tsx                |  |
|  | - Drag & drop JSON / ZIP            |  | - Trusted Principal Issuer Keys                     |  |
|  | - Preset Sample Fixtures Quick-Load |  | - Trusted Counterparty Keys                         |  |
|  | - Emits: (packetJson, fileType)     |  | - Revoked Token JTIs Registry                       |  |
|  |                                     |  | - Emits: (contextJson)                              |  |
|  +-------------------------------------+  +-----------------------------------------------------+  |
|                     \                                           /                                  |
|                      v                                         v                                   |
|  +----------------------------------------------------------------------------------------------+  |
|  |                           IngestionView / page.tsx Container                                 |  |
|  |   const { verifyPacket, verifyBundleZip } = useAipVerifier();                                |  |
|  |   const report = verifyPacket(packetJson, contextJson);                                      |  |
|  +----------------------------------------------------------------------------------------------+  |
|                     /                                           \                                  |
|                    v                                             v                                 |
|  +-------------------------------------+  +-----------------------------------------------------+  |
|  |         TrustFloorBadge.tsx         |  |               VerificationLedger.tsx                |  |
|  | - Stepped Progression Ladder (0..3) |  | - 14-Rule Non-short-circuiting Ledger               |  |
|  | - Derived vs Claimed Floor Marker   |  | - Pure WASM Report Projection (ZERO JS Logic)       |  |
|  | - Visual Downgrade & Tamper Alert   |  | - Interactive Accordion Expansion & Hashes          |  |
|  +-------------------------------------+  +-----------------------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
                                               |
                                     (calls in-memory)
                                               v
+----------------------------------------------------------------------------------------------------+
|                          aip-wasm (Browser WebAssembly Runtime)                                    |
|   verify_evidence_packet(packetJson, contextJson) -> VerificationReport                            |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. IngestionView Container Component Implementation Blueprint

Below is the complete reference implementation for `src/components/ingestion/IngestionView.tsx` (or integrated into `src/app/page.tsx`):

```tsx
"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useAipVerifier } from "@/lib/wasm/useAipVerifier";
import { VerificationReport, VerificationContext } from "@/types/verification";
import { Dropzone } from "@/components/ingestion/Dropzone";
import { TrustAnchorConfig } from "@/components/ingestion/TrustAnchorConfig";
import { TrustFloorBadge } from "@/components/ingestion/TrustFloorBadge";
import { VerificationLedger } from "@/components/ingestion/VerificationLedger";
import { ShieldCheck, Flame, RefreshCw, Key, FileText } from "lucide-react";

export const IngestionView: React.FC = () => {
  const { isReady, verifyPacket, verifyBundleZip, getSample } = useAipVerifier();

  const [currentPacketJson, setCurrentPacketJson] = useState<string>("");
  const [currentContextJson, setCurrentContextJson] = useState<string>("");
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [showAnchorModal, setShowAnchorModal] = useState<boolean>(false);

  // Run verification immediately when packet or context changes
  const runVerification = useCallback(
    (packetJson: string, contextJson: string) => {
      if (!isReady || !packetJson.trim()) return;

      setIsVerifying(true);
      try {
        const result = verifyPacket(packetJson, contextJson);
        setReport(result);
      } catch (err) {
        console.error("WASM verification error:", err);
      } finally {
        setIsVerifying(false);
      }
    },
    [isReady, verifyPacket]
  );

  // Initialize with honest counterparty sample fixture when WASM loads
  useEffect(() => {
    if (isReady && !currentPacketJson) {
      try {
        const samplePacket = getSample("honest_counterparty");
        const sampleContext = getSample("sample_context");
        setCurrentPacketJson(samplePacket);
        setCurrentContextJson(sampleContext);
        runVerification(samplePacket, sampleContext);
      } catch (e) {
        console.warn("Could not pre-load sample packet:", e);
      }
    }
  }, [isReady, currentPacketJson, getSample, runVerification]);

  // Handler: When user drops or selects a packet JSON
  const handlePacketLoaded = (packetJson: string) => {
    setCurrentPacketJson(packetJson);
    runVerification(packetJson, currentContextJson);
  };

  // Handler: When user modifies trust anchors in TrustAnchorConfig
  const handleContextChange = (contextJson: string) => {
    setCurrentContextJson(contextJson);
    if (currentPacketJson) {
      runVerification(currentPacketJson, contextJson);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6">
      {/* ── Top Header & Actions ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            Evidence Ingestion & Verification
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Offline high-assurance inspection of autonomous AI agent EvidencePackets backed by WebAssembly.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAnchorModal(!showAnchorModal)}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <Key className="w-3.5 h-3.5 text-cyan-400" />
            <span>Configure Trust Anchors</span>
          </button>
        </div>
      </div>

      {/* ── Optional Collapsible / Modal Trust Anchor Configuration ── */}
      {showAnchorModal && (
        <div className="mb-4">
          <TrustAnchorConfig
            onContextChange={handleContextChange}
            className="border-cyan-500/40 shadow-[0_0_20px_rgba(0,229,255,0.08)]"
          />
        </div>
      )}

      {/* ── Drag & Drop Zone + Fixture Quick-Select ── */}
      <Dropzone onPacketLoaded={handlePacketLoaded} />

      {/* ── Trust Floor Progression Badge ── */}
      {report && (
        <TrustFloorBadge
          derivedFloor={report.derived_trust_floor || report.trust_floor}
          claimedFloor={report.claimed_trust_floor}
          tamperEvidence={report.tamper_evidence || report.tampered}
          variant="ladder"
        />
      )}

      {/* ── 14-Rule Verification Ledger ── */}
      <VerificationLedger report={report} />
    </div>
  );
};
```

---

## 3. Strict Compliance Checks

1. **Zero-JS Invariant**:
   - Neither `VerificationLedger.tsx` nor `TrustFloorBadge.tsx` calculates any cryptographic check.
   - All 14 rules, their `pass` status, and their `detail` messages are rendered directly from `report.checks`.
2. **14 Rules 1:1 Mapping**:
   - Registry in `src/types/verification.ts` mirrors `aip-protocol::verification_report::rules`.
   - Checks are evaluated non-short-circuiting in Rust and displayed verbatim.
3. **Instant Re-Verification**:
   - `TrustAnchorConfig.onContextChange` passes updated JSON immediately to `verifyPacket(packetJson, contextJson)`.
   - Takes less than 1 millisecond inside client WebAssembly with zero network latency.
