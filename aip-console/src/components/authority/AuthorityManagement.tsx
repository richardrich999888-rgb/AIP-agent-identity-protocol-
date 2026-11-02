"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import { useConsole } from "@/lib/context/ConsoleContext";
import { useEvidence } from "@/lib/wasm/EvidenceContext";
import {
  DelegationTreeNode,
  RevocationEntry,
  RevocationImpact,
  CapabilityScope,
} from "./types";
import {
  computeCascadeRevocations,
  extractDelegationTree,
  calculateRevocationImpact,
  SAMPLE_DELEGATION_TREES,
} from "./revocationCascade";
import { PRESET_SCOPES } from "./presetScopes";

import { ScopeMatrixEditor } from "./ScopeMatrixEditor";
import { LatticeAttenuationPreview } from "./LatticeAttenuationPreview";
import { CascadeRevocationTree } from "./CascadeRevocationTree";
import { RevocationImpactSummary } from "./RevocationImpactSummary";

import {
  Layers,
  GitBranch,
  ShieldAlert,
  Sliders,
  CheckCircle2,
  RefreshCw,
} from "lucide-react";

export interface AuthorityManagementProps {
  className?: string;
}

type AuthoritySubTab = "revocation" | "matrix" | "lattice" | "unified";

export const AuthorityManagement: React.FC<AuthorityManagementProps> = ({
  className = "",
}) => {
  const { loadedPacket } = useConsole();
  const { evidence, contextJson, updateContext, reverify } = useEvidence();

  const [activeSubTab, setActiveSubTab] = useState<AuthoritySubTab>("revocation");
  const [currentTopology, setCurrentTopology] = useState<string>("multi_branch");

  // Flat delegation nodes
  const [nodes, setNodes] = useState<DelegationTreeNode[]>(
    SAMPLE_DELEGATION_TREES.multi_branch.nodes
  );

  // Active revocations list
  const [revocations, setRevocations] = useState<RevocationEntry[]>([]);
  const [isAppliedToVerifier, setIsAppliedToVerifier] = useState<boolean>(false);

  // Matrix scope state (F14)
  const [matrixScope, setMatrixScope] = useState<CapabilityScope>(
    PRESET_SCOPES.ADMIN.scope
  );

  // Load tree when topology changes or packet changes
  useEffect(() => {
    if (currentTopology === "active_packet" && loadedPacket) {
      const extracted = extractDelegationTree(loadedPacket);
      if (extracted.length > 0) {
        setNodes(extracted);
        return;
      }
    }

    const sample = SAMPLE_DELEGATION_TREES[currentTopology];
    if (sample) {
      setNodes(sample.nodes);
    }
  }, [currentTopology, loadedPacket]);

  // Handle Revoking a token JTI
  const handleRevoke = useCallback(
    (targetJti: string) => {
      setIsAppliedToVerifier(false);
      // Run pure BFS cascade revocation
      const newRevocations = computeCascadeRevocations(
        targetJti,
        nodes,
        "security-admin",
        "Compromise"
      );

      // Merge avoiding duplicate entries
      setRevocations((prev) => {
        const existingJtiMap = new Map<string, RevocationEntry>();
        prev.forEach((r) => existingJtiMap.set(r.jti, r));
        newRevocations.forEach((r) => existingJtiMap.set(r.jti, r));
        return Array.from(existingJtiMap.values());
      });
    },
    [nodes]
  );

  // Handle Restoring a token JTI
  const handleRestore = useCallback(
    (targetJti: string) => {
      setIsAppliedToVerifier(false);
      // Find all descendant children that were cascaded from targetJti
      const cascadedFromTarget = computeCascadeRevocations(targetJti, nodes).map(
        (r) => r.jti
      );
      const toRemove = new Set(cascadedFromTarget);

      setRevocations((prev) => prev.filter((r) => !toRemove.has(r.jti)));
    },
    [nodes]
  );

  // Reset all revocations
  const handleResetRevocations = useCallback(() => {
    setRevocations([]);
    setIsAppliedToVerifier(false);
  }, []);

  // Calculate live impact
  const impact: RevocationImpact = useMemo(() => {
    return calculateRevocationImpact(revocations, nodes);
  }, [revocations, nodes]);

  // Synchronize revocations into EvidenceContext
  const handleApplyToVerifier = useCallback(() => {
    try {
      const revokedJtis = revocations.map((r) => r.jti);
      let parsedContext: any = {};
      try {
        parsedContext = JSON.parse(contextJson || "{}");
      } catch {
        parsedContext = {};
      }

      // Serialize both keys for complete compatibility
      const updatedContext = {
        ...parsedContext,
        revoked_jtis: revokedJtis,
        revoked_token_ids: revokedJtis,
      };

      const ctxString = JSON.stringify(updatedContext, null, 2);
      updateContext(ctxString);
      reverify();
      setIsAppliedToVerifier(true);
    } catch (err) {
      console.error("Failed to apply revocations to verifier:", err);
    }
  }, [revocations, contextJson, updateContext, reverify]);

  return (
    <div className={`space-y-6 font-mono ${className}`}>
      {/* ── Sub-Navigation Bar ────────────────────────────────────────────── */}
      <div className="flex border-b border-slate-800 bg-[#080B11] p-1 rounded-md overflow-x-auto text-xs">
        <button
          type="button"
          onClick={() => setActiveSubTab("revocation")}
          className={`px-4 py-2.5 rounded-md flex items-center gap-2 font-bold whitespace-nowrap transition-colors ${
            activeSubTab === "revocation"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <GitBranch className="w-3.5 h-3.5" />
          <span>Cascade Revocation Tree (F16)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab("matrix")}
          className={`px-4 py-2.5 rounded-md flex items-center gap-2 font-bold whitespace-nowrap transition-colors ${
            activeSubTab === "matrix"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Visual Scope Matrix (F14)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab("lattice")}
          className={`px-4 py-2.5 rounded-md flex items-center gap-2 font-bold whitespace-nowrap transition-colors ${
            activeSubTab === "lattice"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Lattice Attenuation Preview (F15)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab("unified")}
          className={`px-4 py-2.5 rounded-md flex items-center gap-2 font-bold whitespace-nowrap transition-colors ${
            activeSubTab === "unified"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Unified Authority Dashboard</span>
        </button>
      </div>

      {/* ── Sub-Tab Views ─────────────────────────────────────────────────── */}
      {activeSubTab === "revocation" && (
        <div className="space-y-6">
          <CascadeRevocationTree
            nodes={nodes}
            revocations={revocations}
            onRevoke={handleRevoke}
            onRestore={handleRestore}
            onReset={handleResetRevocations}
            onTopologyChange={setCurrentTopology}
            currentTopology={currentTopology}
          />

          <RevocationImpactSummary
            impact={impact}
            revocations={revocations}
            onApplyToVerifier={handleApplyToVerifier}
            isApplied={isAppliedToVerifier}
          />
        </div>
      )}

      {activeSubTab === "matrix" && (
        <ScopeMatrixEditor value={matrixScope} onChange={setMatrixScope} />
      )}

      {activeSubTab === "lattice" && (
        <LatticeAttenuationPreview initialParent={matrixScope} />
      )}

      {activeSubTab === "unified" && (
        <div className="space-y-6">
          <CascadeRevocationTree
            nodes={nodes}
            revocations={revocations}
            onRevoke={handleRevoke}
            onRestore={handleRestore}
            onReset={handleResetRevocations}
            onTopologyChange={setCurrentTopology}
            currentTopology={currentTopology}
          />

          <RevocationImpactSummary
            impact={impact}
            revocations={revocations}
            onApplyToVerifier={handleApplyToVerifier}
            isApplied={isAppliedToVerifier}
          />

          <LatticeAttenuationPreview initialParent={matrixScope} />

          <ScopeMatrixEditor value={matrixScope} onChange={setMatrixScope} />
        </div>
      )}
    </div>
  );
};
