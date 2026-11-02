"use client";

import React, { useState, useMemo } from "react";
import {
  X,
  Copy,
  Check,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Key,
  ChevronRight,
  Clock,
  Layers,
  Cpu,
  Fingerprint,
  Zap,
  Receipt,
  FileCode,
} from "lucide-react";
import type { AccountabilityFlowNode, AccountabilityFlowEdge } from "./types";
import type { VerificationReport, RuleResult } from "@/types/verification";
import { BreadcrumbTrail } from "./BreadcrumbTrail";

export interface InspectionSheetProps {
  isOpen: boolean;
  onClose: () => void;
  selectedNode: AccountabilityFlowNode | null;
  nodes: AccountabilityFlowNode[];
  edges: AccountabilityFlowEdge[];
  report: VerificationReport | null;
  onSelectNode: (nodeId: string) => void;
}

const NODE_RULE_MAPPINGS: Record<string, string[]> = {
  principal: ["ROOT_TOKEN_SIGNATURE", "AUTHORITY_CHAIN"],
  authority_grant: ["ROOT_TOKEN_SIGNATURE", "TEMPORAL_VALIDITY", "REVOCATION"],
  delegation: ["DELEGATION_CHAIN", "AUTHORITY_CHAIN", "REVOCATION", "TEMPORAL_VALIDITY"],
  agent: ["AGENT_ID_BINDING", "AGENT_SIGNATURE", "CANONICAL_HASH"],
  decision: ["SCOPE_AUTHORITY", "TEMPORAL_VALIDITY"],
  action: ["ACTION_ATTESTATIONS", "SCOPE_AUTHORITY"],
  receipt: ["RECEIPT_BINDING", "TRUST_FLOOR"],
};

export const InspectionSheet: React.FC<InspectionSheetProps> = ({
  isOpen,
  onClose,
  selectedNode,
  nodes,
  edges,
  report,
  onSelectNode,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"details" | "rules" | "json">("details");

  const nodeData = (selectedNode?.data || {}) as Record<string, any>;
  const kind = (selectedNode?.data?.kind || selectedNode?.type || "unknown").toLowerCase();

  const handleCopy = (text: string, keyId: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedKey(keyId);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getDisplayField = (val: any, fallback = "N/A (Not Provided)"): string => {
    if (val === undefined || val === null || val === "") return fallback;
    return String(val);
  };

  const formatFingerprint = (hex?: string) => {
    if (!hex || hex.length < 16) return hex || "N/A (Not Provided)";
    return `${hex.slice(0, 8)}...${hex.slice(-8)}`;
  };

  const formatTimestamp = (epochMs?: number | null) => {
    if (!epochMs || isNaN(epochMs) || epochMs <= 0) return "N/A (Not Provided)";
    try {
      return new Date(epochMs).toISOString();
    } catch {
      return "N/A (Not Provided)";
    }
  };

  const associatedRules = useMemo(() => {
    if (!report || !report.checks) return [];
    const expected = NODE_RULE_MAPPINGS[kind] || [];
    return report.checks.filter((c) => expected.includes(c.rule));
  }, [report, kind]);

  if (!isOpen || !selectedNode) return null;

  const isVerified = selectedNode.data?.verified ?? true;

  return (
    <aside
      className="absolute top-0 right-0 bottom-0 w-full sm:w-[480px] bg-obsidian-900 border-l border-obsidian-700 shadow-2xl z-40 flex flex-col font-mono overflow-hidden transition-all duration-200"
      aria-label="DAG Node Inspection Sheet"
    >
      {/* ── Header ── */}
      <div className="p-4 border-b border-obsidian-700 bg-obsidian-950 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className={`p-2 rounded-md border ${
              isVerified
                ? "bg-corporate-steel/10 border-corporate-steel/30 text-corporate-steel-light"
                : "bg-corporate-danger/10 border-corporate-danger/30 text-corporate-danger-light"
            }`}
          >
            {kind === "principal" && <ShieldCheck className="w-5 h-5" />}
            {kind === "authority_grant" && <Key className="w-5 h-5" />}
            {kind === "delegation" && <Layers className="w-5 h-5" />}
            {kind === "agent" && <Cpu className="w-5 h-5" />}
            {kind === "decision" && <Fingerprint className="w-5 h-5" />}
            {kind === "action" && <Zap className="w-5 h-5" />}
            {kind === "receipt" && <Receipt className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                {kind.replace("_", " ")}
              </span>
              <span
                className={`px-2 py-0.5 text-[10px] rounded font-bold border ${
                  isVerified
                    ? "bg-corporate-accent/10 text-corporate-accent-light border-corporate-accent/40"
                    : "bg-corporate-danger/10 text-corporate-danger-light border-corporate-danger/40"
                }`}
              >
                {isVerified ? "VERIFIED" : "UNVERIFIED"}
              </span>
            </div>
            <h2 className="text-xs font-bold text-slate-100 truncate max-w-[260px] mt-0.5" title={selectedNode.data?.label || selectedNode.id}>
              {selectedNode.data?.label || selectedNode.id}
            </h2>
          </div>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-obsidian-800 rounded-md transition-colors cursor-pointer"
          title="Close Inspection Sheet"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* ── Breadcrumb Custody Trail ── */}
      <div className="px-4 py-2.5 bg-obsidian-850 border-b border-obsidian-700">
        <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1.5 font-bold">
          Chain of Custody
        </div>
        <BreadcrumbTrail
          selectedNodeId={selectedNode.id}
          nodes={nodes}
          edges={edges}
          onSelectNode={onSelectNode}
        />
      </div>

      {/* ── Tab Switcher ── */}
      <div className="flex border-b border-obsidian-700 bg-obsidian-950 px-4 text-xs font-medium">
        <button
          type="button"
          onClick={() => setActiveTab("details")}
          className={`px-4 py-2.5 border-b-2 transition-colors cursor-pointer ${
            activeTab === "details"
              ? "border-corporate-steel text-corporate-steel-light font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Node Details
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("rules")}
          className={`px-4 py-2.5 border-b-2 transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeTab === "rules"
              ? "border-corporate-steel text-corporate-steel-light font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>Rule Checks</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] bg-obsidian-800 text-slate-300">
            {associatedRules.length}
          </span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("json")}
          className={`px-4 py-2.5 border-b-2 transition-colors cursor-pointer ${
            activeTab === "json"
              ? "border-corporate-steel text-corporate-steel-light font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Raw JSON
        </button>
      </div>

      {/* ── Tab Body Content ── */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {activeTab === "details" && (
          <div className="space-y-3">
            {/* Unverified Warning Banner */}
            {!isVerified && (
              <div className="p-3 rounded-md bg-corporate-danger/10 border border-corporate-danger/40 flex items-start gap-2.5">
                <ShieldAlert className="w-5 h-5 text-corporate-danger-light shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-corporate-danger-light">Verification Violation Detected</div>
                  <div className="text-slate-300 mt-0.5 leading-relaxed">
                    {getDisplayField(nodeData.error || nodeData.ruleDetail, "Cryptographic binding or signature check failed engine validation.")}
                  </div>
                </div>
              </div>
            )}

            {/* Kind-Specific Details */}
            {kind === "principal" && (
              <div className="space-y-2.5">
                <DetailRow
                  label="Principal ID"
                  value={getDisplayField(nodeData.principal_id)}
                  onCopy={() => handleCopy(nodeData.principal_id, "principal_id")}
                  isCopied={copiedKey === "principal_id"}
                />
                <DetailRow
                  label="Display Role"
                  value={getDisplayField(nodeData.display_role)}
                />
                <DetailRow
                  label="Algorithm"
                  value={getDisplayField(nodeData.algorithm, "Ed25519")}
                />
                <DetailRow
                  label="Trust Anchor Status"
                  value={nodeData.isTrustedAnchor ? "VERIFIED TRUST ANCHOR" : "UNTRUSTED ANCHOR"}
                />
              </div>
            )}

            {kind === "authority_grant" && (
              <div className="space-y-2.5">
                <DetailRow
                  label="Root Token JTI"
                  value={getDisplayField(nodeData.jti)}
                  onCopy={() => handleCopy(nodeData.jti, "jti")}
                  isCopied={copiedKey === "jti"}
                />
                <DetailRow
                  label="Issuer Principal ID"
                  value={getDisplayField(nodeData.issuer_id)}
                  onCopy={() => handleCopy(nodeData.issuer_id, "issuer_id")}
                  isCopied={copiedKey === "issuer_id"}
                />
                <DetailRow
                  label="Grantee Agent ID"
                  value={getDisplayField(nodeData.agent_id)}
                  onCopy={() => handleCopy(nodeData.agent_id, "agent_id")}
                  isCopied={copiedKey === "agent_id"}
                />
                <DetailRow
                  label="Issued At"
                  value={formatTimestamp(nodeData.issued_at)}
                />
                <DetailRow
                  label="Expires At"
                  value={nodeData.expires_at ? formatTimestamp(nodeData.expires_at) : "Perpetual (No Expiry)"}
                />
                {/* Scope Matrix */}
                <div className="p-2.5 rounded-md bg-obsidian-850 border border-obsidian-700 space-y-1.5">
                  <div className="text-[11px] text-slate-400 font-bold">Allowed Capability Scope:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {nodeData.scope?.allowed && nodeData.scope.allowed.length > 0 ? (
                      nodeData.scope.allowed.map((s: string) => (
                        <span
                          key={s}
                          className="px-2 py-0.5 rounded text-[10px] bg-corporate-steel/10 text-corporate-steel-light border border-corporate-steel/30"
                        >
                          {s}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500 text-[11px]">N/A (Not Provided)</span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {kind === "delegation" && (
              <div className="space-y-2.5">
                <DetailRow
                  label="Delegation JTI"
                  value={getDisplayField(nodeData.jti)}
                  onCopy={() => handleCopy(nodeData.jti, "jti")}
                  isCopied={copiedKey === "jti"}
                />
                <DetailRow
                  label="Parent Token JTI"
                  value={getDisplayField(nodeData.parent_jti)}
                  onCopy={() => handleCopy(nodeData.parent_jti, "parent_jti")}
                  isCopied={copiedKey === "parent_jti"}
                />
                <DetailRow
                  label="Delegation Depth"
                  value={`Depth ${nodeData.depth ?? 0} (Max 8)`}
                />
                <DetailRow
                  label="Issuer ID"
                  value={getDisplayField(nodeData.issuer_id)}
                  onCopy={() => handleCopy(nodeData.issuer_id, "issuer_id")}
                  isCopied={copiedKey === "issuer_id"}
                />
                <DetailRow
                  label="Grantee ID"
                  value={getDisplayField(nodeData.grantee_id)}
                  onCopy={() => handleCopy(nodeData.grantee_id, "grantee_id")}
                  isCopied={copiedKey === "grantee_id"}
                />
                {/* Scope Details */}
                <div className="p-2.5 rounded-md bg-obsidian-850 border border-obsidian-700 space-y-1.5">
                  <div className="text-[11px] text-slate-400 font-bold">Attenuated Scope:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {nodeData.scope?.allowed && nodeData.scope.allowed.length > 0 ? (
                      nodeData.scope.allowed.map((s: string) => (
                        <span
                          key={s}
                          className="px-2 py-0.5 rounded text-[10px] bg-corporate-steel/10 text-corporate-steel-light border border-corporate-steel/30"
                        >
                          {s}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500 text-[11px]">N/A (Not Provided)</span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {kind === "agent" && (
              <div className="space-y-2.5">
                <DetailRow
                  label="AIP-ID (Decentralized Identity)"
                  value={getDisplayField(nodeData.aip_id)}
                  onCopy={() => handleCopy(nodeData.aip_id, "aip_id")}
                  isCopied={copiedKey === "aip_id"}
                />
                <DetailRow
                  label="Algorithm"
                  value={getDisplayField(nodeData.algorithm, "Ed25519")}
                />
                <DetailRow
                  label="Public Key Fingerprint (19-char)"
                  value={formatFingerprint(nodeData.public_key_hex || nodeData.public_key)}
                  subtext={nodeData.public_key_hex || nodeData.public_key}
                  onCopy={() => handleCopy(nodeData.public_key_hex || nodeData.public_key, "pubkey")}
                  isCopied={copiedKey === "pubkey"}
                />
                {/* Provenance Triple */}
                <div className="p-3 rounded-md bg-obsidian-850 border border-obsidian-700 space-y-1.5">
                  <div className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">
                    Provenance Commitment:
                  </div>
                  <div className="space-y-1 text-slate-300">
                    <div>
                      <span className="text-slate-500">Model:</span>{" "}
                      <span className="text-slate-200">
                        {getDisplayField(nodeData.provenance?.model || nodeData.provenance?.model_hash)}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Environment:</span>{" "}
                      <span className="text-slate-200">
                        {getDisplayField(nodeData.provenance?.environment)}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Toolchain:</span>{" "}
                      <span className="text-slate-200">
                        {getDisplayField(nodeData.provenance?.toolchain)}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {kind === "decision" && (
              <div className="space-y-2.5">
                <DetailRow
                  label="Decision ID"
                  value={getDisplayField(nodeData.decision_id)}
                  onCopy={() => handleCopy(nodeData.decision_id, "decision_id")}
                  isCopied={copiedKey === "decision_id"}
                />
                <DetailRow
                  label="Action Kind"
                  value={
                    typeof nodeData.action_kind === "object" && nodeData.action_kind !== null
                      ? `${nodeData.action_kind.kind || "Standard"}: ${nodeData.action_kind.action || "Write"}`
                      : getDisplayField(nodeData.action_kind)
                  }
                />
                <DetailRow
                  label="Decided At"
                  value={formatTimestamp(nodeData.decided_at)}
                />
                <DetailRow
                  label="Reasoning Summary"
                  value={getDisplayField(nodeData.summary)}
                />
                <DetailRow
                  label="Input Hash"
                  value={formatFingerprint(nodeData.input_hash)}
                  subtext={nodeData.input_hash}
                  onCopy={() => handleCopy(nodeData.input_hash, "input_hash")}
                  isCopied={copiedKey === "input_hash"}
                />
                <DetailRow
                  label="Rationale Hash"
                  value={formatFingerprint(nodeData.rationale_hash)}
                  subtext={nodeData.rationale_hash}
                  onCopy={() => handleCopy(nodeData.rationale_hash, "rationale_hash")}
                  isCopied={copiedKey === "rationale_hash"}
                />
              </div>
            )}

            {kind === "action" && (
              <div className="space-y-2.5">
                <DetailRow
                  label="Action ID"
                  value={getDisplayField(nodeData.action_id)}
                  onCopy={() => handleCopy(nodeData.action_id, "action_id")}
                  isCopied={copiedKey === "action_id"}
                />
                <DetailRow
                  label="Description"
                  value={getDisplayField(nodeData.description)}
                />
                <DetailRow
                  label="Performed At"
                  value={formatTimestamp(nodeData.performed_at)}
                />
                <DetailRow
                  label="Payload Hash"
                  value={formatFingerprint(nodeData.payload_hash)}
                  subtext={nodeData.payload_hash}
                  onCopy={() => handleCopy(nodeData.payload_hash, "payload_hash")}
                  isCopied={copiedKey === "payload_hash"}
                />
              </div>
            )}

            {kind === "receipt" && (
              <div className="space-y-2.5">
                <DetailRow
                  label="Receipt System"
                  value={getDisplayField(nodeData.receipt_system)}
                />
                <DetailRow
                  label="Receipt ID"
                  value={getDisplayField(nodeData.receipt_id)}
                  onCopy={() => handleCopy(nodeData.receipt_id, "receipt_id")}
                  isCopied={copiedKey === "receipt_id"}
                />
                <DetailRow
                  label="Receipt Hash"
                  value={formatFingerprint(nodeData.receipt_hash)}
                  subtext={nodeData.receipt_hash}
                  onCopy={() => handleCopy(nodeData.receipt_hash, "receipt_hash")}
                  isCopied={copiedKey === "receipt_hash"}
                />
                <DetailRow
                  label="Counterparty Status"
                  value={
                    nodeData.countersigned
                      ? "Countersigned (Level 3 Bilateral Verification)"
                      : "Hash Only (Unilateral Receipt)"
                  }
                />
                {nodeData.counterparty_id && (
                  <DetailRow
                    label="Counterparty ID"
                    value={getDisplayField(nodeData.counterparty_id)}
                    onCopy={() => handleCopy(nodeData.counterparty_id, "counterparty_id")}
                    isCopied={copiedKey === "counterparty_id"}
                  />
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Rule Checks Tab ── */}
        {activeTab === "rules" && (
          <div className="space-y-3">
            <div className="text-[11px] text-slate-400">
              Direct 1:1 evaluation results from Rust verification engine:
            </div>
            {associatedRules.length === 0 ? (
              <div className="text-xs text-slate-500 italic p-4 text-center bg-obsidian-850 rounded border border-obsidian-700">
                No direct rule checks mapped for this node kind.
              </div>
            ) : (
              associatedRules.map((ruleResult) => (
                <div
                  key={ruleResult.rule}
                  className={`p-3 rounded-md border text-xs space-y-1.5 ${
                    ruleResult.pass
                      ? "bg-corporate-accent/5 border-corporate-accent/30"
                      : "bg-corporate-danger/5 border-corporate-danger/30"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">
                      {ruleResult.rule}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        ruleResult.pass
                          ? "bg-corporate-accent/20 text-corporate-accent-light"
                          : "bg-corporate-danger/20 text-corporate-danger-light"
                      }`}
                    >
                      {ruleResult.pass ? "PASS" : "FAIL"}
                    </span>
                  </div>
                  <p className="text-slate-300 text-[11px] leading-relaxed">
                    {ruleResult.detail}
                  </p>
                </div>
              ))
            )}
          </div>
        )}

        {/* ── Raw JSON Tab ── */}
        {activeTab === "json" && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-slate-400">JSON Payload</span>
              <button
                type="button"
                onClick={() => handleCopy(JSON.stringify(nodeData, null, 2), "raw_json")}
                className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-obsidian-800 hover:bg-obsidian-700 border border-obsidian-700 text-xs text-corporate-steel-light transition-colors cursor-pointer"
              >
                {copiedKey === "raw_json" ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-corporate-accent-light" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" /> Copy JSON
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 rounded-md bg-obsidian-950 border border-obsidian-800 text-[11px] text-slate-200 overflow-x-auto leading-relaxed max-h-[500px]">
              <code>{JSON.stringify(nodeData, null, 2)}</code>
            </pre>
          </div>
        )}
      </div>
    </aside>
  );
};

// Reusable Detail Row
const DetailRow: React.FC<{
  label: string;
  value: string;
  subtext?: string;
  onCopy?: () => void;
  isCopied?: boolean;
}> = ({ label, value, subtext, onCopy, isCopied }) => {
  return (
    <div className="p-2.5 rounded-md bg-obsidian-850 border border-obsidian-700 flex flex-col gap-1">
      <div className="flex items-center justify-between text-[11px] text-slate-400">
        <span>{label}</span>
        {onCopy && (
          <button
            type="button"
            onClick={onCopy}
            className="text-slate-500 hover:text-corporate-steel-light transition-colors cursor-pointer"
            title="Copy value"
          >
            {isCopied ? (
              <Check className="w-3.5 h-3.5 text-corporate-accent-light" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>
        )}
      </div>
      <div className="text-xs text-slate-100 break-all select-all font-semibold">
        {value}
      </div>
      {subtext && (
        <div className="text-[10px] text-slate-500 break-all">
          {subtext}
        </div>
      )}
    </div>
  );
};
