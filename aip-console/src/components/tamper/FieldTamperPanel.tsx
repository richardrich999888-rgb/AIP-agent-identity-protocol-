"use client";

import React, { useState } from "react";
import {
  FileText,
  UserCheck,
  ShieldAlert,
  Zap,
  Clock,
  Receipt,
  AlertTriangle,
  RotateCcw,
} from "lucide-react";

export interface FieldTamperPanelProps {
  packet: any;
  onChange: (mutatedPacket: any) => void;
  className?: string;
}

type SubTab = "decision" | "agent" | "authority" | "actions" | "receipt";

export const FieldTamperPanel: React.FC<FieldTamperPanelProps> = ({
  packet,
  onChange,
  className = "",
}) => {
  const [activeTab, setActiveTab] = useState<SubTab>("decision");

  if (!packet) {
    return (
      <div className="p-6 text-center text-slate-500 font-mono text-xs">
        No active evidence packet loaded to tamper.
      </div>
    );
  }

  const mutate = (updater: (draft: any) => void) => {
    try {
      const draft = JSON.parse(JSON.stringify(packet));
      updater(draft);
      onChange(draft);
    } catch (err) {
      console.error("Mutation error:", err);
    }
  };

  return (
    <div
      className={`rounded-md border border-slate-800 bg-[#0E131F] font-mono text-xs shadow-xl overflow-hidden ${className}`}
    >
      {/* Sub-Tabs Navigation */}
      <div className="flex border-b border-slate-800 bg-[#080B11] overflow-x-auto">
        <button
          type="button"
          onClick={() => setActiveTab("decision")}
          className={`px-4 py-3 flex items-center gap-2 border-b-2 font-bold whitespace-nowrap transition-colors ${
            activeTab === "decision"
              ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Decision Record</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("agent")}
          className={`px-4 py-3 flex items-center gap-2 border-b-2 font-bold whitespace-nowrap transition-colors ${
            activeTab === "agent"
              ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <UserCheck className="w-3.5 h-3.5" />
          <span>Agent Identity</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("authority")}
          className={`px-4 py-3 flex items-center gap-2 border-b-2 font-bold whitespace-nowrap transition-colors ${
            activeTab === "authority"
              ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Authority & Delegations</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("actions")}
          className={`px-4 py-3 flex items-center gap-2 border-b-2 font-bold whitespace-nowrap transition-colors ${
            activeTab === "actions"
              ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <Zap className="w-3.5 h-3.5" />
          <span>Actions & Timestamps</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("receipt")}
          className={`px-4 py-3 flex items-center gap-2 border-b-2 font-bold whitespace-nowrap transition-colors ${
            activeTab === "receipt"
              ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
          }`}
        >
          <Receipt className="w-3.5 h-3.5" />
          <span>Receipt & Trace</span>
        </button>
      </div>

      {/* Tab Panels */}
      <div className="p-4 sm:p-5 space-y-4">
        {/* ── 1. Decision Tab ── */}
        {activeTab === "decision" && (
          <div className="space-y-4">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Decision Summary (Triggers CANONICAL_HASH & AGENT_SIGNATURE):
              </label>
              <textarea
                value={packet.decision?.summary || ""}
                onChange={(e) =>
                  mutate((p) => {
                    if (!p.decision) p.decision = {};
                    p.decision.summary = e.target.value;
                  })
                }
                rows={3}
                className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Action Kind:
                </label>
                <input
                  type="text"
                  value={
                    typeof packet.decision?.action_kind === "string"
                      ? packet.decision.action_kind
                      : packet.decision?.action_kind?.name || "Standard:Execute"
                  }
                  onChange={(e) =>
                    mutate((p) => {
                      if (!p.decision) p.decision = {};
                      p.decision.action_kind = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Input Commitment Hash (SHA-256):
                </label>
                <input
                  type="text"
                  value={packet.decision?.input_hash || ""}
                  onChange={(e) =>
                    mutate((p) => {
                      if (!p.decision) p.decision = {};
                      p.decision.input_hash = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>
            </div>

            {/* Quick Action Tampering Buttons */}
            <div className="pt-2 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    p.decision.summary =
                      "TAMPERED: Unauthorized credit line increase to $15,000,000";
                  })
                }
                className="px-3 py-1.5 rounded bg-red-950/40 hover:bg-red-950/70 border border-red-800/60 text-red-300 text-xs transition-colors"
              >
                Inject Fraudulent Summary
              </button>

              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    p.decision.input_hash =
                      "0000000000000000000000000000000000000000000000000000000000000000";
                  })
                }
                className="px-3 py-1.5 rounded bg-slate-850 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs transition-colors"
              >
                Zero-Out Input Hash
              </button>
            </div>
          </div>
        )}

        {/* ── 2. Agent Tab ── */}
        {activeTab === "agent" && (
          <div className="space-y-4">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Agent AIP-ID (Triggers AGENT_ID_BINDING):
              </label>
              <input
                type="text"
                value={packet.agent?.aip_id || ""}
                onChange={(e) =>
                  mutate((p) => {
                    if (!p.agent) p.agent = {};
                    p.agent.aip_id = e.target.value;
                  })
                }
                className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Public Key (Hex):
                </label>
                <input
                  type="text"
                  value={packet.agent?.public_key?.key_bytes || ""}
                  onChange={(e) =>
                    mutate((p) => {
                      if (!p.agent) p.agent = {};
                      if (!p.agent.public_key) p.agent.public_key = {};
                      p.agent.public_key.key_bytes = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Model Provenance Hash:
                </label>
                <input
                  type="text"
                  value={packet.agent?.provenance?.model_hash || ""}
                  onChange={(e) =>
                    mutate((p) => {
                      if (!p.agent) p.agent = {};
                      if (!p.agent.provenance) p.agent.provenance = {};
                      p.agent.provenance.model_hash = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>
            </div>

            <div className="pt-2 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    p.agent.aip_id = "aip1mismatchidentity99887766554433221122";
                  })
                }
                className="px-3 py-1.5 rounded bg-red-950/40 hover:bg-red-950/70 border border-red-800/60 text-red-300 text-xs transition-colors"
              >
                Hijack Agent AIP-ID
              </button>

              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    if (p.agent_sig) {
                      if (Array.isArray(p.agent_sig.signature_bytes) && p.agent_sig.signature_bytes.length > 0) {
                        p.agent_sig.signature_bytes[0] ^= 0xff;
                      } else {
                        p.agent_sig.signature_bytes =
                          "bad_signature_bytes_000000000000000000000000000000000000000000";
                      }
                      if ("sig_hex" in p.agent_sig) {
                        p.agent_sig.sig_hex =
                          "bad_signature_bytes_000000000000000000000000000000000000000000";
                      }
                    }
                  })
                }
                className="px-3 py-1.5 rounded bg-amber-950/40 hover:bg-amber-950/70 border border-amber-800/60 text-amber-300 text-xs transition-colors"
              >
                Corrupt Agent Digital Signature (Rule 4)
              </button>
            </div>
          </div>
        )}

        {/* ── 3. Authority Tab ── */}
        {activeTab === "authority" && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Root Principal ID:
                </label>
                <input
                  type="text"
                  value={packet.root_authority?.principal_id || ""}
                  onChange={(e) =>
                    mutate((p) => {
                      if (!p.root_authority) p.root_authority = {};
                      p.root_authority.principal_id = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Root Token JTI (Identifier):
                </label>
                <input
                  type="text"
                  value={packet.root_authority?.root_token?.jti || ""}
                  onChange={(e) =>
                    mutate((p) => {
                      if (!p.root_authority?.root_token) return;
                      p.root_authority.root_token.jti = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>
            </div>

            {/* Delegation Hops Inspection */}
            {Array.isArray(packet.delegation_chain) && packet.delegation_chain.length > 0 && (
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  First Delegation Hop Grantee ID:
                </label>
                <input
                  type="text"
                  value={packet.delegation_chain[0].grantee_id || ""}
                  onChange={(e) =>
                    mutate((p) => {
                      p.delegation_chain[0].grantee_id = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>
            )}

            {/* Authority Mutation Triggers */}
            <div className="pt-2 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    if (p.delegation_chain?.[0]?.scope?.allowed) {
                      p.delegation_chain[0].scope.allowed.push({
                        kind: "Standard",
                        action: "Admin",
                      });
                    }
                  })
                }
                className="px-3 py-1.5 rounded bg-red-950/40 hover:bg-red-950/70 border border-red-800/60 text-red-300 text-xs transition-colors"
              >
                Inject Forbidden Admin Scope (Escalation Violation)
              </button>

              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    if (p.delegation_chain?.[0]) {
                      p.delegation_chain[0].grantee_id = "unexpected-middleman";
                    }
                  })
                }
                className="px-3 py-1.5 rounded bg-amber-950/40 hover:bg-amber-950/70 border border-amber-800/60 text-amber-300 text-xs transition-colors"
              >
                Break Authority Chain Continuity (Rule 7)
              </button>

              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    const rtSig = p.root_authority?.root_token?.issuer_sig;
                    if (rtSig) {
                      const bad = "bad_root_signature_hex_0000000000000000000000000000000000";
                      if (Array.isArray(rtSig.signature_bytes) && rtSig.signature_bytes.length > 0) {
                        rtSig.signature_bytes[0] ^= 0xff;
                      } else {
                        rtSig.signature_bytes = bad;
                      }
                      if ("sig_hex" in rtSig) {
                        rtSig.sig_hex = bad;
                      }
                    }
                  })
                }
                className="px-3 py-1.5 rounded bg-red-950/40 hover:bg-red-950/70 border border-red-800/60 text-red-300 text-xs transition-colors"
              >
                Corrupt Root Token Signature (Rule 5)
              </button>
            </div>
          </div>
        )}

        {/* ── 4. Actions Tab ── */}
        {activeTab === "actions" && (
          <div className="space-y-4">
            {Array.isArray(packet.actions) && packet.actions.length > 0 && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-slate-300 font-semibold mb-1">
                      Action Performed Timestamp (ms):
                    </label>
                    <input
                      type="number"
                      value={packet.actions[0].performed_at || 0}
                      onChange={(e) =>
                        mutate((p) => {
                          p.actions[0].performed_at = Number(e.target.value);
                        })
                      }
                      className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 font-semibold mb-1">
                      Action Payload Hash:
                    </label>
                    <input
                      type="text"
                      value={packet.actions[0].payload_hash || ""}
                      onChange={(e) =>
                        mutate((p) => {
                          p.actions[0].payload_hash = e.target.value;
                        })
                      }
                      className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                    />
                  </div>
                </div>

                <div className="pt-2 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      mutate((p) => {
                        // Invert timestamp: action before decision
                        p.actions[0].performed_at = (p.decision?.decided_at || Date.now()) - 1000000;
                      })
                    }
                    className="px-3 py-1.5 rounded bg-red-950/40 hover:bg-red-950/70 border border-red-800/60 text-red-300 text-xs transition-colors"
                  >
                    Invert Timestamp (Rule 10 Temporal Fraud)
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      mutate((p) => {
                        if (Array.isArray(p.actions[0].payload_hash) && p.actions[0].payload_hash.length > 0) {
                          p.actions[0].payload_hash[0] ^= 0xff;
                        } else {
                          p.actions[0].payload_hash =
                            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffftampered";
                        }
                      })
                    }
                    className="px-3 py-1.5 rounded bg-red-950/40 hover:bg-red-950/70 border border-red-800/60 text-red-300 text-xs transition-colors"
                  >
                    Mutate Action Payload Hash (Rule 11)
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── 5. Receipt & Trace Tab ── */}
        {activeTab === "receipt" && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Claimed Trust Floor:
                </label>
                <select
                  value={packet.claimed_trust_floor || "COUNTERPARTY_SIGNED"}
                  onChange={(e) =>
                    mutate((p) => {
                      p.claimed_trust_floor = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                >
                  <option value="UNVERIFIED">UNVERIFIED</option>
                  <option value="AGENT_SIGNED">AGENT_SIGNED</option>
                  <option value="AUTHORITY_BOUND">AUTHORITY_BOUND</option>
                  <option value="COUNTERPARTY_SIGNED">COUNTERPARTY_SIGNED</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Trace Commitment Hash:
                </label>
                <input
                  type="text"
                  value={packet.trace_binding?.trace_hash || ""}
                  onChange={(e) =>
                    mutate((p) => {
                      if (!p.trace_binding) {
                        p.trace_binding = {
                          trace_id: "trace-001",
                          trace_system: "OpenTelemetry",
                          trace_hash: "",
                        };
                      }
                      p.trace_binding.trace_hash = e.target.value;
                    })
                  }
                  className="w-full bg-[#080B11] border border-slate-800 rounded-md p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>
            </div>

            <div className="pt-2 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    const cpSig = p.receipt_binding?.counterparty_sig;
                    if (cpSig) {
                      const corrupt = "corrupted_counterparty_sig_00000000000000000000000000000000";
                      if (Array.isArray(cpSig.signature_bytes) && cpSig.signature_bytes.length > 0) {
                        cpSig.signature_bytes[0] ^= 0xff;
                      } else {
                        cpSig.signature_bytes = corrupt;
                      }
                      if ("sig_hex" in cpSig) {
                        cpSig.sig_hex = corrupt;
                      }
                    }
                  })
                }
                className="px-3 py-1.5 rounded bg-red-950/40 hover:bg-red-950/70 border border-red-800/60 text-red-300 text-xs transition-colors"
              >
                Corrupt Counterparty Signature (Rule 13)
              </button>

              <button
                type="button"
                onClick={() =>
                  mutate((p) => {
                    if (p.trace_binding) {
                      if (Array.isArray(p.trace_binding.trace_hash) && p.trace_binding.trace_hash.length > 0) {
                        p.trace_binding.trace_hash[0] ^= 0xff;
                      } else {
                        p.trace_binding.trace_hash =
                          "0000000000000000000000000000000000000000000000000000000000000000";
                      }
                    } else {
                      p.trace_binding = {
                        trace_id: "trace-tampered-001",
                        trace_system: "OpenTelemetry",
                        trace_hash: new Array(32).fill(0),
                      };
                    }
                  })
                }
                className="px-3 py-1.5 rounded bg-amber-950/40 hover:bg-amber-950/70 border border-amber-800/60 text-amber-300 text-xs transition-colors"
              >
                Spoof Trace Commitment Hash (Rule 12)
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
