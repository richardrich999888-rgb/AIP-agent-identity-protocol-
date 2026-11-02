"use client";

/**
 * TrustAnchorConfig: Verifier Trust Anchor Configuration for AIP Console
 * Target: aip-console/src/components/ingestion/TrustAnchorConfig.tsx
 *
 * Configures the verifier's trusted root issuer public keys, trusted counterparty
 * public keys, and revoked token JTIs. Triggers instant re-verification on any change.
 */

import React, { useState, useEffect } from "react";
import { VerificationContext } from "@/types/verification";
import {
  Key,
  Shield,
  Trash2,
  Plus,
  RefreshCw,
  Sliders,
  CheckCircle2,
  AlertCircle,
  FileCode,
  ShieldAlert,
  Building,
} from "lucide-react";

export interface TrustAnchorConfigProps {
  initialContext?: VerificationContext;
  onContextChange: (contextJson: string) => void;
  className?: string;
}

// Default Honest Banking Fixture Anchors
const PRESET_BANKING_CONTEXT: VerificationContext = {
  trusted_issuers: {
    "aip12hrTEHHmno9YyKKK7TfzWJWqTHGifXEcrn2p29W9CY":
      "c3c756a5912dd65a3e5e7e0a0ab4949d351bf26618facb21767f939b9b746285",
    "aip1843GAXTcKnohqiq2xaZb386wikYheTS25Nwk51xVCs":
      "59083848d4515a33d10bd2182abb88a9af5ebd0d32e6beeee1053d0e006971e9",
  },
  trusted_counterparties: {
    "ledger.example-bank.com":
      "130d07647878ace03f14725b3a905ed27410a23a7372668c144fc664f062c8c7",
  },
  revoked_jtis: [],
  receipt_data: "LEDGER-90211|INV-2026-0142|$48,200.00|POSTED",
  trace_data:
    "OTel:trace_id=4bf92f3577b34da6a3ce929d0e0e4736;span_id=00f067aa0ba902b7;sampled=1",
};

// Preset: Untrusted Root Issuer
const PRESET_UNTRUSTED_ROOT: VerificationContext = {
  ...PRESET_BANKING_CONTEXT,
  trusted_issuers: {
    // Deliberately omits Alice CFO's key
    "aip1843GAXTcKnohqiq2xaZb386wikYheTS25Nwk51xVCs":
      "59083848d4515a33d10bd2182abb88a9af5ebd0d32e6beeee1053d0e006971e9",
  },
};

// Preset: Revoked Delegation Token
const PRESET_REVOKED_TOKEN: VerificationContext = {
  ...PRESET_BANKING_CONTEXT,
  revoked_jtis: ["489f688002cf7ef611c05d7bda29fe96"],
};

// Preset: Empty Trust Anchors
const PRESET_EMPTY: VerificationContext = {
  trusted_issuers: {},
  trusted_counterparties: {},
  revoked_jtis: [],
};

export const TrustAnchorConfig: React.FC<TrustAnchorConfigProps> = ({
  initialContext,
  onContextChange,
  className = "",
}) => {
  const [issuers, setIssuers] = useState<Record<string, string>>(
    initialContext?.trusted_issuers ??
      initialContext?.issuer_public_keys ??
      PRESET_BANKING_CONTEXT.trusted_issuers!
  );

  const [counterparties, setCounterparties] = useState<Record<string, string>>(
    initialContext?.trusted_counterparties ??
      initialContext?.counterparty_public_keys ??
      PRESET_BANKING_CONTEXT.trusted_counterparties!
  );

  const [revokedJtis, setRevokedJtis] = useState<string[]>(
    initialContext?.revoked_jtis ?? []
  );

  const [activeTab, setActiveTab] = useState<"issuers" | "counterparties" | "revocation" | "raw">(
    "issuers"
  );

  // New item inputs
  const [newIssuerId, setNewIssuerId] = useState("");
  const [newIssuerKey, setNewIssuerKey] = useState("");
  const [newCounterpartyId, setNewCounterpartyId] = useState("");
  const [newCounterpartyKey, setNewCounterpartyKey] = useState("");
  const [newJti, setNewJti] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  // Raw JSON editor state
  const [rawJson, setRawJson] = useState("");
  const [rawJsonError, setRawJsonError] = useState<string | null>(null);

  // Emit serialized VerificationContext JSON whenever anchors change
  const emitContext = (
    updatedIssuers: Record<string, string>,
    updatedCounterparties: Record<string, string>,
    updatedJtis: string[]
  ) => {
    const ctx: VerificationContext = {
      trusted_issuers: updatedIssuers,
      issuer_public_keys: updatedIssuers,
      trusted_counterparties: updatedCounterparties,
      counterparty_public_keys: updatedCounterparties,
      revoked_jtis: updatedJtis,
      receipt_data: PRESET_BANKING_CONTEXT.receipt_data,
      trace_data: PRESET_BANKING_CONTEXT.trace_data,
    };
    const jsonStr = JSON.stringify(ctx, null, 2);
    setRawJson(jsonStr);
    onContextChange(jsonStr);
  };

  // Sync initial raw JSON once
  useEffect(() => {
    emitContext(issuers, counterparties, revokedJtis);
  }, []);

  // Preset loaders
  const loadPreset = (preset: VerificationContext) => {
    const i = preset.trusted_issuers || {};
    const c = preset.trusted_counterparties || {};
    const r = preset.revoked_jtis || [];
    setIssuers(i);
    setCounterparties(c);
    setRevokedJtis(r);
    emitContext(i, c, r);
  };

  // Add Issuer
  const handleAddIssuer = () => {
    setFormError(null);
    const cleanId = newIssuerId.trim();
    const cleanKey = newIssuerKey.trim().toLowerCase();

    if (!cleanId) {
      setFormError("Issuer AIP-ID cannot be empty.");
      return;
    }
    if (!cleanKey || cleanKey.length !== 64 || !/^[0-9a-f]+$/i.test(cleanKey)) {
      setFormError("Public key must be a 64-character hexadecimal Ed25519 key (32 bytes).");
      return;
    }

    const updated = { ...issuers, [cleanId]: cleanKey };
    setIssuers(updated);
    setNewIssuerId("");
    setNewIssuerKey("");
    emitContext(updated, counterparties, revokedJtis);
  };

  const handleRemoveIssuer = (id: string) => {
    const updated = { ...issuers };
    delete updated[id];
    setIssuers(updated);
    emitContext(updated, counterparties, revokedJtis);
  };

  // Add Counterparty
  const handleAddCounterparty = () => {
    setFormError(null);
    const cleanId = newCounterpartyId.trim();
    const cleanKey = newCounterpartyKey.trim().toLowerCase();

    if (!cleanId) {
      setFormError("Counterparty ID cannot be empty.");
      return;
    }
    if (!cleanKey || cleanKey.length !== 64 || !/^[0-9a-f]+$/i.test(cleanKey)) {
      setFormError("Public key must be a 64-character hexadecimal Ed25519 key.");
      return;
    }

    const updated = { ...counterparties, [cleanId]: cleanKey };
    setCounterparties(updated);
    setNewCounterpartyId("");
    setNewCounterpartyKey("");
    emitContext(issuers, updated, revokedJtis);
  };

  const handleRemoveCounterparty = (id: string) => {
    const updated = { ...counterparties };
    delete updated[id];
    setCounterparties(updated);
    emitContext(issuers, updated, revokedJtis);
  };

  // Add Revoked JTI
  const handleAddJti = () => {
    setFormError(null);
    const cleanJti = newJti.trim().replace(/-/g, "").toLowerCase();

    if (cleanJti.length !== 32 || !/^[0-9a-f]+$/i.test(cleanJti)) {
      setFormError("Revoked JTI must be a 32-character hexadecimal token identifier (16 bytes).");
      return;
    }

    if (revokedJtis.includes(cleanJti)) {
      setFormError("This JTI is already in the revocation list.");
      return;
    }

    const updated = [...revokedJtis, cleanJti];
    setRevokedJtis(updated);
    setNewJti("");
    emitContext(issuers, counterparties, updated);
  };

  const handleRemoveJti = (jti: string) => {
    const updated = revokedJtis.filter((item) => item !== jti);
    setRevokedJtis(updated);
    emitContext(issuers, counterparties, updated);
  };

  // Apply Raw JSON
  const handleApplyRawJson = () => {
    setRawJsonError(null);
    try {
      const parsed = JSON.parse(rawJson);
      const i = parsed.trusted_issuers || parsed.issuer_public_keys || {};
      const c = parsed.trusted_counterparties || parsed.counterparty_public_keys || {};
      const r = parsed.revoked_jtis || [];
      setIssuers(i);
      setCounterparties(c);
      setRevokedJtis(r);
      onContextChange(rawJson);
    } catch (e: any) {
      setRawJsonError(`Invalid JSON: ${e.message}`);
    }
  };

  return (
    <div
      className={`rounded-xl border border-slate-800 bg-[#0E131F] overflow-hidden shadow-xl ${className}`}
    >
      {/* Header Bar */}
      <div className="p-4 sm:px-5 border-b border-slate-800 bg-[#080B11]/90 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <Key className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-slate-100 tracking-wide">
            Verifier Trust Anchors & Revocation Context
          </h3>
        </div>

        {/* Preset Context Selector Buttons */}
        <div className="flex items-center gap-1.5 text-xs font-mono">
          <span className="text-slate-500 mr-1 hidden sm:inline">Presets:</span>
          <button
            onClick={() => loadPreset(PRESET_BANKING_CONTEXT)}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            title="Load standard production trusted keys"
          >
            Banking CA
          </button>
          <button
            onClick={() => loadPreset(PRESET_UNTRUSTED_ROOT)}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-400 border border-slate-700 transition-colors"
            title="Omit Alice CFO key to simulate untrusted root"
          >
            Untrusted Root
          </button>
          <button
            onClick={() => loadPreset(PRESET_REVOKED_TOKEN)}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-red-400 border border-slate-700 transition-colors"
            title="Inject revoked JTI to trigger Rule 9 failure"
          >
            Revoked JTI
          </button>
          <button
            onClick={() => loadPreset(PRESET_EMPTY)}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 border border-slate-700 transition-colors"
            title="Clear all anchors"
          >
            Clear All
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="px-5 pt-3 border-b border-slate-800/80 flex items-center gap-4 text-xs font-mono">
        <button
          onClick={() => setActiveTab("issuers")}
          className={`pb-2.5 border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === "issuers"
              ? "border-cyan-400 text-cyan-300 font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          Trusted Principal Issuers ({Object.keys(issuers).length})
        </button>

        <button
          onClick={() => setActiveTab("counterparties")}
          className={`pb-2.5 border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === "counterparties"
              ? "border-cyan-400 text-cyan-300 font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Building className="w-3.5 h-3.5" />
          Trusted Counterparties ({Object.keys(counterparties).length})
        </button>

        <button
          onClick={() => setActiveTab("revocation")}
          className={`pb-2.5 border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === "revocation"
              ? "border-cyan-400 text-cyan-300 font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          Revoked JTIs ({revokedJtis.length})
        </button>

        <button
          onClick={() => setActiveTab("raw")}
          className={`pb-2.5 border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === "raw"
              ? "border-cyan-400 text-cyan-300 font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          Raw Context JSON
        </button>
      </div>

      {/* Tab Content */}
      <div className="p-4 sm:p-5">
        {formError && (
          <div className="mb-4 p-2.5 rounded bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <span>{formError}</span>
          </div>
        )}

        {/* ── 1. Trusted Principal Issuers Tab ── */}
        {activeTab === "issuers" && (
          <div className="space-y-4">
            <p className="text-xs text-slate-400 font-mono">
              Root Authority Ed25519 public keys recognized by this verifier.
              Missing keys trigger Rule 5 (ROOT_TOKEN_SIGNATURE) verifiability gaps.
            </p>

            {/* List */}
            <div className="space-y-2">
              {Object.entries(issuers).length === 0 ? (
                <div className="p-4 rounded border border-dashed border-slate-800 text-center text-xs font-mono text-slate-500">
                  No trusted root issuers configured. All root tokens will fail Rule 5.
                </div>
              ) : (
                Object.entries(issuers).map(([id, keyHex]) => (
                  <div
                    key={id}
                    className="p-3 rounded-lg bg-[#080B11] border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 font-mono text-xs"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-cyan-400 font-semibold">{id}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">
                        Key: <span className="text-slate-300">{keyHex}</span>
                      </div>
                    </div>
                    <button
                      onClick={() => handleRemoveIssuer(id)}
                      className="p-1.5 text-slate-500 hover:text-red-400 transition-colors self-end sm:self-center"
                      title="Remove this trusted issuer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))
              )}
            </div>

            {/* Add Issuer Form */}
            <div className="pt-3 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-12 gap-2">
              <input
                type="text"
                placeholder="Issuer AIP-ID (e.g. aip1...)"
                value={newIssuerId}
                onChange={(e) => setNewIssuerId(e.target.value)}
                className="sm:col-span-5 px-3 py-1.5 rounded bg-[#080B11] border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
              <input
                type="text"
                placeholder="64-char Hex Public Key"
                value={newIssuerKey}
                onChange={(e) => setNewIssuerKey(e.target.value)}
                className="sm:col-span-5 px-3 py-1.5 rounded bg-[#080B11] border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={handleAddIssuer}
                className="sm:col-span-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-black font-bold text-xs font-mono flex items-center justify-center gap-1 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                Add Key
              </button>
            </div>
          </div>
        )}

        {/* ── 2. Trusted Counterparties Tab ── */}
        {activeTab === "counterparties" && (
          <div className="space-y-4">
            <p className="text-xs text-slate-400 font-mono">
              Public keys for external clearinghouses, bank ledgers, or database systems
              verifying bilateral countersigned receipts (Rule 13 RECEIPT_BINDING).
            </p>

            <div className="space-y-2">
              {Object.entries(counterparties).length === 0 ? (
                <div className="p-4 rounded border border-dashed border-slate-800 text-center text-xs font-mono text-slate-500">
                  No counterparties configured. Receipts will be validated by hash only.
                </div>
              ) : (
                Object.entries(counterparties).map(([id, keyHex]) => (
                  <div
                    key={id}
                    className="p-3 rounded-lg bg-[#080B11] border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 font-mono text-xs"
                  >
                    <div className="min-w-0">
                      <div className="text-cyan-400 font-semibold">{id}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">
                        Key: <span className="text-slate-300">{keyHex}</span>
                      </div>
                    </div>
                    <button
                      onClick={() => handleRemoveCounterparty(id)}
                      className="p-1.5 text-slate-500 hover:text-red-400 transition-colors self-end sm:self-center"
                      title="Remove this counterparty"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))
              )}
            </div>

            {/* Add Counterparty Form */}
            <div className="pt-3 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-12 gap-2">
              <input
                type="text"
                placeholder="Counterparty ID (e.g. ledger.example-bank.com)"
                value={newCounterpartyId}
                onChange={(e) => setNewCounterpartyId(e.target.value)}
                className="sm:col-span-5 px-3 py-1.5 rounded bg-[#080B11] border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
              <input
                type="text"
                placeholder="64-char Hex Public Key"
                value={newCounterpartyKey}
                onChange={(e) => setNewCounterpartyKey(e.target.value)}
                className="sm:col-span-5 px-3 py-1.5 rounded bg-[#080B11] border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={handleAddCounterparty}
                className="sm:col-span-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-black font-bold text-xs font-mono flex items-center justify-center gap-1 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                Add Key
              </button>
            </div>
          </div>
        )}

        {/* ── 3. Revoked JTIs Tab ── */}
        {activeTab === "revocation" && (
          <div className="space-y-4">
            <p className="text-xs text-slate-400 font-mono">
              Revocation registry of 16-byte token identifiers (JTIs). Any token in the
              authority chain matching this list immediately fails Rule 9 (REVOCATION).
            </p>

            <div className="space-y-2">
              {revokedJtis.length === 0 ? (
                <div className="p-4 rounded border border-dashed border-slate-800 text-center text-xs font-mono text-emerald-400/80">
                  Revocation registry is empty. Zero revoked tokens active.
                </div>
              ) : (
                revokedJtis.map((jti) => (
                  <div
                    key={jti}
                    className="p-3 rounded-lg bg-red-950/20 border border-red-500/30 flex items-center justify-between gap-2 font-mono text-xs text-red-300"
                  >
                    <span className="truncate">Revoked JTI: {jti}</span>
                    <button
                      onClick={() => handleRemoveJti(jti)}
                      className="p-1.5 text-slate-400 hover:text-slate-200 transition-colors"
                      title="Clear revocation for this JTI"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))
              )}
            </div>

            {/* Add Revocation Form */}
            <div className="pt-3 border-t border-slate-800/80 flex gap-2">
              <input
                type="text"
                placeholder="32-char Hex JTI Token Identifier (16 bytes)"
                value={newJti}
                onChange={(e) => setNewJti(e.target.value)}
                className="flex-1 px-3 py-1.5 rounded bg-[#080B11] border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={handleAddJti}
                className="px-4 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-xs font-mono flex items-center gap-1 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                Revoke Token
              </button>
            </div>
          </div>
        )}

        {/* ── 4. Raw JSON Editor Tab ── */}
        {activeTab === "raw" && (
          <div className="space-y-3">
            {rawJsonError && (
              <div className="p-2 rounded bg-red-950/40 border border-red-500/40 text-red-300 text-xs font-mono">
                {rawJsonError}
              </div>
            )}
            <textarea
              rows={10}
              value={rawJson}
              onChange={(e) => setRawJson(e.target.value)}
              className="w-full p-3 rounded bg-[#080B11] border border-slate-800 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={handleApplyRawJson}
              className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-black font-bold text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Apply JSON & Re-verify
            </button>
          </div>
        )}
      </div>

      {/* Footer Info */}
      <div className="p-3 px-5 bg-[#080B11] border-t border-slate-800 text-[11px] font-mono text-slate-500 flex items-center justify-between">
        <span>Instant client-side re-verification</span>
        <span className="text-cyan-400">Zero network roundtrip (Offline WASM)</span>
      </div>
    </div>
  );
};

export default TrustAnchorConfig;
