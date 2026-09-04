/**
 * HNDL Defense & PQC Telemetry Inspector — the proof modal behind the
 * PQC TRANSPORT card.
 *
 * # What is live and what is SIM, and why the modal says so
 *
 * The protected column, the handshake pipeline and every download bind to
 * the engine's real surfaces: GET /secure/telemetry (a genuinely sealed
 * frame with its ciphertext and round-trip verification), GET /security
 * (the negotiated suite and signer fingerprint), GET /receipts (the Merkle
 * attestation chain) and GET /pqc-transport (kernel enforcement posture).
 * The adversary column is necessarily a simulation — this console
 * intercepts nobody's traffic — so it wears the console's SIM badge, and
 * the eBPF latency figure is displayed as the SYNTRIASS design target it
 * is, because an inspector that dressed a spec number as a live reading
 * would poison trust in every real number beside it. What is real here is
 * impressive enough to not need help.
 */

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import {
  Download,
  FileJson,
  Lock,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Table,
  X,
} from "lucide-react";

import { cn } from "../lib/cn";
import { INK, SURFACE, TYPE } from "../lib/design";
import {
  fetchPqcTransport,
  fetchReceipts,
  fetchSecureTelemetry,
  fetchSecurity,
  type PqcTransport,
  type ReceiptChainSummary,
  type SecureTelemetry,
  type SecurityPosture,
} from "../api/client";
import {
  buildHexComparisonDump,
  buildHndlCertificate,
  KERNEL_LATENCY_TARGET_NS,
  pqcAudit,
  SYNTRIASS_CIPHER_SUITE,
  toPqcForensicCsv,
} from "../telemetry/pqc-audit";
import { downloadTextFile } from "../telemetry/agent-accountability/exporter";
import { agentRegistry } from "../telemetry/governance";

export interface PqcInspectorModalProps {
  open: boolean;
  onClose: () => void;
  /** Fullscreen workspace (the top-bar PQC DEFENSE tab) instead of the
   * centred dialog. Same tabs, same live data — only the frame differs. */
  fullscreen?: boolean;
}

type Tab = "traffic" | "pipeline" | "audit";

/** Refresh cadence for the live frame while the modal is open. The engine
 * seals a fresh envelope per request, so every poll is a new proof. */
const LIVE_REFRESH_MS = 5000;

function hexRows(hex: string, maxRows: number): string[] {
  const rows: string[] = [];
  for (let i = 0; i < hex.length && rows.length < maxRows; i += 32) {
    rows.push(hex.slice(i, i + 32).replace(/(.{2})/g, "$1 ").trimEnd());
  }
  return rows;
}

export default function PqcInspectorModal({
  open,
  onClose,
  fullscreen = false,
}: PqcInspectorModalProps) {
  const [tab, setTab] = useState<Tab>("traffic");
  const [frame, setFrame] = useState<SecureTelemetry | null>(null);
  const [transport, setTransport] = useState<PqcTransport | null>(null);
  const [security, setSecurity] = useState<SecurityPosture | null>(null);
  const [receipts, setReceipts] = useState<ReceiptChainSummary | null>(null);
  const [offline, setOffline] = useState(false);

  // Live audit records — re-render on every sealed ingestion event.
  useSyncExternalStore(
    useCallback((cb: () => void) => pqcAudit.subscribe(cb), []),
    () => pqcAudit.snapshotVersion,
  );
  const records = pqcAudit.records();

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const pull = () => {
      fetchSecureTelemetry()
        .then((f) => !cancelled && (setFrame(f), setOffline(false)))
        .catch(() => !cancelled && setOffline(true));
    };
    pull();
    fetchPqcTransport().then((t) => !cancelled && setTransport(t)).catch(() => undefined);
    fetchSecurity().then((s) => !cancelled && setSecurity(s)).catch(() => undefined);
    fetchReceipts().then((r) => !cancelled && setReceipts(r)).catch(() => undefined);
    const timer = setInterval(pull, LIVE_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [open]);

  // SIM legacy exposure bytes, derived from the real frame's plaintext hash
  // so the demonstration is stable per frame. See the module note.
  const simLegacyHex = useMemo(
    () => (frame ? frame.plaintext_sha256.repeat(8).slice(0, 384) : ""),
    [frame],
  );

  if (!open) return null;

  const agentDid = (() => {
    const roster = agentRegistry.listAgents();
    return roster.length ? roster[roster.length - 1].did : null;
  })();

  const downloadDump = () => {
    if (!frame) return;
    downloadTextFile(
      "hndl-exposure-comparison.txt",
      "text/plain",
      buildHexComparisonDump(frame),
    );
  };
  const downloadCertificate = async () => {
    if (!frame) return;
    const { envelope: _envelope, ...frameSansEnvelope } = frame;
    const certificate = await buildHndlCertificate({
      securityPosture: (security ?? null) as never,
      receiptChain: (receipts ?? null) as never,
      telemetryFrame: frameSansEnvelope as never,
      agentDid,
      auditRecords: records,
    });
    downloadTextFile(
      "hndl-compliance-certificate.json",
      "application/json",
      JSON.stringify(certificate, null, 2) + "\n",
    );
  };
  const downloadCsv = () =>
    downloadTextFile("pqc-forensic-summary.csv", "text/csv", toPqcForensicCsv(records));

  return (
    <div
      className={cn(
        "absolute inset-0 z-40 pointer-events-auto",
        fullscreen
          ? "bg-[#05060a]/[0.97] p-6"
          : "flex items-center justify-center bg-black/60",
      )}
    >
      <div
        className={cn(
          SURFACE.raised,
          "rounded-md flex flex-col",
          fullscreen
            ? "w-full h-full"
            : "w-[54rem] max-w-[94vw] max-h-[86vh]",
        )}
      >
        {/* Header */}
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-cyan-500/20">
          <Lock className="w-4 h-4 text-cyan-300" />
          <span className={cn(TYPE.label, INK.primary)}>
            HNDL Defense & PQC Telemetry Inspector
          </span>
          <span className={cn(TYPE.caption, INK.muted)}>SYNTRIASS KERNEL</span>
          {offline && (
            <span className={cn(TYPE.caption, "text-amber-300")}>
              ENGINE OFFLINE — live frame unavailable
            </span>
          )}
          <button type="button" onClick={onClose} className="ml-auto" title="Close inspector">
            <X className={cn("w-4 h-4", INK.muted)} />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 px-3 pt-2">
          {(
            [
              ["traffic", "LIVE TRAFFIC COMPARISON"],
              ["pipeline", "VERIFICATION PIPELINE"],
              ["audit", "AUDIT & DOWNLOADS"],
            ] as [Tab, string][]
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => setTab(id)}
              className={cn(
                TYPE.caption,
                "px-3 py-1.5 rounded-t border-x border-t",
                tab === id
                  ? "border-cyan-400/40 text-cyan-200 bg-cyan-500/10"
                  : "border-transparent hover:text-cyan-300",
              )}
            >
              {label}
            </button>
          ))}
        </div>

        <div className={cn("overflow-y-auto border-t border-cyan-500/15 px-4 py-3", fullscreen && "flex-1")}>
          {tab === "traffic" && (
            <div className="grid grid-cols-2 gap-4">
              {/* Adversary column — SIM, and says so. */}
              <div className="rounded border border-red-400/40 bg-red-500/5 p-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-300" />
                  <span className={cn(TYPE.caption, "text-red-300")}>
                    [EXPOSED TO HNDL] · ADVERSARY HARVEST FEED
                  </span>
                  <span className={cn(TYPE.caption, "ml-auto text-red-300/80")}>SIM</span>
                </div>
                <div className={cn(TYPE.caption, INK.muted, "mt-1")}>
                  Legacy RSA-2048 / ECC-256 key exchange · vulnerable to Shor's
                  algorithm (published break-horizon estimates cluster before
                  2030 for CRQC-scale adversaries)
                </div>
                <pre className={cn("mt-2 text-[10px] font-mono leading-4 text-red-200/80 overflow-x-auto")}>
                  {frame
                    ? hexRows(simLegacyHex, 10).join("\n")
                    : "— engine offline; no frame to demonstrate against —"}
                </pre>
                <div className={cn(TYPE.caption, "text-red-300/80 mt-1")}>
                  Recorded today, decrypted at CRQC availability. Bytes above
                  are a SIM demonstration — this console intercepts no traffic.
                </div>
              </div>

              {/* Protected column — the real engine frame. */}
              <div className="rounded border border-emerald-400/40 bg-emerald-500/5 p-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-300" />
                  <span className={cn(TYPE.caption, "text-emerald-300")}>
                    [PQC PROTECTED · FIPS 203/204] · SYNTRIASS FEED
                  </span>
                  <span className={cn(TYPE.caption, "ml-auto text-emerald-300/80")}>
                    LIVE
                  </span>
                </div>
                <div className={cn(TYPE.caption, INK.secondary, "mt-1 font-mono")}>
                  {frame?.suite ?? SYNTRIASS_CIPHER_SUITE}
                </div>
                <div className={cn(TYPE.caption, INK.muted)}>
                  AEAD {frame?.aead ?? "—"} · plaintext {frame?.plaintext_bytes ?? "—"} B →
                  envelope {frame?.envelope_bytes ?? "—"} B ·{" "}
                  {frame?.roundtrip_verified ? "round-trip VERIFIED" : "round trip pending"}
                </div>
                <pre className="mt-2 text-[10px] font-mono leading-4 text-emerald-200/80 overflow-x-auto">
                  {frame
                    ? hexRows(frame.envelope.ciphertext_hex, 10).join("\n")
                    : "— engine offline —"}
                </pre>
                <div className={cn(TYPE.caption, INK.muted, "mt-1")}>
                  Kernel interception: eBPF socket layer ·{" "}
                  {transport?.enforcement ?? "fail-closed"} · design target ~
                  {KERNEL_LATENCY_TARGET_NS} ns (spec target, not measured here)
                </div>
              </div>
            </div>
          )}

          {tab === "pipeline" && (
            <div className="space-y-2">
              {[
                {
                  step: "1 · eBPF SOCKET INTERCEPT",
                  body: `${transport?.enforcement_detail ?? "cgroup/connect4 + sock_ops policy; plaintext egress fail-closed"} — design target ~${KERNEL_LATENCY_TARGET_NS} ns (SPEC TARGET)`,
                  live: Boolean(transport),
                },
                {
                  step: "2 · HYBRID ML-KEM-1024 EXCHANGE",
                  body: `${frame?.suite ?? SYNTRIASS_CIPHER_SUITE} — Module-LWE over rank k=4, ring dimension n=256, modulus q=3329 (FIPS 203 parameter set ML-KEM-1024, NIST category 5); hybrid with X25519 so HNDL requires breaking both`,
                  live: Boolean(frame),
                },
                {
                  step: "3 · ML-DSA-87 ATTESTATION",
                  body: security
                    ? `signer ${security.signer_suite} · fingerprint ${security.signer_fingerprint} · minimum level ${security.minimum_level}`
                    : "engine offline — signer posture unavailable",
                  live: Boolean(security),
                },
                {
                  step: "4 · NEXORA ACTION HASH SEAL",
                  body: receipts
                    ? `receipt chain ${receipts.verified ? "VERIFIED" : "UNVERIFIED"} · ${receipts.stages} stages · merkle root ${receipts.merkle_root_hex.slice(0, 16)}… · latest audit digest ${pqcAudit.latest()?.evidenceDigest.slice(0, 16) ?? "—"}…`
                    : "engine offline — receipt chain unavailable",
                  live: Boolean(receipts),
                },
              ].map((s) => (
                <div
                  key={s.step}
                  className={cn(
                    "rounded border p-2.5",
                    s.live ? "border-cyan-400/30" : "border-slate-500/30",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Radio
                      className={cn("w-3 h-3", s.live ? "text-emerald-300" : "text-slate-400")}
                    />
                    <span className={cn(TYPE.caption, INK.secondary)}>{s.step}</span>
                    <span
                      className={cn(
                        TYPE.caption,
                        "ml-auto",
                        s.live ? "text-emerald-300" : "text-slate-400",
                      )}
                    >
                      {s.live ? "LIVE" : "OFFLINE"}
                    </span>
                  </div>
                  <div className={cn(TYPE.body, INK.primary, "mt-1 font-mono break-all")}>
                    {s.body}
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === "audit" && (
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={downloadDump}
                  disabled={!frame}
                  className={cn(TYPE.caption, "flex items-center gap-1.5 rounded border border-cyan-400/30 px-3 py-1.5 hover:text-cyan-200 disabled:opacity-40")}
                  title="Hex dump: SIM legacy exposure vs live engine ciphertext (.txt)"
                >
                  <Download className="w-3.5 h-3.5" /> Exposure Comparison Dump (.txt)
                </button>
                <button
                  type="button"
                  onClick={() => void downloadCertificate()}
                  disabled={!frame}
                  className={cn(TYPE.caption, "flex items-center gap-1.5 rounded border border-cyan-400/30 px-3 py-1.5 hover:text-cyan-200 disabled:opacity-40")}
                  title="Certified JSON binding the live security posture, receipts, telemetry hash and agent DID"
                >
                  <FileJson className="w-3.5 h-3.5" /> HNDL Compliance Certificate (.json)
                </button>
                <button
                  type="button"
                  onClick={downloadCsv}
                  disabled={records.length === 0}
                  className={cn(TYPE.caption, "flex items-center gap-1.5 rounded border border-cyan-400/30 px-3 py-1.5 hover:text-cyan-200 disabled:opacity-40")}
                  title="Flat table of every protected ingestion event this session"
                >
                  <Table className="w-3.5 h-3.5" /> Forensic Summary (.csv)
                </button>
              </div>
              <div>
                <div className={cn(TYPE.caption)}>
                  PROTECTED INGESTION EVENTS · THIS SESSION · {records.length}
                </div>
                <ol className="mt-1 space-y-1 max-h-56 overflow-y-auto">
                  {records.length === 0 && (
                    <li className={cn(TYPE.body, INK.muted)}>
                      No events yet — records seal live as SATCOM and conjunction
                      queries run.
                    </li>
                  )}
                  {[...records].reverse().map((r) => (
                    <li key={r.id} className="flex items-baseline gap-2">
                      <span className={cn(TYPE.caption, INK.muted, "shrink-0")}>
                        {r.timestampUtc.slice(11, 19)}Z
                      </span>
                      <span className={cn(TYPE.body, "font-mono", INK.primary)}>{r.source}</span>
                      <span className={cn(TYPE.caption, "text-emerald-300")}>
                        {r.hndlProtectionStatus}
                      </span>
                      <span className={cn(TYPE.caption, INK.muted, "ml-auto font-mono")}>
                        {r.evidenceDigest.slice(0, 12)}…
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
