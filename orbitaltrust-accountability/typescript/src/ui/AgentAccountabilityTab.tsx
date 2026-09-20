/**
 * Agent Accountability & NEXORA Ledger — the inspection suite's forensic tab.
 *
 * Four views over the live governance stores, top to bottom:
 *
 *   A. the active agent's identity dossier (DID, model/guardrail provenance,
 *      clearance, supervisor, lifecycle status);
 *   B. the NEXORA lifecycle chain as a step tracker — every anchored
 *      milestone from AGENT_GENESIS on, expandable to its exact hashes;
 *   C. the AIP evidence packet inspector — every governed tool call with
 *      side-by-side pre/post state hashes, co-signature posture, and the
 *      chain's live verification verdict;
 *   D. the export suite: certified dossier, forensic JSONL, after-action CSV.
 *
 * # Real-time by subscription, verified on every read
 *
 * The tab subscribes to the identity registry, the accountability ledger,
 * and the governance feed; every notification re-reads the stores and
 * re-runs the NexoraVerifier (SHA-256 via crypto.subtle, recomputed from raw
 * storage — never trusting in-memory state). A record edited in IndexedDB
 * after sealing surfaces immediately as the red INTEGRITY BREACH banner
 * naming the first broken sequence.
 *
 * # Status is never colour alone
 *
 * Per the console's visualisation rules every state word travels with its
 * colour: SUCCESS/FAILED/BLOCKED_BY_POLICY, VERIFIED/BREACH, ACTIVE/REVOKED.
 */

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import {
  Download,
  FileJson,
  Fingerprint,
  Link2,
  ScrollText,
  ShieldCheck,
  ShieldOff,
  Table,
  X,
} from "lucide-react";

import { cn } from "../lib/cn";
import { INK, STATUS, SURFACE, TYPE, type Status } from "../lib/design";
import type { AgentEmployeeProfile } from "../telemetry/agent-identity/agent-profile";
import type { IdentityRegistry } from "../telemetry/agent-identity/identity-registry";
import type { AccountabilityService } from "../telemetry/agent-accountability/accountability-service";
import type { AgentActionLog, AuditVerification } from "../telemetry/agent-accountability/types";
import {
  downloadTextFile,
  toAuditCsv,
  toCertifiedDossierJson,
} from "../telemetry/agent-accountability/exporter";
import {
  buildCompliantMissionDossier,
  exportRegulatoryComplianceMatrix,
} from "../export/dossier-export";
import type { AipEvidencePacket, NexoraLifecycleAnchor } from "../telemetry/nexora/types";
import type { NexoraStore } from "../telemetry/nexora/nexora-store";
import type { NexoraVerifier } from "../telemetry/nexora/nexora-verifier";
import {
  verifyAgentRecords,
  type AgentVerificationReport,
} from "../governance/verification-runner";
import { toAgentDid } from "../telemetry/agent-identity/persistent-identity";
import {
  accountability,
  agentRegistry,
  governanceFeed,
  nexoraStore,
  nexoraVerifier,
} from "../telemetry/governance";

export interface AgentAccountabilityTabProps {
  /** All default to the console's governance singletons. */
  registry?: IdentityRegistry;
  service?: AccountabilityService;
  store?: NexoraStore;
  verifier?: NexoraVerifier;
  className?: string;
}

/** First and last 8 hex chars — enough to eyeball, click for the rest. */
function hashPill(hash: string): string {
  if (!hash) return "—";
  return hash.length <= 20 ? hash : `${hash.slice(0, 8)}…${hash.slice(-8)}`;
}

const CREDENTIAL_TONE: Record<AgentEmployeeProfile["revocationStatus"], Status> = {
  ACTIVE: "live",
  SUSPENDED: "degraded",
  REVOKED: "critical",
};

const PACKET_STATUS_TONE: Record<AipEvidencePacket["toolExecuted"]["status"], string> = {
  SUCCESS: "text-emerald-300",
  FAILED: "text-amber-300",
  BLOCKED_BY_POLICY: "text-red-300",
};

function seqBadge(n: number): string {
  return `#${String(n).padStart(3, "0")}`;
}

function Field({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className={cn(TYPE.caption)}>{label}</div>
      <div className={cn(TYPE.body, mono && "font-mono", INK.primary, "truncate")} title={value}>
        {value}
      </div>
    </div>
  );
}

export default function AgentAccountabilityTab({
  registry = agentRegistry,
  service = accountability,
  store = nexoraStore,
  verifier = nexoraVerifier,
  className,
}: AgentAccountabilityTabProps) {
  useSyncExternalStore(
    useCallback((cb: () => void) => registry.subscribe(cb), [registry]),
    () => registry.snapshotVersion,
  );
  const roster = registry.listAgents();
  const agent = roster[roster.length - 1];
  const agentDidStr = agent ? toAgentDid(agent.agentId) : null;

  const [anchors, setAnchors] = useState<NexoraLifecycleAnchor[]>([]);
  const [packets, setPackets] = useState<AipEvidencePacket[]>([]);
  const [entries, setEntries] = useState<AgentActionLog[]>([]);
  const [report, setReport] = useState<AgentVerificationReport | null>(null);
  const [actionAudit, setActionAudit] = useState<AuditVerification | null>(null);
  const [expandedAnchor, setExpandedAnchor] = useState<string | null>(null);
  const [inspected, setInspected] = useState<AipEvidencePacket | null>(null);

  const refresh = useCallback(async () => {
    if (!agentDidStr || !agent) return;
    const [a, p, e, v] = await Promise.all([
      store.listAnchorsForAgent(agentDidStr),
      store.listPacketsForAgent(agentDidStr),
      service.history(agent.agentId),
      service.verifyAgentAuditTrail(agent.agentId),
    ]);
    // Chain math through the hybrid runner: the Rust WASM core when the
    // built module loads, Web Crypto otherwise.
    const r = await verifyAgentRecords(a, p);
    setAnchors(a);
    setPackets(p);
    setEntries(e);
    setReport(r);
    setActionAudit(v);
  }, [agentDidStr, agent, store, service]);

  useEffect(() => {
    if (!agentDidStr) return;
    void refresh();
    const unsubs = [
      service.subscribe(() => void refresh()),
      governanceFeed.subscribe(() => void refresh()),
    ];
    return () => unsubs.forEach((u) => u());
  }, [agentDidStr, service, refresh]);

  // The first sequence any tier reports broken — what the breach banner names.
  const breach = useMemo(() => {
    const seqs: Array<{ tier: string; seq: number; reason: string }> = [];
    if (report && !report.anchors.valid) {
      seqs.push({ tier: "NEXORA anchor chain", seq: report.anchors.brokenSequence ?? 0, reason: report.anchors.reason ?? "" });
    }
    if (report && !report.packets.valid) {
      seqs.push({ tier: "AIP evidence chain", seq: report.packets.brokenSequence ?? 0, reason: report.packets.reason ?? "" });
    }
    if (report && report.anchors.valid && report.packets.valid && !report.crossConsistent) {
      seqs.push({ tier: "cross-reference", seq: 0, reason: report.findings.join("; ") });
    }
    if (actionAudit && !actionAudit.valid) {
      seqs.push({ tier: "action ledger", seq: actionAudit.brokenAtSequence, reason: actionAudit.reason });
    }
    return seqs.length ? seqs : null;
  }, [report, actionAudit]);

  const feed = useMemo(() => [...packets].reverse(), [packets]);

  const exportDossier = async () => {
    if (!agent || !actionAudit) return;
    const dossier = await buildCompliantMissionDossier({
      identity: agent,
      lifecycleAnchors: anchors,
      evidencePackets: packets,
      actionLedger: entries,
      actionChainVerification: actionAudit,
    });
    downloadTextFile(
      `${agent.agentId}-certified-mission-dossier.json`,
      "application/json",
      toCertifiedDossierJson(dossier),
    );
  };
  const exportComplianceMatrix = async () => {
    if (!agent || !actionAudit) return;
    const dossier = await buildCompliantMissionDossier({
      identity: agent,
      lifecycleAnchors: anchors,
      evidencePackets: packets,
      actionLedger: entries,
      actionChainVerification: actionAudit,
    });
    downloadTextFile(
      `${agent.agentId}-compliance-matrix.json`,
      "application/json",
      exportRegulatoryComplianceMatrix(dossier),
    );
  };
  const exportForensic = async () => {
    if (!agentDidStr) return;
    downloadTextFile(
      `${agent?.agentId}-aip-forensic-stream.jsonl`,
      "application/x-ndjson",
      await verifier.exportAipDossierJsonl(agentDidStr),
    );
  };
  const exportCsv = () => {
    if (!agent || !actionAudit) return;
    downloadTextFile(
      `${agent.agentId}-after-action.csv`,
      "text/csv",
      toAuditCsv(entries, actionAudit),
    );
  };

  if (!agent) {
    return (
      <div className={cn("p-6", className)}>
        <div className={cn(TYPE.body, INK.muted)}>
          No agent has onboarded this session. Arm the voice copilot — its
          genesis, delegation, and every governed action will appear here as
          they are sealed.
        </div>
      </div>
    );
  }

  const tone = STATUS[CREDENTIAL_TONE[agent.revocationStatus]];
  const chainVerified =
    report !== null && report.anchors.valid && report.packets.valid && report.crossConsistent;

  return (
    <div className={cn("flex flex-col gap-3 p-3 overflow-y-auto", className)}>
      {/* Integrity breach banner — shown the instant any tier fails. */}
      {breach && (
        <div className={cn("border border-red-400/60 bg-red-500/10 rounded-md px-3 py-2")}>
          {breach.map((b) => (
            <div key={b.tier} className={cn(TYPE.body, "text-red-300 font-mono")}>
              ⚠️ INTEGRITY BREACH DETECTED{b.seq > 0 ? ` AT SEQUENCE #${b.seq}` : ""} — {b.tier}
              {b.reason ? `: ${b.reason}` : ""}
            </div>
          ))}
        </div>
      )}

      {/* ── A. Identity dossier ─────────────────────────────────────────── */}
      <section className={cn(SURFACE.sunken, "rounded-md p-3")}>
        <div className="flex items-center gap-2 mb-2">
          <Fingerprint className={cn("w-4 h-4", tone.text)} />
          <span className={cn(TYPE.label, INK.secondary)}>Active agent identity dossier</span>
          <span className={cn("flex items-center gap-1.5 ml-auto", tone.text)}>
            <span className={cn("w-1.5 h-1.5 rounded-full", tone.dot)} />
            <span className={TYPE.label}>{agent.revocationStatus}</span>
          </span>
        </div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2">
          <Field label="DECENTRALIZED IDENTIFIER (DID)" value={agent.did} />
          <Field label="SUPERVISOR DID" value={agent.supervisorDid} />
          <Field label="MODEL DIGEST (SHA-256)" value={hashPill(agent.modelDigest)} />
          <Field label="SYSTEM GUARDRAIL HASH" value={hashPill(agent.systemPromptHash)} />
          <Field label="ENGINE / ENCLAVE" value={`${agent.modelEngine} · ${agent.enclaveType}`} />
          <div>
            <div className={cn(TYPE.caption)}>CLEARANCE LEVEL</div>
            <span
              className={cn(
                TYPE.label,
                "inline-block mt-0.5 px-1.5 py-0.5 rounded border border-cyan-500/30",
                INK.primary,
              )}
            >
              {agent.clearanceLevel}
            </span>
          </div>
          <Field label="DEPARTMENT / ORGANIZATION" value={`${agent.department} · ${agent.organization}`} />
          <Field label="CREDENTIAL WINDOW" value={`${agent.issuedAtUtc.slice(0, 19)}Z → ${agent.expiresAtUtc.slice(0, 19)}Z`} />
        </div>
      </section>

      {/* ── B. NEXORA lifecycle chain ───────────────────────────────────── */}
      <section className={cn(SURFACE.sunken, "rounded-md p-3")}>
        <div className="flex items-center gap-2 mb-2">
          <Link2 className={cn("w-4 h-4", INK.secondary)} />
          <span className={cn(TYPE.label, INK.secondary)}>NEXORA monotonic lifecycle chain</span>
          {report &&
            (report.anchors.valid ? (
              <span className={cn(TYPE.caption, "text-emerald-300 flex items-center gap-1")}>
                <ShieldCheck className="w-3 h-3" /> [CHAIN: VERIFIED · {report.anchors.total} ANCHORS]
              </span>
            ) : (
              <span className={cn(TYPE.caption, "text-red-300 flex items-center gap-1")}>
                <ShieldOff className="w-3 h-3" /> [CHAIN: BROKEN @ #{report.anchors.brokenSequence}]
              </span>
            ))}
        </div>
        {anchors.length === 0 && (
          <div className={cn(TYPE.body, INK.muted)}>No lifecycle anchors yet.</div>
        )}
        <ol className="max-h-56 overflow-y-auto pr-1">
          {anchors.map((a, i) => {
            const open = expandedAnchor === a.anchorId;
            const revoked = a.anchorType === "AUTHORITY_REVOCATION";
            return (
              <li key={a.anchorId} className="relative pl-4">
                {/* Connector line of the step tracker. */}
                {i < anchors.length - 1 && (
                  <span className="absolute left-[5px] top-4 bottom-0 w-px bg-cyan-500/25" />
                )}
                <span
                  className={cn(
                    "absolute left-0 top-1.5 w-[11px] h-[11px] rounded-full border",
                    revoked ? "border-red-400 bg-red-500/30" : "border-cyan-400/60 bg-cyan-500/20",
                  )}
                />
                <button
                  type="button"
                  onClick={() => setExpandedAnchor(open ? null : a.anchorId)}
                  className="w-full text-left py-1 flex items-baseline gap-2"
                  title={open ? "Collapse anchor" : "Expand anchor"}
                >
                  <span className={cn(TYPE.body, "font-mono", revoked ? "text-red-300" : INK.primary)}>
                    [{seqBadge(a.sequenceNumber)} {a.anchorType}]
                  </span>
                  <span className={cn(TYPE.caption, INK.muted, "ml-auto shrink-0")}>
                    {a.timestampUtc.slice(11, 19)}Z
                  </span>
                </button>
                {open && (
                  <div className={cn("mb-2 grid grid-cols-1 gap-1", TYPE.body, "font-mono", INK.secondary)}>
                    <div className={cn(TYPE.caption)}>TIMESTAMP UTC</div>
                    <div>{a.timestampUtc}</div>
                    <div className={cn(TYPE.caption)}>MONOTONIC SEQUENCE · ACTOR</div>
                    <div>
                      {a.sequenceNumber} · <span className="break-all">{a.actorDid}</span>
                    </div>
                    <div className={cn(TYPE.caption)}>PREVIOUS ANCHOR HASH</div>
                    <div className="break-all">{a.previousAnchorHash}</div>
                    <div className={cn(TYPE.caption)}>ANCHOR HASH (CRYPTOGRAPHIC SEAL)</div>
                    <div className="break-all">{a.anchorHash}</div>
                    <div className={cn(TYPE.caption)}>PAYLOAD</div>
                    <pre className="text-[10px] whitespace-pre-wrap break-all">
                      {JSON.stringify(a.payload, null, 2)}
                    </pre>
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      </section>

      {/* ── C. AIP evidence packet inspector ────────────────────────────── */}
      <section className={cn(SURFACE.sunken, "rounded-md p-3")}>
        <div className="flex items-center gap-2 mb-2">
          <ScrollText className={cn("w-4 h-4", INK.secondary)} />
          <span className={cn(TYPE.label, INK.secondary)}>AIP evidence packet inspector</span>
          {report &&
            (chainVerified ? (
              <span className={cn(TYPE.caption, "text-emerald-300 flex items-center gap-1")}>
                <ShieldCheck className="w-3 h-3" /> [CHAIN: VERIFIED · CROSS-CONSISTENT]
              </span>
            ) : (
              <span className={cn(TYPE.caption, "text-red-300 flex items-center gap-1")}>
                <ShieldOff className="w-3 h-3" /> [INTEGRITY: COMPROMISED]
              </span>
            ))}
          {report && (
            <span
              className={cn(TYPE.caption, INK.muted)}
              title={`Merkle root ${report.packetMerkleRoot}`}
            >
              ENGINE {report.engine === "wasm" ? "RUST/WASM" : "WEB CRYPTO"}
            </span>
          )}
          <span className={cn(TYPE.caption, INK.muted, "ml-auto")}>{packets.length}</span>
        </div>
        {feed.length === 0 && (
          <div className={cn(TYPE.body, INK.muted)}>
            No governed actions sealed yet — packets append here live.
          </div>
        )}
        <ol className="max-h-72 overflow-y-auto space-y-1.5 pr-1">
          {feed.map((p) => {
            const rowBroken =
              report !== null &&
              !report.packets.valid &&
              p.sequenceNumber >= (report.packets.brokenSequence ?? Infinity);
            const multisig = p.toolExecuted.supervisorCoSignature !== undefined;
            return (
              <li key={p.id}>
                <button
                  type="button"
                  onClick={() => setInspected(p)}
                  className={cn(
                    "w-full text-left rounded border px-2 py-1.5",
                    rowBroken
                      ? "border-red-400/50 bg-red-500/5"
                      : "border-cyan-500/15 hover:border-cyan-400/40",
                  )}
                  title="Open packet deep-dive"
                >
                  <div className="flex items-baseline gap-2">
                    <span className={cn(TYPE.caption, INK.muted)}>[{seqBadge(p.sequenceNumber)}]</span>
                    <span className={cn(TYPE.body, "font-mono", INK.primary)}>
                      {p.toolExecuted.name}
                    </span>
                    <span className={cn(TYPE.caption, PACKET_STATUS_TONE[p.toolExecuted.status])}>
                      {p.toolExecuted.status}
                    </span>
                    <span className={cn(TYPE.caption, INK.muted, "ml-auto shrink-0")}>
                      {p.timestampUtc.slice(11, 19)}Z
                    </span>
                  </div>
                  <div className={cn(TYPE.caption, INK.secondary, "truncate")}>
                    “{p.rawPrompt}”
                  </div>
                  <div className="flex items-center gap-2 font-mono">
                    <span className={cn(TYPE.caption, INK.muted)} title={`preStateHash ${p.preStateHash}`}>
                      PRE {hashPill(p.preStateHash)}
                    </span>
                    <span className={cn(TYPE.caption, INK.muted)}>→</span>
                    <span className={cn(TYPE.caption, INK.muted)} title={`postStateHash ${p.postStateHash}`}>
                      POST {hashPill(p.postStateHash)}
                    </span>
                    <span
                      className={cn(
                        TYPE.caption,
                        "ml-auto shrink-0",
                        multisig ? "text-emerald-300" : INK.secondary,
                      )}
                    >
                      {multisig ? "VERIFIED_MULTISIG" : "AUTONOMOUS_POLICY_PERMITTED"}
                    </span>
                  </div>
                </button>
              </li>
            );
          })}
        </ol>

        {/* Packet deep-dive. */}
        {inspected && (
          <div className={cn(SURFACE.raised, "rounded-md mt-2 max-h-80 flex flex-col")}>
            <div className="flex items-center gap-2 px-3 py-2 border-b border-cyan-500/15">
              <span className={cn(TYPE.label, INK.secondary)}>
                Packet [{seqBadge(inspected.sequenceNumber)}] · {inspected.toolExecuted.name}
              </span>
              <button type="button" onClick={() => setInspected(null)} className="ml-auto" title="Close">
                <X className={cn("w-3.5 h-3.5", INK.muted)} />
              </button>
            </div>
            <div className={cn("overflow-y-auto px-3 py-2 space-y-2 font-mono", TYPE.body, INK.secondary)}>
              <div>
                <div className={cn(TYPE.caption)}>DELEGATION PATH (ROOT → AGENT)</div>
                <div className="break-all">
                  {inspected.delegationPath.length ? inspected.delegationPath.join(" → ") : "(no authority — blocked)"}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className={cn(TYPE.caption)}>PRE-STATE SHA-256</div>
                  <div className="break-all">{inspected.preStateHash}</div>
                </div>
                <div>
                  <div className={cn(TYPE.caption)}>POST-STATE SHA-256</div>
                  <div className="break-all">{inspected.postStateHash}</div>
                </div>
              </div>
              <div>
                <div className={cn(TYPE.caption)}>LIFECYCLE BINDING (ANCHOR-CHAIN HEAD AT EXECUTION)</div>
                <div className="break-all">{inspected.anchorHash || "(unanchored)"}</div>
              </div>
              <div>
                <div className={cn(TYPE.caption)}>PACKET CHAIN HASH</div>
                <div className="break-all">{inspected.packetHash}</div>
              </div>
              <div>
                <div className={cn(TYPE.caption)}>RAW PACKET JSON</div>
                <pre className="text-[10px] whitespace-pre-wrap break-all">
                  {JSON.stringify(inspected, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* ── Regulatory conformity badge ─────────────────────────────────── */}
      {/* The words are earned, not decorative: VERIFIED/SEALED/COMPLIANT
          only while every chain verifies right now; a breach flips all
          three to their honest negative. */}
      <section className={cn(SURFACE.sunken, "rounded-md px-3 py-2 flex flex-col gap-1")}>
        <span className={cn(TYPE.caption)}>REGULATORY CONFORMITY</span>
        <div className={cn(TYPE.body, "font-mono flex flex-wrap gap-x-4 gap-y-1")}>
          <span className={INK.secondary}>
            NIST AI RMF: GOVERN-1.2 / MANAGE-2.4{" "}
            <span className={chainVerified ? "text-emerald-300" : "text-red-300"}>
              [{chainVerified ? "VERIFIED" : "UNVERIFIED"}]
            </span>
          </span>
          <span className={INK.secondary}>
            EU AI Act: Art. 12 &amp; 14 Human Oversight{" "}
            <span className={chainVerified ? "text-emerald-300" : "text-red-300"}>
              [{chainVerified ? "SEALED" : "BROKEN"}]
            </span>
          </span>
          <span className={INK.secondary}>
            ISO 42001: Clause 9 Continuous Audit{" "}
            <span className={chainVerified ? "text-emerald-300" : "text-red-300"}>
              [{chainVerified ? "COMPLIANT" : "NON-CONFORMANT"}]
            </span>
          </span>
        </div>
      </section>

      {/* ── D. Live verification & download suite ───────────────────────── */}
      <section className="flex items-center gap-3 flex-wrap">
        <button
          type="button"
          onClick={() => void exportDossier()}
          disabled={entries.length === 0 || !actionAudit}
          className={cn(
            TYPE.body,
            "flex items-center gap-1.5 rounded border border-cyan-500/30 px-2.5 py-1.5",
            "hover:border-cyan-400/60 hover:text-cyan-200 disabled:opacity-40",
            INK.secondary,
          )}
          title="Genesis + full NEXORA anchor tree + all AIP evidence packets + action ledger, certified by a recomputable root digest"
        >
          <FileJson className="w-3.5 h-3.5" /> 📜 Export Full Certified Mission Dossier (.json)
        </button>
        <button
          type="button"
          onClick={() => void exportForensic()}
          disabled={packets.length === 0}
          className={cn(
            TYPE.body,
            "flex items-center gap-1.5 rounded border border-cyan-500/30 px-2.5 py-1.5",
            "hover:border-cyan-400/60 hover:text-cyan-200 disabled:opacity-40",
            INK.secondary,
          )}
          title="Byte-faithful line-delimited AIP packet stream for automated external verifiers"
        >
          <Download className="w-3.5 h-3.5" /> 📥 Download Forensic Stream (.jsonl)
        </button>
        <button
          type="button"
          onClick={() => void exportComplianceMatrix()}
          disabled={entries.length === 0 || !actionAudit}
          className={cn(
            TYPE.body,
            "flex items-center gap-1.5 rounded border border-cyan-500/30 px-2.5 py-1.5",
            "hover:border-cyan-400/60 hover:text-cyan-200 disabled:opacity-40",
            INK.secondary,
          )}
          title="NIST AI RMF / EU AI Act / ISO 42001 control mappings for every sealed action, tethered to the dossier's root digest"
        >
          <FileJson className="w-3.5 h-3.5" /> 📜 Export Compliance Matrix (.json)
        </button>
        <button
          type="button"
          onClick={exportCsv}
          disabled={entries.length === 0 || !actionAudit}
          className={cn(
            TYPE.body,
            "flex items-center gap-1.5 rounded border border-cyan-500/30 px-2.5 py-1.5",
            "hover:border-cyan-400/60 hover:text-cyan-200 disabled:opacity-40",
            INK.secondary,
          )}
          title="RFC-4180 after-action table with per-row integrity verdicts"
        >
          <Table className="w-3.5 h-3.5" /> 📊 Download After-Action Table (.csv)
        </button>
      </section>
    </div>
  );
}
