/**
 * The live agent action feed: every governed tool invocation, as it lands
 * on the ledger, with its cryptographic standing in plain sight.
 *
 * # Why the feed exists
 *
 * The badge answers "who is acting"; this answers "what is it doing, right
 * now, and can I trust the record". Cards append the moment the
 * accountability service seals an entry — the component subscribes to the
 * ledger, it never polls — and the chain is re-verified on every append,
 * because a feed that says VERIFIED must mean verified *now*, not at mount.
 *
 * # Status is never colour alone
 *
 * SUCCESS/BLOCKED_BY_POLICY/FAILED each carry their word beside their
 * colour, and the integrity banner says VERIFIED or COMPROMISED in text —
 * per the console's standing visualisation rules.
 *
 * # The export buttons live here
 *
 * The moment an operator is looking at the feed is the moment they want the
 * dossier: JSONL for byte-faithful forensic replay, CSV for the after-action
 * table, and the certified JSON bundle whose root digest a verifier can
 * recompute offline.
 */

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import {
  ChevronDown,
  ChevronUp,
  Download,
  FileJson,
  ScrollText,
  ShieldCheck,
  ShieldOff,
  Table,
  X,
} from "lucide-react";

import { cn } from "../lib/cn";
import { INK, STATUS, SURFACE, TYPE } from "../lib/design";
import { officerDid } from "../telemetry/agent-identity/agent-profile";
import type { IdentityRegistry } from "../telemetry/agent-identity/identity-registry";
import type { AccountabilityService } from "../telemetry/agent-accountability/accountability-service";
import type {
  AgentActionLog,
  AuditVerification,
  ConsoleStateSnapshot,
  ExecutionStatus,
} from "../telemetry/agent-accountability/types";
import {
  buildMissionDossier,
  downloadTextFile,
  toAuditCsv,
  toCertifiedDossierJson,
  toJsonl,
} from "../telemetry/agent-accountability/exporter";
import { accountability, agentRegistry } from "../telemetry/governance";

export interface AgentActionFeedHUDProps {
  /** Defaults to the console's governance singletons. */
  registry?: IdentityRegistry;
  service?: AccountabilityService;
  /** Extra change emitters to follow (e.g. a GovernedExecutionFunnel) —
   * anything with the subscribe(listener) => unsubscribe shape. */
  changeSources?: Array<{ subscribe(listener: () => void): () => void }>;
  className?: string;
}

const STATUS_TONE: Record<ExecutionStatus, string> = {
  SUCCESS: "text-emerald-300",
  FAILED: "text-amber-300",
  BLOCKED_BY_POLICY: "text-red-300",
};

function seqBadge(n: number): string {
  return `[#${String(n).padStart(4, "0")}]`;
}

function hashPill(hash: string): string {
  return hash ? `${hash.slice(0, 10)}…` : "—";
}

function StateBlock({ label, state }: { label: string; state: ConsoleStateSnapshot | undefined }) {
  return (
    <div>
      <div className={cn(TYPE.caption)}>{label}</div>
      {state ? (
        <div className={cn(TYPE.body, "font-mono", INK.secondary)}>
          <div>
            CAM {state.cameraCoords.map((c) => c.toFixed(2)).join(" / ")}
          </div>
          <div>SHADER {state.activeShader}</div>
          <div>TARGET {state.selectedTargetId ?? "none"}</div>
        </div>
      ) : (
        <div className={cn(TYPE.body, INK.muted)}>not captured (nothing ran)</div>
      )}
    </div>
  );
}

export default function AgentActionFeedHUD({
  registry = agentRegistry,
  service = accountability,
  changeSources,
  className,
}: AgentActionFeedHUDProps) {
  // Re-render on registry mutations so clearance badges track revocations.
  useSyncExternalStore(
    useCallback((cb: () => void) => registry.subscribe(cb), [registry]),
    () => registry.snapshotVersion,
  );
  const roster = registry.listAgents();
  const agent = roster[roster.length - 1];

  const [open, setOpen] = useState(true);
  const [entries, setEntries] = useState<AgentActionLog[]>([]);
  const [audit, setAudit] = useState<AuditVerification | null>(null);
  const [inspected, setInspected] = useState<AgentActionLog | null>(null);

  const agentId = agent?.agentId;
  const refresh = useCallback(async () => {
    if (!agentId) return;
    setEntries(await service.history(agentId));
    setAudit(await service.verifyAgentAuditTrail(agentId));
  }, [service, agentId]);

  useEffect(() => {
    if (!agentId) return;
    void refresh();
    const unsubs = [service.subscribe(() => void refresh())];
    for (const src of changeSources ?? []) {
      unsubs.push(src.subscribe(() => void refresh()));
    }
    return () => unsubs.forEach((u) => u());
  }, [agentId, service, changeSources, refresh]);

  // Newest first: the operator's question is "what just happened".
  const feed = useMemo(() => [...entries].reverse(), [entries]);

  const exportJsonl = () =>
    downloadTextFile(
      `${agentId}-actions.jsonl`,
      "application/x-ndjson",
      toJsonl(entries),
    );
  const exportCsv = () => {
    if (!audit) return;
    downloadTextFile(`${agentId}-after-action.csv`, "text/csv", toAuditCsv(entries, audit));
  };
  const exportDossier = async () => {
    if (!audit || !agent) return;
    const dossier = await buildMissionDossier({
      identity: agent,
      actionLedger: entries,
      actionChainVerification: audit,
    });
    downloadTextFile(
      `${agentId}-certified-dossier.json`,
      "application/json",
      toCertifiedDossierJson(dossier),
    );
  };

  if (!agent) return null;

  const tone = STATUS[agent.revocationStatus === "ACTIVE" ? "live" : agent.revocationStatus === "SUSPENDED" ? "degraded" : "critical"];

  return (
    <div className={cn("flex flex-col items-end gap-2 w-[21rem]", className)}>
      <div className={cn(SURFACE.base, "rounded-md w-full")}>
        {/* Header: identity, integrity banner, expand/collapse. */}
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="w-full flex items-center gap-2 px-3 py-2 text-left"
          title={open ? "Collapse action feed" : "Expand action feed"}
        >
          <ScrollText className={cn("w-4 h-4", INK.secondary)} />
          <span className={cn(TYPE.label, INK.secondary)}>Agent action feed</span>
          {audit &&
            (audit.valid ? (
              <span className={cn(TYPE.caption, "text-emerald-300 flex items-center gap-1")}>
                <ShieldCheck className="w-3 h-3" /> [CHAIN: VERIFIED]
              </span>
            ) : (
              <span
                className={cn(TYPE.caption, "text-red-300 flex items-center gap-1")}
                title={audit.reason}
              >
                <ShieldOff className="w-3 h-3" /> [INTEGRITY: COMPROMISED]
              </span>
            ))}
          <span className="ml-auto flex items-center gap-2">
            <span className={cn(TYPE.caption, INK.muted)}>{entries.length}</span>
            {open ? (
              <ChevronDown className={cn("w-3.5 h-3.5", INK.muted)} />
            ) : (
              <ChevronUp className={cn("w-3.5 h-3.5", INK.muted)} />
            )}
          </span>
        </button>

        {open && (
          <>
            {/* Export suite. Disabled until there is something to export —
                an empty dossier certifying nothing would still look official. */}
            <div className="flex items-center gap-2 px-3 pb-2 border-b border-cyan-500/15">
              <button
                type="button"
                onClick={exportJsonl}
                disabled={entries.length === 0}
                className={cn(TYPE.caption, "flex items-center gap-1 hover:text-cyan-300 disabled:opacity-40")}
                title="Byte-faithful forensic stream (.jsonl)"
              >
                <Download className="w-3 h-3" /> Export JSONL
              </button>
              <button
                type="button"
                onClick={exportCsv}
                disabled={entries.length === 0 || !audit}
                className={cn(TYPE.caption, "flex items-center gap-1 hover:text-cyan-300 disabled:opacity-40")}
                title="RFC-4180 after-action table (.csv)"
              >
                <Table className="w-3 h-3" /> Download CSV Report
              </button>
              <button
                type="button"
                onClick={() => void exportDossier()}
                disabled={entries.length === 0 || !audit}
                className={cn(TYPE.caption, "flex items-center gap-1 hover:text-cyan-300 disabled:opacity-40")}
                title="Certified mission dossier with recomputable root digest (.json)"
              >
                <FileJson className="w-3 h-3" /> Certified Dossier
              </button>
            </div>

            <ol className="overflow-y-auto max-h-[48vh] px-2 py-2 space-y-1.5">
              {feed.length === 0 && (
                <li className={cn(TYPE.body, INK.muted, "px-1")}>
                  No governed actions yet — the feed appends live.
                </li>
              )}
              {feed.map((e) => {
                const rowBroken = audit && !audit.valid && e.sequenceNumber >= audit.brokenAtSequence;
                return (
                  <li key={e.eventId}>
                    <button
                      type="button"
                      onClick={() => setInspected(e)}
                      className={cn(
                        "w-full text-left rounded border px-2 py-1.5",
                        rowBroken ? "border-red-400/50 bg-red-500/5" : "border-cyan-500/15 hover:border-cyan-400/40",
                      )}
                      title="Open deep-dive"
                    >
                      <div className="flex items-baseline gap-2">
                        <span className={cn(TYPE.caption, INK.muted)}>{seqBadge(e.sequenceNumber)}</span>
                        <span className={cn(TYPE.body, "font-mono", INK.primary)}>
                          {e.toolExecuted.name}
                        </span>
                        <span className={cn(TYPE.caption, STATUS_TONE[e.toolExecuted.executionStatus])}>
                          {e.toolExecuted.executionStatus}
                        </span>
                        <span className={cn(TYPE.caption, INK.muted, "ml-auto shrink-0")}>
                          {e.timestampUtc.slice(11, 19)}Z
                        </span>
                      </div>
                      <div className={cn(TYPE.caption, INK.secondary, "truncate")}>
                        “{e.rawPrompt}” → {e.interpretedIntent}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={cn(TYPE.caption, INK.muted, "truncate")}>
                          {e.agentDid || e.agentId}
                        </span>
                        <span className={cn(TYPE.caption, tone.text)}>{agent.clearanceLevel}</span>
                        <span
                          className={cn(
                            TYPE.caption,
                            "ml-auto font-mono rounded-full border border-cyan-500/25 px-1.5",
                            INK.muted,
                          )}
                          title={`chainHash ${e.chainHash}`}
                        >
                          #{e.sequenceNumber} · {hashPill(e.chainHash)}
                        </span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ol>
          </>
        )}
      </div>

      {/* Deep-dive drawer for one action. */}
      {inspected && (
        <div className={cn(SURFACE.raised, "rounded-md w-full max-h-[60vh] flex flex-col")}>
          <div className="flex items-center gap-2 px-3 py-2 border-b border-cyan-500/15">
            <span className={cn(TYPE.label, INK.secondary)}>
              Action {seqBadge(inspected.sequenceNumber)} · {inspected.toolExecuted.name}
            </span>
            <button
              type="button"
              onClick={() => setInspected(null)}
              className="ml-auto"
              title="Close deep-dive"
            >
              <X className={cn("w-3.5 h-3.5", INK.muted)} />
            </button>
          </div>
          <div className="overflow-y-auto px-3 py-2 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <StateBlock label="PRE-EXECUTION STATE" state={inspected.preExecutionState} />
              <StateBlock label="POST-EXECUTION STATE" state={inspected.postExecutionState} />
            </div>
            <div>
              <div className={cn(TYPE.caption)}>DELEGATION CHAIN</div>
              <div className={cn(TYPE.body, "font-mono", INK.secondary, "break-all")}>
                {officerDid(inspected.supervisorId)} → {inspected.agentDid || inspected.agentId}
              </div>
            </div>
            <div>
              <div className={cn(TYPE.caption)}>CANONICAL CHAIN HASH</div>
              <div className={cn(TYPE.body, "font-mono", INK.secondary, "break-all")}>
                {inspected.chainHash}
              </div>
            </div>
            <div>
              <div className={cn(TYPE.caption)}>RAW JSON PAYLOAD</div>
              <pre className={cn("text-[10px] font-mono", INK.secondary, "whitespace-pre-wrap break-all")}>
                {JSON.stringify(inspected, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
