/**
 * The digital employee ID card, and its audit drawer.
 *
 * # What the chip is for
 *
 * When an autonomous agent can move the camera, task a sensor, or screen the
 * catalogue, the operator must be able to answer "who is acting on this
 * console, under whose authority, and with what standing" at a glance — the
 * same reason human staff wear badges. The chip shows the active agent's
 * identity, department, clearance, supervising human, and credential state.
 * No agent onboarded → nothing rendered: the badge is evidence of a fact,
 * not furniture.
 *
 * # Status is never colour alone
 *
 * Per the console's visualisation rules the state dot always travels with
 * its word (ACTIVE / SUSPENDED / REVOKED), and the chain-verification badge
 * says VERIFIED or BROKEN in text — a colour-blind operator reads the same
 * facts.
 */

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { Download, Fingerprint, ShieldCheck, ShieldOff } from "lucide-react";

import { cn } from "../lib/cn";
import { INK, STATUS, SURFACE, TYPE, type Status } from "../lib/design";
import type { AgentEmployeeProfile } from "../telemetry/agent-identity/agent-profile";
import type { IdentityRegistry } from "../telemetry/agent-identity/identity-registry";
import type { AccountabilityService } from "../telemetry/agent-accountability/accountability-service";
import type {
  AgentActionLog,
  AuditVerification,
} from "../telemetry/agent-accountability/types";
import { downloadAuditDossier } from "../telemetry/agent-accountability/exporter";
import { accountability, agentRegistry } from "../telemetry/governance";

export interface AgentBadgeHUDProps {
  /** Defaults to the console's governance singletons. */
  registry?: IdentityRegistry;
  service?: AccountabilityService;
  className?: string;
}

/** Credential state → console status vocabulary. SUSPENDED is degraded (a
 * reversible operator hold), REVOKED is critical (the kill-switch fired). */
const CREDENTIAL_TONE: Record<AgentEmployeeProfile["revocationStatus"], Status> = {
  ACTIVE: "live",
  SUSPENDED: "degraded",
  REVOKED: "critical",
};

export default function AgentBadgeHUD({
  registry = agentRegistry,
  service = accountability,
  className,
}: AgentBadgeHUDProps) {
  // Subscribing to the version counter (not the roster length) means a
  // revocation — which replaces a profile without changing the count — still
  // re-renders the chip red.
  useSyncExternalStore(
    useCallback((cb: () => void) => registry.subscribe(cb), [registry]),
    () => registry.snapshotVersion,
  );
  // The badge shows the most recently onboarded agent; a multi-agent roster
  // view belongs in a panel, not a corner chip.
  const roster = registry.listAgents();
  const agent = roster[roster.length - 1];

  const [open, setOpen] = useState(false);
  const [history, setHistory] = useState<AgentActionLog[]>([]);
  const [audit, setAudit] = useState<AuditVerification | null>(null);

  const agentId = agent?.agentId;
  const refresh = useCallback(async () => {
    if (!agentId) return;
    setHistory(await service.history(agentId));
    setAudit(await service.verifyAgentAuditTrail(agentId));
  }, [service, agentId]);

  // Live feed: re-pull history and re-verify the chain on every append while
  // the drawer is open. Verification is cheap at HUD scale (one SHA-256 per
  // entry), and a badge that says VERIFIED must mean "verified now".
  useEffect(() => {
    if (!open || !agentId) return;
    void refresh();
    return service.subscribe(() => void refresh());
  }, [open, agentId, service, refresh]);

  const tone = useMemo(
    () => (agent ? STATUS[CREDENTIAL_TONE[agent.revocationStatus]] : null),
    [agent],
  );

  if (!agent || !tone) return null;

  return (
    <div className={cn("flex flex-col items-start gap-2", className)}>
      {open && (
        <div className={cn(SURFACE.raised, "rounded-md w-[24rem] max-h-72 flex flex-col")}>
          <div className="flex items-center gap-2 px-3 py-2 border-b border-cyan-500/15">
            <span className={cn(TYPE.label, INK.secondary)}>Agent audit ledger</span>
            <ChainBadge audit={audit} />
            <div className="ml-auto flex items-center gap-2">
              <button
                type="button"
                title="Download .jsonl dossier"
                className={cn(TYPE.caption, "flex items-center gap-1 hover:text-cyan-300")}
                onClick={() => downloadAuditDossier(history, "jsonl", agent.agentId)}
              >
                <Download className="w-3 h-3" /> jsonl
              </button>
              <button
                type="button"
                title="Download .csv dossier"
                className={cn(TYPE.caption, "flex items-center gap-1 hover:text-cyan-300")}
                onClick={() => downloadAuditDossier(history, "csv", agent.agentId)}
              >
                <Download className="w-3 h-3" /> csv
              </button>
            </div>
          </div>
          <ol className="overflow-y-auto px-3 py-2 space-y-1.5">
            {history.length === 0 && (
              <li className={cn(TYPE.body, INK.muted)}>No actions recorded yet.</li>
            )}
            {history.map((e) => (
              <li key={e.eventId} className="flex items-baseline gap-2">
                <span className={cn(TYPE.caption, "shrink-0 w-8 text-right")}>
                  #{e.sequenceNumber}
                </span>
                <span className={cn(TYPE.body, "font-mono", INK.primary)}>
                  {e.toolExecuted.name}
                </span>
                <span
                  className={cn(
                    TYPE.caption,
                    e.toolExecuted.executionStatus === "SUCCESS" && "text-emerald-300",
                    e.toolExecuted.executionStatus === "FAILED" && "text-amber-300",
                    e.toolExecuted.executionStatus === "BLOCKED_BY_POLICY" &&
                      "text-red-300",
                  )}
                >
                  {e.toolExecuted.executionStatus}
                </span>
                <span className={cn(TYPE.caption, INK.muted, "ml-auto shrink-0")}>
                  {e.timestampUtc.slice(11, 19)}Z
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}

      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title={open ? "Close audit ledger" : "Open audit ledger"}
        className={cn(
          SURFACE.base,
          "rounded-md px-3 py-2 flex items-center gap-3 text-left pointer-events-auto",
          tone.border,
        )}
      >
        <Fingerprint className={cn("w-4 h-4", tone.text)} />
        <div className="flex flex-col">
          <span className={cn(TYPE.body, "font-mono", INK.primary)}>
            {agent.agentName}
          </span>
          <span className={cn(TYPE.caption)}>
            {agent.agentId} · {agent.department} · {agent.clearanceLevel}
          </span>
          <span className={cn(TYPE.caption, INK.muted)}>
            SUPERVISOR {agent.supervisorOperatorId}
          </span>
        </div>
        <span className={cn("flex items-center gap-1.5 ml-2", tone.text)}>
          <span className={cn("w-1.5 h-1.5 rounded-full", tone.dot)} />
          <span className={TYPE.label}>{agent.revocationStatus}</span>
        </span>
      </button>
    </div>
  );
}

function ChainBadge({ audit }: { audit: AuditVerification | null }) {
  if (!audit) {
    return <span className={cn(TYPE.caption, INK.muted)}>[CHAIN: CHECKING…]</span>;
  }
  if (audit.valid) {
    return (
      <span className={cn(TYPE.caption, "text-emerald-300 flex items-center gap-1")}>
        <ShieldCheck className="w-3 h-3" /> [CHAIN: VERIFIED]
      </span>
    );
  }
  return (
    <span
      className={cn(TYPE.caption, "text-red-300 flex items-center gap-1")}
      title={audit.reason}
    >
      <ShieldOff className="w-3 h-3" /> [CHAIN: BROKEN @ #{audit.brokenAtSequence}]
    </span>
  );
}
