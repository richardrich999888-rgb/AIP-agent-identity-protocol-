/**
 * The ACCOUNTABILITY console tab — the forensic record as a first-class
 * section of the sentinel UI, not a modal an operator has to know to open.
 *
 * Two columns over the live governance stores:
 *
 *   * left — the Agent Accountability & NEXORA Ledger view: identity
 *     dossier, lifecycle chain, AIP evidence packet inspector, regulatory
 *     conformity, and the export suite;
 *   * right — the live action ledger: every governed tool call as it seals,
 *     newest first, with its chain verdict.
 *
 * Both subscribe to the same singletons the tactical view writes into, so a
 * JARVIS command spoken on the TACTICAL tab appears here the moment its
 * packet seals — the tab tracks and records every action the agent takes,
 * whichever section the operator is watching.
 */

import { ScrollText } from "lucide-react";

import { cn } from "../lib/cn";
import { INK, SURFACE, TYPE } from "../lib/design";
import AgentAccountabilityTab from "./AgentAccountabilityTab";
import AgentActionFeedHUD from "./AgentActionFeedHUD";

export default function AccountabilityConsole({ className }: { className?: string }) {
  return (
    <div className={cn(SURFACE.raised, "rounded-md flex flex-col font-mono overflow-hidden", className)}>
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-cyan-500/20 shrink-0">
        <ScrollText className={cn("w-4 h-4", INK.secondary)} />
        <span className={cn(TYPE.label, INK.primary)}>
          Agent accountability &amp; NEXORA ledger
        </span>
        <span className={cn(TYPE.caption, INK.muted)}>
          Every governed action — tracked, sealed, verified on every read
        </span>
      </div>
      <div className="flex-1 min-h-0 flex">
        <AgentAccountabilityTab className="flex-1 min-w-0" />
        <div className="w-[22rem] shrink-0 border-l border-cyan-500/15 overflow-y-auto p-3">
          <AgentActionFeedHUD className="w-full" />
        </div>
      </div>
    </div>
  );
}
