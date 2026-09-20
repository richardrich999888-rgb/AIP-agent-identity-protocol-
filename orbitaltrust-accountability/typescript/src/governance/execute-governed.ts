/**
 * The ergonomic governed-execution facade for UI and tool callers.
 *
 *   executeGoverned({
 *     agentDid: "did:syntriass:agent:AGT-0481-JARVIS",
 *     toolName: "screen_conjunction_threats",
 *     parameters: { ... },
 *   })
 *
 * Callers name a tool and its parameters; everything else — identity
 * resolution, policy evaluation, capability dispatch, state snapshot
 * hashing, AIP evidence sealing, ledger commit — happens inside the
 * governed pipeline this facade routes into. With the WASM bridge
 * initialized, every digest in that pipeline (payload hashes, snapshot
 * comparisons, chain seals) is computed by the Rust core through the
 * telemetry crypto seam.
 *
 * The console registers its live executor when the tactical capabilities
 * come up (App's capability effect) and unregisters on teardown; before
 * registration the facade refuses honestly rather than pretending a
 * console exists.
 */

import type { ToolResult } from "../agent/tactical-tools";

export interface GovernedExecutionRequest {
  /** The acting agent's DID. Optional: the console has one active agent,
   * and the registered executor resolves it; a mismatching DID is refused
   * rather than silently reattributed. */
  agentDid?: string;
  toolName: string;
  parameters: Record<string, unknown>;
  /** The operator utterance or UI intent, recorded as the ledger's
   * rawPrompt. Defaults to naming the tool. */
  transcript?: string;
}

/** The live pipeline behind the facade: dispatches one tool call under
 * full governance and returns the spoken-style result. */
export type GovernedExecutor = (
  call: { name: string; args: Record<string, unknown> },
  transcript: string,
) => Promise<ToolResult>;

interface RegisteredExecutor {
  execute: GovernedExecutor;
  /** DID of the agent the executor acts as, for the mismatch check. */
  agentDid: string;
}

let registered: RegisteredExecutor | null = null;

/** Registers the console's live executor. Returns the unregister function;
 * a later registration simply replaces an earlier one (last console wins,
 * matching how the capability surface rebuilds on globe remounts). */
export function registerGovernedExecutor(
  agentDid: string,
  execute: GovernedExecutor,
): () => void {
  const record: RegisteredExecutor = { execute, agentDid };
  registered = record;
  return () => {
    if (registered === record) registered = null;
  };
}

/** Executes one tool call under full governance. Never throws: every
 * failure mode is an `ok: false` result, like the rest of the dispatch
 * stack. */
export async function executeGoverned(
  request: GovernedExecutionRequest,
): Promise<ToolResult> {
  const executor = registered;
  if (!executor) {
    return {
      ok: false,
      summary: "No governed executor is registered — the tactical console is not up.",
    };
  }
  if (request.agentDid !== undefined && request.agentDid !== executor.agentDid) {
    return {
      ok: false,
      summary: `No governed executor for ${request.agentDid}; the active agent is ${executor.agentDid}.`,
    };
  }
  return executor.execute(
    { name: request.toolName, args: request.parameters },
    request.transcript ?? `[console] ${request.toolName}`,
  );
}
