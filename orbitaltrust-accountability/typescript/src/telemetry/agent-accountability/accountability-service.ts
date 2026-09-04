/**
 * The accountability service: wraps tool executions with policy enforcement
 * and provenance hashing, and can mathematically verify that a recorded
 * history has not been edited or fabricated.
 *
 * # The chain construction
 *
 * Each entry's `chainHash = SHA-256(previousHash + canonicalPayload)`, where
 * the canonical payload is the entry minus `previousHash` and `chainHash`
 * (the previous hash enters the digest once, as the explicit prefix). The
 * first link's `previousHash` is the published GENESIS_HASH. Editing any
 * historical field changes that entry's payload, therefore its chainHash,
 * therefore the previousHash every later entry was hashed against — one edit
 * breaks every subsequent link, which is what makes the ledger
 * tamper-*evident* rather than merely append-only by convention.
 *
 * # Why the guard is consulted here and not by callers
 *
 * If callers checked policy themselves and then asked this service to log,
 * a denial and its REJECTED_POLICY_VIOLATION record could drift apart — a
 * refactor forgets the log call and blocked actions silently vanish from
 * history. `executeGoverned` is the only path that runs a tool, so the
 * verdict and its ledger entry are produced by the same code motion.
 */

import {
  evaluateToolInvocation,
  type CoSignatureVerifier,
  type PolicyVerdict,
  type RuntimeAttestation,
  type ToolManifest,
} from "../agent-identity/permission-guard";
import type { AgentEmployeeProfile } from "../agent-identity/agent-profile";
import { canonicalJson, sha256Hex, type Jsonish } from "../crypto";
import {
  GENESIS_HASH,
  type AgentActionLog,
  type AuditVerification,
  type ConsoleStateSnapshot,
  type ExecutionStatus,
} from "./types";
import type { LedgerStorage } from "./ledger-storage";

/** One governed invocation request. */
export interface GovernedInvocation {
  profile: AgentEmployeeProfile;
  /** Voice transcript / prompt as received. */
  rawPrompt: string;
  /** Tool-call intent the prompt was interpreted as. */
  interpretedIntent: string;
  toolName: string;
  inputParams: Record<string, unknown>;
  /** Console state at the moment of the request. */
  preExecutionState: ConsoleStateSnapshot;
  /** What the runtime attests to be executing, checked against the signed
   * credential's modelDigest / systemPromptHash. */
  runtimeAttestation?: RuntimeAttestation;
  /** Supervisor multi-sig ticket for tools in the profile's
   * requiresDualKeyAuthorization list. */
  supervisorCoSignature?: string;
  /** The actual effect. Only runs when policy allows. May return the
   * post-execution console state for the record. */
  execute: () => Promise<ConsoleStateSnapshot | void> | ConsoleStateSnapshot | void;
}

export interface GovernedOutcome {
  verdict: PolicyVerdict;
  status: ExecutionStatus;
  entry: AgentActionLog;
}

/** The canonical bytes of an entry: everything except the two chain fields.
 * Exported so the verifier and the writer cannot disagree about them. */
export function entryPayload(
  entry: Omit<AgentActionLog, "previousHash" | "chainHash">,
): string {
  const payload: Jsonish = {
    eventId: entry.eventId,
    sequenceNumber: entry.sequenceNumber,
    timestampUtc: entry.timestampUtc,
    agentId: entry.agentId,
    // Optional/newer fields ride through canonicalJson, which drops
    // undefined keys — so entries sealed before these fields existed still
    // reproduce their original bytes and their chains still verify.
    agentDid: entry.agentDid,
    modelDigest: entry.modelDigest,
    supervisorId: entry.supervisorId,
    supervisorCoSignature: entry.supervisorCoSignature,
    rawPrompt: entry.rawPrompt,
    interpretedIntent: entry.interpretedIntent,
    toolExecuted: {
      name: entry.toolExecuted.name,
      // Params are arbitrary JSON from the caller; the canonical serializer
      // handles nesting, and non-JSON values would have already failed the
      // structured-clone into storage anyway.
      inputParams: entry.toolExecuted.inputParams as Jsonish,
      executionStatus: entry.toolExecuted.executionStatus,
      errorMessage: entry.toolExecuted.errorMessage,
    },
    preExecutionState: snapshotPayload(entry.preExecutionState),
    postExecutionState: entry.postExecutionState
      ? snapshotPayload(entry.postExecutionState)
      : undefined,
  };
  return canonicalJson(payload);
}

function snapshotPayload(s: ConsoleStateSnapshot): Jsonish {
  return {
    cameraCoords: [...s.cameraCoords],
    activeShader: s.activeShader,
    selectedTargetId: s.selectedTargetId,
  };
}

export class AccountabilityService {
  /** Chain tail per agent, so appends do not re-read the whole ledger. */
  private readonly tails = new Map<string, { hash: string; sequence: number }>();
  /** Serializes appends per service so two concurrent invocations cannot
   * both read the same tail and fork the chain. */
  private queue: Promise<unknown> = Promise.resolve();
  private readonly listeners = new Set<() => void>();

  constructor(
    private readonly storage: LedgerStorage,
    private readonly manifest: ToolManifest,
    /** How supervisor co-signatures are verified — typically the identity
     * registry's `verifySupervisorCoSignature`. Without one, dual-key tools
     * are unexecutable through this service, which is the safe default. */
    private readonly verifyCoSignature?: CoSignatureVerifier,
  ) {}

  /** Subscribe to ledger appends. Returns the unsubscribe function. */
  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * The one path that runs a tool. Checks policy; a denial halts execution
   * (the tool body never runs) and is recorded as BLOCKED_BY_POLICY — the
   * REJECTED_POLICY_VIOLATION event. An allowed tool runs, and success or
   * failure is recorded with the same provenance.
   */
  executeGoverned(invocation: GovernedInvocation): Promise<GovernedOutcome> {
    const chained = this.queue.then(() => this.run(invocation));
    // Keep the queue alive past failures; the caller still sees the reason.
    this.queue = chained.catch(() => undefined);
    return chained;
  }

  private async run(invocation: GovernedInvocation): Promise<GovernedOutcome> {
    const { profile, toolName } = invocation;
    const verdict = await evaluateToolInvocation(profile, toolName, this.manifest, {
      runtimeAttestation: invocation.runtimeAttestation,
      supervisorCoSignature: invocation.supervisorCoSignature,
      verifyCoSignature: this.verifyCoSignature,
    });

    let status: ExecutionStatus;
    let errorMessage: string | undefined;
    let postExecutionState: ConsoleStateSnapshot | undefined;

    if (!verdict.allowed) {
      status = "BLOCKED_BY_POLICY";
      errorMessage = `REJECTED_POLICY_VIOLATION ${verdict.violation.code}: ${verdict.violation.detail}`;
    } else {
      try {
        const post = await invocation.execute();
        postExecutionState = post ?? undefined;
        status = "SUCCESS";
      } catch (err) {
        status = "FAILED";
        errorMessage = err instanceof Error ? err.message : String(err);
      }
    }

    const entry = await this.append({
      agentId: profile.agentId,
      agentDid: profile.did,
      modelDigest: profile.modelDigest,
      supervisorId: profile.supervisorOperatorId,
      // Sealed even on a blocked attempt: "an invalid co-signature was
      // presented" is itself evidence a debrief needs.
      ...(invocation.supervisorCoSignature !== undefined
        ? { supervisorCoSignature: invocation.supervisorCoSignature }
        : {}),
      rawPrompt: invocation.rawPrompt,
      interpretedIntent: invocation.interpretedIntent,
      toolExecuted: {
        name: toolName,
        inputParams: invocation.inputParams,
        executionStatus: status,
        ...(errorMessage !== undefined ? { errorMessage } : {}),
      },
      preExecutionState: invocation.preExecutionState,
      ...(postExecutionState !== undefined ? { postExecutionState } : {}),
    });

    return { verdict, status, entry };
  }

  private async append(
    body: Omit<
      AgentActionLog,
      "eventId" | "sequenceNumber" | "timestampUtc" | "previousHash" | "chainHash"
    >,
  ): Promise<AgentActionLog> {
    const tail = await this.tail(body.agentId);
    const unsealed = {
      ...body,
      eventId: crypto.randomUUID(),
      sequenceNumber: tail.sequence + 1,
      timestampUtc: new Date().toISOString(),
    };
    const previousHash = tail.hash;
    const chainHash = await sha256Hex(previousHash + entryPayload(unsealed));
    const entry: AgentActionLog = { ...unsealed, previousHash, chainHash };
    await this.storage.append(entry);
    this.tails.set(body.agentId, { hash: chainHash, sequence: entry.sequenceNumber });
    for (const l of this.listeners) l();
    return entry;
  }

  /** Current chain tail for an agent, recovered from storage on first use so
   * a reloaded console continues the persisted chain instead of forking it. */
  private async tail(agentId: string): Promise<{ hash: string; sequence: number }> {
    const cached = this.tails.get(agentId);
    if (cached) return cached;
    const existing = await this.storage.listByAgent(agentId);
    const last = existing[existing.length - 1];
    const tail = last
      ? { hash: last.chainHash, sequence: last.sequenceNumber }
      : { hash: GENESIS_HASH, sequence: 0 };
    this.tails.set(agentId, tail);
    return tail;
  }

  /** All entries for an agent, oldest first — the HUD drawer's feed. */
  history(agentId: string): Promise<AgentActionLog[]> {
    return this.storage.listByAgent(agentId);
  }

  /**
   * Recomputes the whole chain from genesis and reports the first link that
   * fails. A `valid: true` is a mathematical statement: these exact entries,
   * in this order, are the ones that were written.
   */
  async verifyAgentAuditTrail(agentId: string): Promise<AuditVerification> {
    const entries = await this.storage.listByAgent(agentId);
    let expectedPrevious = GENESIS_HASH;
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (entry.sequenceNumber !== i + 1) {
        return broken(entries.length, entry.sequenceNumber,
          `sequence gap: expected ${i + 1}, found ${entry.sequenceNumber}`);
      }
      if (entry.previousHash !== expectedPrevious) {
        return broken(entries.length, entry.sequenceNumber,
          "previousHash does not match the preceding entry's chainHash");
      }
      const { previousHash, chainHash, ...payload } = entry;
      const recomputed = await sha256Hex(previousHash + entryPayload(payload));
      if (recomputed !== chainHash) {
        return broken(entries.length, entry.sequenceNumber,
          "chainHash does not match the recorded payload — entry modified after sealing");
      }
      expectedPrevious = chainHash;
    }
    return { valid: true, entries: entries.length };
  }
}

function broken(
  entries: number,
  brokenAtSequence: number,
  reason: string,
): AuditVerification {
  return { valid: false, entries, brokenAtSequence, reason };
}
