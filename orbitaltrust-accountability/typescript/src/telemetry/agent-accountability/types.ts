/**
 * The ledger's record shape: one entry per attempted tool invocation,
 * binding the action to the digital worker that took it and the human who
 * delegated the session, chained by SHA-256 so history cannot be edited
 * without breaking every hash after the edit.
 */

/** Console state captured around an execution, so an after-action review can
 * see not just what was commanded but what the operator was looking at. */
export interface ConsoleStateSnapshot {
  cameraCoords: [number, number, number];
  activeShader: string;
  selectedTargetId?: string;
}

export type ExecutionStatus = "SUCCESS" | "FAILED" | "BLOCKED_BY_POLICY";

export interface AgentActionLog {
  /** UUID v4. */
  eventId: string;
  /** Monotonic per-agent sequence, starting at 1. */
  sequenceNumber: number;
  /** ISO-8601 UTC. */
  timestampUtc: string;
  /** Identity of the acting digital worker. */
  agentId: string;
  /** The agent's W3C DID (`did:syntriass:agent:<id>`). */
  agentDid: string;
  /** SHA-256 of the model weights the credential attests — recorded per
   * entry so a dossier row names the exact model that acted. */
  modelDigest: string;
  /** Human who authorized or delegated the session. */
  supervisorId: string;
  /** Present when the tool demanded dual-key authorization: the supervisor
   * co-signature the invocation carried, sealed into the chain with it. */
  supervisorCoSignature?: string;
  /** Voice transcript / prompt as received. */
  rawPrompt: string;
  /** Tool-call intent the prompt was interpreted as. */
  interpretedIntent: string;
  toolExecuted: {
    name: string;
    inputParams: Record<string, unknown>;
    executionStatus: ExecutionStatus;
    errorMessage?: string;
  };
  preExecutionState: ConsoleStateSnapshot;
  postExecutionState?: ConsoleStateSnapshot;
  /** chainHash of the previous entry; GENESIS_HASH for the first. */
  previousHash: string;
  /** SHA-256(previousHash + canonical payload of this entry). */
  chainHash: string;
}

/** Anchor for the first link of every agent's chain. A published constant
 * rather than an empty string, so "unset" and "genesis" cannot be confused. */
export const GENESIS_HASH = "0".repeat(64);

/** Outcome of an audit-trail verification pass. */
export type AuditVerification =
  | { valid: true; entries: number }
  | {
      valid: false;
      entries: number;
      /** Sequence number of the first entry that fails verification. */
      brokenAtSequence: number;
      reason: string;
    };
