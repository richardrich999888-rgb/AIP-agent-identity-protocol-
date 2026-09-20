/**
 * The governed execution funnel — the one path a persistent-identity agent's
 * tool call travels:
 *
 *   [1 Identity verification] → [2 Authority evaluation] → [3 Execution]
 *     → [4 Evidence sealing] → [5 Ledger commit]
 *
 * Stages 1–2 answer *who is acting* and *under what authority*, against the
 * durable store rather than anything the caller hands in — a forged profile
 * object gets nowhere, because the funnel looks the DID up itself. Stage 3
 * runs the tool only on a clean verdict. Stages 4–5 run on *every* path:
 * a refusal is sealed into the same chain as a success, because "the agent
 * tried and was stopped" is exactly the history a debrief needs.
 *
 * The funnel never throws on a policy failure — the verdict is data, and
 * the evidence packet is the record. It throws only on infrastructure
 * failure (storage down), where pretending to have sealed evidence would
 * be worse than failing loudly.
 */

import { canonicalJson, sha256Hex, type Jsonish } from "../crypto";
import { meetsClearance } from "../agent-identity/agent-profile";
import type { ToolManifest } from "../agent-identity/permission-guard";
import type {
  AgentDidString,
  DelegatedAuthorityGrant,
  EvidencePacket,
  PqcAuditStamp,
} from "../agent-identity/persistent-identity";
import type { IdentityStore } from "../agent-identity/identity-store";
import { EVIDENCE_GENESIS_HASH, evidencePacketPayload } from "./verifier";

export type FunnelRejectionCode =
  | "IDENTITY_NOT_REGISTERED"
  | "MODEL_INTEGRITY_COMPROMISED"
  | "NO_ACTIVE_GRANT"
  | "GRANT_SIGNATURE_INVALID"
  | "UNKNOWN_TOOL"
  | "TOOL_NOT_GRANTED"
  | "CLEARANCE_INSUFFICIENT"
  | "RATE_LIMIT_EXCEEDED"
  | "REQUIRES_SUPERVISOR_MULTISIG";

export interface FunnelRejection {
  code: FunnelRejectionCode;
  /** Which stage refused: 1 = identity, 2 = authority. */
  stage: 1 | 2;
  detail: string;
}

export type FunnelVerdict = { permitted: true } | { permitted: false; rejection: FunnelRejection };

/** What the host attests to be executing right now. */
export interface RuntimeParameters {
  modelDigest: string;
  systemPromptHash: string;
}

export interface GovernedToolRequest {
  agentDid: AgentDidString;
  /** What the runtime is executing; checked against the stored identity. */
  runtimeParameters: RuntimeParameters;
  rawPrompt: string;
  toolName: string;
  inputParams: Record<string, unknown>;
  /** Pre-action viewport/entity state; hashed into the packet. */
  preState: Jsonish;
  /** Supervisor multi-sig ticket, for tools in the grant's
   * requiresMultiSigTools list. */
  supervisorCoSignature?: string;
  /** The effect. Runs only when permitted; may return the post-action
   * state, which is hashed into the packet (defaults to the pre-state — a
   * blocked or state-less action changed nothing). */
  execute: () => Promise<Jsonish | void> | Jsonish | void;
}

export interface FunnelOutcome {
  verdict: FunnelVerdict;
  status: EvidencePacket["toolExecuted"]["status"];
  packet: EvidencePacket;
}

type MaybePromise<T> = T | Promise<T>;

export interface GovernedExecutionConfig {
  store: IdentityStore;
  /** Tool → clearance mandate. Tools absent from the manifest are refused
   * even when a grant names them: default-deny needs one authority. */
  manifest: ToolManifest;
  /** Verifies the delegator's signature over a grant's terms — typically
   * DelegationAuthority.verifyGrant. Without it, no grant verifies. */
  verifyGrant: (grant: DelegatedAuthorityGrant) => MaybePromise<boolean>;
  /** Verifies a supervisor co-signature — typically
   * DelegationAuthority.verifyCoSignature. */
  verifyCoSignature: (
    grant: DelegatedAuthorityGrant,
    toolName: string,
    signatureHex: string,
  ) => MaybePromise<boolean>;
  /** Clock override for tests. */
  now?: () => string;
  /** PQC transport posture to stamp into every sealed packet (the
   * evidenceDigest is computed per packet). Optional: a funnel without one
   * seals packets without the stamp, exactly as before. */
  pqcContext?: Omit<PqcAuditStamp, "evidenceDigest">;
}

export class GovernedExecutionFunnel {
  /** Chain tail per agent, recovered from storage on first use so a
   * reloaded console continues the persisted chain instead of forking it. */
  private readonly tails = new Map<string, { hash: string; sequence: number }>();
  /** Serializes the whole funnel per service: two concurrent invocations
   * must not read the same tail (or the same rate-limit window) and race. */
  private queue: Promise<unknown> = Promise.resolve();
  private readonly listeners = new Set<() => void>();

  constructor(private readonly config: GovernedExecutionConfig) {}

  /** Fires after every ledger commit (success, failure, or policy block),
   * so a live UI feed appends without polling. Returns the unsubscribe. */
  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  execute(request: GovernedToolRequest): Promise<FunnelOutcome> {
    const chained = this.queue.then(() => this.run(request));
    this.queue = chained.catch(() => undefined);
    return chained;
  }

  private now(): string {
    return this.config.now?.() ?? new Date().toISOString();
  }

  private async run(request: GovernedToolRequest): Promise<FunnelOutcome> {
    const { store } = this.config;
    const nowUtc = this.now();

    // ── Stage 1: identity verification ─────────────────────────────────
    let rejection: FunnelRejection | null = null;
    const identity = await store.getPersistentIdentity(request.agentDid);
    if (!identity) {
      rejection = reject(1, "IDENTITY_NOT_REGISTERED",
        `no persistent identity for ${request.agentDid}`);
    } else if (
      request.runtimeParameters.modelDigest !== identity.modelDigest ||
      request.runtimeParameters.systemPromptHash !== identity.systemPromptHash
    ) {
      rejection = reject(1, "MODEL_INTEGRITY_COMPROMISED",
        "Active runtime model weights or prompt hash mismatch");
    }

    // ── Stage 2: authority evaluation ──────────────────────────────────
    let grant: DelegatedAuthorityGrant | null = null;
    if (!rejection) {
      grant = await store.getActiveGrantForAgent(request.agentDid);
      if (!grant) {
        rejection = reject(2, "NO_ACTIVE_GRANT",
          `no ACTIVE grant within its validity window for ${request.agentDid}`);
      } else if (!(await this.config.verifyGrant(grant))) {
        rejection = reject(2, "GRANT_SIGNATURE_INVALID",
          `grant ${grant.grantId} fails the delegator's signature — terms modified after issue`);
      } else {
        rejection = await this.evaluateGrant(grant, request, nowUtc);
      }
    }

    // ── Stage 3: execution ─────────────────────────────────────────────
    let status: EvidencePacket["toolExecuted"]["status"];
    let error: string | undefined;
    let postState: Jsonish = request.preState;
    if (rejection) {
      status = "BLOCKED_BY_POLICY";
      error = `REJECTED_POLICY_VIOLATION ${rejection.code}: ${rejection.detail}`;
    } else {
      try {
        const post = await request.execute();
        if (post !== undefined) postState = post;
        status = "SUCCESS";
      } catch (err) {
        status = "FAILED";
        error = err instanceof Error ? err.message : String(err);
      }
    }

    // ── Stage 4: evidence sealing ──────────────────────────────────────
    const tail = await this.tail(request.agentDid);
    const unsealed: Omit<EvidencePacket, "previousPacketHash" | "packetHash"> = {
      id: crypto.randomUUID(),
      sequenceNumber: tail.sequence + 1,
      timestampUtc: nowUtc,
      agentDid: request.agentDid,
      grantId: grant?.grantId ?? "",
      delegatorDid: grant?.delegatorDid ?? "did:syntriass:officer:UNRESOLVED",
      delegationChain: grant ? [...grant.delegationChain] : [],
      modelDigest: identity?.modelDigest ?? request.runtimeParameters.modelDigest,
      rawPrompt: request.rawPrompt,
      toolExecuted: {
        name: request.toolName,
        inputParams: request.inputParams,
        status,
        ...(request.supervisorCoSignature !== undefined
          ? { supervisorCoSignature: request.supervisorCoSignature }
          : {}),
        ...(error !== undefined ? { error } : {}),
      },
      preStateHash: await sha256Hex(canonicalJson(request.preState)),
      postStateHash: await sha256Hex(canonicalJson(postState)),
      ...(this.config.pqcContext
        ? {
            pqcAuditRecord: {
              ...this.config.pqcContext,
              // Genuinely computed per action: the digest of exactly what
              // this SATCOM pull / conjunction query carried.
              evidenceDigest: await sha256Hex(
                canonicalJson(request.inputParams as Jsonish),
              ),
            },
          }
        : {}),
    };
    const previousPacketHash = tail.hash;
    const packetHash = await sha256Hex(
      previousPacketHash + evidencePacketPayload(unsealed),
    );
    const packet: EvidencePacket = { ...unsealed, previousPacketHash, packetHash };

    // ── Stage 5: ledger commit ─────────────────────────────────────────
    // The tail advances only after storage accepts the packet, so a failed
    // commit cannot leave the in-memory chain ahead of the durable one.
    await store.appendEvidencePacket(packet);
    this.tails.set(request.agentDid, {
      hash: packetHash,
      sequence: packet.sequenceNumber,
    });
    for (const l of this.listeners) l();

    const verdict: FunnelVerdict = rejection
      ? { permitted: false, rejection }
      : { permitted: true };
    return { verdict, status, packet };
  }

  /** The grant-level checks of stage 2, in an order that reports the most
   * fundamental failure first; multi-sig last, as an additional requirement
   * on an otherwise-permitted call. */
  private async evaluateGrant(
    grant: DelegatedAuthorityGrant,
    request: GovernedToolRequest,
    nowUtc: string,
  ): Promise<FunnelRejection | null> {
    const mandate = this.config.manifest[request.toolName];
    if (!mandate) {
      return reject(2, "UNKNOWN_TOOL",
        `tool "${request.toolName}" has no mandate in the manifest`);
    }
    if (!grant.grantedTools.includes(request.toolName)) {
      return reject(2, "TOOL_NOT_GRANTED",
        `grant ${grant.grantId} does not delegate "${request.toolName}"`);
    }
    if (!meetsClearance(grant.clearanceLevel, mandate.minimumClearance)) {
      return reject(2, "CLEARANCE_INSUFFICIENT",
        `tool "${request.toolName}" requires ${mandate.minimumClearance}; ` +
          `grant holds ${grant.clearanceLevel}`);
    }
    if (await this.rateLimitExceeded(grant, request.agentDid, nowUtc)) {
      return reject(2, "RATE_LIMIT_EXCEEDED",
        `grant ${grant.grantId} allows ${grant.rateLimitMaxPerHour} executed actions/hour`);
    }
    if (grant.requiresMultiSigTools.includes(request.toolName)) {
      const sig = request.supervisorCoSignature;
      if (!sig) {
        return reject(2, "REQUIRES_SUPERVISOR_MULTISIG",
          "High-consequence tool requires human supervisor co-signature");
      }
      if (!(await this.config.verifyCoSignature(grant, request.toolName, sig))) {
        return reject(2, "REQUIRES_SUPERVISOR_MULTISIG",
          `supervisor co-signature for "${request.toolName}" failed verification`);
      }
    }
    return null;
  }

  /** Executed actions (SUCCESS or FAILED) in the trailing hour, against the
   * grant's ceiling. Blocked attempts do not consume quota — the limit
   * bounds what the agent *does*, and refusals are already bounded by
   * policy. */
  private async rateLimitExceeded(
    grant: DelegatedAuthorityGrant,
    agentDid: string,
    nowUtc: string,
  ): Promise<boolean> {
    const packets = await this.config.store.listEvidenceForAgent(agentDid);
    const cutoff = Date.parse(nowUtc) - 60 * 60 * 1000;
    const executed = packets.filter(
      (p) =>
        p.toolExecuted.status !== "BLOCKED_BY_POLICY" &&
        Date.parse(p.timestampUtc) > cutoff,
    ).length;
    return executed >= grant.rateLimitMaxPerHour;
  }

  private async tail(agentDid: string): Promise<{ hash: string; sequence: number }> {
    const cached = this.tails.get(agentDid);
    if (cached) return cached;
    const existing = await this.config.store.listEvidenceForAgent(agentDid);
    const last = existing[existing.length - 1];
    const tail = last
      ? { hash: last.packetHash, sequence: last.sequenceNumber }
      : { hash: EVIDENCE_GENESIS_HASH, sequence: 0 };
    this.tails.set(agentDid, tail);
    return tail;
  }
}

function reject(
  stage: 1 | 2,
  code: FunnelRejectionCode,
  detail: string,
): FunnelRejection {
  return { code, stage, detail };
}
