/**
 * The AIP evidence sealer: the one path a consequential action travels
 * under NEXORA governance.
 *
 *   lifecycle check (born, not closed, model digest matches the chain)
 *     → authority resolution (delegation graph, attenuated scope)
 *       → execution → packet sealing → ledger commit
 *         → ACTION_EXECUTION_SEAL anchor naming the packet
 *
 * Two bindings make the packet non-repudiable beyond its own hash chain:
 * it carries the anchor-chain head hash at execution time (the exact
 * lifecycle state it ran under), and the executed action is anchored back
 * into the lifecycle chain naming the packet's hash — so evidence and
 * history cross-reference, and neither can be rewritten without
 * contradicting the other.
 *
 * The expected model digest comes from the lifecycle chain itself — the
 * genesis anchor, superseded by the newest MODEL_VERSION_MIGRATION — not
 * from a mutable identity row: "which weights should be running" is a
 * question the verifiable history answers.
 */

import { canonicalJson, sha256Hex, type Jsonish } from "../crypto";
import { meetsClearance } from "../agent-identity/agent-profile";
import type { ToolManifest } from "../agent-identity/permission-guard";
import type { AgentDidString } from "../agent-identity/persistent-identity";
import type { AipEvidencePacket, EffectiveAuthority } from "./types";
import type { NexoraStore } from "./nexora-store";
import { isTerminalRevocation, type NexoraAnchorChain } from "./anchor-chain";
import type { AipDelegationAuthority, AipDelegationGraph } from "./delegation-graph";
import { AIP_EVIDENCE_GENESIS_HASH, aipPacketPayloadBytes } from "./nexora-verifier";

export type AipRejectionCode =
  | "AGENT_NOT_BORN"
  | "LIFECYCLE_CLOSED"
  | "MODEL_INTEGRITY_COMPROMISED"
  | "NO_EFFECTIVE_AUTHORITY"
  | "UNKNOWN_TOOL"
  | "TOOL_NOT_IN_SCOPE"
  | "CLEARANCE_INSUFFICIENT"
  | "REQUIRES_SUPERVISOR_MULTISIG";

export interface AipRejection {
  code: AipRejectionCode;
  detail: string;
}

export type AipVerdict = { permitted: true } | { permitted: false; rejection: AipRejection };

export interface AipToolRequest {
  agentDid: AgentDidString;
  /** SHA-256 of the weights/quant profile the runtime is executing. */
  runtimeModelDigest: string;
  rawPrompt: string;
  toolName: string;
  inputParams: Record<string, unknown>;
  preState: Jsonish;
  supervisorCoSignature?: string;
  /** Runs only when permitted; may return the post-action state. */
  execute: () => Promise<Jsonish | void> | Jsonish | void;
}

export interface AipOutcome {
  verdict: AipVerdict;
  status: AipEvidencePacket["toolExecuted"]["status"];
  packet: AipEvidencePacket;
  /** The lifecycle anchor sealing this action; null when the chain was not
   * writable (agent unborn or terminally revoked). */
  sealAnchorId: string | null;
}

export interface AipSealerConfig {
  store: NexoraStore;
  anchors: NexoraAnchorChain;
  graph: AipDelegationGraph;
  authority: AipDelegationAuthority;
  /** Tool → clearance mandate; tools absent are refused even when a
   * delegation names them — default-deny needs one authority. */
  manifest: ToolManifest;
  now?: () => string;
}

export class AipEvidenceSealer {
  private readonly tails = new Map<string, { hash: string; sequence: number }>();
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly config: AipSealerConfig) {}

  execute(request: AipToolRequest): Promise<AipOutcome> {
    const chained = this.queue.then(() => this.run(request));
    this.queue = chained.catch(() => undefined);
    return chained;
  }

  private now(): string {
    return this.config.now?.() ?? new Date().toISOString();
  }

  private async run(request: AipToolRequest): Promise<AipOutcome> {
    const { anchors, graph, store } = this.config;

    // ── Lifecycle checks ───────────────────────────────────────────────
    let rejection: AipRejection | null = null;
    const born = await anchors.isBorn(request.agentDid);
    const closed = born && (await anchors.isClosed(request.agentDid));
    if (!born) {
      rejection = { code: "AGENT_NOT_BORN",
        detail: `${request.agentDid} has no AGENT_GENESIS anchor` };
    } else if (closed) {
      rejection = { code: "LIFECYCLE_CLOSED",
        detail: `${request.agentDid} lifecycle is closed by a terminal revocation` };
    } else {
      const expected = await this.expectedModelDigest(request.agentDid);
      if (expected !== null && expected !== request.runtimeModelDigest) {
        rejection = { code: "MODEL_INTEGRITY_COMPROMISED",
          detail: "runtime model digest does not match the lifecycle chain's binding" };
      }
    }

    // ── Authority resolution ───────────────────────────────────────────
    let effective: EffectiveAuthority | null = null;
    if (!rejection) {
      effective = await graph.resolveAuthority(request.agentDid);
      if (!effective) {
        rejection = { code: "NO_EFFECTIVE_AUTHORITY",
          detail: `no rooted, unrevoked delegation path for ${request.agentDid}` };
      } else {
        rejection = await this.evaluateAuthority(effective, request);
      }
    }

    // ── Execution ──────────────────────────────────────────────────────
    let status: AipEvidencePacket["toolExecuted"]["status"];
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

    // ── Packet sealing ─────────────────────────────────────────────────
    const chainWritable = born && !closed;
    const tail = await this.tail(request.agentDid);
    const unsealed: Omit<AipEvidencePacket, "previousPacketHash" | "packetHash"> = {
      id: crypto.randomUUID(),
      sequenceNumber: tail.sequence + 1,
      timestampUtc: this.now(),
      agentDid: request.agentDid,
      // "" when the lifecycle chain has no head to bind to — an unborn or
      // terminated agent's attempts are still evidence, just unanchored.
      anchorHash: chainWritable ? await anchors.headHash(request.agentDid) : "",
      delegationPath: effective ? [...effective.path] : [],
      edgeId: effective ? effective.edgeIds[effective.edgeIds.length - 1] : "",
      modelDigest: request.runtimeModelDigest,
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
    };
    const previousPacketHash = tail.hash;
    const packetHash = await sha256Hex(
      previousPacketHash + aipPacketPayloadBytes(unsealed),
    );
    const packet: AipEvidencePacket = { ...unsealed, previousPacketHash, packetHash };

    // ── Ledger commit, then the lifecycle seal ─────────────────────────
    await store.appendPacket(packet);
    this.tails.set(request.agentDid, { hash: packetHash, sequence: packet.sequenceNumber });

    let sealAnchorId: string | null = null;
    if (chainWritable) {
      const seal = await this.config.anchors.appendAnchor({
        anchorType: "ACTION_EXECUTION_SEAL",
        agentDid: request.agentDid,
        actorDid: request.agentDid,
        payload: { packetId: packet.id, packetHash: packet.packetHash, status },
      });
      sealAnchorId = seal.anchorId;
    }

    const verdict: AipVerdict = rejection
      ? { permitted: false, rejection }
      : { permitted: true };
    return { verdict, status, packet, sealAnchorId };
  }

  private async evaluateAuthority(
    effective: EffectiveAuthority,
    request: AipToolRequest,
  ): Promise<AipRejection | null> {
    const mandate = this.config.manifest[request.toolName];
    if (!mandate) {
      return { code: "UNKNOWN_TOOL",
        detail: `tool "${request.toolName}" has no mandate in the manifest` };
    }
    if (!effective.scope.includes(request.toolName)) {
      return { code: "TOOL_NOT_IN_SCOPE",
        detail: `effective delegated scope does not include "${request.toolName}"` };
    }
    if (!meetsClearance(effective.clearanceLevel, mandate.minimumClearance)) {
      return { code: "CLEARANCE_INSUFFICIENT",
        detail: `tool "${request.toolName}" requires ${mandate.minimumClearance}; ` +
          `the delegation path holds ${effective.clearanceLevel}` };
    }
    if (effective.multiSigTools.includes(request.toolName)) {
      const sig = request.supervisorCoSignature;
      const edge = await this.config.store.getEdge(
        effective.edgeIds[effective.edgeIds.length - 1],
      );
      if (!sig || !edge) {
        return { code: "REQUIRES_SUPERVISOR_MULTISIG",
          detail: "High-consequence tool requires human supervisor co-signature" };
      }
      if (!(await this.config.authority.verifyCoSignature(edge, request.toolName, sig))) {
        return { code: "REQUIRES_SUPERVISOR_MULTISIG",
          detail: `supervisor co-signature for "${request.toolName}" failed verification` };
      }
    }
    return null;
  }

  /** The digest the lifecycle chain currently binds: genesis, superseded by
   * the newest MODEL_VERSION_MIGRATION. Null when unreadable. */
  private async expectedModelDigest(agentDid: string): Promise<string | null> {
    const anchors = await this.config.store.listAnchorsForAgent(agentDid);
    let digest: string | null = null;
    for (const a of anchors) {
      if (isTerminalRevocation(a)) break;
      if (a.anchorType === "AGENT_GENESIS" || a.anchorType === "MODEL_VERSION_MIGRATION") {
        const d = a.payload.modelDigest;
        if (typeof d === "string") digest = d;
      }
    }
    return digest;
  }

  private async tail(agentDid: string): Promise<{ hash: string; sequence: number }> {
    const cached = this.tails.get(agentDid);
    if (cached) return cached;
    const existing = await this.config.store.listPacketsForAgent(agentDid);
    const last = existing[existing.length - 1];
    const tail = last
      ? { hash: last.packetHash, sequence: last.sequenceNumber }
      : { hash: AIP_EVIDENCE_GENESIS_HASH, sequence: 0 };
    this.tails.set(agentDid, tail);
    return tail;
  }
}
