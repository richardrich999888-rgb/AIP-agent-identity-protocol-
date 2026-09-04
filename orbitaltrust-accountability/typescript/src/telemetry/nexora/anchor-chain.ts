/**
 * The NEXORA lifecycle anchor chain: an agent's verifiable history.
 *
 * Rules the chain enforces at write time (and the verifier re-checks
 * independently at read time):
 *
 * - The first anchor for an agent must be AGENT_GENESIS, and genesis can
 *   never recur: an agent is born once. Genesis binds the model digest, so
 *   "which weights was this agent born with" is anchored, not asserted.
 * - A terminal AUTHORITY_REVOCATION (payload `{ terminal: true }`) closes
 *   the chain forever. A non-terminal revocation (a suspension) records
 *   the milestone but leaves the chain open for reinstatement anchors.
 * - Every anchor is hash-chained: SHA-256(previousAnchorHash + canonical
 *   payload), from a published genesis constant — one historical edit
 *   breaks every later link.
 */

import { canonicalJson, sha256Hex, type Jsonish } from "../crypto";
import type { AgentDidString } from "../agent-identity/persistent-identity";
import type { NexoraAnchorType, NexoraLifecycleAnchor } from "./types";
import type { NexoraStore } from "./nexora-store";

/** Genesis constant anchoring every agent's first lifecycle anchor. */
export const NEXORA_GENESIS_HASH = "0".repeat(64);

/** The canonical bytes of an anchor: everything except the two chain
 * fields. Exported so writer and verifier share one definition. */
export function anchorPayloadBytes(
  anchor: Omit<NexoraLifecycleAnchor, "previousAnchorHash" | "anchorHash">,
): string {
  const payload: Jsonish = {
    anchorId: anchor.anchorId,
    sequenceNumber: anchor.sequenceNumber,
    anchorType: anchor.anchorType,
    agentDid: anchor.agentDid,
    actorDid: anchor.actorDid,
    timestampUtc: anchor.timestampUtc,
    payload: anchor.payload as Jsonish,
  };
  return canonicalJson(payload);
}

/** True when this anchor closes its agent's chain forever. */
export function isTerminalRevocation(anchor: NexoraLifecycleAnchor): boolean {
  return (
    anchor.anchorType === "AUTHORITY_REVOCATION" && anchor.payload.terminal === true
  );
}

export interface AnchorInput {
  anchorType: NexoraAnchorType;
  agentDid: AgentDidString;
  actorDid: string;
  payload: Record<string, unknown>;
}

export class NexoraAnchorChain {
  /** Chain tail per agent, recovered from storage on first use so a
   * reloaded console continues the persisted chain instead of forking it. */
  private readonly tails = new Map<
    string,
    { hash: string; sequence: number; closed: boolean; born: boolean }
  >();
  /** Serializes appends so two concurrent milestones cannot both read the
   * same tail and fork the chain. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly store: NexoraStore,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  appendAnchor(input: AnchorInput): Promise<NexoraLifecycleAnchor> {
    const chained = this.queue.then(() => this.run(input));
    this.queue = chained.catch(() => undefined);
    return chained;
  }

  /** Latest anchor hash for an agent — what evidence packets bind to. */
  async headHash(agentDid: string): Promise<string> {
    return (await this.tail(agentDid)).hash;
  }

  /** True once a terminal AUTHORITY_REVOCATION has been anchored. */
  async isClosed(agentDid: string): Promise<boolean> {
    return (await this.tail(agentDid)).closed;
  }

  /** True once AGENT_GENESIS has been anchored. */
  async isBorn(agentDid: string): Promise<boolean> {
    return (await this.tail(agentDid)).born;
  }

  private async run(input: AnchorInput): Promise<NexoraLifecycleAnchor> {
    const tail = await this.tail(input.agentDid);
    if (tail.closed) {
      throw new Error(
        `lifecycle chain for ${input.agentDid} is closed by a terminal revocation`,
      );
    }
    if (input.anchorType === "AGENT_GENESIS") {
      if (tail.born) {
        throw new Error(`${input.agentDid} already has a genesis anchor`);
      }
      if (typeof input.payload.modelDigest !== "string") {
        // Genesis exists to bind the model digest; a genesis without one
        // would anchor nothing.
        throw new Error("AGENT_GENESIS payload must bind a modelDigest");
      }
    } else if (!tail.born) {
      throw new Error(
        `first anchor for ${input.agentDid} must be AGENT_GENESIS, got ${input.anchorType}`,
      );
    }

    const unsealed: Omit<NexoraLifecycleAnchor, "previousAnchorHash" | "anchorHash"> = {
      anchorId: crypto.randomUUID(),
      sequenceNumber: tail.sequence + 1,
      anchorType: input.anchorType,
      agentDid: input.agentDid,
      actorDid: input.actorDid,
      timestampUtc: this.now(),
      payload: input.payload,
    };
    const previousAnchorHash = tail.hash;
    const anchorHash = await sha256Hex(previousAnchorHash + anchorPayloadBytes(unsealed));
    const anchor: NexoraLifecycleAnchor = { ...unsealed, previousAnchorHash, anchorHash };

    await this.store.appendAnchor(anchor);
    this.tails.set(input.agentDid, {
      hash: anchorHash,
      sequence: anchor.sequenceNumber,
      closed: isTerminalRevocation(anchor),
      born: true,
    });
    return anchor;
  }

  private async tail(
    agentDid: string,
  ): Promise<{ hash: string; sequence: number; closed: boolean; born: boolean }> {
    const cached = this.tails.get(agentDid);
    if (cached) return cached;
    const anchors = await this.store.listAnchorsForAgent(agentDid);
    const last = anchors[anchors.length - 1];
    const tail = last
      ? {
          hash: last.anchorHash,
          sequence: last.sequenceNumber,
          closed: anchors.some(isTerminalRevocation),
          born: true,
        }
      : { hash: NEXORA_GENESIS_HASH, sequence: 0, closed: false, born: false };
    this.tails.set(agentDid, tail);
    return tail;
  }
}
