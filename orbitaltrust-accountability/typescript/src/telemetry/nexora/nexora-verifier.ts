/**
 * Independent deterministic verification of the NEXORA tiers.
 *
 * This module owns the canonical byte layout of an AIP evidence packet (the
 * sealer imports it, so writer and verifier cannot disagree), and verifies
 * three things, each recomputed from raw storage with no trust in any
 * service's in-memory state:
 *
 * 1. the lifecycle anchor chain — hashes, sequence, genesis-first, nothing
 *    after a terminal revocation;
 * 2. the evidence packet chain — hashes and sequence;
 * 3. the cross-references between them — every packet's anchorHash must be
 *    a real anchor hash of that agent, and every ACTION_EXECUTION_SEAL
 *    must name a real packet by its exact hash.
 *
 * The cross-check is what makes tampering with either chain futile even in
 * isolation: rewrite history and the packets no longer bind to it; rewrite
 * an action and its seal anchor contradicts it.
 */

import { canonicalJson, sha256Hex, type Jsonish } from "../crypto";
import type { AipEvidencePacket } from "./types";
import type { NexoraStore } from "./nexora-store";
import {
  anchorPayloadBytes,
  isTerminalRevocation,
  NEXORA_GENESIS_HASH,
} from "./anchor-chain";

/** Genesis constant for every agent's AIP packet chain. */
export const AIP_EVIDENCE_GENESIS_HASH = "0".repeat(64);

/** The canonical bytes of a packet: everything except the two chain fields. */
export function aipPacketPayloadBytes(
  packet: Omit<AipEvidencePacket, "previousPacketHash" | "packetHash">,
): string {
  const payload: Jsonish = {
    id: packet.id,
    sequenceNumber: packet.sequenceNumber,
    timestampUtc: packet.timestampUtc,
    agentDid: packet.agentDid,
    anchorHash: packet.anchorHash,
    delegationPath: [...packet.delegationPath],
    edgeId: packet.edgeId,
    modelDigest: packet.modelDigest,
    rawPrompt: packet.rawPrompt,
    toolExecuted: {
      name: packet.toolExecuted.name,
      inputParams: packet.toolExecuted.inputParams as Jsonish,
      status: packet.toolExecuted.status,
      supervisorCoSignature: packet.toolExecuted.supervisorCoSignature,
      error: packet.toolExecuted.error,
    },
    preStateHash: packet.preStateHash,
    postStateHash: packet.postStateHash,
  };
  return canonicalJson(payload);
}

export interface ChainVerdict {
  valid: boolean;
  total: number;
  brokenSequence?: number;
  reason?: string;
}

export interface NexoraAgentReport {
  anchors: ChainVerdict;
  packets: ChainVerdict;
  /** True when both chains verify AND every cross-reference holds. */
  crossConsistent: boolean;
  /** Human-readable findings for anything that failed. */
  findings: string[];
}

export class NexoraVerifier {
  constructor(private readonly store: NexoraStore) {}

  /** Tier 2 verification: the lifecycle anchor chain. */
  async verifyAnchorChain(agentDid: string): Promise<ChainVerdict> {
    const anchors = await this.store.listAnchorsForAgent(agentDid);
    let expectedPrevious = NEXORA_GENESIS_HASH;
    let closedAt: number | null = null;
    for (let i = 0; i < anchors.length; i++) {
      const anchor = anchors[i];
      if (anchor.sequenceNumber !== i + 1) {
        return broken(anchors.length, anchor.sequenceNumber,
          `sequence gap: expected ${i + 1}, found ${anchor.sequenceNumber}`);
      }
      if (i === 0 && anchor.anchorType !== "AGENT_GENESIS") {
        return broken(anchors.length, anchor.sequenceNumber,
          `chain must begin with AGENT_GENESIS, found ${anchor.anchorType}`);
      }
      if (i > 0 && anchor.anchorType === "AGENT_GENESIS") {
        return broken(anchors.length, anchor.sequenceNumber,
          "second AGENT_GENESIS — an agent is born once");
      }
      if (closedAt !== null) {
        return broken(anchors.length, anchor.sequenceNumber,
          `anchor after terminal revocation at sequence ${closedAt}`);
      }
      if (anchor.previousAnchorHash !== expectedPrevious) {
        return broken(anchors.length, anchor.sequenceNumber,
          "previousAnchorHash does not match the preceding anchor's hash");
      }
      const { previousAnchorHash, anchorHash, ...payload } = anchor;
      const recomputed = await sha256Hex(previousAnchorHash + anchorPayloadBytes(payload));
      if (recomputed !== anchorHash) {
        return broken(anchors.length, anchor.sequenceNumber,
          "anchorHash does not match the recorded payload — anchor modified after sealing");
      }
      expectedPrevious = anchorHash;
      if (isTerminalRevocation(anchor)) closedAt = anchor.sequenceNumber;
    }
    return { valid: true, total: anchors.length };
  }

  /** Tier 4 verification: the AIP evidence packet chain. */
  async verifyPacketChain(agentDid: string): Promise<ChainVerdict> {
    const packets = await this.store.listPacketsForAgent(agentDid);
    let expectedPrevious = AIP_EVIDENCE_GENESIS_HASH;
    for (let i = 0; i < packets.length; i++) {
      const packet = packets[i];
      if (packet.sequenceNumber !== i + 1) {
        return broken(packets.length, packet.sequenceNumber,
          `sequence gap: expected ${i + 1}, found ${packet.sequenceNumber}`);
      }
      if (packet.previousPacketHash !== expectedPrevious) {
        return broken(packets.length, packet.sequenceNumber,
          "previousPacketHash does not match the preceding packet's hash");
      }
      const { previousPacketHash, packetHash, ...payload } = packet;
      const recomputed = await sha256Hex(
        previousPacketHash + aipPacketPayloadBytes(payload),
      );
      if (recomputed !== packetHash) {
        return broken(packets.length, packet.sequenceNumber,
          "packetHash does not match the recorded payload — packet modified after sealing");
      }
      expectedPrevious = packetHash;
    }
    return { valid: true, total: packets.length };
  }

  /**
   * The full deterministic report for one agent: both chains plus the
   * cross-references binding them together.
   */
  async verifyAgent(agentDid: string): Promise<NexoraAgentReport> {
    const anchors = await this.verifyAnchorChain(agentDid);
    const packets = await this.verifyPacketChain(agentDid);
    const findings: string[] = [];
    if (!anchors.valid) {
      findings.push(`anchor chain broken at sequence ${anchors.brokenSequence}: ${anchors.reason}`);
    }
    if (!packets.valid) {
      findings.push(`packet chain broken at sequence ${packets.brokenSequence}: ${packets.reason}`);
    }

    // Cross-references are only meaningful over chains that individually
    // verify; a broken chain already fails the report.
    let crossConsistent = anchors.valid && packets.valid;
    if (crossConsistent) {
      const anchorRows = await this.store.listAnchorsForAgent(agentDid);
      const packetRows = await this.store.listPacketsForAgent(agentDid);
      const anchorHashes = new Set(anchorRows.map((a) => a.anchorHash));
      const packetHashes = new Set(packetRows.map((p) => p.packetHash));

      for (const p of packetRows) {
        if (p.anchorHash !== "" && !anchorHashes.has(p.anchorHash)) {
          crossConsistent = false;
          findings.push(
            `packet #${p.sequenceNumber} binds anchorHash ${p.anchorHash.slice(0, 12)}… ` +
              "which is not in the agent's lifecycle chain",
          );
        }
      }
      for (const a of anchorRows) {
        if (a.anchorType !== "ACTION_EXECUTION_SEAL") continue;
        const sealed = a.payload.packetHash;
        if (typeof sealed !== "string" || !packetHashes.has(sealed)) {
          crossConsistent = false;
          findings.push(
            `seal anchor #${a.sequenceNumber} names a packet hash absent from the ledger`,
          );
        }
      }
    }

    return { anchors, packets, crossConsistent, findings };
  }

  /** Machine dossier: one sealed packet per line, byte-faithful. */
  async exportAipDossierJsonl(agentDid: string): Promise<string> {
    const packets = await this.store.listPacketsForAgent(agentDid);
    return (
      packets.map((p) => JSON.stringify(p)).join("\n") + (packets.length ? "\n" : "")
    );
  }
}

function broken(total: number, brokenSequence: number, reason: string): ChainVerdict {
  return { valid: false, total, brokenSequence, reason };
}
