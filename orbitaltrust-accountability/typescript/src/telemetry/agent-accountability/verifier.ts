/**
 * Independent verification of the evidence ledger.
 *
 * This module owns the canonical byte layout of an EvidencePacket, and the
 * execution funnel imports it from here — the writer and the verifier
 * *cannot* disagree about what was hashed, because there is only one
 * definition. Verification recomputes the entire chain from the genesis
 * anchor; a `valid: true` is a mathematical statement that these exact
 * packets, in this order, are the ones that were sealed.
 */

import { canonicalJson, sha256Hex, type Jsonish } from "../crypto";
import type { EvidencePacket } from "../agent-identity/persistent-identity";
import type { IdentityStore } from "../agent-identity/identity-store";

/** Genesis anchor for every agent's packet chain. */
export const EVIDENCE_GENESIS_HASH = "0".repeat(64);

/** The canonical bytes of a packet: everything except the two chain fields
 * (previousPacketHash enters the digest once, as the explicit prefix). */
export function evidencePacketPayload(
  packet: Omit<EvidencePacket, "previousPacketHash" | "packetHash">,
): string {
  const payload: Jsonish = {
    id: packet.id,
    sequenceNumber: packet.sequenceNumber,
    timestampUtc: packet.timestampUtc,
    agentDid: packet.agentDid,
    grantId: packet.grantId,
    delegatorDid: packet.delegatorDid,
    delegationChain: [...packet.delegationChain],
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
    // Optional stamp; canonicalJson drops it when absent, so packets sealed
    // before it existed still reproduce their original bytes.
    pqcAuditRecord: packet.pqcAuditRecord
      ? {
          cipherSuite: packet.pqcAuditRecord.cipherSuite,
          hndlProtectionStatus: packet.pqcAuditRecord.hndlProtectionStatus,
          kernelLatencyNs: packet.pqcAuditRecord.kernelLatencyNs,
          latencyProvenance: packet.pqcAuditRecord.latencyProvenance,
          evidenceDigest: packet.pqcAuditRecord.evidenceDigest,
        }
      : undefined,
  };
  return canonicalJson(payload);
}

export interface EvidenceChainVerdict {
  valid: boolean;
  totalPackets: number;
  /** Sequence number of the first packet that fails verification. */
  brokenSequence?: number;
  reason?: string;
}

export class EvidenceVerifier {
  constructor(private readonly store: IdentityStore) {}

  /** Recomputes every link of one agent's chain from genesis. */
  async verifyEvidenceChain(agentDid: string): Promise<EvidenceChainVerdict> {
    const packets = await this.store.listEvidenceForAgent(agentDid);
    let expectedPrevious = EVIDENCE_GENESIS_HASH;
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
        previousPacketHash + evidencePacketPayload(payload),
      );
      if (recomputed !== packetHash) {
        return broken(packets.length, packet.sequenceNumber,
          "packetHash does not match the recorded payload — packet modified after sealing");
      }
      expectedPrevious = packetHash;
    }
    return { valid: true, totalPackets: packets.length };
  }

  /** Machine dossier: one sealed packet per line, byte-faithful, so a
   * downstream verifier can re-run the chain math on the exported file. */
  async exportEvidenceDossierJsonl(agentDid: string): Promise<string> {
    const packets = await this.store.listEvidenceForAgent(agentDid);
    return (
      packets.map((p) => JSON.stringify(p)).join("\n") + (packets.length ? "\n" : "")
    );
  }

  /** Debrief-table dossier. Nested structures flattened; the chain hashes
   * ride along so even the spreadsheet copy carries its provenance. */
  async exportEvidenceDossierCsv(agentDid: string): Promise<string> {
    const packets = await this.store.listEvidenceForAgent(agentDid);
    const header = [
      "sequenceNumber",
      "timestampUtc",
      "agentDid",
      "grantId",
      "delegatorDid",
      "delegationChain",
      "modelDigest",
      "toolName",
      "status",
      "error",
      "supervisorCoSignature",
      "rawPrompt",
      "inputParams",
      "preStateHash",
      "postStateHash",
      "previousPacketHash",
      "packetHash",
      "id",
    ];
    const rows = packets.map((p) =>
      [
        String(p.sequenceNumber),
        p.timestampUtc,
        p.agentDid,
        p.grantId,
        p.delegatorDid,
        p.delegationChain.join(" > "),
        p.modelDigest,
        p.toolExecuted.name,
        p.toolExecuted.status,
        p.toolExecuted.error ?? "",
        p.toolExecuted.supervisorCoSignature ?? "",
        p.rawPrompt,
        JSON.stringify(p.toolExecuted.inputParams),
        p.preStateHash,
        p.postStateHash,
        p.previousPacketHash,
        p.packetHash,
        p.id,
      ]
        .map(csvCell)
        .join(","),
    );
    return [header.map(csvCell).join(","), ...rows].join("\r\n") + "\r\n";
  }
}

/** RFC-4180 quoting: always quote, double any embedded quote — prompts are
 * free text, so commas, quotes and newlines are the norm. */
function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

function broken(
  totalPackets: number,
  brokenSequence: number,
  reason: string,
): EvidenceChainVerdict {
  return { valid: false, totalPackets, brokenSequence, reason };
}
