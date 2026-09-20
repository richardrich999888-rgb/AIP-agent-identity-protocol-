/**
 * The frontend verification runner: chain math through the Rust WASM core
 * (Web Crypto fallback), cross-reference law in plain TypeScript.
 *
 * The split is principled, not incidental: hashing and chain recomputation
 * are the byte-exact, performance-sensitive work the shared core exists
 * for; the cross-references (packet ↔ seal anchor, lifecycle binding) are
 * pure set logic over already-verified records, where a second
 * implementation costs nothing and an extra language boundary buys nothing.
 *
 * The report shape matches `NexoraVerifier.verifyAgent`, plus the engine
 * that actually ran, so the inspection tab can say which implementation
 * stands behind its VERIFIED badge.
 */

import type { NexoraAgentReport } from "../telemetry/nexora/nexora-verifier";
import type { AipEvidencePacket, NexoraLifecycleAnchor } from "../telemetry/nexora/types";
import { getVerifierEngine } from "./wasm";

export interface AgentVerificationReport extends NexoraAgentReport {
  /** Which implementation computed the chain verdicts. */
  engine: "wasm" | "webcrypto";
  /** Merkle root over the evidence packet set. */
  packetMerkleRoot: string;
}

/**
 * Verifies one agent's records: both hash chains via the engine, then the
 * cross-references binding them (every packet's non-empty anchorHash must
 * be a real anchor, every seal anchor must name a real packet).
 */
export async function verifyAgentRecords(
  anchors: NexoraLifecycleAnchor[],
  packets: AipEvidencePacket[],
): Promise<AgentVerificationReport> {
  const engine = await getVerifierEngine();
  const [anchorVerdict, packetVerdict, packetMerkleRoot] = await Promise.all([
    engine.verifyAnchorChain(anchors),
    engine.verifyEvidencePackets(packets),
    engine.merkleRoot(packets.map((p) => p.packetHash)),
  ]);

  const findings: string[] = [];
  if (!anchorVerdict.valid) {
    findings.push(
      `anchor chain broken at sequence ${anchorVerdict.brokenSequence}: ${anchorVerdict.reason}`,
    );
  }
  if (!packetVerdict.valid) {
    findings.push(
      `packet chain broken at sequence ${packetVerdict.brokenSequence}: ${packetVerdict.reason}`,
    );
  }

  // Cross-references are only meaningful over chains that individually
  // verify — same rule as the store-bound verifier.
  let crossConsistent = anchorVerdict.valid && packetVerdict.valid;
  if (crossConsistent) {
    const anchorHashes = new Set(anchors.map((a) => a.anchorHash));
    const sealedPacketHashes = new Set(
      anchors
        .filter((a) => a.anchorType === "ACTION_EXECUTION_SEAL")
        .map((a) => a.payload.packetHash)
        .filter((h): h is string => typeof h === "string"),
    );
    const packetHashes = new Set(packets.map((p) => p.packetHash));

    for (const p of packets) {
      if (p.anchorHash !== "" && !anchorHashes.has(p.anchorHash)) {
        crossConsistent = false;
        findings.push(
          `packet #${p.sequenceNumber} binds anchorHash ${p.anchorHash.slice(0, 12)}… ` +
            "which is not in the agent's lifecycle chain",
        );
      }
    }
    for (const sealed of sealedPacketHashes) {
      if (!packetHashes.has(sealed)) {
        crossConsistent = false;
        findings.push("a seal anchor names a packet hash absent from the ledger");
      }
    }
  }

  return {
    anchors: anchorVerdict,
    packets: packetVerdict,
    crossConsistent,
    findings,
    engine: engine.engine,
    packetMerkleRoot,
  };
}
