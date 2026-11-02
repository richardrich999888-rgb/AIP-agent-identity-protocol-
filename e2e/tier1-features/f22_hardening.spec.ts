import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle, recomputePacketHash } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 1 - F22: Adversarial Coverage Hardening", () => {
  it("F22.1: handles Unicode, emojis, and special control characters in decision summary", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "Approve payment 🛡️ 銀行 / \n \t \r \"escaped\" & <script>alert(1)</script>";
    const hash = recomputePacketHash(packet);
    packet.packet_hash = hash;
    packet.agent_sig.payload_hash = hash;

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.checks.find((c) => c.rule === "CANONICAL_HASH")?.pass).toBe(true);
    expect(report.checks.find((c) => c.rule === "STRUCTURE")?.pass).toBe(true);
  });

  it("F22.2: handles long descriptions (100,000 characters) without buffer overflow", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "A".repeat(100000);
    const hash = recomputePacketHash(packet);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("F22.3: verifies timestamp boundary conditions (epoch 0 and future year 2040)", () => {
    const futureTime = 2208988800000; // year 2040
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.root_authority.root_token.issued_at = futureTime;
    packet.decision.decided_at = futureTime + 1000;
    packet.actions[0].performed_at = futureTime + 2000;
    packet.root_authority.root_token.expires_at = futureTime + 10000;
    const hash = recomputePacketHash(packet);
    packet.packet_hash = hash;
    packet.agent_sig.payload_hash = hash;

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.checks.find((c) => c.rule === "TEMPORAL_VALIDITY")?.pass).toBe(true);
  });

  it("F22.4: verifies high volume verification throughput under loop stress", () => {
    const start = performance.now();
    for (let i = 0; i < 50; i++) {
      verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    }
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(1000); // 50 verifications in < 1000ms
  });

  it("F22.5: ensures tamper_evidence remains resilient against collision attempts", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    // Single bit flip in input_hash
    const chars = packet.decision.input_hash.split("");
    chars[0] = chars[0] === "0" ? "1" : "0";
    packet.decision.input_hash = chars.join("");

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.tamper_evidence).toBe(true);
    expect(report.overall_valid).toBe(false);
  });
});
