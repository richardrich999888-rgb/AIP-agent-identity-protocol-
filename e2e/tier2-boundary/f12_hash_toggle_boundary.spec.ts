import { describe, it, expect } from "vitest";
import { recomputePacketHash, verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F12: Smart Hash Recalculation Toggle Boundaries", () => {
  it("F12.B1: double-recalculating hash on unmodified packet is strictly idempotent", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    const hash1 = recomputePacketHash(packet);
    const hash2 = recomputePacketHash(packet);
    expect(hash1).toBe(hash2);
    expect(hash1).toBe(packet.packet_hash);
  });

  it("F12.B2: toggling hash with missing agent_sig still flags AGENT_SIGNATURE rule", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "Altered summary";
    packet.packet_hash = recomputePacketHash(packet);
    delete packet.agent_sig; // Signature completely removed

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.checks.find((c) => c.rule === "CANONICAL_HASH")?.pass).toBe(true);
    expect(report.checks.find((c) => c.rule === "AGENT_SIGNATURE")?.pass).toBe(false);
  });

  it("F12.B3: toggling hash updates exactly 64 lowercase hex characters", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "New summary for testing";
    const newHash = recomputePacketHash(packet);
    expect(newHash).toMatch(/^[0-9a-f]{64}$/);
    expect(newHash).not.toBe(packet.packet_hash);
  });

  it("F12.B4: toggling hash does not modify original agent identity or root authority fields", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    const originalAipId = packet.agent.aip_id;
    const originalPrincipal = packet.root_authority.principal_id;

    packet.decision.summary = "Summary altered";
    packet.packet_hash = recomputePacketHash(packet);

    expect(packet.agent.aip_id).toBe(originalAipId);
    expect(packet.root_authority.principal_id).toBe(originalPrincipal);
  });

  it("F12.B5: restoring original summary after hash toggle returns back to fully valid state", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    const originalSummary = packet.decision.summary;
    const originalHash = packet.packet_hash;

    // Mutate and toggle
    packet.decision.summary = "Tampered";
    packet.packet_hash = recomputePacketHash(packet);

    // Revert back
    packet.decision.summary = originalSummary;
    packet.packet_hash = originalHash;

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(true);
    expect(report.derived_trust_floor).toBe("COUNTERPARTY_SIGNED");
  });
});
