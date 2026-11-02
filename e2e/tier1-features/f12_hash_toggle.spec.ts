import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle, recomputePacketHash } from "../support/reference_oracle.js";
import {
  createTamperedSummaryPacket,
  createTamperedHashPacket,
  DEFAULT_VERIFICATION_CONTEXT,
} from "../fixtures/evidence_packets.js";

describe("Tier 1 - F12: Smart Hash Recalculation Toggle", () => {
  it("F12.1: naive attacker without hash toggle fails CANONICAL_HASH", () => {
    const packet = createTamperedSummaryPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(false);
  });

  it("F12.2: smart attacker with hash toggle fixes CANONICAL_HASH check", () => {
    const packet = createTamperedHashPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(true);
    expect(hashCheck?.detail).toContain("matches packet_hash");
  });

  it("F12.3: smart attacker still caught by AGENT_SIGNATURE failure", () => {
    const packet = createTamperedHashPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const sigCheck = report.checks.find((c) => c.rule === "AGENT_SIGNATURE");
    expect(sigCheck?.pass).toBe(false);
    expect(sigCheck?.detail).toContain("signature payload hash does not cover current packet contents");
  });

  it("F12.4: smart attacker toggle maintains overall tamper_evidence = true", () => {
    const packet = createTamperedHashPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.tamper_evidence).toBe(true);
    expect(report.overall_valid).toBe(false);
  });

  it("F12.5: toggling hash dynamically updates recomputed hash value", () => {
    const packet = createTamperedSummaryPacket();
    const beforeHash = packet.packet_hash;
    const computed = recomputePacketHash(packet);
    expect(computed).not.toBe(beforeHash);
    packet.packet_hash = computed;
    expect(packet.packet_hash).toBe(computed);
  });
});
