import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F2: Fixture Generation Pipeline Boundaries", () => {
  it("F2.B1: fixture with corrupted magic bytes fails STRUCTURE rule", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.magic = [0x42, 0x41, 0x44, 0x31]; // "BAD1"
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const structCheck = report.checks.find((c) => c.rule === "STRUCTURE");
    expect(structCheck?.pass).toBe(false);
    expect(structCheck?.detail).toContain("bad magic");
  });

  it("F2.B2: fixture with unsupported version (version: 2) fails STRUCTURE rule", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.version = 2;
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const structCheck = report.checks.find((c) => c.rule === "STRUCTURE");
    expect(structCheck?.pass).toBe(false);
    expect(structCheck?.detail).toContain("unsupported version");
  });

  it("F2.B3: fixture with empty actions array fails STRUCTURE rule", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.actions = [];
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const structCheck = report.checks.find((c) => c.rule === "STRUCTURE");
    expect(structCheck?.pass).toBe(false);
    expect(structCheck?.detail).toContain("no action attestations");
  });

  it("F2.B4: fixture with empty decision summary fails STRUCTURE rule", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "";
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const structCheck = report.checks.find((c) => c.rule === "STRUCTURE");
    expect(structCheck?.pass).toBe(false);
    expect(structCheck?.detail).toContain("empty decision summary");
  });

  it("F2.B5: fixture with inverted action timestamp fails TEMPORAL_VALIDITY rule", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.actions[0].performed_at = packet.decision.decided_at - 50000;
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const temporalCheck = report.checks.find((c) => c.rule === "TEMPORAL_VALIDITY");
    expect(temporalCheck?.pass).toBe(false);
    expect(temporalCheck?.detail).toContain("performed before authorizing decision");
  });
});
