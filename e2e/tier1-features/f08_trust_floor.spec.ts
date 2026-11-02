import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import {
  validHonestCounterpartyPacket,
  createAuthorityBoundPacket,
  createAgentSignedPacket,
  createTamperedSummaryPacket,
  DEFAULT_VERIFICATION_CONTEXT,
} from "../fixtures/evidence_packets.js";

describe("Tier 1 - F8: Trust Floor Progression Ladder", () => {
  it("F8.1: derives Level 3 (COUNTERPARTY_SIGNED) when bilateral receipt verified", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.derived_trust_floor).toBe("COUNTERPARTY_SIGNED");
    expect(report.claimed_trust_floor).toBe("COUNTERPARTY_SIGNED");
  });

  it("F8.2: derives Level 2 (AUTHORITY_BOUND) when authority chain holds but no countersignature", () => {
    const packet = createAuthorityBoundPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.derived_trust_floor).toBe("AUTHORITY_BOUND");
    expect(report.claimed_trust_floor).toBe("AUTHORITY_BOUND");
  });

  it("F8.3: derives Level 1 (AGENT_SIGNED) when only agent cryptographic integrity passes", () => {
    const packet = createAgentSignedPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.derived_trust_floor).toBe("AGENT_SIGNED");
    expect(report.claimed_trust_floor).toBe("AGENT_SIGNED");
  });

  it("F8.4: derives Level 0 (UNVERIFIED) when payload modified after sealing", () => {
    const packet = createTamperedSummaryPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.derived_trust_floor).toBe("UNVERIFIED");
  });

  it("F8.5: fails Rule 14 TRUST_FLOOR if claimed floor exceeds derived floor", () => {
    const packet = createAuthorityBoundPacket();
    packet.claimed_trust_floor = "COUNTERPARTY_SIGNED"; // Claim exceeds derived AuthorityBound
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const floorCheck = report.checks.find((c) => c.rule === "TRUST_FLOOR");
    expect(floorCheck?.pass).toBe(false);
    expect(floorCheck?.detail).toContain("claimed floor COUNTERPARTY_SIGNED exceeds what the evidence supports");
  });
});
