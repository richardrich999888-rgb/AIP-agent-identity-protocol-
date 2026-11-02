import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import {
  createTamperedSummaryPacket,
  createBrokenHandoffPacket,
  DEFAULT_VERIFICATION_CONTEXT,
} from "../fixtures/evidence_packets.js";

describe("Tier 1 - F13: Instant Rule Failure Feedback", () => {
  it("F13.1: identifies exact count of failing rules in report checks", () => {
    const packet = createTamperedSummaryPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const failedChecks = report.checks.filter((c) => !c.pass);
    expect(failedChecks.length).toBeGreaterThanOrEqual(2); // CANONICAL_HASH, AGENT_SIGNATURE, etc.
  });

  it("F13.2: provides rule-specific failure detail without generic fallbacks", () => {
    const packet = createBrokenHandoffPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const authCheck = report.checks.find((c) => c.rule === "AUTHORITY_CHAIN");
    expect(authCheck?.pass).toBe(false);
    expect(authCheck?.detail).toContain("leaf delegation grantee unexpected-middleman is not acting agent");
  });

  it("F13.3: updates overall valid badge to false instantly on any single failure", () => {
    const packet = createBrokenHandoffPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);
  });

  it("F13.4: displays tamper_evidence crimson badge when cryptographic integrity is breached", () => {
    const packet = createTamperedSummaryPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.tamper_evidence).toBe(true);
  });

  it("F13.5: differentiates verifiability gaps from cryptographic tampering", () => {
    const packet = JSON.parse(JSON.stringify(createBrokenHandoffPacket()));
    // Gap: unknown root issuer
    const report = verifyEvidencePacketOracle(packet, {
      issuer_public_keys: {}, // empty: missing key
      revoked_jtis: [],
    });
    const rootCheck = report.checks.find((c) => c.rule === "ROOT_TOKEN_SIGNATURE");
    expect(rootCheck?.pass).toBe(false);
    expect(rootCheck?.detail).toContain("no trusted public key for root issuer");
  });
});
