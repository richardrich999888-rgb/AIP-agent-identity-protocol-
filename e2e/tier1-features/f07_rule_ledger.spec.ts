import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";
import { RuleName } from "../support/types.js";

describe("Tier 1 - F7: 14-Rule Verification Ledger", () => {
  const EXPECTED_RULES: RuleName[] = [
    "STRUCTURE",
    "AGENT_ID_BINDING",
    "CANONICAL_HASH",
    "AGENT_SIGNATURE",
    "ROOT_TOKEN_SIGNATURE",
    "DELEGATION_CHAIN",
    "AUTHORITY_CHAIN",
    "SCOPE_AUTHORITY",
    "REVOCATION",
    "TEMPORAL_VALIDITY",
    "ACTION_ATTESTATIONS",
    "TRACE_BINDING",
    "RECEIPT_BINDING",
    "TRUST_FLOOR",
  ];

  it("F7.1: evaluates exactly 14 non-short-circuiting verification checks", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.checks.length).toBe(14);
    const rules = report.checks.map((c) => c.rule);
    expect(rules).toEqual(EXPECTED_RULES);
  });

  it("F7.2: returns pass=true for all rules on honest counterparty packet", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    for (const check of report.checks) {
      expect(check.pass).toBe(true);
    }
  });

  it("F7.3: includes informative detail string for each rule result", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    for (const check of report.checks) {
      expect(check.detail).toBeDefined();
      expect(check.detail.length).toBeGreaterThan(5);
    }
    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.detail).toContain("matches packet_hash");
  });

  it("F7.4: ledger passes verified_at timestamp to UI for audit freshness", () => {
    const now = 1772530000000;
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, {
      ...DEFAULT_VERIFICATION_CONTEXT,
      now,
    });
    expect(report.verified_at).toBe(now);
  });

  it("F7.5: overall_valid reflects strict conjunction of all 14 checks", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    const manualAllPass = report.checks.every((c) => c.pass);
    expect(report.overall_valid).toBe(manualAllPass);
  });
});
