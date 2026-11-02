import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F13: Failure Feedback Real-Time Boundaries", () => {
  it("F13.B1: handles multiple cascading rule failures simultaneously", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "Tampered summary";
    packet.agent_sig.signature_bytes = "corrupted_sig";
    packet.root_authority.root_token.issuer_sig.signature_bytes = "bad_root_sig";

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const failedRules = report.checks.filter((c) => !c.pass).map((c) => c.rule);
    expect(failedRules).toContain("CANONICAL_HASH");
    expect(failedRules).toContain("AGENT_SIGNATURE");
    expect(failedRules).toContain("ROOT_TOKEN_SIGNATURE");
    expect(report.tamper_evidence).toBe(true);
  });

  it("F13.B2: failure details never leak raw internal stack trace paths", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.actions[0].action_kind = { kind: "Custom", name: "unpermitted:action" };
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    for (const check of report.checks) {
      expect(check.detail).not.toContain("at Object.");
      expect(check.detail).not.toContain("Error:");
    }
  });

  it("F13.B3: formats semicolon-separated failure lists cleanly", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.actions.push({
      action_id: "act-unauthorized-1",
      action_kind: { kind: "Standard", action: "Admin" }, // not permitted in child
      description: "Admin op",
      payload_hash: packet.actions[0].payload_hash,
      performed_at: packet.actions[0].performed_at,
      agent_sig: packet.actions[0].agent_sig,
    });
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const scopeCheck = report.checks.find((c) => c.rule === "SCOPE_AUTHORITY");
    expect(scopeCheck?.pass).toBe(false);
    expect(scopeCheck?.detail).toContain("prohibited outside effective scope");
  });

  it("F13.B4: transitions UI ledger from red failure back to green pass when fixed", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    // Tamper
    packet.decision.summary = "Tampered";
    let report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);

    // Fix
    packet.decision.summary = validHonestCounterpartyPacket.decision.summary;
    report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(true);
  });

  it("F13.B5: verifies all rule names in checks match normative 14-rule enum exactly", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    const validNames = new Set([
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
    ]);
    for (const check of report.checks) {
      expect(validNames.has(check.rule)).toBe(true);
    }
  });
});
