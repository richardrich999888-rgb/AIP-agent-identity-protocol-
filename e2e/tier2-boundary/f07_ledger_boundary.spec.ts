import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F7: 14-Rule Verification Ledger Boundaries", () => {
  it("F7.B1: evaluates all 14 rules even when rule 1 (STRUCTURE) fails", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.magic = [0x00, 0x00, 0x00, 0x00];
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    // Strict non-short-circuiting requirement
    expect(report.checks.length).toBe(14);
  });

  it("F7.B2: action signature tampering triggers Rule 11 fail without crashing ledger", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.actions[0].agent_sig.signature_bytes = "corrupted";
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const actCheck = report.checks.find((c) => c.rule === "ACTION_ATTESTATIONS");
    expect(actCheck?.pass).toBe(false);
    expect(report.tamper_evidence).toBe(true);
  });

  it("F7.B3: expired root token fails Rule 10 TEMPORAL_VALIDITY", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.root_authority.root_token.expires_at = packet.decision.decided_at - 1000;
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const timeCheck = report.checks.find((c) => c.rule === "TEMPORAL_VALIDITY");
    expect(timeCheck?.pass).toBe(false);
    expect(timeCheck?.detail).toContain("exceeds root token expiration");
  });

  it("F7.B4: trace data hash mismatch flags Rule 12 TRACE_BINDING", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, {
      ...DEFAULT_VERIFICATION_CONTEXT,
      trace_data: "mismatched-trace-data-payload-xyz",
    });
    const traceCheck = report.checks.find((c) => c.rule === "TRACE_BINDING");
    expect(traceCheck?.pass).toBe(false);
    expect(traceCheck?.detail).toContain("does NOT match the bound trace_hash");
    expect(report.tamper_evidence).toBe(true);
  });

  it("F7.B5: receipt data hash mismatch flags Rule 13 RECEIPT_BINDING", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, {
      ...DEFAULT_VERIFICATION_CONTEXT,
      receipt_data: "mismatched-receipt-data-wrong-payload",
    });
    const rcptCheck = report.checks.find((c) => c.rule === "RECEIPT_BINDING");
    expect(rcptCheck?.pass).toBe(false);
    expect(rcptCheck?.detail).toContain("does not match bound receipt_hash");
    expect(report.tamper_evidence).toBe(true);
  });
});
