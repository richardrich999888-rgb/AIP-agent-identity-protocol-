import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import {
  validHonestCounterpartyPacket,
  createTamperedSummaryPacket,
  createScopeEscalationPacket,
  DEFAULT_VERIFICATION_CONTEXT,
} from "../fixtures/evidence_packets.js";

describe("Tier 1 - F11: Adversarial Tamper Sandbox", () => {
  it("F11.1: vector 1 - decision summary tampering triggers CANONICAL_HASH failure", () => {
    const packet = createTamperedSummaryPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);
    expect(report.tamper_evidence).toBe(true);
    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(false);
  });

  it("F11.2: vector 2 - action payload hash mutation triggers ACTION_ATTESTATIONS failure", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.actions[0].payload_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    packet.actions[0].payload_hash += "tampered";
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);
    expect(report.tamper_evidence).toBe(true);
    const actCheck = report.checks.find((c) => c.rule === "ACTION_ATTESTATIONS");
    expect(actCheck?.pass).toBe(false);
  });

  it("F11.3: vector 3 - scope escalation attack triggers DELEGATION_CHAIN failure", () => {
    const packet = createScopeEscalationPacket();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);
    expect(report.tamper_evidence).toBe(true);
    const delCheck = report.checks.find((c) => c.rule === "DELEGATION_CHAIN");
    expect(delCheck?.pass).toBe(false);
    expect(delCheck?.detail).toContain("attenuation violation");
  });

  it("F11.4: vector 4 - identity hijacking triggers AGENT_ID_BINDING mismatch", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.agent.aip_id = "aip1mismatchidentity99887766554433221122";
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const idCheck = report.checks.find((c) => c.rule === "AGENT_ID_BINDING");
    expect(idCheck?.pass).toBe(false);
    expect(idCheck?.detail).toContain("does not match derived ID");
  });

  it("F11.5: vector 5 - counterparty signature tampering triggers RECEIPT_BINDING failure", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    if (packet.receipt_binding?.counterparty_sig) {
      packet.receipt_binding.counterparty_sig.signature_bytes = "corrupted_sig_hex_bytes";
    }
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const rcptCheck = report.checks.find((c) => c.rule === "RECEIPT_BINDING");
    expect(rcptCheck?.pass).toBe(false);
    expect(report.tamper_evidence).toBe(true);
  });
});
