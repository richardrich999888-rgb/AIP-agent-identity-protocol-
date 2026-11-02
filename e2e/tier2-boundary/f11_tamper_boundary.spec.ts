import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F11: Adversarial Tamper Sandbox Boundaries", () => {
  it("F11.B1: single bit modification in agent signature bytes triggers tamper evidence", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    const chars = packet.agent_sig.signature_bytes.split("");
    chars[0] = chars[0] === "a" ? "b" : "a";
    chars.push("bad");
    packet.agent_sig.signature_bytes = chars.join("");

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.tamper_evidence).toBe(true);
    expect(report.overall_valid).toBe(false);
  });

  it("F11.B2: altering single whitespace in decision summary triggers hash mismatch", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary += " "; // single trailing space added
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(false);
    expect(report.tamper_evidence).toBe(true);
  });

  it("F11.B3: reordering action attestations array changes canonical hash", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.actions.push({
      action_id: "act-002",
      action_kind: { kind: "Standard", action: "Read" },
      description: "Second action",
      payload_hash: "1111111111111111111111111111111111111111111111111111111111111111",
      performed_at: packet.actions[0].performed_at + 100,
      agent_sig: packet.actions[0].agent_sig,
    });
    // Reverse order
    packet.actions.reverse();
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(false);
  });

  it("F11.B4: swapping input_hash and rationale_hash breaks CANONICAL_HASH", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    const tmp = packet.decision.input_hash;
    packet.decision.input_hash = packet.decision.rationale_hash;
    packet.decision.rationale_hash = tmp;
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(false);
    expect(report.tamper_evidence).toBe(true);
  });

  it("F11.B5: mutating model provenance commitment invalidates AGENT_ID_BINDING", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.agent.aip_id = "aip1corruptprovenancecommitment112233445566";
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const idCheck = report.checks.find((c) => c.rule === "AGENT_ID_BINDING");
    expect(idCheck?.pass).toBe(false);
  });
});
