import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle, recomputePacketHash } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 3 - Pipeline 2: Tampering -> Hash Fixing -> Rule Failure Feedback", () => {
  it("P2.1: payload modification immediately fails CANONICAL_HASH in failure ledger", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "MUTATED: Divert funds to offshore treasury account";

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);
    expect(report.tamper_evidence).toBe(true);

    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(false);
    expect(hashCheck?.detail).toContain("packet modified after sealing");
  });

  it("P2.2: smart attacker hash recalculation fixes CANONICAL_HASH while AGENT_SIGNATURE remains failed", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "MUTATED: Divert funds to offshore treasury account";

    // Simulate smart attacker toggle: recalculate hash
    const fixedHash = recomputePacketHash(packet);
    packet.packet_hash = fixedHash;

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);

    // Rule 3 (CANONICAL_HASH) now passes
    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(true);

    // Rule 4 (AGENT_SIGNATURE) still fails because agent signed the original hash!
    const sigCheck = report.checks.find((c) => c.rule === "AGENT_SIGNATURE");
    expect(sigCheck?.pass).toBe(false);
    expect(sigCheck?.detail).toContain("signature payload hash does not cover current packet contents");

    // Zero-trust guarantee: overall verdict is still TAMPERED
    expect(report.overall_valid).toBe(false);
    expect(report.tamper_evidence).toBe(true);
  });

  it("P2.3: tamper detection cascades to downgrade Trust Floor to UNVERIFIED", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "MUTATED: Divert funds";

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.derived_trust_floor).toBe("UNVERIFIED");

    const floorCheck = report.checks.find((c) => c.rule === "TRUST_FLOOR");
    expect(floorCheck?.pass).toBe(false);
  });

  it("P2.4: modifying action payload hash triggers action attestation failure in ledger", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.actions[0].payload_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    packet.packet_hash = recomputePacketHash(packet); // Hash recalculated

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const actCheck = report.checks.find((c) => c.rule === "ACTION_ATTESTATIONS");
    expect(actCheck?.pass).toBe(false);
    expect(report.tamper_evidence).toBe(true);
  });

  it("P2.5: full revert of all tampered fields restores 100% pass across all 14 rules", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.decision.summary = "Temporary tamper";
    packet.packet_hash = recomputePacketHash(packet);

    // Revert
    packet.decision.summary = validHonestCounterpartyPacket.decision.summary;
    packet.packet_hash = validHonestCounterpartyPacket.packet_hash;

    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(true);
    expect(report.checks.every((c) => c.pass)).toBe(true);
  });
});
