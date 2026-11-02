import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle, recomputePacketHash } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 4 - Scenario 3: Forensic Tamper Investigation & Non-Repudiation", () => {
  it("S3.1: ingests suspicious packet and identifies post-sealing modification", () => {
    const suspect = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    suspect.decision.summary = "Attacker modified payment to route $5,000,000 to unauthorized account";

    const report = verifyEvidencePacketOracle(suspect, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);
    expect(report.tamper_evidence).toBe(true);

    const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
    expect(hashCheck?.pass).toBe(false);
    expect(hashCheck?.detail).toContain("packet modified after sealing");
  });

  it("S3.2: forensic hash diff pinpoints that recomputed hash differs from stored hash", () => {
    const suspect = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    suspect.decision.summary = "Modified summary text";

    const originalHash = suspect.packet_hash;
    const recomputed = recomputePacketHash(suspect);

    expect(recomputed).not.toBe(originalHash);
  });

  it("S3.3: detects advanced attacker attempting hash-recalculation to bypass integrity check", () => {
    const suspect = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    suspect.decision.summary = "Modified summary text";
    suspect.packet_hash = recomputePacketHash(suspect); // Smart attacker recalculated hash

    const report = verifyEvidencePacketOracle(suspect, DEFAULT_VERIFICATION_CONTEXT);

    // Hash check fooled:
    expect(report.checks.find((c) => c.rule === "CANONICAL_HASH")?.pass).toBe(true);

    // Cryptographic signature caught:
    const sigCheck = report.checks.find((c) => c.rule === "AGENT_SIGNATURE");
    expect(sigCheck?.pass).toBe(false);
    expect(sigCheck?.detail).toContain("signature payload hash does not cover current packet contents");

    // Defense holds:
    expect(report.tamper_evidence).toBe(true);
    expect(report.overall_valid).toBe(false);
  });

  it("S3.4: proves non-repudiation: agent signature cannot be forged without private key", () => {
    const suspect = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    suspect.decision.summary = "Attacker unauthorized decision";
    suspect.packet_hash = recomputePacketHash(suspect);
    suspect.agent_sig.payload_hash = suspect.packet_hash;
    // Forged signature
    suspect.agent_sig.signature_bytes = "forged_signature_attempt_hex_bad";

    const report = verifyEvidencePacketOracle(suspect, DEFAULT_VERIFICATION_CONTEXT);
    const sigCheck = report.checks.find((c) => c.rule === "AGENT_SIGNATURE");
    expect(sigCheck?.pass).toBe(false);
    expect(sigCheck?.detail).toContain("agent signature cryptographic verification failed");
  });

  it("S3.5: downgrades Trust Floor to UNVERIFIED and produces detailed forensic report", () => {
    const suspect = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    suspect.decision.summary = "Tampered";

    const report = verifyEvidencePacketOracle(suspect, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.derived_trust_floor).toBe("UNVERIFIED");

    const floorCheck = report.checks.find((c) => c.rule === "TRUST_FLOOR");
    expect(floorCheck?.pass).toBe(false);
  });
});
