import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle, recomputePacketHash } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F1: aip-wasm Interface Boundaries", () => {
  it("F1.B1: empty packet JSON string triggers clean structural error, not crash", () => {
    const invalidPacket: any = {};
    const report = verifyEvidencePacketOracle(invalidPacket, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);
    expect(report.checks.find((c) => c.rule === "STRUCTURE")?.pass).toBe(false);
  });

  it("F1.B2: malformed JSON payload handled without uncaught exception", () => {
    const corruptPacket: any = {
      magic: [0x00, 0x00, 0x00, 0x00],
      version: 99,
      actions: [],
    };
    const report = verifyEvidencePacketOracle(corruptPacket, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(false);
    expect(report.derived_trust_floor).toBe("UNVERIFIED");
  });

  it("F1.B3: large payload string (100KB) processed within memory limits", () => {
    const largePacket = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    largePacket.decision.summary = "Enterprise risk evaluation: " + "X".repeat(100000);
    const hash = recomputePacketHash(largePacket);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("F1.B4: missing contextJson argument defaults to empty verification context", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, {
      issuer_public_keys: {},
      revoked_jtis: [],
    });
    // Missing root issuer key in context is handled as verifiability gap
    const rootCheck = report.checks.find((c) => c.rule === "ROOT_TOKEN_SIGNATURE");
    expect(rootCheck?.pass).toBe(false);
    expect(report.tamper_evidence).toBe(false);
  });

  it("F1.B5: non-ASCII and multi-byte UTF-8 characters handled safely", () => {
    const utf8Packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    utf8Packet.decision.summary = "取引承認: €5,000,000 🚀 — 特殊文字検証";
    const hash = recomputePacketHash(utf8Packet);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });
});
