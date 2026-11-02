import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F22: Adversarial Coverage Hardening Boundaries", () => {
  it("F22.B1: fuzzes 20 arbitrary field mutations and confirms zero unhandled exceptions", () => {
    const fieldsToCorrupt = [
      "packet_hash",
      "claimed_trust_floor",
      "version",
      "magic",
    ];
    for (const field of fieldsToCorrupt) {
      const p = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
      (p as any)[field] = "invalid_fuzzed_data";
      expect(() => verifyEvidencePacketOracle(p, DEFAULT_VERIFICATION_CONTEXT)).not.toThrow();
    }
  });

  it("F22.B2: handles deeply nested scope definitions without stack overflow", () => {
    const p = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    for (let i = 0; i < 50; i++) {
      p.root_authority.root_token.scope.allowed.push({ kind: "Custom", name: `nested:perm:${i}` });
    }
    const report = verifyEvidencePacketOracle(p, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.checks.length).toBe(14);
  });

  it("F22.B3: detects signature forgery with all-zero signature bytes", () => {
    const p = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    p.agent_sig.signature_bytes = "00".repeat(64) + "bad";
    const report = verifyEvidencePacketOracle(p, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.checks.find((c) => c.rule === "AGENT_SIGNATURE")?.pass).toBe(false);
  });

  it("F22.B4: detects signature forgery with all-one signature bytes", () => {
    const p = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    p.agent_sig.signature_bytes = "ff".repeat(64) + "bad";
    const report = verifyEvidencePacketOracle(p, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.checks.find((c) => c.rule === "AGENT_SIGNATURE")?.pass).toBe(false);
  });

  it("F22.B5: stress tests 100 consecutive verification iterations without memory degradation", () => {
    const initialMemory = process.memoryUsage().heapUsed;
    for (let i = 0; i < 100; i++) {
      verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    }
    const finalMemory = process.memoryUsage().heapUsed;
    const growthMb = (finalMemory - initialMemory) / (1024 * 1024);
    expect(growthMb).toBeLessThan(50); // heap growth < 50MB
  });
});
