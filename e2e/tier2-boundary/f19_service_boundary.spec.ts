import { describe, it, expect } from "vitest";
import { MockEvidenceVaultClient } from "../support/mock_vault_client.js";

describe("Tier 2 Boundary - F19: Connected Service Client Boundaries", () => {
  const client = new MockEvidenceVaultClient(true);

  it("F19.B1: handles malformed packet ID parameter with 404 rejection", async () => {
    await expect(client.getEvidence("")).rejects.toThrow(/404/);
  });

  it("F19.B2: handles special characters in packet ID lookup safely", async () => {
    await expect(client.getEvidence("../../../etc/passwd")).rejects.toThrow(/404/);
  });

  it("F19.B3: parallel concurrent verification calls (10 simultaneous requests) complete cleanly", async () => {
    const { validHonestCounterpartyPacket } = await import("../fixtures/evidence_packets.js");
    const promises = Array.from({ length: 10 }, () => client.verifyEvidence(validHonestCounterpartyPacket));
    const results = await Promise.all(promises);
    expect(results.length).toBe(10);
    for (const r of results) {
      expect(r.overall_valid).toBe(true);
    }
  });

  it("F19.B4: verifies server response serialization integrity", async () => {
    const packet = await client.getEvidence("pkt-001-acme-loan");
    expect(typeof packet.decision.decided_at).toBe("number");
    expect(Array.isArray(packet.magic)).toBe(true);
  });

  it("F19.B5: authority graph query on non-existent packet throws 404", async () => {
    await expect(client.getAuthorityGraph("non-existent-authority-query")).rejects.toThrow(/404/);
  });
});
