import { describe, it, expect } from "vitest";
import { MockEvidenceVaultClient } from "../support/mock_vault_client.js";
import { createAuthorityBoundPacket } from "../fixtures/evidence_packets.js";

describe("Tier 1 - F20: Offline Mock Fallback Mode", () => {
  const offlineClient = new MockEvidenceVaultClient(false);

  it("F20.1: reports isLive() false when operating in offline fallback mode", () => {
    expect(offlineClient.isLive()).toBe(false);
  });

  it("F20.2: operates offline verification without network access", async () => {
    const packet = createAuthorityBoundPacket();
    const report = await offlineClient.verifyEvidence(packet);
    expect(report.overall_valid).toBe(true);
    expect(report.derived_trust_floor).toBe("AUTHORITY_BOUND");
  });

  it("F20.3: stores new evidence packet in offline local store", async () => {
    const customPacket = createAuthorityBoundPacket();
    customPacket.decision.decision_id = "offline-saved-pkt-555";
    offlineClient.seedPacket("offline-saved-pkt-555", customPacket);

    const retrieved = await offlineClient.getEvidence("offline-saved-pkt-555");
    expect(retrieved.decision.decision_id).toBe("offline-saved-pkt-555");
  });

  it("F20.4: supports toggling live state dynamically on network recovery", () => {
    offlineClient.setLive(true);
    expect(offlineClient.isLive()).toBe(true);
    offlineClient.setLive(false);
    expect(offlineClient.isLive()).toBe(false);
  });

  it("F20.5: generates signed audit ZIP export completely offline in client", async () => {
    const zipBytes = await offlineClient.exportBundle("pkt-001-acme-loan");
    expect(zipBytes.length).toBeGreaterThan(0);
    const text = new TextDecoder().decode(zipBytes);
    const parsed = JSON.parse(text);
    expect(parsed["manifest.json"]).toBeDefined();
  });
});
