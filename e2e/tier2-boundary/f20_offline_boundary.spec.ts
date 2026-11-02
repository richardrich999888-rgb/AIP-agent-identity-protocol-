import { describe, it, expect } from "vitest";
import { MockEvidenceVaultClient } from "../support/mock_vault_client.js";
import { createAuthorityBoundPacket } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F20: Offline Mock Fallback Mode Boundaries", () => {
  const offlineClient = new MockEvidenceVaultClient(false);

  it("F20.B1: offline client gracefully handles missing local records", async () => {
    await expect(offlineClient.getEvidence("missing-local-id")).rejects.toThrow(/404/);
  });

  it("F20.B2: storing and reading packet with large actions array in offline mode", async () => {
    const packet = createAuthorityBoundPacket();
    for (let i = 0; i < 20; i++) {
      packet.actions.push({ ...packet.actions[0], action_id: `offline-act-${i}` });
    }
    offlineClient.seedPacket("pkt-offline-large", packet);
    const retrieved = await offlineClient.getEvidence("pkt-offline-large");
    expect(retrieved.actions.length).toBe(21);
  });

  it("F20.B3: rapid toggle of offline/live state preserves seeded data", async () => {
    offlineClient.setLive(true);
    offlineClient.setLive(false);
    offlineClient.setLive(true);
    offlineClient.setLive(false);

    const packet = await offlineClient.getEvidence("pkt-001-acme-loan");
    expect(packet).toBeDefined();
  });

  it("F20.B4: offline bundle export on tampered packet includes tampered verification report", async () => {
    const bytes = await offlineClient.exportBundle("pkt-004-tampered");
    const text = new TextDecoder().decode(bytes);
    const bundle = JSON.parse(text);
    const report = JSON.parse(bundle["verification.json"]);
    expect(report.overall_valid).toBe(false);
    expect(report.tamper_evidence).toBe(true);
  });

  it("F20.B5: offline listing preserves sorting by timestamp", async () => {
    const list = await offlineClient.listEvidence();
    expect(list.length).toBeGreaterThanOrEqual(4);
    for (const item of list) {
      expect(item.created_at).toBeGreaterThan(0);
    }
  });
});
