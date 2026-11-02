import { describe, it, expect } from "vitest";
import { MockEvidenceVaultClient } from "../support/mock_vault_client.js";

describe("Tier 1 - F17: Evidence Vault Explorer Table", () => {
  const client = new MockEvidenceVaultClient();

  it("F17.1: lists all stored evidence summaries in multi-tenant table", async () => {
    const list = await client.listEvidence();
    expect(list.length).toBeGreaterThanOrEqual(4);
    for (const item of list) {
      expect(item.id).toBeDefined();
      expect(item.tenant_id).toBeDefined();
      expect(item.decision_summary).toBeDefined();
    }
  });

  it("F17.2: filters evidence table by Trust Floor (e.g. COUNTERPARTY_SIGNED)", async () => {
    const list = await client.listEvidence({ trust_floor: "COUNTERPARTY_SIGNED" });
    expect(list.length).toBeGreaterThanOrEqual(1);
    for (const item of list) {
      expect(item.trust_floor).toBe("COUNTERPARTY_SIGNED");
    }
  });

  it("F17.3: searches table records by keyword query", async () => {
    const list = await client.listEvidence({ query: "commercial credit" });
    expect(list.length).toBe(1);
    expect(list[0].decision_summary).toContain("commercial credit facility");
  });

  it("F17.4: retrieves full EvidencePacket detail by ID", async () => {
    const packet = await client.getEvidence("pkt-001-acme-loan");
    expect(packet).toBeDefined();
    expect(packet.magic).toEqual([0x41, 0x45, 0x50, 0x31]);
    expect(packet.decision.decision_id).toBe("d001-loan-approval-acme-corp");
  });

  it("F17.5: generates accountability graph from vault table item", async () => {
    const graph = await client.getAuthorityGraph("pkt-001-acme-loan");
    expect(graph.nodes.length).toBeGreaterThanOrEqual(7);
    expect(graph.edges.length).toBeGreaterThanOrEqual(6);
  });
});
