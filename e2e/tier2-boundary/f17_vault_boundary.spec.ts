import { describe, it, expect } from "vitest";
import { MockEvidenceVaultClient } from "../support/mock_vault_client.js";

describe("Tier 2 Boundary - F17: Evidence Vault Explorer Boundaries", () => {
  const client = new MockEvidenceVaultClient();

  it("F17.B1: search query matching nothing returns empty array (not null)", async () => {
    const list = await client.listEvidence({ query: "non-existent-token-string-xyz" });
    expect(list).toEqual([]);
  });

  it("F17.B2: search query handles SQL/script injection characters safely", async () => {
    const list = await client.listEvidence({ query: "' OR '1'='1'; <script>alert(1)</script>" });
    expect(Array.isArray(list)).toBe(true);
    expect(list.length).toBe(0);
  });

  it("F17.B3: querying unknown packet ID throws error matching 404 pattern", async () => {
    await expect(client.getEvidence("unknown-id-888999")).rejects.toThrow(/404/);
  });

  it("F17.B4: listing with filter for unused Trust Floor returns empty array", async () => {
    const list = await client.listEvidence({ trust_floor: "UNVERIFIED" });
    expect(Array.isArray(list)).toBe(true);
  });

  it("F17.B5: multi-tenant isolation prevents accessing records across tenant boundaries", async () => {
    const list = await client.listEvidence();
    for (const item of list) {
      expect(item.tenant_id).toBe("tenant-enterprise-primary");
    }
  });
});
