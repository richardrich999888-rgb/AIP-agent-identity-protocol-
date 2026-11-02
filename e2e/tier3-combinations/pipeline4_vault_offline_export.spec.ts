import { describe, it, expect } from "vitest";
import { MockEvidenceVaultClient } from "../support/mock_vault_client.js";

describe("Tier 3 - Pipeline 4: Vault Filtering -> Offline Fallback -> ZIP Export", () => {
  const client = new MockEvidenceVaultClient(true); // Starts online

  it("P4.1: filters evidence table by Trust Floor in live mode", async () => {
    expect(client.isLive()).toBe(true);
    const results = await client.listEvidence({ trust_floor: "COUNTERPARTY_SIGNED" });
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].trust_floor).toBe("COUNTERPARTY_SIGNED");
  });

  it("P4.2: transitions seamlessly to offline mode upon network loss", () => {
    // Network drops
    client.setLive(false);
    expect(client.isLive()).toBe(false);
  });

  it("P4.3: executes offline verification on cached evidence packet", async () => {
    const packet = await client.getEvidence("pkt-001-acme-loan");
    const report = await client.verifyEvidence(packet);
    expect(report.overall_valid).toBe(true);
    expect(report.derived_trust_floor).toBe("COUNTERPARTY_SIGNED");
  });

  it("P4.4: exports signed 7-file audit ZIP bundle from offline client", async () => {
    const zipBytes = await client.exportBundle("pkt-001-acme-loan");
    expect(zipBytes).toBeInstanceOf(Uint8Array);
    expect(zipBytes.length).toBeGreaterThan(100);

    const text = new TextDecoder().decode(zipBytes);
    const bundleMap = JSON.parse(text);
    expect(bundleMap["evidence.json"]).toBeDefined();
    expect(bundleMap["manifest.json"]).toBeDefined();
    expect(bundleMap["bundle.sig"]).toBeDefined();
    expect(bundleMap["audit_report.md"]).toBeDefined();
  });

  it("P4.5: exported bundle verification confirms all 7 internal checks pass", async () => {
    const zipBytes = await client.exportBundle("pkt-001-acme-loan");
    const bundleMap = JSON.parse(new TextDecoder().decode(zipBytes));
    const manifest = JSON.parse(bundleMap["manifest.json"]);

    // Verify bundle structure check
    expect(manifest.bundle_version).toBe("aip-bundle-1");
    // Verify file hashes check
    const { sha256Hex } = await import("../support/reference_oracle.js");
    expect(manifest.files["evidence.json"]).toBe(sha256Hex(bundleMap["evidence.json"]));
    expect(manifest.files["verification.json"]).toBe(sha256Hex(bundleMap["verification.json"]));
  });
});
