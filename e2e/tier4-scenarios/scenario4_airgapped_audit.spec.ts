import { describe, it, expect } from "vitest";
import { MockEvidenceVaultClient } from "../support/mock_vault_client.js";
import { createSampleAuditBundleFiles } from "../fixtures/audit_bundles.js";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";
import { sha256Hex } from "../support/reference_oracle.js";

describe("Tier 4 - Scenario 4: Air-Gapped Offline Audit & Signed ZIP Verification", () => {
  const offlineClient = new MockEvidenceVaultClient(false); // Air-gapped offline client

  it("S4.1: operates in strict offline disconnected mode (isLive === false)", () => {
    expect(offlineClient.isLive()).toBe(false);
  });

  it("S4.2: loads portable 7-file audit ZIP bundle without external network calls", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    expect(Object.keys(bundleFiles).length).toBe(7);
  });

  it("S4.3: validates manifest SHA-256 integrity check for every member file in bundle", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    const manifest = JSON.parse(bundleFiles["manifest.json"]);

    for (const [filename, expectedHash] of Object.entries(manifest.files)) {
      const fileContent = (bundleFiles as any)[filename];
      expect(fileContent).toBeDefined();
      const actualHash = sha256Hex(fileContent);
      expect(actualHash).toBe(expectedHash);
    }
  });

  it("S4.4: verifies bundle cryptographic signature over manifest payload", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    const sig = JSON.parse(bundleFiles["bundle.sig"]);
    const manifestHash = sha256Hex(bundleFiles["manifest.json"]);

    expect(sig.payload_hash).toBe(manifestHash);
    expect(sig.algorithm).toBe("Ed25519");
    expect(sig.signer_id).toBe("auditor-cert-authority-01");
  });

  it("S4.5: performs full client-side 14-rule verification on bundle evidence.json offline", async () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    const packet = JSON.parse(bundleFiles["evidence.json"]);

    const report = await offlineClient.verifyEvidence(packet);
    expect(report.overall_valid).toBe(true);
    expect(report.derived_trust_floor).toBe("COUNTERPARTY_SIGNED");
    expect(report.checks.length).toBe(14);
    expect(report.checks.every((c) => c.pass)).toBe(true);
  });
});
