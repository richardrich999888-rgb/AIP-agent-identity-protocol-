import { describe, it, expect } from "vitest";
import { createSampleAuditBundleFiles } from "../fixtures/audit_bundles.js";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";
import { sha256Hex } from "../support/reference_oracle.js";

describe("Tier 1 - F18: Signed ZIP Bundle Export", () => {
  const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);

  it("F18.1: contains all 7 mandatory audit bundle files", () => {
    const requiredFiles = [
      "evidence.json",
      "verification.json",
      "audit_report.md",
      "accountability_graph.json",
      "accountability_graph.dot",
      "manifest.json",
      "bundle.sig",
    ];
    for (const filename of requiredFiles) {
      expect(bundleFiles).toHaveProperty(filename);
    }
  });

  it("F18.2: verifies manifest.json lists correct SHA-256 hashes of all member files", () => {
    const manifest = JSON.parse(bundleFiles["manifest.json"]);
    expect(manifest.files["evidence.json"]).toBe(sha256Hex(bundleFiles["evidence.json"]));
    expect(manifest.files["verification.json"]).toBe(sha256Hex(bundleFiles["verification.json"]));
    expect(manifest.files["audit_report.md"]).toBe(sha256Hex(bundleFiles["audit_report.md"]));
    expect(manifest.files["accountability_graph.json"]).toBe(sha256Hex(bundleFiles["accountability_graph.json"]));
    expect(manifest.files["accountability_graph.dot"]).toBe(sha256Hex(bundleFiles["accountability_graph.dot"]));
  });

  it("F18.3: verifies bundle.sig payload_hash covers manifest.json hash", () => {
    const manifestHash = sha256Hex(bundleFiles["manifest.json"]);
    const sig = JSON.parse(bundleFiles["bundle.sig"]);
    expect(sig.payload_hash).toBe(manifestHash);
    expect(sig.algorithm).toBe("Ed25519");
  });

  it("F18.4: includes human-readable audit_report.md summary with verification results", () => {
    const reportMd = bundleFiles["audit_report.md"];
    expect(reportMd).toContain("# AIP Enterprise Audit Report");
    expect(reportMd).toContain("Overall Valid: true");
    expect(reportMd).toContain("COUNTERPARTY_SIGNED");
  });

  it("F18.5: client exportBundle returns non-empty byte buffer", async () => {
    const { MockEvidenceVaultClient } = await import("../support/mock_vault_client.js");
    const client = new MockEvidenceVaultClient();
    const bytes = await client.exportBundle("pkt-001-acme-loan");
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(500);
  });
});
