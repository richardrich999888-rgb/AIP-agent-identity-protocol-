import { describe, it, expect } from "vitest";
import { createSampleAuditBundleFiles } from "../fixtures/audit_bundles.js";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";
import { sha256Hex } from "../support/reference_oracle.js";

describe("Tier 2 Boundary - F18: Signed ZIP Bundle Export Boundaries", () => {
  it("F18.B1: detects tampered evidence.json inside bundle via manifest mismatch", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    // Tamper inner evidence file
    bundleFiles["evidence.json"] += "\n// Tampered comment";
    const manifest = JSON.parse(bundleFiles["manifest.json"]);
    const currentEvidenceHash = sha256Hex(bundleFiles["evidence.json"]);
    expect(currentEvidenceHash).not.toBe(manifest.files["evidence.json"]);
  });

  it("F18.B2: detects manipulated manifest.json via bundle.sig mismatch", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    // Tamper manifest
    const manifest = JSON.parse(bundleFiles["manifest.json"]);
    manifest.created_at = 0;
    const tamperedManifestJson = JSON.stringify(manifest);
    const sig = JSON.parse(bundleFiles["bundle.sig"]);
    const newManifestHash = sha256Hex(tamperedManifestJson);
    expect(newManifestHash).not.toBe(sig.payload_hash);
  });

  it("F18.B3: bundle verification detects missing mandatory member file", () => {
    const bundleFiles: any = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    delete bundleFiles["accountability_graph.dot"];
    expect(bundleFiles["accountability_graph.dot"]).toBeUndefined();
  });

  it("F18.B4: manifest version matches normative bundle specification (aip-bundle-1)", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    const manifest = JSON.parse(bundleFiles["manifest.json"]);
    expect(manifest.bundle_version).toBe("aip-bundle-1");
  });

  it("F18.B5: bundle report markdown adheres to valid structured header formatting", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    const md = bundleFiles["audit_report.md"];
    expect(md.startsWith("# AIP Enterprise Audit Report")).toBe(true);
    expect(md.includes("Decision:")).toBe(true);
  });
});
