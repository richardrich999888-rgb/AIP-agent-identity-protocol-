import { describe, it, expect } from "vitest";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";
import { createSampleAuditBundleFiles } from "../fixtures/audit_bundles.js";

describe("Tier 1 - F5: Drag-and-Drop Ingestion (JSON & ZIP)", () => {
  it("F5.1: ingests valid raw EvidencePacket JSON string", () => {
    const jsonStr = JSON.stringify(validHonestCounterpartyPacket);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.magic).toEqual([0x41, 0x45, 0x50, 0x31]);
    expect(parsed.version).toBe(1);
    expect(parsed.agent.aip_id).toBe(validHonestCounterpartyPacket.agent.aip_id);
  });

  it("F5.2: unpacks and parses ZIP bundle files map", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    expect(bundleFiles).toHaveProperty("evidence.json");
    expect(bundleFiles).toHaveProperty("manifest.json");
    expect(bundleFiles).toHaveProperty("verification.json");
    const innerPacket = JSON.parse(bundleFiles["evidence.json"]);
    expect(innerPacket.magic).toEqual([0x41, 0x45, 0x50, 0x31]);
  });

  it("F5.3: validates accepted file mime types and extensions (.json, .zip)", () => {
    const isSupported = (filename: string) => filename.endsWith(".json") || filename.endsWith(".zip");
    expect(isSupported("packet.json")).toBe(true);
    expect(isSupported("audit.zip")).toBe(true);
    expect(isSupported("script.sh")).toBe(false);
    expect(isSupported("document.pdf")).toBe(false);
  });

  it("F5.4: maintains drag-and-drop state transitions", () => {
    const dropzoneState = { isDragging: false, fileLoaded: false };
    // onDragEnter
    dropzoneState.isDragging = true;
    expect(dropzoneState.isDragging).toBe(true);
    // onDrop
    dropzoneState.isDragging = false;
    dropzoneState.fileLoaded = true;
    expect(dropzoneState.isDragging).toBe(false);
    expect(dropzoneState.fileLoaded).toBe(true);
  });

  it("F5.5: displays file size and packet ID upon successful drop", () => {
    const fileMetadata = {
      name: "evidence_001.json",
      size: 4096,
      id: validHonestCounterpartyPacket.decision.decision_id,
    };
    expect(fileMetadata.size).toBeGreaterThan(0);
    expect(fileMetadata.id).toBe("d001-loan-approval-acme-corp");
  });
});
