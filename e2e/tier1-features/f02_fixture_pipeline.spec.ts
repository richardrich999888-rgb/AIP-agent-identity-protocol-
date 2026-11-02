import { describe, it, expect } from "vitest";
import {
  validHonestCounterpartyPacket,
  createAuthorityBoundPacket,
  createAgentSignedPacket,
  createTamperedSummaryPacket,
  createScopeEscalationPacket,
} from "../fixtures/evidence_packets.js";
import { createSampleAuditBundleFiles } from "../fixtures/audit_bundles.js";

describe("Tier 1 - F2: Test Fixture Generation Pipeline", () => {
  it("F2.1: produces valid CounterpartySigned packet with non-empty signatures", () => {
    const packet = validHonestCounterpartyPacket;
    expect(packet.magic).toEqual([0x41, 0x45, 0x50, 0x31]);
    expect(packet.claimed_trust_floor).toBe("COUNTERPARTY_SIGNED");
    expect(packet.receipt_binding?.counterparty_sig).toBeDefined();
  });

  it("F2.2: generates AuthorityBound packet with un-countersigned receipt", () => {
    const packet = createAuthorityBoundPacket();
    expect(packet.claimed_trust_floor).toBe("AUTHORITY_BOUND");
    expect(packet.receipt_binding?.counterparty_sig).toBeUndefined();
  });

  it("F2.3: generates AgentSigned packet with empty delegation chain", () => {
    const packet = createAgentSignedPacket();
    expect(packet.claimed_trust_floor).toBe("AGENT_SIGNED");
    expect(packet.delegation_chain.length).toBe(0);
  });

  it("F2.4: generates Tampered packet with modified summary payload", () => {
    const packet = createTamperedSummaryPacket();
    expect(packet.decision.summary).toContain("TAMPERED");
  });

  it("F2.5: generates signed 7-file audit ZIP bundle with manifest", () => {
    const files = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    const manifest = JSON.parse(files["manifest.json"]);
    expect(manifest.bundle_version).toBe("aip-bundle-1");
    expect(Object.keys(manifest.files).length).toBe(5);
  });
});
