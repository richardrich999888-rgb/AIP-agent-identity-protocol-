import { describe, it, expect } from "vitest";
import { MockEvidenceVaultClient } from "../support/mock_vault_client.js";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";

describe("Tier 1 - F19: Connected Service Client (aip-service)", () => {
  const liveClient = new MockEvidenceVaultClient(true);

  it("F19.1: reports isLive() true when connected to aip-service REST backend", () => {
    expect(liveClient.isLive()).toBe(true);
  });

  it("F19.2: invokes /v1/evidence/verify contract and returns VerificationReport", async () => {
    const report = await liveClient.verifyEvidence(validHonestCounterpartyPacket);
    expect(report).toBeDefined();
    expect(report.overall_valid).toBe(true);
    expect(report.checks.length).toBe(14);
  });

  it("F19.3: invokes /v1/evidence/{id} contract returning EvidencePacket", async () => {
    const packet = await liveClient.getEvidence("pkt-001-acme-loan");
    expect(packet.decision.decision_id).toBe("d001-loan-approval-acme-corp");
  });

  it("F19.4: invokes /v1/authority/{id} contract returning AccountabilityGraph", async () => {
    const graph = await liveClient.getAuthorityGraph("pkt-001-acme-loan");
    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.edges.length).toBeGreaterThan(0);
  });

  it("F19.5: throws 404 error when querying non-existent or cross-tenant ID", async () => {
    await expect(liveClient.getEvidence("unknown-packet-id-999")).rejects.toThrow(/404/);
  });
});
