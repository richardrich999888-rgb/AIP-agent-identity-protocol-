import { describe, it, expect } from "vitest";
import { reconstructAccountabilityGraph } from "../support/dag_oracle.js";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";

describe("Tier 1 - F10: DAG Node Inspection Sheet", () => {
  const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);

  it("F10.1: inspects Agent node showing AIP-ID and provenance commitment hashes", () => {
    const agentNode = graph.nodes.find((n) => n.kind === "agent");
    expect(agentNode).toBeDefined();
    expect(agentNode?.data.aip_id).toBe(validHonestCounterpartyPacket.agent.aip_id);
    expect(agentNode?.data.public_key).toBeDefined();
    expect(agentNode?.data.provenance.model_hash).toBeDefined();
  });

  it("F10.2: inspects AuthorityGrant node showing JTI, issuer, and scope", () => {
    const authNode = graph.nodes.find((n) => n.kind === "authority_grant");
    expect(authNode).toBeDefined();
    expect(authNode?.data.jti).toBe(validHonestCounterpartyPacket.root_authority.root_token.jti);
    expect(authNode?.data.scope.allowed.length).toBeGreaterThan(0);
  });

  it("F10.3: inspects Decision node displaying action kind, hashes, and decided_at", () => {
    const decisionNode = graph.nodes.find((n) => n.kind === "decision");
    expect(decisionNode).toBeDefined();
    expect(decisionNode?.data.decision_id).toBe(validHonestCounterpartyPacket.decision.decision_id);
    expect(decisionNode?.data.summary).toBe(validHonestCounterpartyPacket.decision.summary);
    expect(decisionNode?.data.decided_at).toBeGreaterThan(0);
  });

  it("F10.4: inspects Action node displaying description and payload hash", () => {
    const actionNode = graph.nodes.find((n) => n.kind === "action");
    expect(actionNode).toBeDefined();
    expect(actionNode?.data.action_id).toBe("act-001-transfer");
    expect(actionNode?.data.payload_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("F10.5: inspects Receipt node displaying counterparty and countersignature status", () => {
    const receiptNode = graph.nodes.find((n) => n.kind === "receipt");
    expect(receiptNode).toBeDefined();
    expect(receiptNode?.data.receipt_system).toBe("core-banking-gateway");
    expect(receiptNode?.data.countersigned).toBe(true);
  });
});
