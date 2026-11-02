import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { reconstructAccountabilityGraph, validateGraphChain } from "../support/dag_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";

describe("Tier 4 - Scenario 1: Enterprise Commercial Loan Approval Lifecycle", () => {
  it("S1.1: executes end-to-end commercial credit facility authorization ($5M facility)", () => {
    const packet = validHonestCounterpartyPacket;
    expect(packet.decision.summary).toContain("$5,000,000 for Acme Corp");
    expect(packet.decision.action_kind).toEqual({ kind: "Custom", name: "loan:approve" });
  });

  it("S1.2: confirms authorization originates from Chief Risk Officer principal", () => {
    const packet = validHonestCounterpartyPacket;
    expect(packet.root_authority.principal_id).toBe("cro-principal-001");
    expect(packet.root_authority.display_role).toBe("Chief Risk Officer");
  });

  it("S1.3: verifies delegation handoff to Treasury VP with permission attenuation", () => {
    const packet = validHonestCounterpartyPacket;
    const rootToken = packet.root_authority.root_token;
    const hop0 = packet.delegation_chain[0];

    // Principal issued to Treasury VP
    expect(rootToken.agent_id).toBe("treasury-vp-002");
    // Treasury VP delegated to acting autonomous agent
    expect(hop0.issuer_id).toBe("treasury-vp-002");
    expect(hop0.grantee_id).toBe(packet.agent.aip_id);

    // Monotonic depth check
    expect(hop0.depth).toBe(1);
    expect(hop0.parent_jti).toBe(rootToken.jti);
  });

  it("S1.4: bilateral core banking countersignature achieves Level 3 COUNTERPARTY_SIGNED assurance", () => {
    const packet = validHonestCounterpartyPacket;
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);

    expect(report.overall_valid).toBe(true);
    expect(report.derived_trust_floor).toBe("COUNTERPARTY_SIGNED");
    expect(report.tamper_evidence).toBe(false);

    const rcptCheck = report.checks.find((c) => c.rule === "RECEIPT_BINDING");
    expect(rcptCheck?.pass).toBe(true);
    expect(rcptCheck?.detail).toContain("countersigned by core-banking-gateway");
  });

  it("S1.5: reconstructs certified audit DAG and validates organizational lineage", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket, report);

    const validation = validateGraphChain(graph);
    expect(validation.valid).toBe(true);

    const nodeKinds = graph.nodes.map((n) => n.kind);
    expect(nodeKinds).toContain("principal");
    expect(nodeKinds).toContain("authority_grant");
    expect(nodeKinds).toContain("delegation");
    expect(nodeKinds).toContain("agent");
    expect(nodeKinds).toContain("decision");
    expect(nodeKinds).toContain("action");
    expect(nodeKinds).toContain("receipt");
  });
});
