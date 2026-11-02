import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { reconstructAccountabilityGraph, validateGraphChain, toDot } from "../support/dag_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";
import { createSampleAuditBundleFiles } from "../fixtures/audit_bundles.js";

describe("Tier 3 - Pipeline 1: Ingestion -> WASM Verification -> DAG Rendering", () => {
  it("P1.1: ingests raw JSON string, verifies via engine, and builds 7-node DAG", () => {
    // 1. Ingestion
    const jsonStr = JSON.stringify(validHonestCounterpartyPacket);
    const packet = JSON.parse(jsonStr);
    expect(packet.magic).toEqual([0x41, 0x45, 0x50, 0x31]);

    // 2. Engine Verification
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.overall_valid).toBe(true);
    expect(report.derived_trust_floor).toBe("COUNTERPARTY_SIGNED");

    // 3. DAG Rendering
    const graph = reconstructAccountabilityGraph(packet, report);
    expect(graph.nodes.length).toBe(7);
    expect(graph.edges.length).toBe(6);
    expect(validateGraphChain(graph).valid).toBe(true);
  });

  it("P1.2: node verification badges reflect 1:1 engine report rules", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket, report);

    const principalNode = graph.nodes.find((n) => n.kind === "principal");
    const agentNode = graph.nodes.find((n) => n.kind === "agent");
    const decisionNode = graph.nodes.find((n) => n.kind === "decision");

    expect(principalNode?.verified).toBe(report.checks.find((c) => c.rule === "ROOT_TOKEN_SIGNATURE")?.pass);
    expect(agentNode?.verified).toBe(report.checks.find((c) => c.rule === "AGENT_ID_BINDING")?.pass);
    expect(decisionNode?.verified).toBe(report.checks.find((c) => c.rule === "SCOPE_AUTHORITY")?.pass);
  });

  it("P1.3: bundle ZIP extraction feeds directly into WASM verification and DAG pipeline", () => {
    const files = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    const evidencePacket = JSON.parse(files["evidence.json"]);

    const report = verifyEvidencePacketOracle(evidencePacket, DEFAULT_VERIFICATION_CONTEXT);
    const graph = reconstructAccountabilityGraph(evidencePacket, report);

    expect(graph.claimed_trust_floor).toBe("COUNTERPARTY_SIGNED");
    expect(graph.derived_trust_floor).toBe("COUNTERPARTY_SIGNED");
  });

  it("P1.4: DAG to DOT string export accurately reflects edge relationships", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket, report);
    const dot = toDot(graph);

    expect(dot).toContain('"principal" -> "authority_grant" [label="Issues"]');
    expect(dot).toContain('"authority_grant" -> "delegation:0" [label="Delegates"]');
    expect(dot).toContain('"agent" -> "decision" [label="Decides"]');
    expect(dot).toContain('"decision" -> "action:0" [label="Performs"]');
    expect(dot).toContain('"action:0" -> "receipt" [label="Produces"]');
  });

  it("P1.5: invalid ingested packet propagates unverified status to DAG node badges", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.agent.aip_id = "aip1corruptaipid11223344556677889900";
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const graph = reconstructAccountabilityGraph(packet, report);

    const agentNode = graph.nodes.find((n) => n.kind === "agent");
    expect(agentNode?.verified).toBe(false);
  });
});
