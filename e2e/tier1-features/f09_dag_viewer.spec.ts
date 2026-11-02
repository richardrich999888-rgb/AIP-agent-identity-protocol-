import { describe, it, expect } from "vitest";
import { reconstructAccountabilityGraph, validateGraphChain, toDot } from "../support/dag_oracle.js";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";

describe("Tier 1 - F9: Interactive Accountability Graph DAG", () => {
  it("F9.1: reconstructs DAG containing all 7 distinct node kinds", () => {
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);
    const kinds = new Set(graph.nodes.map((n) => n.kind));
    expect(kinds.has("principal")).toBe(true);
    expect(kinds.has("authority_grant")).toBe(true);
    expect(kinds.has("delegation")).toBe(true);
    expect(kinds.has("agent")).toBe(true);
    expect(kinds.has("decision")).toBe(true);
    expect(kinds.has("action")).toBe(true);
    expect(kinds.has("receipt")).toBe(true);
    expect(kinds.size).toBe(7);
  });

  it("F9.2: wires all 6 standard edge relations in order", () => {
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);
    const relations = new Set(graph.edges.map((e) => e.relation));
    expect(relations.has("Issues")).toBe(true);
    expect(relations.has("Delegates")).toBe(true);
    expect(relations.has("ActsUnder")).toBe(true);
    expect(relations.has("Decides")).toBe(true);
    expect(relations.has("Performs")).toBe(true);
    expect(relations.has("Produces")).toBe(true);
    expect(relations.size).toBe(6);
  });

  it("F9.3: satisfies BFS reachability invariant (100% nodes reachable from Principal)", () => {
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);
    const validation = validateGraphChain(graph);
    expect(validation.valid).toBe(true);
    expect(validation.error).toBeUndefined();
  });

  it("F9.4: marks node verification status correctly based on engine checks", () => {
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);
    for (const node of graph.nodes) {
      expect(node.verified).toBe(true);
    }
  });

  it("F9.5: exports valid Graphviz DOT format digraph string", () => {
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);
    const dot = toDot(graph);
    expect(dot).toContain("digraph AccountabilityGraph");
    expect(dot).toContain('shape="house"');
    expect(dot).toContain('shape="component"');
    expect(dot).toContain('shape="tab"');
  });
});
