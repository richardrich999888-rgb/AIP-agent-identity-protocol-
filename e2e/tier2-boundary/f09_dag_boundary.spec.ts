import { describe, it, expect } from "vitest";
import { reconstructAccountabilityGraph, validateGraphChain } from "../support/dag_oracle.js";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";
import { AccountabilityGraph } from "../support/types.js";

describe("Tier 2 Boundary - F9: Accountability DAG Graph Boundaries", () => {
  it("F9.B1: detects unreachable orphan action node via BFS chain validation", () => {
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);
    // Add disconnected node
    graph.nodes.push({
      id: "orphan-action-node",
      kind: "action",
      label: "Unauthorized detached action",
      verified: false,
      data: {},
    });
    const validation = validateGraphChain(graph);
    expect(validation.valid).toBe(false);
    expect(validation.error).toContain("Unreachable node(s) detected: orphan-action-node");
  });

  it("F9.B2: validates graph with 0 delegation hops (direct principal to agent connection)", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.delegation_chain = [];
    packet.root_authority.root_token.agent_id = packet.agent.aip_id;
    const graph = reconstructAccountabilityGraph(packet);
    const validation = validateGraphChain(graph);
    expect(validation.valid).toBe(true);
    // ActsUnder connects directly from authority_grant to agent
    const actsUnderEdge = graph.edges.find((e) => e.relation === "ActsUnder");
    expect(actsUnderEdge?.source).toBe("authority_grant");
    expect(actsUnderEdge?.target).toBe("agent");
  });

  it("F9.B3: supports high-density action nodes (25 parallel action attestations)", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    for (let i = 1; i < 25; i++) {
      packet.actions.push({
        action_id: `act-batch-${i}`,
        action_kind: { kind: "Standard", action: "Write" },
        description: `Batch item ${i}`,
        payload_hash: packet.actions[0].payload_hash,
        performed_at: packet.actions[0].performed_at + i,
        agent_sig: packet.actions[0].agent_sig,
      });
    }
    const graph = reconstructAccountabilityGraph(packet);
    expect(graph.nodes.filter((n) => n.kind === "action").length).toBe(25);
    const validation = validateGraphChain(graph);
    expect(validation.valid).toBe(true);
  });

  it("F9.B4: fails validation if graph contains zero principal nodes", () => {
    const corruptGraph: AccountabilityGraph = {
      nodes: [{ id: "agent", kind: "agent", label: "Agent", verified: true, data: {} }],
      edges: [],
      claimed_trust_floor: "AGENT_SIGNED",
      derived_trust_floor: "AGENT_SIGNED",
    };
    const validation = validateGraphChain(corruptGraph);
    expect(validation.valid).toBe(false);
    expect(validation.error).toContain("Expected 1 principal node, found 0");
  });

  it("F9.B5: fails validation if graph contains multiple conflicting principal nodes", () => {
    const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);
    graph.nodes.push({
      id: "principal-2",
      kind: "principal",
      label: "Conflicting Principal",
      verified: false,
      data: {},
    });
    const validation = validateGraphChain(graph);
    expect(validation.valid).toBe(false);
    expect(validation.error).toContain("Expected 1 principal node, found 2");
  });
});
