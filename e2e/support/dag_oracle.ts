import {
  EvidencePacket,
  AccountabilityGraph,
  GraphNode,
  GraphEdge,
  VerificationReport,
} from "./types.js";

/**
 * Reconstructs the AccountabilityGraph DAG from an EvidencePacket per PROJECT.md §6
 */
export function reconstructAccountabilityGraph(
  packet: EvidencePacket,
  report?: VerificationReport
): AccountabilityGraph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  // 1. Principal Node
  nodes.push({
    id: "principal",
    kind: "principal",
    label: `${packet.root_authority.display_role} (${packet.root_authority.principal_id})`,
    verified: report?.checks.find((c) => c.rule === "ROOT_TOKEN_SIGNATURE")?.pass ?? true,
    data: {
      principal_id: packet.root_authority.principal_id,
      display_role: packet.root_authority.display_role,
    },
  });

  // 2. AuthorityGrant Node (Root Token)
  const rootToken = packet.root_authority.root_token;
  nodes.push({
    id: "authority_grant",
    kind: "authority_grant",
    label: `root token ${rootToken.jti.slice(0, 8)} → ${rootToken.agent_id}`,
    verified: report?.checks.find((c) => c.rule === "ROOT_TOKEN_SIGNATURE")?.pass ?? true,
    data: {
      jti: rootToken.jti,
      issuer_id: rootToken.issuer_id,
      agent_id: rootToken.agent_id,
      scope: rootToken.scope,
      issued_at: rootToken.issued_at,
      expires_at: rootToken.expires_at,
    },
  });

  edges.push({
    id: "e_issues",
    source: "principal",
    target: "authority_grant",
    relation: "Issues",
  });

  // 3. Delegation Hops
  let lastAuthorityNode = "authority_grant";
  if (packet.delegation_chain && packet.delegation_chain.length > 0) {
    packet.delegation_chain.forEach((hop, i) => {
      const hopId = `delegation:${i}`;
      nodes.push({
        id: hopId,
        kind: "delegation",
        label: `hop ${i} (depth ${hop.depth}): ${hop.issuer_id} → ${hop.grantee_id}`,
        verified: report?.checks.find((c) => c.rule === "DELEGATION_CHAIN")?.pass ?? true,
        data: {
          jti: hop.jti,
          parent_jti: hop.parent_jti,
          issuer_id: hop.issuer_id,
          grantee_id: hop.grantee_id,
          depth: hop.depth,
          scope: hop.scope,
        },
      });

      edges.push({
        id: `e_delegates_${i}`,
        source: lastAuthorityNode,
        target: hopId,
        relation: "Delegates",
      });
      lastAuthorityNode = hopId;
    });
  }

  // 4. Agent Node
  nodes.push({
    id: "agent",
    kind: "agent",
    label: packet.agent.aip_id,
    verified: report?.checks.find((c) => c.rule === "AGENT_ID_BINDING")?.pass ?? true,
    data: {
      aip_id: packet.agent.aip_id,
      algorithm: packet.agent.public_key.algorithm,
      public_key: packet.agent.public_key.key_bytes,
      provenance: packet.agent.provenance,
    },
  });

  edges.push({
    id: "e_acts_under",
    source: lastAuthorityNode,
    target: "agent",
    relation: "ActsUnder",
  });

  // 5. Decision Node
  nodes.push({
    id: "decision",
    kind: "decision",
    label: packet.decision.summary,
    verified: report?.checks.find((c) => c.rule === "SCOPE_AUTHORITY")?.pass ?? true,
    data: {
      decision_id: packet.decision.decision_id,
      action_kind: packet.decision.action_kind,
      summary: packet.decision.summary,
      input_hash: packet.decision.input_hash,
      rationale_hash: packet.decision.rationale_hash,
      decided_at: packet.decision.decided_at,
    },
  });

  edges.push({
    id: "e_decides",
    source: "agent",
    target: "decision",
    relation: "Decides",
  });

  // 6. Action Nodes
  packet.actions.forEach((act, idx) => {
    const actId = `action:${idx}`;
    nodes.push({
      id: actId,
      kind: "action",
      label: act.description,
      verified: report?.checks.find((c) => c.rule === "ACTION_ATTESTATIONS")?.pass ?? true,
      data: {
        action_id: act.action_id,
        action_kind: act.action_kind,
        description: act.description,
        payload_hash: act.payload_hash,
        performed_at: act.performed_at,
      },
    });

    edges.push({
      id: `e_performs_${idx}`,
      source: "decision",
      target: actId,
      relation: "Performs",
    });
  });

  // 7. Receipt Node (if present)
  if (packet.receipt_binding) {
    const rb = packet.receipt_binding;
    nodes.push({
      id: "receipt",
      kind: "receipt",
      label: `${rb.receipt_id} @ ${rb.receipt_system}`,
      verified: report?.checks.find((c) => c.rule === "RECEIPT_BINDING")?.pass ?? true,
      data: {
        receipt_system: rb.receipt_system,
        receipt_id: rb.receipt_id,
        receipt_hash: rb.receipt_hash,
        counterparty_id: rb.counterparty_id,
        countersigned: !!rb.counterparty_sig,
      },
    });

    packet.actions.forEach((_, idx) => {
      edges.push({
        id: `e_produces_${idx}`,
        source: `action:${idx}`,
        target: "receipt",
        relation: "Produces",
      });
    });
  }

  return {
    nodes,
    edges,
    claimed_trust_floor: packet.claimed_trust_floor,
    derived_trust_floor: report?.derived_trust_floor ?? packet.claimed_trust_floor,
  };
}

/**
 * Validates graph reachability and invariants using BFS
 */
export function validateGraphChain(graph: AccountabilityGraph): { valid: boolean; error?: string } {
  // Invariant 1: Exactly 1 principal node
  const principals = graph.nodes.filter((n) => n.kind === "principal");
  if (principals.length !== 1) {
    return { valid: false, error: `Expected 1 principal node, found ${principals.length}` };
  }

  // Invariant 2: All nodes must be reachable from principal
  const rootId = principals[0].id;
  const visited = new Set<string>();
  const queue = [rootId];
  visited.add(rootId);

  // Build adjacency list
  const adj = new Map<string, string[]>();
  for (const edge of graph.edges) {
    if (!adj.has(edge.source)) adj.set(edge.source, []);
    adj.get(edge.source)!.push(edge.target);
  }

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const neighbors = adj.get(curr) || [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push(neighbor);
      }
    }
  }

  const unvisited = graph.nodes.filter((n) => !visited.has(n.id));
  if (unvisited.length > 0) {
    return {
      valid: false,
      error: `Unreachable node(s) detected: ${unvisited.map((n) => n.id).join(", ")}`,
    };
  }

  return { valid: true };
}

/**
 * Export graph to Graphviz DOT string
 */
export function toDot(graph: AccountabilityGraph): string {
  const lines: string[] = ["digraph AccountabilityGraph {", "  rankdir=LR;"];
  for (const node of graph.nodes) {
    const shape =
      node.kind === "principal"
        ? "house"
        : node.kind === "authority_grant"
        ? "note"
        : node.kind === "delegation"
        ? "cds"
        : node.kind === "agent"
        ? "component"
        : node.kind === "decision"
        ? "diamond"
        : node.kind === "action"
        ? "box"
        : "tab";
    lines.push(`  "${node.id}" [label="${node.label.replace(/"/g, '\\"')}", shape="${shape}"];`);
  }
  for (const edge of graph.edges) {
    lines.push(`  "${edge.source}" -> "${edge.target}" [label="${edge.relation}"];`);
  }
  lines.push("}");
  return lines.join("\n");
}
