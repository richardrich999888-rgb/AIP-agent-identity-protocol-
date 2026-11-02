import {
  DelegationTreeNode,
  RevocationEntry,
  RevocationImpact,
  TokenStatus,
  CapabilityScope,
} from "./types";

/**
 * Pure BFS cascade revocation traversal matching e2e/support/lattice_oracle.ts
 */
export function computeCascadeRevocations(
  targetJti: string,
  delegationTree: { jti: string; parent_jti?: string }[],
  revokedBy: string = "security-admin",
  primaryReason: "Compromise" | "AdminRevocation" | "KeyRotation" | "Expired" = "Compromise"
): RevocationEntry[] {
  const result: RevocationEntry[] = [];
  const queue: string[] = [targetJti];

  // Primary revocation
  result.push({
    jti: targetJti,
    revoked_at: Date.now(),
    reason: primaryReason,
    cascade: true,
    revoked_by: revokedBy,
  });

  while (queue.length > 0) {
    const current = queue.shift()!;
    // Find all children
    const children = delegationTree.filter((node) => node.parent_jti === current);
    for (const child of children) {
      result.push({
        jti: child.jti,
        revoked_at: Date.now(),
        reason: "AdminRevocation",
        cascade: true,
        revoked_by: revokedBy,
      });
      queue.push(child.jti);
    }
  }

  return result;
}

/**
 * Extracts flat tree nodes from EvidencePacket
 */
export function extractDelegationTree(packet: any): DelegationTreeNode[] {
  if (!packet) return [];
  const nodes: DelegationTreeNode[] = [];

  if (packet.root_authority?.root_token) {
    const root = packet.root_authority.root_token;
    nodes.push({
      jti: root.jti,
      parent_jti: undefined,
      type: "root",
      depth: 0,
      issuer_id: packet.root_authority.principal_id || "principal-root",
      grantee_id: root.agent_id || "agent-root",
      role: packet.root_authority.display_role || "Chief Risk Officer",
      scope: root.scope,
      issued_at: root.issued_at || Date.now() - 3600000,
      expires_at: root.expires_at || Date.now() + 86400000,
      status: "VALID",
    });
  }

  if (Array.isArray(packet.delegation_chain)) {
    packet.delegation_chain.forEach((hop: any, idx: number) => {
      const isLeaf = idx === packet.delegation_chain.length - 1;
      nodes.push({
        jti: hop.jti,
        parent_jti: hop.parent_jti,
        type: isLeaf ? "leaf" : "intermediate",
        depth: hop.depth || idx + 1,
        issuer_id: hop.issuer_id,
        grantee_id: hop.grantee_id,
        role: isLeaf ? "Acting Autonomous Agent" : `Intermediate Delegate (Hop ${hop.depth || idx + 1})`,
        scope: hop.scope,
        issued_at: hop.issued_at || Date.now() - 1800000,
        expires_at: hop.expires_at || Date.now() + 86400000,
        status: "VALID",
      });
    });
  }

  return nodes;
}

/**
 * Calculates impact statistics from revocation entries and node trees
 */
export function calculateRevocationImpact(
  revocations: RevocationEntry[],
  nodes: DelegationTreeNode[]
): RevocationImpact {
  const totalRevoked = revocations.length;
  const primaryRevocations = revocations.filter((r) => r.reason !== "AdminRevocation").length;
  const cascadedRevocations = totalRevoked - primaryRevocations;

  const revokedJtiSet = new Set(revocations.map((r) => r.jti));
  const affectedAgentsSet = new Set<string>();
  let brokenDelegations = 0;
  let maxCascadeDepth = 0;

  nodes.forEach((node) => {
    if (revokedJtiSet.has(node.jti)) {
      if (node.grantee_id) {
        affectedAgentsSet.add(node.grantee_id);
      }
      if (node.depth > maxCascadeDepth) {
        maxCascadeDepth = node.depth;
      }
      if (node.parent_jti) {
        brokenDelegations++;
      }
    }
  });

  return {
    totalRevoked,
    primaryRevocations,
    cascadedRevocations,
    affectedAgents: Array.from(affectedAgentsSet),
    brokenDelegations,
    maxCascadeDepth,
  };
}

/**
 * Pre-defined canonical topologies for inspection and testing
 */
export const SAMPLE_DELEGATION_TREES: Record<
  string,
  { name: string; description: string; nodes: DelegationTreeNode[] }
> = {
  multi_branch: {
    name: "Multi-Branch Organization (5 Nodes)",
    description: "Standard branching topology with 1 Root, 2 Intermediate hops, and 2 Leaf agents.",
    nodes: [
      {
        jti: "token-root",
        parent_jti: undefined,
        type: "root",
        depth: 0,
        issuer_id: "principal:org-root",
        grantee_id: "agent:exec-team",
        role: "Chief Executive Principal",
        issued_at: 1772520000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      {
        jti: "token-hop-1a",
        parent_jti: "token-root",
        type: "intermediate",
        depth: 1,
        issuer_id: "agent:exec-team",
        grantee_id: "agent:treasury-vp",
        role: "Treasury VP Delegate",
        issued_at: 1772521000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      {
        jti: "token-hop-2a",
        parent_jti: "token-hop-1a",
        type: "leaf",
        depth: 2,
        issuer_id: "agent:treasury-vp",
        grantee_id: "agent:wire-operator-01",
        role: "Wire Operator Leaf",
        issued_at: 1772522000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      {
        jti: "token-hop-1b",
        parent_jti: "token-root",
        type: "intermediate",
        depth: 1,
        issuer_id: "agent:exec-team",
        grantee_id: "agent:risk-director",
        role: "Risk Management Director",
        issued_at: 1772521500000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      {
        jti: "token-hop-2b",
        parent_jti: "token-hop-1b",
        type: "leaf",
        depth: 2,
        issuer_id: "agent:risk-director",
        grantee_id: "agent:compliance-auditor",
        role: "Compliance Auditor Leaf",
        issued_at: 1772522500000,
        expires_at: 1772606400000,
        status: "VALID",
      },
    ],
  },
  enterprise_loan: {
    name: "Enterprise Loan Delegation Chain",
    description: "Normative Enterprise Loan scenario: Chief Risk Officer → Treasury VP → Loan Approval Agent.",
    nodes: [
      {
        jti: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        parent_jti: undefined,
        type: "root",
        depth: 0,
        issuer_id: "cro-principal-001",
        grantee_id: "treasury-vp-002",
        role: "Chief Risk Officer",
        issued_at: 1772520000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      {
        jti: "b2c3d4e5f60718293a4b5c6d7e8f90a1",
        parent_jti: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        type: "leaf",
        depth: 1,
        issuer_id: "treasury-vp-002",
        grantee_id: "aip12x9K8yM4QvB7eR6tP3sW1uZbAcD5fGhJ7",
        role: "Acting Loan Approval Agent",
        issued_at: 1772524000000,
        expires_at: 1772535000000,
        status: "VALID",
      },
    ],
  },
  wide_tree: {
    name: "Wide Delegation Fanout (1 Root, 10 Children)",
    description: "Tests high-fanout cascade revocation: revoking the single root invalidates all 10 worker sub-agents.",
    nodes: [
      {
        jti: "wide-root-jti",
        parent_jti: undefined,
        type: "root",
        depth: 0,
        issuer_id: "principal:cluster-manager",
        grantee_id: "agent:coordinator",
        role: "Swarm Coordinator",
        issued_at: 1772520000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      ...Array.from({ length: 10 }, (_, i) => ({
        jti: `worker-token-${i + 1}`,
        parent_jti: "wide-root-jti",
        type: "leaf" as const,
        depth: 1,
        issuer_id: "agent:coordinator",
        grantee_id: `agent:worker-${i + 1}`,
        role: `Worker Submitter Agent #${i + 1}`,
        issued_at: 1772520500000 + i * 1000,
        expires_at: 1772606400000,
        status: "VALID" as const,
      })),
    ],
  },
  deep_chain: {
    name: "Deep 4-Hop Linear Chain",
    description: "Tests sequential BFS traversal down a deep authority delegation pipeline.",
    nodes: [
      {
        jti: "hop-0-root",
        parent_jti: undefined,
        type: "root",
        depth: 0,
        issuer_id: "principal:authority-zero",
        grantee_id: "agent:hop-1-agent",
        role: "Tier 0 Root Authority",
        issued_at: 1772520000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      {
        jti: "hop-1-jti",
        parent_jti: "hop-0-root",
        type: "intermediate",
        depth: 1,
        issuer_id: "agent:hop-1-agent",
        grantee_id: "agent:hop-2-agent",
        role: "Tier 1 Regional Coordinator",
        issued_at: 1772521000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      {
        jti: "hop-2-jti",
        parent_jti: "hop-1-jti",
        type: "intermediate",
        depth: 2,
        issuer_id: "agent:hop-2-agent",
        grantee_id: "agent:hop-3-agent",
        role: "Tier 2 Branch Manager",
        issued_at: 1772522000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
      {
        jti: "hop-3-jti",
        parent_jti: "hop-2-jti",
        type: "leaf",
        depth: 3,
        issuer_id: "agent:hop-3-agent",
        grantee_id: "agent:leaf-executor",
        role: "Tier 3 Leaf Executor",
        issued_at: 1772523000000,
        expires_at: 1772606400000,
        status: "VALID",
      },
    ],
  },
};
