import type { ReachabilityResult } from "./types";

export interface ReachableCandidateNode {
  id: string;
  kind?: string;
  [key: string]: unknown;
}

export interface ReachableCandidateEdge {
  source?: string;
  target?: string;
  from?: string;
  to?: string;
  [key: string]: unknown;
}

/**
 * Validates Single-Principal Reachability Invariants:
 * 1. Exactly 1 principal node exists (F9.B4, F9.B5).
 * 2. 100% of nodes in the graph must be reachable from Principal via BFS (F9.3, F9.B1).
 * 3. Detects orphan and disconnected nodes.
 */
export function verifySinglePrincipalReachability(
  nodes: ReachableCandidateNode[],
  edges: ReachableCandidateEdge[]
): ReachabilityResult {
  // Invariant 1: Exactly 1 principal node
  const principals = nodes.filter(
    (n) => (n.kind || "").toLowerCase() === "principal" || n.id === "principal"
  );

  if (principals.length !== 1) {
    return {
      valid: false,
      error: `Expected 1 principal node, found ${principals.length}`,
      rootPrincipalId: principals[0]?.id,
      reachableNodeIds: [],
      orphanNodeIds: nodes.map((n) => n.id),
      totalNodes: nodes.length,
    };
  }

  const rootId = principals[0].id;

  // Build forward directed adjacency list
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    const src = (edge.source || edge.from || "") as string;
    const tgt = (edge.target || edge.to || "") as string;
    if (!src || !tgt) continue;

    if (!adjacency.has(src)) {
      adjacency.set(src, []);
    }
    adjacency.get(src)!.push(tgt);
  }

  // BFS Traversal starting from root Principal
  const visited = new Set<string>();
  const queue: string[] = [rootId];
  visited.add(rootId);

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const neighbors = adjacency.get(curr) || [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push(neighbor);
      }
    }
  }

  // Check for orphan / unreachable nodes
  const orphanNodes = nodes.filter((n) => !visited.has(n.id)).map((n) => n.id);

  if (orphanNodes.length > 0) {
    return {
      valid: false,
      error: `Unreachable node(s) detected: ${orphanNodes.join(", ")}`,
      rootPrincipalId: rootId,
      reachableNodeIds: Array.from(visited),
      orphanNodeIds: orphanNodes,
      totalNodes: nodes.length,
    };
  }

  return {
    valid: true,
    rootPrincipalId: rootId,
    reachableNodeIds: Array.from(visited),
    orphanNodeIds: [],
    totalNodes: nodes.length,
  };
}
