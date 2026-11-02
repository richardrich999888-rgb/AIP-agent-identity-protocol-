import type {
  LayoutDirection,
  AccountabilityFlowNode,
  AccountabilityFlowEdge,
} from "./types";

export interface LayoutOptions {
  direction?: LayoutDirection;
  nodeWidth?: number;
  nodeHeight?: number;
  actionNodeWidth?: number;
  actionNodeHeight?: number;
  rankGap?: number;
  siblingGap?: number;
}

/**
 * Deterministic Hierarchical DAG Layout Algorithm (Pure TypeScript, Zero External Dependencies)
 * Guarantees centered, non-overlapping node placement for 0 to 8 delegation hops and 25+ parallel actions.
 * Supports both Left-to-Right (LR) and Top-to-Bottom (TB) directions with mathematical cross-axis centering.
 */
export function computeHierarchicalLayout(
  nodes: AccountabilityFlowNode[],
  edges: AccountabilityFlowEdge[],
  options: LayoutOptions = {}
): { nodes: AccountabilityFlowNode[]; edges: AccountabilityFlowEdge[] } {
  const direction: LayoutDirection = options.direction || "LR";
  const standardWidth = options.nodeWidth || 300;
  const standardHeight = options.nodeHeight || 150;
  const actionWidth = options.actionNodeWidth || 280;
  const actionHeight = options.actionNodeHeight || 120;
  const rankGap = options.rankGap || 110;
  const siblingGap = options.siblingGap || 28;

  if (nodes.length === 0) {
    return { nodes: [], edges };
  }

  // Count delegation nodes
  const delegationNodes = nodes.filter((n) => n.data?.kind === "delegation" || n.type === "delegation");
  const delegationCount = delegationNodes.length;

  // Determine rank layer for each node
  const getRank = (node: AccountabilityFlowNode): number => {
    const kind = (node.data?.kind || node.type || "").toLowerCase();
    switch (kind) {
      case "principal":
        return 0;
      case "authority_grant":
        return 1;
      case "delegation": {
        const hopIdx =
          typeof node.data?.hop_index === "number"
            ? node.data.hop_index
            : parseInt(node.id.split(":")[1] || "0", 10);
        return 2 + (isNaN(hopIdx) ? 0 : hopIdx);
      }
      case "agent":
        return 2 + delegationCount;
      case "decision":
        return 3 + delegationCount;
      case "action":
        return 4 + delegationCount;
      case "receipt":
        return 5 + delegationCount;
      default:
        return 6 + delegationCount;
    }
  };

  // Group nodes by rank
  const layers = new Map<number, AccountabilityFlowNode[]>();
  for (const node of nodes) {
    const r = getRank(node);
    if (!layers.has(r)) layers.set(r, []);
    layers.get(r)!.push(node);
  }

  // Sort ranks in topological order
  const sortedRanks = Array.from(layers.keys()).sort((a, b) => a - b);

  // Helper dimension getters
  const getNodeW = (n: AccountabilityFlowNode): number =>
    (n.data?.kind || n.type) === "action" ? actionWidth : standardWidth;

  const getNodeH = (n: AccountabilityFlowNode): number =>
    (n.data?.kind || n.type) === "action" ? actionHeight : standardHeight;

  const getNodeCrossDim = (n: AccountabilityFlowNode): number =>
    direction === "LR" ? getNodeH(n) : getNodeW(n);

  const getNodeMainDim = (n: AccountabilityFlowNode): number =>
    direction === "LR" ? getNodeW(n) : getNodeH(n);

  // 1. Calculate maximum cross-axis span across all layers to ensure perfect visual centering
  let maxCrossSpan = 0;
  for (const rank of sortedRanks) {
    const layerNodes = layers.get(rank)!;
    const totalCross = layerNodes.reduce((acc, n) => acc + getNodeCrossDim(n), 0);
    const span = totalCross + Math.max(0, layerNodes.length - 1) * siblingGap;
    if (span > maxCrossSpan) {
      maxCrossSpan = span;
    }
  }

  // 2. Track progressive main-axis coordinate per rank to handle differing node sizes
  let currentMainOffset = 40;
  const positionedNodes: AccountabilityFlowNode[] = [];

  for (let rankIdx = 0; rankIdx < sortedRanks.length; rankIdx++) {
    const rank = sortedRanks[rankIdx];
    const layerNodes = layers.get(rank)!;

    // Sort actions by index or id if applicable
    if (rank === 4 + delegationCount) {
      layerNodes.sort((a, b) => {
        const idxA = a.data?.index ?? parseInt(a.id.split(":")[1] || "0", 10);
        const idxB = b.data?.index ?? parseInt(b.id.split(":")[1] || "0", 10);
        return idxA - idxB;
      });
    }

    const layerCrossDim = layerNodes.reduce((acc, n) => acc + getNodeCrossDim(n), 0);
    const layerSpan = layerCrossDim + Math.max(0, layerNodes.length - 1) * siblingGap;
    let crossOffset = (maxCrossSpan - layerSpan) / 2 + 40;

    let maxMainDimInLayer = 0;

    for (const node of layerNodes) {
      const nodeW = getNodeW(node);
      const nodeH = getNodeH(node);
      const mainDim = getNodeMainDim(node);
      if (mainDim > maxMainDimInLayer) {
        maxMainDimInLayer = mainDim;
      }

      let x = 0;
      let y = 0;

      if (direction === "LR") {
        x = currentMainOffset;
        y = crossOffset;
        crossOffset += nodeH + siblingGap;
      } else {
        // TB layout
        x = crossOffset;
        y = currentMainOffset;
        crossOffset += nodeW + siblingGap;
      }

      positionedNodes.push({
        ...node,
        position: { x, y },
        data: {
          ...node.data,
          layoutDirection: direction,
        },
      });
    }

    currentMainOffset += maxMainDimInLayer + rankGap;
  }

  return { nodes: positionedNodes, edges };
}
