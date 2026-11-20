export const kindNames = {
  human: "Human owner",
  agent: "Agent",
  workload: "Workload",
  process: "Process",
  tool: "Tool",
  service: "Service",
  action: "Executed action",
  evidence: "Evidence",
  unknown: "Unresolved identity",
} as const;

export type NodeKind = keyof typeof kindNames;
export type Relation = "observed" | "declared" | "inferred";

export interface TopologyNode {
  id: string;
  label: string;
  kind: NodeKind;
  status?: string;
  owner?: string;
  scope?: string;
  at?: string;
  evidence?: string;
  confidence?: number;
}

export interface TopologyEdge {
  source: string;
  target: string;
  relation: Relation;
  label?: string;
  evidence?: string;
  at?: string;
}

export interface PlotNode extends TopologyNode {
  x: number;
  y: number;
  lane: number;
}

export interface GraphLayout {
  nodes: PlotNode[];
  edges: TopologyEdge[];
  unresolved: number;
}

export const NODE_WIDTH = 158;
export const NODE_HEIGHT = 64;

function adjacency(ids: string[], edges: TopologyEdge[]) {
  const result = new Map(ids.map((id) => [id, [] as string[]]));
  for (const edge of edges) result.get(edge.source)?.push(edge.target);
  return result;
}

// Condense cycles before determining depth. A valid relationship may form a
// cycle (for example a tool callback), and may also have multiple incoming edges.
function components(ids: string[], edges: TopologyEdge[]) {
  const out = adjacency(ids, edges);
  const incoming = adjacency(
    ids,
    edges.map((e) => ({ ...e, source: e.target, target: e.source })),
  );
  const seen = new Set<string>();
  const finished: string[] = [];
  for (const id of ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    const stack = [{ id, child: 0 }];
    while (stack.length) {
      const frame = stack[stack.length - 1];
      const next = out.get(frame.id)!;
      if (frame.child >= next.length) {
        finished.push(frame.id);
        stack.pop();
        continue;
      }
      const child = next[frame.child++];
      if (!seen.has(child)) {
        seen.add(child);
        stack.push({ id: child, child: 0 });
      }
    }
  }
  const group = new Map<string, number>();
  const members: string[][] = [];
  for (const id of finished.reverse()) {
    if (group.has(id)) continue;
    const index = members.length;
    const list: string[] = [];
    members.push(list);
    const stack = [id];
    group.set(id, index);
    while (stack.length) {
      const current = stack.pop()!;
      list.push(current);
      for (const parent of incoming.get(current)!)
        if (!group.has(parent)) {
          group.set(parent, index);
          stack.push(parent);
        }
    }
    list.sort();
  }
  const downstream = members.map(() => new Set<number>());
  const indegree = members.map(() => 0);
  for (const edge of edges) {
    const a = group.get(edge.source)!;
    const b = group.get(edge.target)!;
    if (a === b || downstream[a].has(b)) continue;
    downstream[a].add(b);
    indegree[b]++;
  }
  const roots = members
    .filter((_, index) => indegree[index] === 0)
    .map((m) => m[0]);
  const queue = indegree.flatMap((n, i) => (n === 0 ? [i] : []));
  const depth = members.map(() => 0);
  for (let i = 0; i < queue.length; i++) {
    const component = queue[i];
    for (const child of downstream[component]) {
      depth[child] = Math.max(depth[child], depth[component] + 1);
      if (--indegree[child] === 0) queue.push(child);
    }
  }
  return { roots, lane: (id: string) => depth[group.get(id)!] };
}

export function prepareGraph(
  nodes: TopologyNode[],
  edges: TopologyEdge[],
  collapsed: ReadonlySet<string> = new Set(),
): GraphLayout {
  const byId = new Map(
    nodes.filter((n) => n.id && n.label).map((n) => [n.id, n]),
  );
  const ids = Array.from(byId.keys()).sort();
  const valid = edges.filter(
    (e) =>
      byId.has(e.source) &&
      byId.has(e.target) &&
      ["observed", "declared", "inferred"].includes(e.relation),
  );
  const full = components(ids, valid);
  const expanded = valid.filter((e) => !collapsed.has(e.source));
  const outgoing = adjacency(ids, expanded);
  const visible = new Set<string>();
  const work = [...full.roots];
  while (work.length) {
    const id = work.pop()!;
    if (visible.has(id)) continue;
    visible.add(id);
    for (const child of outgoing.get(id)!)
      if (!visible.has(child)) work.push(child);
  }
  const visibleEdges = expanded.filter(
    (e) => visible.has(e.source) && visible.has(e.target),
  );
  const depth = components([...visible], visibleEdges).lane;
  const lanes = new Map<number, TopologyNode[]>();
  for (const id of ids.filter((id) => visible.has(id))) {
    const lane = depth(id);
    const stack = lanes.get(lane) ?? [];
    stack.push(byId.get(id)!);
    lanes.set(lane, stack);
  }
  const plotted: PlotNode[] = [];
  for (const [index, list] of lanes)
    list.forEach((node, i) => {
      plotted.push({
        ...node,
        x: index * (NODE_WIDTH + 60),
        y: (i - (list.length - 1) / 2) * (NODE_HEIGHT + 28),
        lane: i,
      });
    });
  return {
    nodes: plotted,
    edges: visibleEdges,
    unresolved: edges.length - valid.length,
  };
}

export const relationNames: Record<Relation, string> = {
  observed: "Observed",
  declared: "Declared",
  inferred: "Inferred",
};
export type GraphCommand = {
  kind: "fit" | "in" | "out" | "focus";
  epoch: number;
  nodeId?: string;
};
