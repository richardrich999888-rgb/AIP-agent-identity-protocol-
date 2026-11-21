import type { Entry, Exec } from "../types";
export interface TraceStep {
  at: string;
  id: string;
  label: string;
  source: string;
  basis: "Observed" | "Declared" | "Inferred";
  identity: string;
  agent: string;
  confidence: number;
  batch: string;
}
export function fixtureTrace(e: Exec): TraceStep[] {
  const steps: [number, string, string, TraceStep["basis"], string][] = [];
  if (e.registered) {
    steps.push(
      [
        -4800,
        "Agent registration",
        "AIP registry fixture",
        "Declared",
        e.agent,
      ],
      [
        -3200,
        "Delegated authorization",
        "AIP authority fixture",
        "Declared",
        e.owner,
      ],
    );
  }
  steps.push([
    0,
    e.kind === "Human" ? "Browser interaction" : "Workload execution",
    e.kind === "Human" ? "Interaction gateway fixture" : "Sniffer Dog fixture",
    "Observed",
    e.process,
  ]);
  if (e.kind === "Agent" && e.action !== "Block")
    steps.push([
      180,
      "Tool invocation",
      "MCP receipt fixture",
      "Observed",
      e.tool,
    ]);
  if (e.kind === "Agent" && e.parent && e.parent !== "Missing parent")
    steps.push([
      260,
      "Child–parent association",
      "AIP registry fixture",
      "Declared",
      e.parent,
    ]);
  steps.push(
    [460, "Evidence generated", "Fixture signer", "Observed", e.batch],
    [
      690,
      "Identity reconciliation",
      "Correlation fixture",
      "Inferred",
      e.agent || "Unbound",
    ],
  );
  return steps.map(([offset, label, source, basis, identity], i) => ({
    id: e.id + "." + i,
    label,
    source,
    basis,
    identity,
    at: new Date(Date.parse(e.at) + offset).toISOString(),
    agent: e.agent || "Unbound",
    confidence: e.confidence,
    batch: e.batch,
  }));
}
export function fixtureGraph(
  e: Exec,
  registry: Entry[],
  mode: "identity" | "runtime" | "lineage",
) {
  type N = {
    id: string;
    label: string;
    kind:
      | "human"
      | "agent"
      | "workload"
      | "process"
      | "tool"
      | "service"
      | "action"
      | "unknown";
    status?: string;
    owner?: string;
    scope?: string;
    at: string;
    evidence: string;
    confidence?: number;
  };
  type E = {
    source: string;
    target: string;
    label: string;
    relation: "observed" | "declared" | "inferred";
    evidence: string;
    at: string;
  };
  const nodes = new Map<string, N>(),
    edges: E[] = [];
  const add = (
    id: string,
    label: string,
    kind: N["kind"],
    more: Partial<N> = {},
  ) => {
    nodes.set(id, { id, label, kind, at: e.at, evidence: e.batch, ...more });
    return id;
  };
  const link = (s: string, t: string, l: string, r: E["relation"]) => {
    if (s && t && !edges.some((x) => x.source === s && x.target === t))
      edges.push({
        source: s,
        target: t,
        label: l,
        relation: r,
        at: e.at,
        evidence: e.batch,
      });
  };
  const def = registry.find((a) => a.id === e.agent);
  let previous = "";
  if (e.owner !== "Unassigned")
    previous = add("H-" + e.owner, e.owner, "human", {
      status: "Directory entry",
    });
  if (def) {
    const chain: Entry[] = [def];
    if (mode !== "runtime") {
      let p = def;
      while (p.fields.parent && chain.length < 7) {
        const a = registry.find((r) => r.id === p.fields.parent);
        if (!a || chain.some((r) => r.id === a.id)) break;
        chain.unshift(a);
        p = a;
      }
    }
    for (const a of chain) {
      const id = add(
        a.id,
        a.name,
        a.state === "Suspected ghost" ? "unknown" : "agent",
        {
          state: a.state,
          owner: String(a.fields.owner),
          scope: String(a.fields.scope),
          status: a.state,
          confidence: Number(a.fields.confidence),
        } as Partial<N>,
      );
      if (previous) link(previous, id, "Delegation", "declared");
      previous = id;
    }
  }
  const proc = add(
    e.process,
    e.process,
    e.kind === "Human" ? "workload" : "process",
    { status: "Observed", confidence: e.confidence },
  );
  if (previous) link(previous, proc, "Attribution", "inferred");
  if (e.kind === "Agent" && e.action !== "Block") {
    const tool = add("T-" + e.tool, e.tool, "tool", {
      scope: "Request receipt",
    });
    link(proc, tool, "Tool invocation", "observed");
  }
  const act = add(e.id, e.action + " decision", "action", {
    status: "Simulated",
  });
  link(proc, act, "Gateway decision", "observed");
  return { nodes: [...nodes.values()], edges };
}
