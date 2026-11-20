import { field, analyticsTabs } from "../product";
import {
  type Bundle,
  type Entry,
  type Exec,
  type Metric,
  type PageDef,
  type Provenance,
  type Role,
  type Count,
  type Point,
  groups,
  guards,
} from "../types";
import {
  apps,
  agents,
  dormantAgents,
  sensors,
  mcp,
  people,
  policies,
  safeCases,
  AS_OF,
  DAY,
  allEvents,
  entry,
} from "./fixtures";
import { fixtureTrace, fixtureGraph } from "./trace";
import { verify, batches } from "./verification";
export type Edits = Map<string, Entry>;
const withEdits = (kind: string, base: Entry[], edits: Edits) => {
  const m = new Map(base.map((v) => [v.id, v]));
  for (const [key, v] of edits) if (key.startsWith(kind + "/")) m.set(v.id, v);
  return [...m.values()];
};
export const catalog = (edits: Edits) => withEdits("apps", apps, edits);
export function policyList(edits: Edits): Entry[] {
  const base = withEdits("policies", policies, edits).sort(
    (a, b) =>
      Number(a.fields.priority) - Number(b.fields.priority) ||
      a.id.localeCompare(b.id),
  );
  const order = edits.get("ordering/policies");
  if (!order) return base;
  const ids = String(order.fields.ids).split(","),
    rank = (id: string) => {
      const i = ids.indexOf(id);
      return i < 0 ? ids.length : i;
    };
  return base
    .sort((a, b) => rank(a.id) - rank(b.id))
    .map((r, i) => ({ ...r, fields: { ...r.fields, priority: i + 1 } }));
}
export const agentList = (edits: Edits) =>
  withEdits("agents", [...agents, ...dormantAgents], edits);
export const sum = (xs: Exec[], f: (e: Exec) => number) =>
  xs.reduce((n, x) => n + f(x), 0);
export function counts<T>(
  xs: T[],
  key: (v: T) => string,
  weight: (v: T) => number = () => 1,
): Count[] {
  const m = new Map<string, number>();
  for (const r of xs) {
    const k = key(r);
    if (k) m.set(k, (m.get(k) ?? 0) + weight(r));
  }
  return [...m]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value || a.name.localeCompare(b.name));
}
function daysBefore(n: number) {
  return new Date(
    Date.parse(AS_OF.slice(0, 10) + "T00:00:00Z") - n * DAY,
  ).toISOString();
}
export function demoMeta(
  params: URLSearchParams,
  role: Role,
  source: string,
): Provenance {
  const d = Number(params.get("days") ?? 7),
    days = [1, 7, 14, 30].includes(d) ? d : 7;
  const group = params.get("group") || "All groups";
  return {
    mode: "demo",
    source,
    asOf: AS_OF,
    processedAt: new Date().toISOString(),
    status: "Processed",
    start: daysBefore(days - 1),
    end: AS_OF,
    group,
    role,
    days,
  };
}
function inventory(xs: Exec[], reg: Entry[], type: "app" | "agent"): Entry[] {
  const recent = new Map<string, Exec>(),
    owners = new Map<string, Set<string>>(),
    coverage = new Map<string, Set<string>>(),
    totals = new Map<string, number>();
  for (const e of xs) {
    const key = e[type];
    if (!key) continue;
    if (!recent.has(key)) recent.set(key, e);
    const set = owners.get(key) ?? new Set();
    if (e.owner !== "Unassigned") set.add(e.owner);
    owners.set(key, set);
    const sens = coverage.get(key) ?? new Set();
    sens.add(e.sensor);
    coverage.set(key, sens);
    totals.set(key, (totals.get(key) ?? 0) + 1);
  }
  return reg.flatMap((r) => {
    const key = type === "app" ? r.name : r.id,
      e = recent.get(key);
    if (!e) return [];
    return [
      {
        ...r,
        at: e.at,
        fields: {
          ...r.fields,
          users: owners.get(key)!.size,
          identities: [...owners.get(key)!].join(", "),
          sensorCoverage: [...coverage.get(key)!].join(", "),
          usage: totals.get(key)!,
          batch: e.batch,
          event: e.id,
          workload: e.process,
          decision: e.action,
        },
      },
    ];
  });
}
export function eventRow(
  e: Exec,
  kind: string,
  verified: boolean,
  edits: Edits,
): Entry {
  const caseKind = [
      "alerts",
      "investigations",
      "posture",
      "protection/runtime",
    ].includes(kind),
    conv = kind === "conversations" || kind === "intents";
  const state = caseKind
    ? ["Open", "In review", "Open", "Resolved"][Number(e.id.slice(-2)) % 4]
    : e.action;
  const r = entry(
    caseKind
      ? e.id.replace("EV", "ALT")
      : conv
        ? e.id.replace("EV", "CNV")
        : e.id,
    caseKind
      ? e.detection
      : conv
        ? e.intent
        : e.kind === "Agent"
          ? "Agent execution"
          : e.kind === "Human"
            ? "Human interaction"
            : "Unattributed execution",
    e.group,
    e.kind === "Human" ? "Interaction gateway fixture" : "Sniffer Dog fixture",
    state,
    {
      actor: e.actor,
      user: e.owner,
      owner: e.owner,
      kind: e.kind,
      app: e.app,
      model: e.model,
      agent: e.agent || "Unbound",
      parent: e.parent || "None recorded",
      policy: e.policy,
      policyVersion: 1,
      guardrail: e.guard,
      decision: e.action,
      enforcement: "Simulated",
      risk: e.severity,
      priority: ["High", "Critical"].includes(e.severity)
        ? "High risk"
        : "Other",
      intent: e.intent,
      preview: e.prompt,
      response: e.response,
      event: e.id,
      trace: e.trace,
      workload: e.process,
      sensor: e.sensor,
      tool: e.tool,
      confidence: e.confidence,
      verification: verified ? "Verified" : "Unverified",
      batch: e.batch,
      correlation:
        e.kind === "Unknown"
          ? "Inferred candidate"
          : "Observed workload · correlated identity",
      assignee: "Unassigned",
      day: e.at.slice(0, 10),
      tokens: e.tokens,
      cost: e.cost,
      costKind: e.costKind,
      provider: e.model.startsWith("GPT")
        ? "OpenAI"
        : e.model.startsWith("Claude")
          ? "Anthropic"
          : e.model.startsWith("Gemini")
            ? "Google"
            : e.model === "Codestral"
              ? "Mistral"
              : "Self-hosted",
    },
    e.at,
  );
  const edit = edits.get("alerts/" + r.id);
  return edit && caseKind
    ? {
        ...r,
        state: edit.state,
        notes: edit.notes,
        version: edit.version,
        fields: { ...r.fields, assignee: edit.fields.assignee ?? "Unassigned" },
      }
    : r;
}
function bucketPoints(xs: Exec[], meta: Provenance): Point[] {
  const bins = meta.days === 1 ? 12 : meta.days,
    width = meta.days === 1 ? 2 * 3600000 : DAY,
    start = Date.parse(meta.start);
  const points = Array.from({ length: bins }, (_, i) => {
    const at = new Date(start + i * width).toISOString();
    return {
      at,
      label:
        meta.days === 1
          ? at.slice(11, 16)
          : new Intl.DateTimeFormat("en-US", {
              month: "short",
              day: "numeric",
              timeZone: "UTC",
            }).format(new Date(at)),
      interactions: 0,
      executions: 0,
      blocked: 0,
      human: 0,
      unknown: 0,
      spend: 0,
      risk: 0,
    };
  });
  for (const e of xs) {
    const b = points[Math.floor((Date.parse(e.at) - start) / width)];
    if (!b) continue;
    b.interactions++;
    b.executions += Number(e.kind === "Agent");
    b.human += Number(e.kind === "Human");
    b.unknown += Number(e.kind === "Unknown");
    b.blocked += Number(e.action === "Block");
    b.spend += e.cost;
    b.risk += Number(e.alert);
  }
  return points;
}
const inGroup = (r: { group: string }, g: string) =>
  g === "All groups" || r.group === g || r.group === "All groups";
export function runRules(
  policy: Entry,
  condition: string,
  group: string,
  app: string,
) {
  if (
    policy.state !== "Enabled" ||
    (policy.fields.scope !== "All groups" && policy.fields.scope !== group) ||
    (policy.fields.destination !== "All applications" &&
      policy.fields.destination !== app)
  )
    return {
      action: "Allow",
      matched: "No active policy in scope",
      enforcement: "Simulated",
    };
  const hit = Object.entries(policy.rules ?? {}).find(
    ([, rule]) =>
      rule.enabled && rule.condition.toLowerCase() === condition.toLowerCase(),
  );
  return hit
    ? {
        action: hit[1].action,
        matched: hit[0],
        response: hit[1].response,
        enforcement: "Simulated",
      }
    : {
        action: "Allow",
        matched: "No matching condition",
        enforcement: "Simulated",
      };
}
export function paginate(
  rows: Entry[],
  p: PageDef,
  params: URLSearchParams,
  b: Bundle,
) {
  const search = (params.get("q") ?? "").toLowerCase().trim();
  let filtered = rows;
  const facetKeys = [
    ...new Set([
      ...p.filters,
      "state",
      "risk",
      "kind",
      "classification",
      "priority",
      "verification",
      "app",
      "day",
      "guardrail",
      "event",
      "agent",
      "batch",
    ]),
  ];
  b.facets = Object.fromEntries(
    facetKeys.map((k) => [
      k,
      [...new Set(rows.map((r) => String(field(r, k))).filter(Boolean))]
        .sort()
        .slice(0, 65),
    ]),
  );
  for (const k of facetKeys) {
    if (k === "group") continue;
    const v = params.get(k);
    if (v) filtered = filtered.filter((r) => String(field(r, k)) === v);
  }
  if (search)
    filtered = filtered.filter((r) =>
      [r.name, r.id, r.state, r.group, ...Object.values(r.fields)].some((x) =>
        String(x).toLowerCase().includes(search),
      ),
    );
  const sort = params.get("sort") || (p.api === "policies" ? "priority" : "at"),
    dir =
      params.get("dir") === "asc" || (!params.has("dir") && sort === "priority")
        ? 1
        : -1;
  filtered = [...filtered].sort((a, b) => {
    const aa = field(a, sort),
      bb = field(b, sort);
    return (
      dir *
      (typeof aa === "number" && typeof bb === "number"
        ? aa - bb
        : String(aa).localeCompare(String(bb), undefined, { numeric: true }))
    );
  });
  b.total = filtered.length;
  b.pageSize = Math.max(1, Math.min(100, Number(params.get("size")) || 12));
  b.page = Math.max(
    1,
    Math.min(
      Math.ceil(b.total / b.pageSize) || 1,
      Number(params.get("page")) || 1,
    ),
  );
  const id = params.get("id");
  if (id) b.selected = rows.find((r) => r.id === id);
  b.rows = filtered.slice((b.page - 1) * b.pageSize, b.page * b.pageSize);
  return b;
}
function defineMetrics(
  xs: Exec[],
  prior: Exec[],
  valid: Set<string>,
  appreg: Entry[],
  agentreg: Entry[],
  meta: Provenance,
) {
  const appstates = new Map(appreg.map((r) => [r.name, r.state])),
    agstates = new Map(agentreg.map((r) => [r.id, r.state]));
  const defs: [
    string,
    string,
    string,
    string,
    string,
    (e: Exec[]) => number,
  ][] = [
    [
      "agents",
      "Discovered agents",
      "Distinct observed identities with agent evidence. Suspected candidates are excluded.",
      "ai-agents?tab=identified",
      "AIP registry",
      (s) =>
        new Set(s.filter((e) => e.kind === "Agent").map((e) => e.agent)).size,
    ],
    [
      "shadow",
      "Shadow AI apps",
      "Distinct observed applications with unknown or blocked approval.",
      "shadow-ai",
      "Discovery",
      (s) =>
        new Set(
          s
            .filter((e) =>
              ["Unknown", "Blocked"].includes(
                appstates.get(e.app) ?? "Unknown",
              ),
            )
            .map((e) => e.app),
        ).size,
    ],
    [
      "alerts",
      "High-risk alerts",
      "Critical and high severity detections in the selected window.",
      "alerts?priority=High%20risk",
      "Detection engine",
      (s) =>
        s.filter((e) => e.alert && ["Critical", "High"].includes(e.severity))
          .length,
    ],
    [
      "verified",
      "Verified events",
      "Share of event records included in a batch that passed a signature and digest check.",
      "verification?state=Verified",
      "Evidence verifier",
      (s) =>
        s.length
          ? Math.round(
              (1000 * s.filter((e) => valid.has(e.batch)).length) / s.length,
            ) / 10
          : 0,
    ],
    [
      "apps",
      "Active AI applications",
      "Unique applications with observed usage.",
      "ai-applications",
      "Discovery",
      (s) => new Set(s.map((e) => e.app)).size,
    ],
    [
      "ghost",
      "Suspected ghost agents",
      "Candidate identities referenced by inferred activity without a trusted binding.",
      "ghost-orphan-agents?classification=Suspected%20ghost",
      "Identity correlation",
      (s) =>
        new Set(
          s
            .filter((e) => agstates.get(e.agent) === "Suspected ghost")
            .map((e) => e.agent),
        ).size,
    ],
    [
      "orphan",
      "Orphan agents",
      "Observed agents with missing accountable ownership.",
      "ghost-orphan-agents?classification=Orphan",
      "AIP registry",
      (s) =>
        new Set(
          s
            .filter((e) => agstates.get(e.agent) === "Orphan")
            .map((e) => e.agent),
        ).size,
    ],
    [
      "blocked",
      "Blocked interactions",
      "Interactions with a recorded simulated block decision.",
      "conversations?state=Block",
      "Policy decisions",
      (s) => s.filter((e) => e.action === "Block").length,
    ],
    [
      "executions",
      "Verified agent executions",
      "Identified agent executions covered by a verified batch.",
      "sniffer-dog?kind=Agent&verification=Verified",
      "Sniffer Dog",
      (s) => s.filter((e) => e.kind === "Agent" && valid.has(e.batch)).length,
    ],
  ];
  const days = Array.from({ length: meta.days }, (_, i) =>
    new Date(Date.parse(meta.start) + i * DAY).toISOString().slice(0, 10),
  );
  return defs.map(([key, label, info, href, source, fn]): Metric => ({
    key,
    label,
    info,
    href,
    source,
    value: fn(xs),
    prior: fn(prior),
    series: days.map((d) => fn(xs.filter((e) => e.at.startsWith(d)))),
  }));
}
export async function aggregate(
  p: PageDef,
  params: URLSearchParams,
  role: Role,
  edits: Edits,
  audit: Entry[] = [],
): Promise<Bundle> {
  const meta = demoMeta(params, role, "VANIAN synthetic replay · " + p.api);
  const all = allEvents().filter((e) => inGroup(e, meta.group)),
    xs = all.filter((e) => e.at >= meta.start && e.at <= meta.end);
  const prior = all.filter(
    (e) => e.at >= daysBefore(meta.days * 2 - 1) && e.at < meta.start,
  );
  const needOverview = p.slug === "home" || p.slug === "security-posture";
  const ids = [
    ...new Set((needOverview ? [...xs, ...prior] : xs).map((e) => e.batch)),
  ];
  const valid = new Set(
    (
      await Promise.all(ids.map(async (k) => ((await verify(k)) ? k : "")))
    ).filter(Boolean),
  );
  const active = xs.filter((e) => valid.has(e.batch)),
    reg = catalog(edits),
    areg = agentList(edits);
  const appRows = inventory(xs, reg, "app"),
    agentRows = inventory(xs, areg, "agent");
  const sens = sensors.filter(
    (s) => inGroup(s, meta.group) && s.at >= meta.start && s.at <= meta.end,
  );
  const pol = policyList(edits);
  const b: Bundle = {
    meta,
    rows: [],
    total: 0,
    page: 1,
    pageSize: 12,
    groups: [...groups],
  };
  let rows: Entry[] = [];
  const api = p.api;
  let analytic = xs;
  if (p.section === "Analytics") {
    const label =
      params.get("view") ||
      ({
        "data-analytics": "Data Protection",
        "risk-analysis": "Risk Analysis",
        "ai-adoption": "AI Adoption",
        roi: "ROI",
        "behavioral-activity": "Behavioral Activity",
      }[p.slug] ??
        "Behavioral Activity");
    if (!analyticsTabs.includes(label)) throw Error("Unknown analytics view");
    if (guards.includes(label) && label !== "Behavioral Activity")
      analytic = xs.filter((e) => e.guard === label);
    if (label === "SOC Dashboard") analytic = xs.filter((e) => e.alert);
  }
  b.trend = bucketPoints(analytic, meta);
  const amount = (e: Exec) => e.cost;
  b.summaries = {
    apps: counts(analytic, (e) => e.app),
    risk: counts(analytic, (e) => e.severity),
    alerts: counts(
      analytic.filter((e) => e.alert),
      (e) => e.severity,
    ),
    categories: counts(appRows, (r) => String(r.fields.category)),
    actors: counts(analytic, (e) => e.kind),
    decisions: counts(analytic, (e) => e.action),
    agents: counts(
      analytic.filter((e) => e.kind === "Agent"),
      (e) => e.actor,
    ),
    users: counts(analytic, (e) => e.owner),
    intents: counts(analytic, (e) => e.intent),
    guards: counts(analytic, (e) => e.guard),
    lineage: counts(agentRows, (e) => e.state),
    modelCost: counts(xs, (e) => e.model, amount),
    appCost: counts(xs, (e) => e.app, amount),
    userCost: counts(
      xs.filter((e) => e.kind === "Human"),
      (e) => e.actor,
      amount,
    ),
    agentCost: counts(
      xs.filter((e) => e.kind === "Agent"),
      (e) => e.actor,
      amount,
    ),
    departmentCost: counts(xs, (e) => e.group, amount),
    providerCost: counts(
      xs,
      (e) =>
        e.model.startsWith("GPT")
          ? "OpenAI"
          : e.model.startsWith("Claude")
            ? "Anthropic"
            : e.model.startsWith("Gemini")
              ? "Google"
              : e.model === "Codestral"
                ? "Mistral"
                : "Self-hosted",
      amount,
    ),
  };
  b.stats = {
    interactions: analytic.length,
    agents: analytic.filter((e) => e.kind === "Agent").length,
    unknown: xs.filter((e) => e.kind === "Unknown").length,
    human: analytic.filter((e) => e.kind === "Human").length,
    blocked: analytic.filter((e) => e.action === "Block").length,
    verified: active.length,
    batches: new Set(xs.map((x) => x.batch)).size,
    apps: appRows.length,
    newApps: appRows.filter((r) => String(r.fields.firstSeen) >= meta.start)
      .length,
    highApps: appRows.filter((r) => r.fields.risk === "High").length,
    healthy: sens.filter((s) => s.state === "Healthy").length,
    sensors: sens.length,
    overhead: sens.length
      ? sens.reduce((n, r) => n + Number(r.fields.overhead), 0) / sens.length
      : 0,
    violations: xs.filter((e) => e.action !== "Allow").length,
    tokens: sum(xs, (e) => e.tokens),
    metered: sum(
      xs.filter((e) => e.costKind === "Metered"),
      amount,
    ),
    estimated: sum(
      xs.filter((e) => e.costKind === "Estimated"),
      amount,
    ),
    cost: sum(xs, amount),
    riskEvents: analytic.filter((e) => e.alert).length,
  };
  b.stats.orderVersion = edits.get("ordering/policies")?.version ?? 0;
  b.stats.budgetVersion =
    edits.get("budgets/BUD-" + meta.group + meta.days)?.version ?? 0;
  b.stats.budget = Number(
    edits.get("budgets/BUD-" + meta.group + meta.days)?.fields.amount ?? 0,
  );
  const record = (e: Exec, kind = api) =>
    eventRow(e, kind, valid.has(e.batch), edits);
  b.sensors = sens;
  if (needOverview) {
    b.metrics = defineMetrics(xs, prior, valid, reg, areg, meta);
    b.references = xs
      .filter((e) => e.alert)
      .slice(0, 5)
      .map((e) => record(e, "alerts"));
  }
  if (api === "overview") return b;
  if (["snifferdog/events", "agents/lineage", "identity"].includes(api)) {
    const filtered = xs.filter(
      (e) =>
        (!params.get("sensor") || e.sensor === params.get("sensor")) &&
        (!params.get("agent") || e.agent === params.get("agent")) &&
        (!params.get("kind") || e.kind === params.get("kind")),
    );
    const chosen = params.get("trace");
    const trace = chosen
      ? filtered.find((e) => e.trace === chosen)
      : (filtered.find(
          (e) => e.registered && e.parent && e.action !== "Block",
        ) ?? filtered[0]);
    if (trace) {
      b.graph = fixtureGraph(
        trace,
        areg,
        api === "agents/lineage"
          ? "lineage"
          : api === "identity"
            ? "identity"
            : "runtime",
      );
      b.timeline = fixtureTrace(trace);
      b.series = [
        ...new Set([
          trace.trace,
          ...filtered
            .filter((e) => e.agent)
            .slice(0, 25)
            .map((e) => e.trace),
        ]),
      ];
    }
  }
  if (
    ["discovery/apps", "discovery/catalog", "discovery/shadow"].includes(api)
  ) {
    rows = api.endsWith("shadow")
      ? appRows.filter((r) => ["Unknown", "Blocked"].includes(r.state))
      : appRows;
  } else if (
    [
      "discovery/agents",
      "discovery/inventory",
      "discovery/exceptions",
      "identity",
      "agents/lineage",
    ].includes(api)
  ) {
    rows = api.endsWith("exceptions")
      ? agentRows.filter((r) =>
          ["Orphan", "Suspected ghost", "Unregistered"].includes(r.state),
        )
      : agentRows;
    if (params.get("classification") === "Inactive") {
      rows = dormantAgents
        .filter((r) => inGroup(r, meta.group))
        .map((r) => ({
          ...r,
          fields: {
            ...r.fields,
            usage: 0,
            period: "Historical last observation",
          },
        }));
    }
    if (params.get("classification") === "Unknown") {
      rows = agentRows
        .filter((r) => ["Suspected ghost", "Unregistered"].includes(r.state))
        .map((r) => ({
          ...r,
          fields: { ...r.fields, classification: "Unknown" },
        }));
    }
    if (params.get("tab") === "identified")
      rows = rows.filter((r) => r.state !== "Suspected ghost");
    if (api === "agents/lineage" || api === "identity")
      b.references = agentRows;
  } else if (api === "discovery/mcp") {
    rows = mcp
      .filter((s) => inGroup(s, meta.group))
      .map((s) => {
        const matching = xs.filter((e) => e.tool === s.name);
        return {
          ...s,
          at: matching[0]?.at ?? s.at,
          fields: {
            ...s.fields,
            endpoint: "https://" + s.id.toLowerCase() + ".demo.invalid/mcp",
            calls: matching.length,
            connectedAgents: new Set(
              matching.map((e) => e.agent).filter(Boolean),
            ).size,
            risk: s.state === "Restricted" ? "High" : "Low",
            schema:
              '{"type":"object","properties":{"record_id":{"type":"string"}}}',
            policy: "Delegated tool access",
          },
        };
      });
    if (params.get("tab") === "Tools")
      rows = rows.flatMap((r) =>
        String(r.fields.toolNames)
          .split(", ")
          .map((t) => ({
            ...r,
            id: r.id + "/" + t,
            name: t,
            fields: { ...r.fields, server: r.name },
          })),
      );
  } else if (
    ["alerts", "investigations", "posture", "protection/runtime"].includes(api)
  )
    rows = xs.filter((e) => e.alert).map((e) => record(e));
  else if (api === "policies")
    rows = pol.filter(
      (r) =>
        r.fields.scope === "All groups" ||
        meta.group === "All groups" ||
        r.fields.scope === meta.group,
    );
  else if (
    ["guardrails", "protection/models", "protection/data"].includes(api)
  ) {
    rows = pol.flatMap((r) =>
      Object.entries(r.rules ?? {})
        .filter(
          ([g]) =>
            api === "guardrails" ||
            (api.endsWith("models")
              ? /Model|Agent Identity|Delegation|MCP/.test(g)
              : g === "Data Protection"),
        )
        .map(([g, rule]) =>
          entry(
            r.id + "/" + g,
            g,
            r.group,
            "Policy registry",
            rule.enabled ? "Enabled" : "Disabled",
            {
              policy: r.name,
              policyId: r.id,
              condition: rule.condition,
              action: rule.action,
              response: rule.response,
              enforcement: "Simulated",
            },
            r.at,
          ),
        ),
    );
  } else if (api === "red-teaming") {
    rows = safeCases.map(
      ([name, g, expected], i) =>
        edits.get("assessments/TEST-" + i) ??
        entry("TEST-" + i, name, "All groups", "Policy test catalog", "Ready", {
          guardrail: g,
          expected,
          scope: "Isolated policy simulator",
          target: policies[i % policies.length].name,
          risk: "Medium",
          remediation: "Review the matched rule and run the check again.",
        }),
    );
  } else if (api === "compliance" || api === "governance") {
    rows = ["ISO/IEC 27001", "ISO/IEC 42001", "Customer controls"]
      .flatMap((f, i) =>
        [
          "Access control review",
          "Activity traceability",
          "Incident review",
        ].map((n, j) =>
          entry(
            "CTL-" + i + j,
            n,
            groups[(i + j) % 4],
            "Customer mapping fixture",
            xs.length ? "Evidence available" : "Awaiting evidence",
            {
              framework: f,
              owner: people[(i + j) % 4].name,
              coverage: xs[0]?.batch ?? "Unlinked",
              assessment: "Draft mapping · assessment pending",
              exception:
                j === 2
                  ? "Independent assessor review pending"
                  : "None recorded",
            },
          ),
        ),
      )
      .filter((r) => inGroup(r, meta.group));
  } else if (api === "evidence" || api === "verification") {
    rows = [...new Set(xs.map((e) => e.batch))].map((id) => {
      const items = batches().get(id)!;
      return entry(
        id,
        id.slice(2, 12) + " · " + items[0].group,
        items[0].group,
        "Ed25519 fixture signer",
        valid.has(id) ? "Verified" : "Unverified",
        {
          items: items.length,
          key: "vanian-demo-ed25519-v1",
          algorithm: "Ed25519",
          retention: "Reproducible fixture",
          batch: id,
        },
        items[0].at,
      );
    });
  } else if (api === "audit") {
    meta.source = "Workspace change log · evaluation tenant";
    meta.asOf = meta.processedAt;
    meta.end = meta.processedAt;
    meta.start = new Date(
      Date.parse(meta.asOf.slice(0, 10) + "T00:00:00Z") - (meta.days - 1) * DAY,
    ).toISOString();
    meta.status = "Recorded";
    rows = audit.filter(
      (r) => inGroup(r, meta.group) && r.at >= meta.start && r.at <= meta.end,
    );
  } else if (api === "users")
    rows = people.filter((r) => inGroup(r, meta.group));
  else if (api === "groups") {
    rows = groups
      .filter((g) => meta.group === "All groups" || meta.group === g)
      .map((g) =>
        entry("GRP-" + g, g, g, "Directory fixture", "Active", {
          members: people
            .filter((u) => u.group === g)
            .map((u) => u.name)
            .join(", "),
          role: "Workspace group",
        }),
      );
  } else if (api === "integrations") {
    rows = [
      ["AIP Identity", "Authority", "Identity and delegation"],
      ["Sniffer Dog", "Sensor", "Independent runtime observation"],
      ["MCP gateway", "Gateway", "Request / dispatch receipts"],
      ["Identity provider", "SSO / SCIM", "Identity provisioning"],
      ["Provider billing", "FinOps", "Cost attribution"],
      ["SIEM export", "SIEM", "Security event delivery"],
    ].map(([n, t, c], i) =>
      entry(
        "INT-" + i,
        n,
        "All groups",
        "Connector inventory",
        i < 3 ? "Replay available" : "Unconfigured",
        {
          type: t,
          coverage: c,
          requires: "Tenant-bound service connection",
          enforcement: "No live enforcement",
        },
      ),
    );
  } else if (api === "settings" || api.startsWith("admin/")) {
    const items: Record<string, string[][]> = {
      settings: [
        ["Workspace", "VANIAN evaluation"],
        ["Session role", role],
        ["Data redaction", "Masked by default"],
        ["Retention", "Fixed demo replay"],
      ],
      "admin/sso": [
        ["Identity provider", "Private-site sign-in"],
        ["Enterprise SSO", "Integration required"],
        ["SCIM provisioning", "Integration required"],
      ],
      "admin/rbac": [
        ["Administrator", "Manage demo policy, role and scope"],
        ["Analyst", "Investigations and redacted telemetry"],
        ["Auditor", "Read-only evidence and reports"],
      ],
      "admin/deployments": [
        ["Hosted workspace", "Private application"],
        ["Private cloud", "Qualification pending"],
        ["Customer-hosted collector", "Native verifier bridge required"],
        ["Backups and upgrades", "Customer acceptance pending"],
      ],
      "admin/billing": [
        ["Subscription", "Evaluation workspace"],
        ["Metered invoices", "Billing provider required"],
        ["Support agreement", "No SLA configured"],
      ],
    };
    rows = (items[api] ?? []).map(([n, v], i) =>
      entry(
        "CFG-" + i,
        n,
        "All groups",
        "Workspace configuration",
        "Workspace",
        { value: v },
      ),
    );
  } else rows = analytic.map((e) => record(e));
  const target = params.get("id");
  if (target) {
    const sel = rows.find((r) => r.id === target);
    if (sel) {
      const related = xs
        .filter(
          (e) =>
            sel.id === e.agent ||
            sel.name === e.app ||
            sel.name === e.tool ||
            sel.name === e.policy ||
            sel.fields.event === e.id ||
            sel.id === e.batch ||
            sel.fields.trace === e.trace,
        )
        .slice(0, 12);
      b.references = related.map((e) => record(e, "runtime"));
      if (related[0]) {
        b.timeline = fixtureTrace(related[0]);
        if (
          [
            "alerts",
            "investigations",
            "posture",
            "protection/runtime",
          ].includes(api)
        ) {
          const event = related[0],
            g = fixtureGraph(event, areg, "runtime");
          const policyId = "POLICY-" + event.policy;
          const guardId = "CONTROL-" + event.guard;
          g.nodes.push(
            {
              id: policyId,
              label: event.policy,
              kind: "service",
              at: event.at,
              evidence: event.batch,
              status: "Declared policy",
            },
            {
              id: guardId,
              label: event.guard,
              kind: "action",
              at: event.at,
              evidence: event.batch,
              status: "Matched guardrail",
            },
          );
          g.edges.push(
            {
              source: policyId,
              target: guardId,
              relation: "declared",
              label: "Includes control",
              at: event.at,
              evidence: event.batch,
            },
            {
              source: guardId,
              target: event.id,
              relation: "observed",
              label: "Reported decision",
              at: event.at,
              evidence: event.batch,
            },
          );
          b.graph = g;
        }
      }
    }
  }
  return paginate(rows, p, params, b);
}
