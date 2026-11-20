import { groups, guards, type Entry, type Exec, type Group } from "../types";
export const AS_OF = "2026-11-20T18:00:00.000Z";
export const DAY = 86_400_000;
export const snapshot = Date.parse(AS_OF);
const date = (days: number) => new Date(snapshot - days * DAY).toISOString();
export function entry(
  id: string,
  name: string,
  group: string,
  source: string,
  state: string,
  fields: Entry["fields"] = {},
  at = AS_OF,
): Entry {
  return { id, name, group, source, state, fields, at, version: 1 };
}
const appsData = [
  ["ChatGPT", "AI tools", "chatgpt.com"],
  ["Claude", "AI tools", "claude.ai"],
  ["GitHub Copilot", "Software development", "github.com"],
  ["Gemini", "Productivity", "gemini.google.com"],
  ["Perplexity", "Research", "perplexity.ai"],
  ["Cursor", "Software development", "cursor.com"],
  ["Notion AI", "Productivity", "notion.so"],
  ["Mistral Le Chat", "AI tools", "chat.mistral.ai"],
  ["Adobe Firefly", "Image generation", "firefly.adobe.com"],
  ["Harvey", "Legal", "harvey.ai"],
  ["Glean", "Research", "glean.com"],
  ["Microsoft Copilot", "Productivity", "copilot.microsoft.com"],
  ["Jasper", "Productivity", "jasper.ai"],
  ["Replit", "Software development", "replit.com"],
  ["Writer", "Productivity", "writer.com"],
  ["Midjourney", "Image generation", "midjourney.com"],
  ["Cohere", "AI tools", "cohere.com"],
  ["AlphaSense", "Finance", "alpha-sense.com"],
  ["Abridge", "Healthcare", "abridge.com"],
  ["Runway", "Image generation", "runwayml.com"],
  ["Elicit", "Research", "elicit.com"],
  ["Sourcegraph Cody", "Software development", "sourcegraph.com"],
  ["Gamma", "Productivity", "gamma.app"],
  ["DeepL", "Productivity", "deepl.com"],
  ["Hebbia", "Finance", "hebbia.ai"],
  ["Tabnine", "Software development", "tabnine.com"],
  ["You.com", "Research", "you.com"],
  ["Lexis+ AI", "Legal", "lexisnexis.com"],
  ["Granola", "Productivity", "granola.ai"],
  ["Spline AI", "Image generation", "spline.design"],
  ["NotebookLM", "Research", "notebooklm.google.com"],
  ["Sana", "Productivity", "sana.ai"],
];
const ownerNames = [
  "Maya Chen",
  "Arjun Rao",
  "Lena Ortiz",
  "Noah Park",
  "Eva Torres",
  "Sam Patel",
  "Imani Cole",
  "Theo Klein",
];
export const people = ownerNames.map((n, i) =>
  entry("USR-" + (201 + i), n, groups[i % 4], "Directory fixture", "Active", {
    role: i < 2 ? "Administrator" : i % 3 ? "Analyst" : "Auditor",
    identity: n.toLowerCase().replace(" ", ".") + "@demo.invalid",
  }),
);
export const apps = appsData.map(([name, category, domain], i) =>
  entry(
    "APP-" + (101 + i),
    name,
    groups[i % 4],
    "Egress discovery fixture",
    i % 9 === 5 ? "Blocked" : i % 6 === 1 ? "Unknown" : "Approved",
    {
      category,
      domain,
      risk: i % 9 === 5 ? "High" : i % 6 === 1 ? "Medium" : "Low",
      icon: name.slice(0, 2),
      firstSeen: date(i >= 29 ? 3 : 55),
      policy: "Corporate AI usage",
    },
  ),
);
const names = [
  "Atlas Orchestrator",
  "Ledger Supervisor",
  "Ops Coordinator",
  "Research Director",
  "Build Assistant",
  "Invoice Analyst",
  "Support Triage",
  "Research Assistant",
  "Code Reviewer",
  "Settlement Worker",
  "Index Builder",
  "Citation Agent",
  "Artifact Writer",
  "Reconciliation Bot",
  "Runbook Agent",
  "Source Collector",
  "Build Delegate",
  "Ledger Delegate",
  "Ops Delegate",
  "Research Delegate",
  "Tool Broker",
  "Payment Router",
  "Log Normalizer",
  "Document Reader",
  "Drift Observer",
  "Unbound Worker",
  "Trace Candidate",
  "Detached Reviewer",
];
export const agents = names.map((name, i) => {
  const owner = ownerNames[i % 4],
    orphan = [21, 25, 27].includes(i),
    ghost = [24, 26].includes(i),
    unreg = i === 22,
    suspended = i === 23;
  const state = ghost
    ? "Suspected ghost"
    : orphan
      ? "Orphan"
      : unreg
        ? "Unregistered"
        : suspended
          ? "Suspended"
          : "Registered";
  const parent =
    i < 4
      ? ""
      : orphan
        ? "Missing parent"
        : "AGT-" + (101 + (i < 8 ? i % 4 : i - 4));
  return entry(
    "AGT-" + (101 + i),
    name,
    groups[i % 4],
    ghost ? "Behavioral correlation fixture" : "Agent registry fixture",
    state,
    {
      framework: ["LangGraph", "OpenAI Agents SDK", "CrewAI", "Google ADK"][
        i % 4
      ],
      parent,
      owner: orphan ? "Unassigned" : owner,
      environment: ["Kubernetes", "Linux VM", "Container", "Sandbox"][i % 4],
      risk: ghost || orphan ? "High" : unreg ? "Medium" : "Low",
      classification: state,
      confidence: ghost ? 64 : unreg ? 72 : 96 + (i % 4),
      evidence: ghost
        ? "Inferred · candidate only"
        : "Registry and observed workload",
      scope: [
        "repository:read",
        "ledger:read",
        "tickets:read",
        "documents:read",
      ][i % 4],
      authorization: suspended
        ? "Revoked"
        : ghost || orphan || unreg
          ? "Unresolved"
          : "Delegated",
      firstSeen: date(i > 24 ? 4 : 58),
    },
  );
});
export const dormantAgents = ["Release Auditor", "Budget Forecaster"].map(
  (name, i) =>
    entry(
      "AGT-" + (140 + i),
      name,
      groups[i],
      "Historical registry fixture",
      "Inactive",
      {
        framework: ["LangGraph", "OpenAI Agents SDK"][i],
        parent: "",
        owner: ownerNames[i],
        environment: "Container",
        authorization: "Expired",
        classification: "Inactive",
        risk: "Low",
        confidence: 94,
        sensorCoverage: "Last heartbeat outside window",
        scope: "read",
        evidence: "Historical registry observation",
      },
      date(42 + i),
    ),
);
export const sensors = Array.from({ length: 8 }, (_, i) =>
  entry(
    "SNS-" + (41 + i),
    [
      "edge-01",
      "ledger-01",
      "ops-01",
      "research-01",
      "edge-02",
      "ledger-02",
      "ops-02",
      "research-02",
    ][i],
    groups[i % 4],
    "Sensor heartbeat fixture",
    i === 6 ? "Delayed" : "Healthy",
    {
      host: "worker-" + (i + 11),
      overhead: [0.31, 0.34, 0.24, 0.41, 0.27, 0.35, 0.3, 0.28][i],
      zone: ["US East", "EU West", "AP South", "US West"][i % 4],
    },
    new Date(snapshot - (i === 6 ? 16 : 1 + (i % 3)) * 60000).toISOString(),
  ),
);
export const mcp = [
  "Repository tools",
  "Finance ledger",
  "Service desk",
  "Research index",
  "Artifact store",
  "Payments gateway",
  "Log search",
  "Document store",
].map((n, i) =>
  entry(
    "MCP-" + (11 + i),
    n,
    groups[i % 4],
    "MCP registry fixture",
    i === 5 ? "Restricted" : "Approved",
    {
      owner: ownerNames[i % 4],
      tools: 2 + (i % 4),
      scope: [
        "repository:read",
        "ledger:read",
        "tickets:read",
        "documents:read",
      ][i % 4],
      transport: "Streamable HTTP",
      toolNames: [
        "list_files, read_file",
        "list_entries, read_entry",
        "list_tickets, read_ticket",
        "search_documents, read_document",
      ][i % 4],
    },
  ),
);
export const policyNames = [
  "Corporate AI usage",
  "Sensitive data egress",
  "Model identity assurance",
  "Delegated tool access",
  "Outbound content safety",
];
export const policies = policyNames.map((name, i) => {
  const at = date(9 + i);
  const p = entry(
    "POL-" + (100 + i),
    name,
    "All groups",
    "Policy registry fixture",
    i === 4 ? "Disabled" : "Enabled",
    {
      priority: i + 1,
      scope: i === 3 ? "Engineering" : "All groups",
      destination: i === 2 ? "Claude" : "All applications",
      action: ["Warn", "Block", "Alert", "Block", "Warn"][i],
      enforcement: "Simulated",
      description: [
        "Guide access to sanctioned AI applications.",
        "Mask sensitive content sent to external models.",
        "Check configured model identity and behavior.",
        "Validate agent scope before a tool call.",
        "Screen outbound responses.",
      ][i],
    },
    at,
  );
  p.rules = Object.fromEntries(
    guards.map((g, j) => [
      g,
      {
        enabled: i === 0 ? j % 2 === 0 : j === [0, 1, 3, 6, 2][i],
        condition: [
          "Unapproved application",
          "Sensitive data present",
          "Restricted response category",
          "Identity mismatch",
          "Unexpected model behavior",
          "External destination",
          "Missing delegated scope",
          "Unbound agent identity",
          "Invalid parent authorization",
          "Unapproved MCP tool",
        ][j],
        action: String(p.fields.action),
        response: "Request held for policy review.",
      },
    ]),
  );
  p.history = [
    { version: 1, at, actor: "Demo administrator", change: "Policy created" },
  ];
  return p;
});
const intents = [
  "Document summary",
  "Code assistance",
  "Financial analysis",
  "Research query",
  "Content generation",
  "Data extraction",
  "Tool invocation",
];
const detections = [
  "Sensitive data in prompt",
  "Unapproved AI application",
  "Missing delegation scope",
  "Model identity mismatch",
  "Unattributed process activity",
  "Restricted destination",
  "Unsafe response category",
];
const prompts = [
  "Summarize the quarterly operating report for [REDACTED].",
  "Review this change and explain the build result.",
  "Classify the invoice line for account [REDACTED].",
  "Find approved source material for this research question.",
  "Draft a customer update using the approved template.",
  "Extract the totals from the masked statement.",
  "Read the assigned tool record under the delegated scope.",
];
const modelNames = [
  "GPT-4.1",
  "Claude Sonnet",
  "Gemini Pro",
  "Codestral",
  "Llama 3.3",
];
function generator(seed: number) {
  let x = seed >>> 0;
  return () => {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    return x / 4294967296;
  };
}
export function demoEvents(): Exec[] {
  const result: Exec[] = [];
  for (let d = 0; d < 63; d++) {
    const rng = generator(12077 + Math.imul(d + 8, 81231));
    const start = Date.parse("2026-11-20T00:00:00.000Z") - d * DAY;
    const count = Math.round(
      142 +
        Math.max(0, 55 - d) * 1.8 +
        39 * Math.sin(d * 1.41 + 0.4) +
        36 * Math.cos(d * 0.79 + 0.8),
    );
    for (let i = 0; i < count; i++) {
      const g = Math.floor(rng() * 4),
        group = groups[g],
        ai = Math.floor(rng() * (d > 5 ? 29 : 32)),
        a = apps[ai];
      const idx = g + Math.floor(rng() * (d > 4 ? 6 : 7)) * 4,
        agent = agents[idx];
      const r = rng();
      const identified = r < 0.43 + 0.16 * Math.sin(d * 1.55);
      const candidate = identified && agent.state === "Suspected ghost";
      const kind: Exec["kind"] = candidate
        ? "Unknown"
        : identified
          ? "Agent"
          : r > 0.967
            ? "Unknown"
            : "Human";
      const intentIndex = Math.floor(rng() * intents.length),
        riskR = rng();
      const risk =
        riskR < 0.012
          ? "Critical"
          : riskR < 0.062
            ? "High"
            : riskR < 0.17
              ? "Medium"
              : "Low";
      const action =
        risk === "Critical"
          ? "Block"
          : risk === "High"
            ? i % 3
              ? "Block"
              : "Warn"
            : risk === "Medium"
              ? i % 3
                ? "Warn"
                : "Alert"
              : "Allow";
      const en = Math.floor(rng() * 7),
        owner = ownerNames[g + (i % 5 === 0 ? 4 : 0)],
        token = Math.round(240 + rng() * 5100),
        appName = a.name;
      const id = "EV-" + (900000 - d * 400 - i);
      result.push({
        id,
        at: new Date(
          start +
            Math.floor(
              ((i + 0.2 + rng() * 0.7) / count) *
                (d === 0 ? 18 : 23.9) *
                3600000,
            ),
        ).toISOString(),
        group,
        app: appName,
        model: modelNames[ai % 5],
        kind,
        actor:
          kind === "Agent"
            ? agent.name
            : kind === "Human"
              ? owner
              : "Unattributed workload",
        owner:
          kind === "Unknown"
            ? "Unassigned"
            : kind === "Human"
              ? owner
              : String(agent.fields.owner),
        agent: identified ? agent.id : "",
        parent: kind === "Agent" ? String(agent.fields.parent) : "",
        action,
        severity: risk,
        intent: intents[intentIndex],
        detection: detections[en],
        guard: guards[en],
        policy: policyNames[en % 4],
        tokens: token,
        cost: Number((token * (1 + (ai % 4)) * 0.000003).toFixed(5)),
        costKind: i % 4 ? "Metered" : "Estimated",
        sensor: sensors[g + (i % 3 === 0 ? 4 : 0)].id,
        process:
          kind === "Human"
            ? "browser-session"
            : "worker-" + (4000 + ((i * 11 + d) % 850)),
        confidence: candidate
          ? 64
          : kind === "Unknown"
            ? 0
            : kind === "Human"
              ? 99
              : Number(agent.fields.confidence),
        batch:
          "B-" +
          new Date(start).toISOString().slice(0, 10) +
          "-" +
          group.slice(0, 3).toUpperCase(),
        prompt: prompts[intentIndex],
        response:
          action === "Block"
            ? "Response withheld by the simulated policy."
            : "Redacted response available for investigation.",
        alert:
          risk === "Critical" ||
          risk === "High" ||
          (risk === "Medium" && i % 9 === 0),
        registered: kind === "Agent" && agent.state === "Registered",
        tool: mcp[g + (i % 4 === 1 ? 4 : 0)].name,
        trace: "TR-" + (300000 + d * 400 + i),
      });
    }
  }
  return result.sort((a, b) => b.at.localeCompare(a.at));
}
let eventCache: Exec[] | undefined;
export const allEvents = () => (eventCache ??= demoEvents());
export function rawPrompt(e: Exec) {
  return e.prompt.replace("[REDACTED]", "DEMO-ACCOUNT-0042");
}
export const safeCases = [
  ["Unapproved application", "Behavioral Activity", "Warn"],
  ["Sensitive data present", "Data Protection", "Block"],
  ["Identity mismatch", "Model Identity Protection", "Alert"],
  ["Missing delegated scope", "Risk Analysis", "Block"],
  ["Prompt injection signal", "Model Protection", "Block"],
  ["Jailbreak signal", "Model Protection", "Block"],
  ["Unapproved MCP tool", "MCP Tool Governance", "Block"],
  ["Invalid parent authorization", "Delegation Authorization", "Block"],
];
