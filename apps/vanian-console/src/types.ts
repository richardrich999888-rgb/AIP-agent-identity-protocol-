export type Mode = "demo" | "live";
export type Role = "Administrator" | "Analyst" | "Auditor";
export type Group = "Engineering" | "Finance" | "Operations" | "Research";
export const groups: Group[] = [
  "Engineering",
  "Finance",
  "Operations",
  "Research",
];
export const actions = ["Allow", "Warn", "Block", "Route", "Alert"] as const;
export const severities = ["Critical", "High", "Medium", "Low"] as const;
export const guards = [
  "Behavioral Activity",
  "Data Protection",
  "Harmful Response Prevention",
  "Model Identity Protection",
  "Model Protection",
  "Organizational Behavior",
  "Risk Analysis",
  "Agent Identity Verification",
  "Delegation Authorization",
  "MCP Tool Governance",
];
export type Cell = string | number | boolean;
export interface Note {
  text: string;
  at: string;
  actor: string;
}
export interface Rule {
  enabled: boolean;
  condition: string;
  action: string;
  response: string;
}
export interface Entry {
  id: string;
  name: string;
  at: string;
  group: string;
  source: string;
  state: string;
  fields: Record<string, Cell>;
  version?: number;
  notes?: Note[];
  rules?: Record<string, Rule>;
  history?: { version: number; at: string; actor: string; change: string }[];
}
export interface Exec {
  id: string;
  at: string;
  group: Group;
  app: string;
  model: string;
  actor: string;
  owner: string;
  agent: string;
  parent: string;
  kind: "Human" | "Agent" | "Unknown";
  action: string;
  severity: string;
  intent: string;
  detection: string;
  guard: string;
  policy: string;
  tokens: number;
  cost: number;
  costKind: "Metered" | "Estimated";
  sensor: string;
  process: string;
  confidence: number;
  batch: string;
  prompt: string;
  response: string;
  alert: boolean;
  registered: boolean;
  tool: string;
  trace: string;
}
export interface Provenance {
  mode: Mode;
  source: string;
  asOf: string;
  processedAt: string;
  status: string;
  start: string;
  end: string;
  group: string;
  role: Role;
  days: number;
}
export interface Metric {
  key: string;
  label: string;
  value: number;
  prior: number;
  series: number[];
  info: string;
  href: string;
  source: string;
}
export interface Point {
  label: string;
  at: string;
  interactions: number;
  executions: number;
  blocked: number;
  human: number;
  unknown: number;
  spend: number;
  risk: number;
}
export interface Count {
  name: string;
  value: number;
}
export interface Bundle {
  timeline?: import("./server/trace").TraceStep[];
  graph?: ReturnType<typeof import("./server/trace").fixtureGraph>;
  meta: Provenance;
  rows: Entry[];
  total: number;
  page: number;
  pageSize: number;
  metrics?: Metric[];
  trend?: Point[];
  summaries?: Record<string, Count[]>;
  references?: Entry[];
  stats?: Record<string, number>;
  sensors?: Entry[];
  groups?: string[];
  selected?: Entry;
  series?: string[];
  edges?: { source: string; target: string }[];
  facets?: Record<string, string[]>;
}
export type Column = [key: string, title: string];
export interface PageDef {
  slug: string;
  title: string;
  section: string;
  icon: string;
  api: string;
  description: string;
  columns: Column[];
  filters: string[];
}
