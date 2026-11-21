import { pages as base } from "./product";
import type { PageDef, Role } from "./types";
const copy = (
  slug: string,
  title: string,
  source: string,
  api?: string,
  icon?: string,
): PageDef => ({
  ...base.find((x) => x.slug === source)!,
  slug,
  title,
  ...(api ? { api } : {}),
  ...(icon ? { icon } : {}),
});
const extra: PageDef[] = [
  copy(
    "app-catalog",
    "App Catalog",
    "ai-applications",
    "discovery/catalog",
    "book",
  ),
  copy(
    "intent-classification",
    "Intent Classification",
    "conversations",
    "intents",
    "list",
  ),
  copy(
    "runtime-protection",
    "Runtime Protection",
    "security-posture",
    "protection/runtime",
    "shield",
  ),
  copy("groups", "Groups", "users-groups", "groups", "users"),
  copy(
    "verification",
    "Verification",
    "evidence-audit",
    "verification",
    "checkcircle",
  ),
  copy("audit-trails", "Audit Trails", "evidence-audit", "audit", "history"),
  copy("token-usage", "Token Usage", "ai-finops", "finops/tokens", "cpu"),
  copy(
    "cost-optimization",
    "Cost Optimization",
    "ai-finops",
    "finops/optimization",
    "sliders",
  ),
  ...[
    ["deployments", "Deployments", "server"],
    ["sso", "SSO & SCIM", "fingerprint"],
    ["rbac", "Roles & Permissions", "key"],
    ["billing", "Billing", "wallet"],
  ].map(([s, t, i]) => copy(s, t, "settings", "admin/" + s, i)),
  ...[
    ["behavioral-activity", "Behavioral Activity"],
    ["data-analytics", "Data Protection"],
    ["risk-analysis", "Risk Analysis"],
    ["ai-adoption", "AI Adoption"],
    ["roi", "ROI"],
  ].map(([s, t]) => copy(s, t, "analytics", "analytics/" + s)),
];
const order: Record<string, string[]> = {
  Overview: ["home", "security-posture"],
  Discovery: [
    "ai-applications",
    "app-catalog",
    "ai-agents",
    "shadow-ai",
    "mcp-servers",
  ],
  Analytics: [
    "behavioral-activity",
    "data-analytics",
    "risk-analysis",
    "ai-adoption",
    "roi",
    "analytics",
  ],
  Conversations: ["conversations", "intent-classification"],
  Security: [
    "alerts",
    "investigations",
    "runtime-protection",
    "guardrails",
    "model-protection",
    "data-protection",
    "ai-red-teaming",
  ],
  Governance: [
    "policies",
    "users-groups",
    "groups",
    "compliance",
    "ai-governance",
  ],
  "Agent Accountability": [
    "sniffer-dog",
    "identity-authorization",
    "agent-lineage",
    "ghost-orphan-agents",
    "attribution",
    "agent-inventory",
    "runtime-activity",
  ],
  Evidence: ["evidence-audit", "verification", "audit-trails"],
  "AI FinOps": ["ai-finops", "token-usage", "cost-optimization"],
  Administration: [
    "integrations",
    "deployments",
    "sso",
    "rbac",
    "billing",
    "settings",
  ],
};
const titles: Record<string, string> = {
  "ai-agents": "AI Agents",
  conversations: "Conversation Explorer",
  "identity-authorization": "AIP Identity",
  "evidence-audit": "Execution Evidence",
  "users-groups": "Users",
  "ghost-orphan-agents": "Ghost & Orphan AI",
  "ai-finops": "Spending",
  "behavioral-activity": "Behavioral Activity",
};
const definitions = [...base, ...extra];
export const sections = Object.keys(order);
export const pages = sections.flatMap((section) =>
  order[section].map((slug) => ({
    ...definitions.find((x) => x.slug === slug)!,
    section,
    ...(titles[slug] ? { title: titles[slug] } : {}),
  })),
);
export const bySlug = Object.fromEntries(pages.map((p) => [p.slug, p]));
export const byApi = Object.fromEntries(pages.map((p) => [p.api, p]));
export function canRead(p: PageDef, role: Role) {
  return (
    p.section !== "Administration" ||
    ["settings", "integrations"].includes(p.slug) ||
    role === "Administrator"
  );
}
export const defaultOpen = ["Overview", "Discovery", "Agent Accountability"];
