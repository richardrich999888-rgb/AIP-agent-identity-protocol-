import { z } from "zod";
import { byApi, canRead } from "../navigation";
import { fail } from "./access";
import type { Role, Bundle } from "../types";
const cells = z.record(z.union([z.string(), z.number().finite(), z.boolean()]));
const row = z.object({
  id: z.string(),
  name: z.string(),
  at: z.string().datetime(),
  source: z.string().min(1),
  state: z.string(),
  group: z.string(),
  fields: cells,
  version: z.number().optional(),
});
const point = z.object({
  label: z.string(),
  at: z.string().datetime(),
  interactions: z.number(),
  executions: z.number(),
  blocked: z.number(),
  human: z.number(),
  unknown: z.number(),
  spend: z.number(),
  risk: z.number(),
});
const metric = z.object({
  key: z.string(),
  label: z.string(),
  value: z.number().finite(),
  prior: z.number().finite(),
  series: z.array(z.number()),
  info: z.string(),
  href: z.string().regex(/^[a-z][a-z0-9-]*(\?[^#]*)?$/),
  source: z.string().min(1),
});
const node = z.object({
  id: z.string(),
  label: z.string(),
  kind: z.enum([
    "human",
    "agent",
    "workload",
    "process",
    "tool",
    "service",
    "action",
    "unknown",
  ]),
  status: z.string().optional(),
  owner: z.string().optional(),
  scope: z.string().optional(),
  at: z.string().datetime(),
  evidence: z.string(),
  confidence: z.number().min(0).max(100).optional(),
});
const edge = z.object({
  source: z.string(),
  target: z.string(),
  label: z.string(),
  relation: z.enum(["observed", "declared", "inferred"]),
  at: z.string().datetime(),
  evidence: z.string(),
});
const listing = z.object({
  graph: z.object({ nodes: z.array(node), edges: z.array(edge) }).optional(),
  meta: z.object({
    mode: z.literal("live"),
    source: z.string().min(1),
    asOf: z.string().datetime(),
    processedAt: z.string().datetime(),
    status: z.string().min(1),
    start: z.string().datetime(),
    end: z.string().datetime(),
    days: z.number(),
    group: z.string(),
    role: z.enum(["Administrator", "Analyst", "Auditor"]),
  }),
  rows: z.array(row),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
  metrics: z.array(metric).optional(),
  trend: z.array(point).optional(),
  stats: z.record(z.number().finite()).optional(),
  summaries: z
    .record(z.array(z.object({ name: z.string(), value: z.number().finite() })))
    .optional(),
  selected: row.optional(),
  references: z.array(row).optional(),
  sensors: z.array(row).optional(),
  groups: z.array(z.string()).optional(),
  facets: z.record(z.array(z.string())).optional(),
});
export async function live(
  req: Request,
  api: string,
  params: URLSearchParams,
  env: Cloudflare.Env,
) {
  if (
    !env.VANIAN_API_ORIGIN ||
    !env.VANIAN_API_TOKEN ||
    !env.VANIAN_LIVE_MEMBERS
  )
    fail(
      503,
      "LIVE_UNCONFIGURED",
      "This workspace has no authenticated live telemetry connection.",
    );
  const uid = req.headers.get("oai-authenticated-user-id");
  if (!uid)
    fail(
      401,
      "SIGN_IN_REQUIRED",
      "Sign in with a provisioned workspace identity.",
    );
  let members: Record<string, { tenant: string; role: Role }>;
  try {
    members = JSON.parse(env.VANIAN_LIVE_MEMBERS);
  } catch {
    fail(
      503,
      "CONFIGURATION_ERROR",
      "Live workspace membership is unavailable.",
    );
  }
  const m = Object.hasOwn(members!, uid!) ? members![uid!] : undefined;
  if (
    !m ||
    !m.tenant ||
    !["Administrator", "Analyst", "Auditor"].includes(m.role)
  )
    fail(
      403,
      "ACCESS_DENIED",
      "This identity has no live workspace membership.",
    );
  const def = byApi[api];
  if (!def || !canRead(def, m.role))
    fail(403, "ACCESS_DENIED", "This resource is unavailable for your role.");
  if (req.method !== "GET")
    fail(
      409,
      "CAPABILITY_UNAVAILABLE",
      "Live mutations require a qualified enforcement connector.",
    );
  const base = new URL(env.VANIAN_API_ORIGIN!);
  if (base.protocol !== "https:" || base.username || base.password)
    fail(
      503,
      "CONFIGURATION_ERROR",
      "The telemetry origin must use an authenticated HTTPS endpoint.",
    );
  const upstream = new URL("/v1/" + api, base);
  for (const [k, v] of params)
    if (
      [
        "days",
        "group",
        "q",
        "sort",
        "dir",
        "size",
        "page",
        "id",
        "tab",
        "view",
        "day",
        "recordKind",
        "agent",
        ...def.filters,
      ].includes(k)
    )
      upstream.searchParams.set(k, v);
  let res: Response;
  try {
    res = await fetch(upstream, {
      // Keep the service credential on the configured origin. The Worker returns redirects for explicit rejection below.
      redirect: "manual",
      headers: {
        Authorization: "Bearer " + env.VANIAN_API_TOKEN,
        "X-Vanian-Tenant": m.tenant,
        "X-Vanian-Role": m.role,
        "X-Vanian-Subject": uid!,
      },
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    fail(
      503,
      "SOURCE_OFFLINE",
      "The authorized telemetry service is unreachable.",
    );
  }
  if (res!.status >= 300 && res!.status < 400)
    fail(
      502,
      "SOURCE_REDIRECT",
      "The configured telemetry endpoint returned a redirect.",
    );
  if (!res!.ok)
    fail(
      res!.status === 403 ? 403 : 503,
      "SOURCE_UNAVAILABLE",
      "The connected source cannot supply this view.",
    );
  if (res!.headers.get("X-Vanian-Tenant") !== m.tenant)
    fail(502, "TENANT_MISMATCH", "The source returned a mismatched tenant.");
  const parsed = listing.safeParse(await res!.json());
  if (!parsed.success || parsed.data.meta.role !== m.role)
    fail(
      502,
      "INVALID_CONTRACT",
      "The source returned incomplete telemetry provenance.",
    );
  const data = parsed.data;
  for (const r of [
    ...data.rows,
    ...(data.references ?? []),
    ...(data.sensors ?? []),
    ...(data.selected ? [data.selected] : []),
  ]) {
    for (const k of Object.keys(r.fields))
      if (/prompt|response|preview|original|secret|content/i.test(k))
        r.fields[k] = "[Redacted by console policy]";
  }
  return data as Bundle;
}
