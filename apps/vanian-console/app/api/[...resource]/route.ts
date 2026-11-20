import { env } from "cloudflare:workers";
import { ZodError } from "zod";
import { canRead, byApi } from "../../../src/navigation";
import { aggregate } from "../../../src/server/aggregate";
import {
  changes,
  mutationBody,
  fail,
  getAudit,
  HttpFault,
  session,
} from "../../../src/server/access";
import { live } from "../../../src/server/live";
import { observationStream } from "../../../src/server/stream";
import { mutate } from "../../../src/server/mutations";
export const dynamic = "force-dynamic";
async function handle(req: Request) {
  let cookie: string | undefined;
  const response = (obj: unknown, status = 200) =>
    Response.json(obj, {
      status,
      headers: {
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        ...(cookie ? { "Set-Cookie": cookie } : {}),
      },
    });
  try {
    const u = new URL(req.url),
      api = u.pathname.replace(/^\/api\//, "").replace(/\/$/, ""),
      mode = u.searchParams.get("mode") || "demo";
    if (!["demo", "live"].includes(mode))
      fail(400, "INVALID_MODE", "Unknown workspace mode.");
    if (mode === "live") {
      if (api === "snifferdog/stream" && req.method === "GET")
        return await observationStream(req, u.searchParams, env);
      return response(await live(req, api, u.searchParams, env));
    }
    if (!env.DB)
      fail(503, "STORE_UNAVAILABLE", "Workspace storage is unavailable.");
    const body = req.method === "POST" ? await mutationBody(req) : undefined;
    const s = await session(req, env.DB!);
    cookie = s.cookie;
    if (req.method === "GET" && api === "session")
      return response({ role: s.role, mode: "demo" });
    const edits = await changes(env.DB!, s.tenant);
    if (body !== undefined)
      return response(await mutate(env.DB!, s, api, body, edits));
    const def = byApi[api];
    if (!def) fail(404, "NOT_FOUND", "Unknown resource.");
    if (!canRead(def, s.role))
      fail(403, "ROLE_REQUIRED", "This view requires administrator access.");
    const b = await aggregate(
      def,
      u.searchParams,
      s.role,
      edits,
      api === "audit" ? await getAudit(env.DB!, s.tenant) : [],
    );
    for (const row of [...b.rows, ...(b.selected ? [b.selected] : [])])
      if (row.fields.snapshots) {
        row.fields = {
          ...row.fields,
          rollbackVersions: Object.keys(
            JSON.parse(String(row.fields.snapshots)),
          ).join(", "),
        };
        delete row.fields.snapshots;
      }
    return response(b);
  } catch (e) {
    if (e instanceof HttpFault)
      return response(
        { error: { code: e.code, message: e.message } },
        e.status,
      );
    if (e instanceof ZodError)
      return response(
        {
          error: {
            code: "INVALID_INPUT",
            message: "One or more fields are invalid.",
          },
        },
        422,
      );
    console.error(
      "VANIAN request error",
      e instanceof Error ? e.message : "unexpected error",
    );
    return response(
      {
        error: {
          code: "PROCESSING_FAILED",
          message: "The source could not process this request.",
        },
      },
      500,
    );
  }
}
export const GET = handle;
export const POST = handle;
