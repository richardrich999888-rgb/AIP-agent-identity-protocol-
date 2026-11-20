import type { Role, Entry } from "../types";
import type { Edits } from "./aggregate";
export class HttpFault extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}
export function fail(status: number, code: string, message: string): never {
  throw new HttpFault(status, code, message);
}
export interface Session {
  subject: string;
  tenant: string;
  role: Role;
  cookie?: string;
  id: string;
}
export async function session(req: Request, db: D1Database): Promise<Session> {
  const id =
    (req.headers.get("cookie") ?? "").match(
      /(?:^|;\s*)vanian_session=([\da-f-]{36})(?:;|$)/,
    )?.[1] ?? "";
  const uid = req.headers.get("oai-authenticated-user-id") || "";
  const userTenant = uid ? "demo:user:" + uid : "";
  if (id) {
    const row = await db
      .prepare(
        "SELECT tenant, role FROM demo_sessions WHERE id=? AND expires>?",
      )
      .bind(id, Date.now())
      .first<{ tenant: string; role: Role }>();
    if (
      row &&
      ((userTenant && row.tenant === userTenant) ||
        (!userTenant && row.tenant.startsWith("demo:browser:")))
    )
      return {
        subject: uid || "Demo operator",
        tenant: row.tenant,
        role: row.role,
        id,
      };
  }
  const token = crypto.randomUUID(),
    tenant = userTenant || "demo:browser:" + crypto.randomUUID(),
    role: Role = "Administrator";
  await db
    .prepare(
      "INSERT INTO demo_sessions(id,tenant,role,expires) VALUES(?,?,?,?)",
    )
    .bind(token, tenant, role, Date.now() + 86400000 * 14)
    .run();
  return {
    subject: uid || "Demo operator",
    tenant,
    role,
    id: token,
    cookie:
      "vanian_session=" +
      token +
      "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=1209600",
  };
}
export async function changes(db: D1Database, tenant: string): Promise<Edits> {
  const got = await db
    .prepare("SELECT kind,id,payload FROM workspace_changes WHERE tenant=?")
    .bind(tenant)
    .all<{ kind: string; id: string; payload: string }>();
  return new Map(
    got.results.map((r) => [
      r.kind + "/" + r.id,
      JSON.parse(r.payload) as Entry,
    ]),
  );
}
export async function getAudit(
  db: D1Database,
  tenant: string,
): Promise<Entry[]> {
  const got = await db
    .prepare(
      "SELECT * FROM workspace_audit WHERE tenant=? ORDER BY at DESC LIMIT 1000",
    )
    .bind(tenant)
    .all<{
      id: string;
      action: string;
      at: string;
      actor: string;
      record: string;
      detail: string;
    }>();
  return got.results.map((r) => ({
    id: r.id,
    name: r.action,
    at: r.at,
    source: "Workspace audit log",
    state: "Recorded",
    group: "All groups",
    fields: { actor: r.actor, record: r.record, detail: r.detail },
  }));
}
export async function save(
  db: D1Database,
  s: Session,
  kind: string,
  v: Entry,
  expected: number,
  action: string,
) {
  const now = new Date().toISOString(),
    revision = expected + 1;
  const payload = JSON.stringify({ ...v, version: revision });
  const record = db
    .prepare(
      "INSERT INTO workspace_changes(tenant,kind,id,version,payload,modified) SELECT ?,?,?,?,?,? WHERE (EXISTS(SELECT 1 FROM workspace_changes WHERE tenant=? AND kind=? AND id=? AND version=?) OR (? IN (0,1) AND NOT EXISTS(SELECT 1 FROM workspace_changes WHERE tenant=? AND kind=? AND id=?))) ON CONFLICT(tenant,kind,id) DO UPDATE SET version=excluded.version,payload=excluded.payload,modified=excluded.modified WHERE workspace_changes.version=?",
    )
    .bind(
      s.tenant,
      kind,
      v.id,
      revision,
      payload,
      now,
      s.tenant,
      kind,
      v.id,
      expected,
      expected,
      s.tenant,
      kind,
      v.id,
      expected,
    );
  const audit = db
    .prepare(
      "INSERT INTO workspace_audit(id,tenant,record,actor,action,at,detail) SELECT ?,?,?,?,?,?,? WHERE changes()=1",
    )
    .bind(
      crypto.randomUUID(),
      s.tenant,
      v.id,
      s.role,
      action,
      now,
      "Version " + revision,
    );
  const result = await db.batch([record, audit]);
  if (result[0].meta.changes !== 1)
    fail(
      409,
      "VERSION_CONFLICT",
      "This record changed. Refresh it before saving.",
    );
  return { ...v, version: revision };
}
export function checkOrigin(req: Request) {
  const origin = req.headers.get("origin");
  if (origin && origin !== new URL(req.url).origin)
    fail(
      403,
      "ORIGIN_DENIED",
      "This action requires the same workspace origin.",
    );
  if (!req.headers.get("content-type")?.startsWith("application/json"))
    fail(415, "JSON_REQUIRED", "Send an application/json request.");
}

const maxMutationBytes = 64_000;

export async function mutationBody(req: Request) {
  if (Number(req.headers.get("Content-Length")) > maxMutationBytes)
    fail(413, "BODY_TOO_LARGE", "The change exceeds the request limit.");
  const reader = req.body?.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let body = "",
    bytes = 0;
  if (reader) {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > maxMutationBytes) {
          await reader.cancel();
          fail(413, "BODY_TOO_LARGE", "The change exceeds the request limit.");
        }
        body += decoder.decode(value, { stream: true });
      }
      body += decoder.decode();
    } catch (error) {
      if (error instanceof HttpFault) throw error;
      fail(400, "INVALID_BODY", "Use a complete UTF-8 request body.");
    } finally {
      reader.releaseLock();
    }
  }
  // Consume a bounded request before replying to keep a reused HTTP connection synchronized.
  checkOrigin(req);
  let data: unknown;
  try {
    data = JSON.parse(body);
  } catch {
    fail(400, "INVALID_JSON", "Invalid request body.");
  }
  if (!data || typeof data !== "object" || Array.isArray(data))
    fail(422, "INVALID_INPUT", "Send a JSON object containing the change.");
  return data as Record<string, unknown>;
}
