import { testDataControl } from "./data-controls";
import { z } from "zod";
import { type Entry, guards, actions, groups, type Role } from "../types";
import { byApi } from "../navigation";
import {
  aggregate,
  catalog,
  agentList,
  policyList,
  runRules,
  type Edits,
} from "./aggregate";
import { allEvents, entry, policies, safeCases, rawPrompt } from "./fixtures";
import { exportBatch } from "./verification";
import { fail, save, type Session } from "./access";
const txt = z.string().trim().min(1).max(200);
const rules = z.record(
  z.object({
    enabled: z.boolean(),
    condition: txt,
    action: z.enum(actions),
    response: z.string().max(500),
  }),
);
const edit = z.object({
  name: txt,
  description: z.string().max(600),
  scope: z.enum(["All groups", ...groups] as [string, ...string[]]),
  destination: txt,
  action: z.enum(actions),
  state: z.enum(["Enabled", "Disabled", "Pending approval"]),
  priority: z.number().int().min(1).max(999),
  rules,
});
export async function mutate(
  db: D1Database,
  s: Session,
  api: string,
  input: any,
  edits: Edits,
) {
  const admin = () => {
    if (s.role !== "Administrator")
      fail(403, "ROLE_REQUIRED", "Administrator access is required.");
  };
  const write = () => {
    if (s.role === "Auditor")
      fail(403, "ROLE_REQUIRED", "This role has read-only access.");
  };
  if (api === "session/role") {
    const role = z
      .enum(["Administrator", "Analyst", "Auditor"])
      .parse(input.role);
    await db
      .prepare("UPDATE demo_sessions SET role=? WHERE id=? AND tenant=?")
      .bind(role, s.id, s.tenant)
      .run();
    return { role, scope: "Synthetic tenant only" };
  }
  if (api === "protection/data/test") return testDataControl(input);
  if (api === "evaluation/request") {
    const email = z.string().email().max(240).parse(input.email),
      message = z
        .string()
        .max(500)
        .parse(input.message ?? "");
    return save(
      db,
      s,
      "evaluation",
      entry(
        "REQ-" + crypto.randomUUID(),
        "Guided demo request",
        "All groups",
        "Evaluation workspace",
        "Recorded",
        { contact: email, focus: message },
      ),
      0,
      "Demo request recorded",
    );
  }
  if (api === "content/reveal") {
    admin();
    const e = allEvents().find((x) => x.id === input.id);
    if (!e) fail(404, "NOT_FOUND", "Event unavailable.");
    await db
      .prepare(
        "INSERT INTO workspace_audit (id,tenant,record,actor,action,at,detail) VALUES(?,?,?,?,?,?,?)",
      )
      .bind(
        crypto.randomUUID(),
        s.tenant,
        e.id,
        s.role,
        "Original content viewed",
        new Date().toISOString(),
        "Explicit reveal of synthetic content",
      )
      .run();
    return { content: rawPrompt(e), mode: "demo" };
  }
  if (api === "evidence/verify" || api === "evidence/export") {
    const v = await exportBatch(String(input.id));
    if (!v) fail(404, "NOT_FOUND", "Evidence batch unavailable.");
    return api.endsWith("export")
      ? v
      : {
          id: v.id,
          verified: v.verified,
          digest: v.hash,
          signature: v.signature,
          key: v.publicKey,
          algorithm: v.algorithm,
          checkedAt: new Date().toISOString(),
        };
  }
  const expected = z
    .number()
    .int()
    .min(0)
    .parse(input.version ?? 0);
  const persist = (kind: string, r: Entry, action: string) =>
    save(db, s, kind, r, expected, action);
  if (api === "finops/budget") {
    admin();
    const g = z
      .enum(["All groups", ...groups] as [string, ...string[]])
      .parse(input.group);
    const days = z.number().int().min(1).max(30).parse(input.days);
    const amount = z.number().positive().max(1e9).parse(input.amount);
    const id = "BUD-" + g + days;
    const last = edits.get("budgets/" + id)?.version ?? 0;
    if (expected !== last)
      fail(409, "VERSION_CONFLICT", "Refresh the budget before saving.");
    return save(
      db,
      s,
      "budgets",
      entry(id, "Spend budget", g, "Demo budget registry", "Enabled", {
        amount,
        days,
      }),
      expected,
      "Budget configured",
    );
  }
  if (api === "policies/reorder") {
    admin();
    const direction = z.enum(["up", "down"]).parse(input.direction);
    const list = policyList(edits);
    const pos = list.findIndex((r) => r.id === input.id),
      target = pos + (direction === "up" ? -1 : 1);
    if (pos < 0 || target < 0 || target >= list.length)
      fail(
        422,
        "INVALID_POSITION",
        "This policy cannot move further in that direction.",
      );
    const version = edits.get("ordering/policies")?.version ?? 0;
    if (expected !== version)
      fail(
        409,
        "VERSION_CONFLICT",
        "Policy order changed. Refresh to reorder.",
      );
    const ids = list.map((r) => r.id);
    [ids[pos], ids[target]] = [ids[target], ids[pos]];
    return save(
      db,
      s,
      "ordering",
      entry(
        "policies",
        "Policy order",
        "All groups",
        "Policy registry",
        "Applied",
        { ids: ids.join(",") },
      ),
      expected,
      "Policy order updated",
    );
  }
  if (api === "policies/simulate") {
    const p = policyList(edits).find((x) => x.id === input.id);
    if (!p) fail(404, "NOT_FOUND", "Policy unavailable.");
    return runRules(
      p,
      String(input.condition),
      String(input.group ?? "Engineering"),
      String(input.app ?? "Claude"),
    );
  }
  if (api === "policies") {
    admin();
    const list = policyList(edits);
    const prior = list.find((x) => x.id === input.id);
    if (input.id && !prior) fail(404, "NOT_FOUND", "Policy unavailable.");
    if (prior && expected !== prior.version)
      fail(409, "VERSION_CONFLICT", "Refresh the policy before saving.");
    const old =
      prior ??
      entry(
        "POL-" + crypto.randomUUID().slice(0, 8),
        "New policy",
        "All groups",
        "Demo policy registry",
        "Disabled",
        {},
      );
    let next: Entry = structuredClone(old);
    let change = "Policy updated";
    const now = new Date().toISOString();
    if (input.op === "duplicate") {
      const newId = "POL-" + crypto.randomUUID().slice(0, 8);
      return save(
        db,
        s,
        "policies",
        {
          ...next,
          id: newId,
          name: next.name + " (copy)",
          state: "Disabled",
          at: now,
          history: [
            {
              version: 1,
              at: now,
              actor: s.role,
              change: "Duplicated " + old.id,
            },
          ],
        },
        0,
        "Policy duplicated",
      );
    }
    if (input.op === "rollback") {
      const history = JSON.parse(String(old.fields.snapshots ?? "{}"));
      const previous = history[String(input.target)];
      if (!previous)
        fail(
          400,
          "INVALID_VERSION",
          "No rollback snapshot exists for that revision.",
        );
      next = {
        ...old,
        ...previous,
        fields: { ...previous.fields, snapshots: old.fields.snapshots ?? "{}" },
      };
      change = "Rolled back to v" + input.target;
    } else if (input.op === "approve") {
      if (old.state !== "Pending approval")
        fail(409, "INVALID_STATE", "Submit the policy for approval first.");
      next.state = "Enabled";
      change = "Demo approval recorded";
    } else {
      const v = edit.parse(input.record);
      if (Object.keys(v.rules).some((k) => !guards.includes(k)))
        fail(422, "INVALID_RULE", "Unknown guardrail.");
      next = {
        ...old,
        name: v.name,
        state: v.state,
        rules: v.rules,
        fields: {
          ...old.fields,
          description: v.description,
          priority: v.priority,
          scope: v.scope,
          destination: v.destination,
          action: v.action,
          enforcement: "Simulated",
        },
      };
      change = prior
        ? v.state === "Pending approval"
          ? "Submitted for approval"
          : "Policy updated"
        : "Created policy";
    }
    const savedFields = { ...old.fields };
    delete savedFields.snapshots;
    const versions = JSON.parse(String(old.fields.snapshots ?? "{}"));
    if (prior)
      versions[String(expected)] = {
        name: old.name,
        state: old.state,
        fields: savedFields,
        rules: old.rules,
      };
    next.fields.snapshots = JSON.stringify(versions);
    next.at = now;
    next.history = [
      ...(old.history ?? []),
      { version: expected + 1, at: now, actor: s.role, change },
    ];
    return persist("policies", next, change);
  }
  if (api === "discovery/apps") {
    admin();
    const r = catalog(edits).find((x) => x.id === input.id);
    if (!r) fail(404, "NOT_FOUND", "Application unavailable.");
    if (expected !== (r.version ?? 1))
      fail(409, "VERSION_CONFLICT", "Application version changed.");
    return persist(
      "apps",
      {
        ...r,
        state: z
          .enum(["Approved", "Restricted", "Blocked", "Unknown"])
          .parse(input.state),
        fields: {
          ...r.fields,
          risk: z.enum(["Critical", "High", "Medium", "Low"]).parse(input.risk),
          category: txt.parse(input.category),
          policy: txt.parse(input.policy),
        },
      },
      "Application reviewed",
    );
  }
  if (api === "identity") {
    admin();
    const r = agentList(edits).find((x) => x.id === input.id);
    if (!r) fail(404, "NOT_FOUND", "Agent unavailable.");
    if (expected !== (r.version ?? 1))
      fail(409, "VERSION_CONFLICT", "Identity version changed.");
    return persist(
      "agents",
      {
        ...r,
        fields: {
          ...r.fields,
          scope: txt.parse(input.scope),
          authorization: "Configured · simulated",
        },
      },
      "Delegation scope edited",
    );
  }
  if (api === "alerts") {
    write();
    const q = new URLSearchParams({ id: txt.parse(input.id), days: "30" });
    const result = await aggregate(byApi.alerts, q, s.role, edits);
    const r = result.selected;
    if (!r) fail(404, "NOT_FOUND", "Alert unavailable.");
    if (expected !== (r.version ?? 1))
      fail(409, "VERSION_CONFLICT", "Investigation version changed.");
    const note = z
      .string()
      .trim()
      .max(1500)
      .parse(input.note ?? "");
    return persist(
      "alerts",
      {
        ...r,
        state: z.enum(["Open", "In review", "Resolved"]).parse(input.state),
        fields: {
          ...r.fields,
          assignee: z
            .enum(["Unassigned", "Maya Chen", "Arjun Rao", "SOC queue"])
            .parse(input.assignee),
        },
        notes: [
          ...(r.notes ?? []),
          ...(note
            ? [{ text: note, actor: s.role, at: new Date().toISOString() }]
            : []),
        ],
      },
      "Investigation updated",
    );
  }
  if (api === "red-teaming") {
    write();
    const n = Number(String(input.id).replace("TEST-", ""));
    const c = safeCases[n];
    if (!c) fail(404, "NOT_FOUND", "Check unavailable.");
    const p = policyList(edits).find(
      (x) => x.id === policies[n % policies.length].id,
    )!;
    const actual = runRules(p, c[0], "Engineering", "Claude");
    const old = edits.get("assessments/TEST-" + n);
    const r = entry(
      "TEST-" + n,
      c[0],
      "All groups",
      "Benign policy test",
      actual.action === c[2] ? "Passed" : "Review required",
      {
        guardrail: c[1],
        expected: c[2],
        actual: actual.action,
        scope: "Isolated policy simulator",
        target: p.name,
        risk: "Medium",
        evidence: JSON.stringify(actual),
        remediation: "Compare the expected decision to current policy scope.",
      },
      new Date().toISOString(),
    );
    r.history = [
      ...(old?.history ?? []),
      {
        version: expected + 1,
        at: r.at,
        actor: s.role,
        change: r.state + " · " + actual.action,
      },
    ];
    return persist("assessments", r, "Policy regression check");
  }
  fail(404, "NOT_FOUND", "Unknown operation.");
}
