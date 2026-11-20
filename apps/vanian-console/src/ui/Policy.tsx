"use client";
import { useState, useEffect } from "react";
import { guards, groups, actions, type Entry, type Rule } from "../types";
import { useDesk, request } from "./context";
import { Badge, DataPairs, Field, I, Layer, Select, stamp } from "./primitives";
import { Empty } from "./primitives";
const blank = () =>
  Object.fromEntries(
    guards.map((g) => [
      g,
      {
        enabled: false,
        condition: "Requires review",
        action: "Warn",
        response: "Request requires review.",
      },
    ]),
  );
export function PolicyEditor({
  row,
  close,
}: {
  row: Entry | null;
  close: () => void;
}) {
  const d = useDesk(),
    [tab, T] = useState("General"),
    [name, N] = useState(row?.name ?? ""),
    [desc, D] = useState(String(row?.fields.description ?? "")),
    [scope, Sc] = useState(String(row?.fields.scope ?? "All groups")),
    [dest, De] = useState(
      String(row?.fields.destination ?? "All applications"),
    ),
    [action, A] = useState(String(row?.fields.action ?? "Warn")),
    [state, St] = useState(row?.state ?? "Disabled"),
    [prio, Pr] = useState(
      Number(row?.fields.priority ?? (d.data?.total ?? 0) + 1),
    ),
    [rules, R] = useState<Record<string, Rule>>(row?.rules ?? blank()),
    [cond, C] = useState(""),
    [testGroup, TG] = useState("Engineering"),
    [testApp, TA] = useState("Claude"),
    [result, Res] = useState(""),
    [busy, B] = useState(false),
    [err, E] = useState("");
  const can = d.mode === "demo" && d.role === "Administrator";
  const record = () => ({
    name,
    description: desc,
    scope,
    destination: dest,
    action,
    state,
    priority: prio,
    rules,
  });
  async function act(op: string, target?: number) {
    B(true);
    E("");
    try {
      await request("policies", d.mode, d.params, {
        id: row?.id,
        version: row?.version ?? 0,
        op,
        target,
        record: record(),
      });
      d.refresh();
      d.toast(
        op === "rollback"
          ? "Earlier configuration restored"
          : "Policy change saved",
      );
      close();
    } catch (e) {
      E((e as Error).message);
    } finally {
      B(false);
    }
  }
  const categories = [
    "General",
    "Sources & destinations",
    "Guardrails",
    "Simulation",
    "Version history",
  ];
  const change = (key: string, k: keyof Rule, v: string | boolean) =>
    R({ ...rules, [key]: { ...rules[key], [k]: v } });
  return (
    <Layer title={row ? "Policy editor" : "Create policy"} wide close={close}>
      <div className="editor-heading">
        <Badge kind="violet">Demo policy registry</Badge>
        <h3>{name || "Untitled policy"}</h3>
        <p>
          {row?.id ?? "New record"} · {row ? "Version " + row.version : "Draft"}{" "}
          · Simulated decisions
        </p>
      </div>
      <div className="policy-editor">
        <aside>
          {categories.map((t) => (
            <button
              className={t === tab ? "on" : ""}
              key={t}
              onClick={() => T(t)}
            >
              {t}
              <I n="right" size={13} />
            </button>
          ))}
        </aside>
        <div className="editor-form">
          <h3>{tab}</h3>
          {tab === "General" && (
            <>
              <Field label="Policy name">
                <input
                  maxLength={200}
                  value={name}
                  onChange={(e) => N(e.target.value)}
                  readOnly={!can}
                />
              </Field>
              <Field label="Description">
                <textarea
                  value={desc}
                  onChange={(e) => D(e.target.value)}
                  readOnly={!can}
                />
              </Field>
              <div className="form-grid">
                <Field label="Priority">
                  <input
                    type="number"
                    min={1}
                    max={999}
                    value={prio}
                    onChange={(e) => Pr(Number(e.target.value))}
                    readOnly={!!row || !can}
                    title="Use the policy list controls to change the order"
                  />
                </Field>
                <Field label="Default action">
                  <Select
                    label="Default action"
                    value={action}
                    options={[...actions]}
                    onChange={A}
                  />
                </Field>
              </div>
              <Field label="State">
                <Select
                  label="Policy state"
                  value={state}
                  options={["Enabled", "Disabled", "Pending approval"]}
                  onChange={St}
                />
              </Field>
            </>
          )}
          {tab === "Sources & destinations" && (
            <>
              <Field label="Source scope">
                <Select
                  label="Source scope"
                  options={["All groups", ...groups]}
                  value={scope}
                  onChange={Sc}
                />
              </Field>
              <Field label="Destination application">
                <input
                  value={dest}
                  onChange={(e) => De(e.target.value)}
                  readOnly={!can}
                  list="dest-suggestions"
                />
                <datalist id="dest-suggestions">
                  <option>All applications</option>
                  <option>Claude</option>
                  <option>ChatGPT</option>
                </datalist>
              </Field>
            </>
          )}
          {tab === "Guardrails" &&
            guards.map((g) => {
              const rule = rules[g] ?? blank()[g];
              return (
                <details key={g} className="guard">
                  <summary>
                    {g}
                    <Badge>{rule.enabled ? "Enabled" : "Disabled"}</Badge>
                  </summary>
                  <label className="checkrow">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={(e) => change(g, "enabled", e.target.checked)}
                      disabled={!can}
                    />
                    Enable this guardrail
                  </label>
                  <Field label="Matching condition">
                    <input
                      value={rule.condition}
                      onChange={(e) => change(g, "condition", e.target.value)}
                      readOnly={!can}
                    />
                  </Field>
                  <Field label="Enforcement action">
                    <Select
                      value={rule.action}
                      onChange={(v) => change(g, "action", v)}
                      options={[...actions]}
                      label="Guardrail action"
                    />
                  </Field>
                  <Field label="Custom response">
                    <textarea
                      value={rule.response}
                      onChange={(e) => change(g, "response", e.target.value)}
                      readOnly={!can}
                    />
                  </Field>
                </details>
              );
            })}
          {tab === "Simulation" && (
            <>
              <p className="muted">
                Evaluate the saved policy against a labeled, benign test
                condition.
              </p>
              <Field label="Condition">
                <Select
                  value={cond}
                  onChange={C}
                  options={[
                    ["", "Select a condition"],
                    ...Object.values(rules)
                      .map((r) => r.condition)
                      .filter((x, i, a) => a.indexOf(x) === i),
                  ]}
                  label="Test condition"
                />
              </Field>
              <Field label="Test group">
                <Select
                  label="Test group"
                  value={testGroup}
                  options={groups}
                  onChange={TG}
                />
              </Field>
              <Field label="Test application">
                <input value={testApp} onChange={(e) => TA(e.target.value)} />
              </Field>
              <button
                className="btn"
                disabled={!row || !cond || busy}
                onClick={async () => {
                  try {
                    const r = await request(
                      "policies/simulate",
                      d.mode,
                      d.params,
                      {
                        id: row?.id,
                        condition: cond,
                        app: testApp,
                        group: testGroup,
                      },
                    );
                    Res(r.action + " · " + r.matched + " · " + r.enforcement);
                  } catch (e) {
                    E((e as Error).message);
                  }
                }}
              >
                <I n="play" size={14} />
                Simulate
              </button>
              {result && (
                <p className="notice" role="status">
                  {result}
                </p>
              )}
            </>
          )}
          {tab === "Version history" &&
            (row?.history ?? [])
              .slice()
              .reverse()
              .map((h) => (
                <div key={h.version} className="version">
                  <b>
                    v{h.version} · {h.change}
                  </b>
                  <small>
                    {stamp(h.at, true)} · {h.actor}
                  </small>
                  {can && h.version !== (row?.version ?? 0) && (
                    <button
                      className="text-btn"
                      disabled={busy}
                      onClick={() => act("rollback", h.version)}
                    >
                      Restore this version
                    </button>
                  )}
                </div>
              ))}
        </div>
      </div>
      {err && (
        <p role="alert" className="error-msg">
          {err}
        </p>
      )}
      <div className="layer-foot">
        <button className="btn" onClick={close}>
          Close
        </button>
        {row && can && (
          <button
            className="btn"
            disabled={busy}
            onClick={() => act("duplicate")}
          >
            Duplicate
          </button>
        )}
        {can && row?.state === "Pending approval" && (
          <button className="btn" onClick={() => act("approve")}>
            Approve in demo
          </button>
        )}
        {can && (
          <button
            className="btn primary"
            disabled={!name.trim() || busy}
            onClick={() => act("save")}
          >
            Save policy
          </button>
        )}
      </div>
    </Layer>
  );
}
export function PolicyList() {
  const d = useDesk(),
    [editor, E] = useState<Entry | null | undefined>(undefined),
    [q, Q] = useState("");
  const b = d.data!;
  const rows = b.rows;
  const [moving, Move] = useState(false);
  useEffect(() => {
    const value = d.params.get("q") ?? "";
    if (value === q) return;
    const t = setTimeout(() => d.set({ q: q || null, page: null }), 250);
    return () => clearTimeout(t);
  }, [q, d.params.get("q"), d.set]);
  const change = async (r: Entry, dir: string) => {
    Move(true);
    try {
      await request("policies/reorder", d.mode, d.params, {
        id: r.id,
        direction: dir,
        version: b.stats?.orderVersion ?? 0,
      });
      d.refresh();
      d.toast("Policy priority updated");
    } catch (e) {
      d.toast((e as Error).message);
    } finally {
      Move(false);
    }
  };
  return (
    <>
      <div className="module-tools" data-tour="records">
        <label className="searchbox">
          <I n="search" size={15} />
          <input
            placeholder="Search policies…"
            aria-label="Search policies"
            value={q}
            onChange={(e) => Q(e.target.value)}
          />
        </label>
        {d.role === "Administrator" && d.mode === "demo" && (
          <button className="btn primary" onClick={() => E(null)}>
            <I n="plus" size={15} />
            Create policy
          </button>
        )}
      </div>
      <div className="policy-list">
        {rows.map((r, i) => (
          <div className="policy-arrange" key={r.id}>
            <button className="policy-row" onClick={() => E(r)}>
              <span className="order">{r.fields.priority}</span>
              <span className="policy-copy">
                <b>{r.name}</b>
                <small>
                  {r.fields.scope} <I n="right" size={11} />{" "}
                  {r.fields.destination} ·{" "}
                  {Object.values(r.rules ?? {}).filter((x) => x.enabled).length}{" "}
                  guardrails
                </small>
              </span>
              <span className="mono">v{r.version}</span>
              <Badge>{r.fields.action}</Badge>
              <Badge dot>{r.state}</Badge>
              <I n="right" size={16} />
            </button>
            {d.role === "Administrator" && (
              <div className="order-controls">
                <button
                  className="icon-btn"
                  aria-label={"Move " + r.name + " up"}
                  disabled={moving || (b.page === 1 && i === 0)}
                  onClick={() => change(r, "up")}
                >
                  <I n="down" size={13} className="rotate" />
                </button>
                <button
                  className="icon-btn"
                  aria-label={"Move " + r.name + " down"}
                  disabled={
                    moving || (b.page - 1) * b.pageSize + i + 1 >= b.total
                  }
                  onClick={() => change(r, "down")}
                >
                  <I n="down" size={13} />
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
      {b.total > b.pageSize && (
        <div className="pager">
          <span>
            Page {b.page} of {Math.ceil(b.total / b.pageSize)}
          </span>
          <div>
            <button
              className="btn"
              disabled={b.page === 1}
              onClick={() => d.set({ page: String(b.page - 1) })}
            >
              Previous
            </button>
            <button
              className="btn"
              disabled={b.page * b.pageSize >= b.total}
              onClick={() => d.set({ page: String(b.page + 1) })}
            >
              Next
            </button>
          </div>
        </div>
      )}
      {!rows.length && <Empty />}
      {editor !== undefined && (
        <PolicyEditor row={editor} close={() => E(undefined)} />
      )}
    </>
  );
}
