"use client";
import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { type Bundle, type Entry } from "../types";
import { bySlug } from "../navigation";
import { pretty } from "../product";
import { useDesk, request } from "./context";
import {
  Badge,
  DataPairs,
  Field,
  I,
  Layer,
  Loading,
  Select,
  saveFile,
  stamp,
} from "./primitives";
import { Topology } from "./visual/Topology";
import { EvidenceSeal } from "./visual/EvidenceSeal";
import { AlertContext } from "./AlertContext";
import { PolicyEditor } from "./Policy";
export default function Detail({
  row,
  slug,
  close,
}: {
  row: Entry;
  slug: string;
  close: () => void;
}) {
  const d = useDesk(),
    p = bySlug[slug],
    q = new URLSearchParams(d.params);
  q.set("id", row.id);
  const [revision, U] = useState(0),
    query = useQuery({
      queryKey: ["detail", p.api, row.id, d.mode, q.toString(), revision],
      queryFn: () => request<Bundle>(p.api, d.mode, q),
      retry: false,
    });
  const r = query.data?.selected ?? row;
  const [note, N] = useState(""),
    [status, St] = useState(r.state),
    [assignee, As] = useState(String(r.fields.assignee ?? "Unassigned")),
    [newRisk, Ri] = useState(String(r.fields.risk ?? "Low")),
    [category, Ca] = useState(String(r.fields.category ?? "Other")),
    [policy, Po] = useState(String(r.fields.policy ?? "Corporate AI usage")),
    [scope, Sc] = useState(String(r.fields.scope ?? "")),
    [proof, P] = useState<any>(null),
    [raw, Raw] = useState(""),
    [busy, B] = useState(false),
    [error, E] = useState(""),
    [tab, T] = useState("Overview"),
    [policyEdit, PE] = useState<Entry | null>(null);
  const isAlert = r.id.startsWith("ALT-"),
    isApp = r.id.startsWith("APP-"),
    isAgent = r.id.startsWith("AGT-"),
    isGuard = r.fields.policyId,
    isEvidence = r.id.startsWith("B-"),
    isConv = r.id.startsWith("CNV-"),
    isExec = r.id.startsWith("EV-"),
    isTest = r.id.startsWith("TEST-");
  const batch = r.fields.batch || (isEvidence ? r.id : "");
  const canEdit = d.mode === "demo" && d.role === "Administrator",
    canCase = d.mode === "demo" && d.role !== "Auditor";
  async function job(f: () => Promise<void>) {
    B(true);
    E("");
    try {
      await f();
    } catch (e) {
      E((e as Error).message);
    } finally {
      B(false);
    }
  }
  async function persist(api: string, input: object) {
    await request(api, d.mode, d.params, {
      id: r.id,
      version: r.version ?? 1,
      ...input,
    });
    U((n) => n + 1);
    d.refresh();
    d.toast("Change saved to the demo workspace");
  }
  const act = async () => {
    if (isAlert) {
      await persist("alerts", { note, state: status, assignee });
      N("");
    } else if (isApp)
      await persist("discovery/apps", {
        state: status,
        risk: newRisk,
        category,
        policy,
      });
    else if (isAgent) await persist("identity", { scope });
  };
  const ts = query.data?.timeline ?? [];
  const overviewKeys =
    isAlert || isConv || isExec
      ? [
          "intent",
          "risk",
          "decision",
          "enforcement",
          "policy",
          "policyVersion",
          "guardrail",
          "actor",
          "app",
          "model",
          "agent",
          "parent",
          "owner",
          "workload",
          "tool",
          "sensor",
          "confidence",
          "correlation",
          "trace",
          "batch",
        ]
      : Object.keys(r.fields).filter(
          (k) =>
            ![
              "snapshots",
              "raw",
              "preview",
              "response",
              "rules",
              "rollbackVersions",
            ].includes(k),
        );
  const exportRecord = () =>
    saveFile(
      "vanian-" + d.mode + "-" + r.id.replaceAll("/", "-") + ".json",
      JSON.stringify(
        {
          mode: d.mode,
          source: r.source,
          snapshot: query.data?.meta.asOf,
          processedAt: query.data?.meta.processedAt,
          status: query.data?.meta.status,
          record: r,
          related: query.data?.references ?? [],
          timeline: ts,
        },
        null,
        2,
      ),
    );
  return (
    <Layer
      drawer
      title={
        isAlert
          ? "Alert investigation"
          : isConv
            ? "Conversation forensics"
            : isEvidence
              ? "Execution evidence"
              : "Record details"
      }
      close={close}
    >
      <div className="drawer-body">
        <div className="detail-hero">
          <div>
            <Badge kind="violet">
              {d.mode === "demo" ? "Simulation" : "Live telemetry"}
            </Badge>{" "}
            <Badge dot>{r.state}</Badge>{" "}
            {isAlert && r.fields.risk && <Badge>{r.fields.risk}</Badge>}
          </div>
          <h2>{r.name}</h2>
          <p className="mono">
            {r.id} · {stamp(r.at, true)}
          </p>
        </div>
        {query.isError && (
          <p role="alert" className="error-msg">
            {query.error.message}
          </p>
        )}
        <div className="tabs">
          {[
            "Overview",
            "Evidence",
            ...(isAlert || isAgent || isApp || isConv || isExec
              ? ["Timeline"]
              : []),
            ...(isAlert ? ["Correlation", "Case notes"] : []),
          ].map((t) => (
            <button
              className={t === tab ? "on" : ""}
              key={t}
              onClick={() => T(t)}
            >
              {t}
            </button>
          ))}
        </div>
        {tab === "Overview" && (
          <>
            {isAlert ? (
              <AlertContext record={r} />
            ) : (
              <section>
                <h3>Record context</h3>
                <DataPairs
                  items={[
                    ["Source", r.source],
                    ["Group", r.group],
                    ["Observed at", stamp(r.at, true)],
                    ...overviewKeys
                      .filter((k) => r.fields[k] !== undefined)
                      .map(
                        (k) =>
                          [
                            k === "confidence"
                              ? "Attribution confidence"
                              : pretty(k),
                            k === "confidence" &&
                            typeof r.fields[k] === "number"
                              ? r.fields[k] + "%"
                              : String(r.fields[k]),
                          ] as [string, string],
                      ),
                  ]}
                />
              </section>
            )}
            {(isConv || isAlert) && (
              <section>
                <h3>Interaction content</h3>
                <small className="muted">Policy-masked preview</small>
                <blockquote>
                  {raw || r.fields.preview || "No permitted prompt."}
                </blockquote>
                <p>{r.fields.response}</p>
                {canEdit && !raw && (
                  <button
                    className="btn small"
                    onClick={() =>
                      job(async () => {
                        const v = await request(
                          "content/reveal",
                          d.mode,
                          d.params,
                          { id: r.fields.event },
                        );
                        Raw(v.content);
                      })
                    }
                  >
                    Reveal synthetic original
                  </button>
                )}
              </section>
            )}
            {isApp && canEdit && (
              <section>
                <h3>Catalog controls</h3>
                <div className="form-grid">
                  <Field label="Approval">
                    <Select
                      value={status}
                      options={["Approved", "Restricted", "Blocked", "Unknown"]}
                      onChange={St}
                      label="Approval"
                    />
                  </Field>
                  <Field label="Risk">
                    <Select
                      value={newRisk}
                      options={["Low", "Medium", "High", "Critical"]}
                      onChange={Ri}
                      label="Risk"
                    />
                  </Field>
                </div>
                <Field label="Category">
                  <input
                    value={category}
                    onChange={(e) => Ca(e.target.value)}
                  />
                </Field>
                <Field label="Access policy">
                  <input value={policy} onChange={(e) => Po(e.target.value)} />
                </Field>
                <button
                  className="btn primary"
                  disabled={busy}
                  onClick={() => job(act)}
                >
                  Save application
                </button>
              </section>
            )}
            {isAgent && canEdit && (
              <section>
                <h3>Delegated permissions</h3>
                <Field label="Authorized capability">
                  <input value={scope} onChange={(e) => Sc(e.target.value)} />
                </Field>
                <button
                  className="btn"
                  disabled={busy || !scope.trim()}
                  onClick={() => job(act)}
                >
                  Save scope
                </button>
              </section>
            )}
            {isGuard && canEdit && (
              <button
                className="btn"
                onClick={() =>
                  job(async () => {
                    const qp = new URLSearchParams(d.params);
                    qp.set("id", String(isGuard));
                    const v = await request<Bundle>("policies", d.mode, qp);
                    if (v.selected) PE(v.selected);
                  })
                }
              >
                Configure in policy editor
              </button>
            )}
            {isTest && canCase && (
              <section>
                <h3>Scoped assessment</h3>
                <p>
                  Evaluate this predefined condition against the saved demo
                  policy.
                </p>
                <button
                  className="btn"
                  disabled={busy}
                  onClick={() => job(() => persist("red-teaming", {}))}
                >
                  <I n="play" size={14} />
                  Run policy check
                </button>
                {r.history?.map((h) => (
                  <small key={h.version} className="block">
                    {stamp(h.at)} · {h.change}
                  </small>
                ))}
              </section>
            )}
          </>
        )}
        {tab === "Correlation" && (
          <section>
            <h3>Threat correlation map</h3>
            {query.data?.graph ? (
              <Topology
                title="Detection relationships"
                nodes={query.data.graph.nodes}
                edges={query.data.graph.edges}
              />
            ) : (
              <p className="muted">
                No evidence-linked relationships supplied.
              </p>
            )}
          </section>
        )}
        {tab === "Evidence" && (
          <section>
            <h3>Evidence chain</h3>
            <DataPairs
              items={[
                ["Source", r.source],
                [
                  "Evidence reference",
                  String(batch || r.fields.coverage || "No linked batch"),
                ],
                ["Observed at", stamp(r.at, true)],
                ["Processing", query.data?.meta.status ?? "Loading"],
              ]}
            />
            {batch && d.mode === "demo" && (
              <>
                <div className="verify-box">
                  <EvidenceSeal
                    state={
                      busy
                        ? "verifying"
                        : proof
                          ? proof.verified
                            ? "verified"
                            : "invalid"
                          : "unverified"
                    }
                  />
                  <div>
                    <b>
                      {proof
                        ? proof.verified
                          ? "Signature verified"
                          : "Verification failed"
                        : "Verify signed batch"}
                    </b>
                    <p>
                      {proof
                        ? stamp(proof.checkedAt, true)
                        : "Recalculate its digest and check the Ed25519 signature."}
                    </p>
                  </div>
                </div>
                <button
                  className="btn primary"
                  disabled={busy}
                  onClick={() =>
                    job(async () =>
                      P(
                        await request("evidence/verify", d.mode, d.params, {
                          id: batch,
                        }),
                      ),
                    )
                  }
                >
                  Verify evidence
                </button>{" "}
                <button
                  className="btn"
                  disabled={busy}
                  onClick={() =>
                    job(async () => {
                      const b = await request(
                        "evidence/export",
                        d.mode,
                        d.params,
                        { id: batch },
                      );
                      saveFile(
                        String(batch) + ".json",
                        JSON.stringify(b, null, 2),
                      );
                    })
                  }
                >
                  Download batch
                </button>
                {proof && <p className="hash mono">{proof.digest}</p>}
              </>
            )}
          </section>
        )}
        {tab === "Timeline" && (
          <section>
            <h3>Execution & authorization timeline</h3>
            {query.isLoading ? (
              <Loading />
            ) : ts.length ? (
              <ol className="timeline">
                {ts.map((x) => (
                  <li key={x.id}>
                    <span className="time-node" />
                    <div>
                      <b>{x.label}</b> <Badge>{x.basis}</Badge>
                      <small>
                        {stamp(x.at, true)} · {x.source}
                      </small>
                      <small className="mono">
                        {x.id} · {x.identity} · {x.agent} · {x.confidence}% ·{" "}
                        {x.batch}
                      </small>
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="muted">
                No correlated execution trace in this window.
              </p>
            )}
            {!!query.data?.references?.length && (
              <>
                <h3>Related activity</h3>
                {query.data.references.slice(0, 7).map((e) => (
                  <div key={e.id} className="mini-record">
                    <span>{e.name}</span>
                    <small>
                      {e.id} · {stamp(e.at)}
                    </small>
                  </div>
                ))}
              </>
            )}
          </section>
        )}
        {(tab === "Case notes" || (tab === "Overview" && isAlert)) && (
          <section>
            <h3>Investigation</h3>
            {canCase ? (
              <>
                <div className="form-grid">
                  <Field label="Status">
                    <Select
                      value={status}
                      onChange={St}
                      options={["Open", "In review", "Resolved"]}
                      label="Investigation status"
                    />
                  </Field>
                  <Field label="Assign to">
                    <Select
                      value={assignee}
                      onChange={As}
                      options={[
                        "Unassigned",
                        "Maya Chen",
                        "Arjun Rao",
                        "SOC queue",
                      ]}
                      label="Assignee"
                    />
                  </Field>
                </div>
                <Field label="Analyst note">
                  <textarea
                    placeholder="Add an investigation note…"
                    value={note}
                    onChange={(e) => N(e.target.value)}
                  />
                </Field>
                <button
                  className="btn primary"
                  disabled={busy}
                  onClick={() => job(act)}
                >
                  Save investigation
                </button>
              </>
            ) : (
              <p className="muted">
                {r.fields.assignee} · {r.state}
              </p>
            )}
            {(r.notes ?? []).map((n, i) => (
              <div className="version" key={i}>
                <b>{n.text}</b>
                <small>
                  {n.actor} · {stamp(n.at, true)}
                </small>
              </div>
            ))}
          </section>
        )}
        {error && (
          <p role="alert" className="error-msg">
            {error}
          </p>
        )}
      </div>
      <div className="layer-foot">
        <span className="muted">{r.source}</span>
        <button className="btn" onClick={exportRecord}>
          <I n="download" size={14} />
          Export record
        </button>
      </div>
      {policyEdit && <PolicyEditor row={policyEdit} close={() => PE(null)} />}
    </Layer>
  );
}
