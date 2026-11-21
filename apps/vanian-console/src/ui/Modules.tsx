"use client";
import { useState, useEffect } from "react";
import { useDesk, request } from "./context";
import {
  Field,
  DataPairs,
  Select,
  I,
  Badge,
  Empty,
  fmt,
  money,
  stamp,
  saveFile,
} from "./primitives";
import { Card } from "./Home";
import { Bars, Donut, TimeChart, CostChart } from "./charts";
import { Table, exportRows } from "./Table";
import { PolicyList } from "./Policy";
import { analyticsTabs } from "../product";
import { type Entry, type Column } from "../types";
import { RuntimeMasthead } from "./visual/RuntimeMasthead";
import { OrbitalSensors } from "./visual/OrbitalSensors";
import { Topology, type GraphExport } from "./visual/Topology";
import { DlpTest, CostProjection } from "./Protection";
import { NativeResearchPanel } from "./research/NativeResearchPanel";
export function MiniMetrics({ items }: { items: [string, string, string?][] }) {
  const d = useDesk();
  return (
    <div className="mini-metrics">
      {items.map(([label, value, h]) => (
        <div
          key={label}
          title={
            d.data?.meta.source +
            " · " +
            (d.data ? stamp(d.data.meta.asOf) : "") +
            " · " +
            d.data?.meta.status
          }
        >
          <span>{label}</span>
          <strong>{value}</strong>
          {h && <small>{h}</small>}
        </div>
      ))}
    </div>
  );
}
function Tabs({
  values,
  current,
  onChange,
}: {
  values: string[];
  current: string;
  onChange: (s: string) => void;
}) {
  return (
    <div className="tabs section-tabs">
      {values.map((v) => (
        <button
          key={v}
          className={v === current ? "on" : ""}
          onClick={() => onChange(v)}
        >
          {v}
        </button>
      ))}
    </div>
  );
}
function Discovery() {
  const d = useDesk(),
    b = d.data!,
    s = b.stats ?? {},
    key = d.page.slug;
  if (
    key === "ai-applications" ||
    key === "app-catalog" ||
    key === "shadow-ai"
  ) {
    return (
      <>
        <Tabs
          values={[
            "Discovered applications",
            "Application catalog",
            "Shadow AI",
          ]}
          current={
            key === "app-catalog"
              ? "Application catalog"
              : key === "shadow-ai"
                ? "Shadow AI"
                : "Discovered applications"
          }
          onChange={(v) =>
            d.go(
              v === "Application catalog"
                ? "app-catalog"
                : v === "Shadow AI"
                  ? "shadow-ai"
                  : "ai-applications",
            )
          }
        />
        <MiniMetrics
          items={[
            ["Discovered applications", fmt(s.apps)],
            ["Newly discovered", fmt(s.newApps)],
            ["High-risk applications", fmt(s.highApps)],
          ]}
        />
        <div className="discovery-layout">
          <aside>
            <Card
              title={
                key === "app-catalog"
                  ? "Catalog categories"
                  : "Applications by category"
              }
            >
              <div className="facet-list">
                <button
                  className={!d.params.get("category") ? "on" : ""}
                  onClick={() => d.set({ category: null, page: null })}
                >
                  All categories
                </button>
                {b.summaries?.categories.map((k) => (
                  <button
                    className={d.params.get("category") === k.name ? "on" : ""}
                    key={k.name}
                    onClick={() => d.set({ category: k.name, page: null })}
                  >
                    {k.name}
                    <b>{k.value}</b>
                  </button>
                ))}
              </div>
            </Card>
            <Card title="Discovery activity">
              <TimeChart
                points={b.trend ?? []}
                onDay={(v) => d.go("runtime-activity?day=" + v.slice(0, 10))}
              />
            </Card>
          </aside>
          <Table
            title={
              key === "app-catalog"
                ? "Application catalog"
                : key === "shadow-ai"
                  ? "Shadow AI findings"
                  : "Discovered applications"
            }
          />
        </div>
      </>
    );
  }
  if (key === "mcp-servers") {
    const tab = d.params.get("tab") ?? "MCP Servers";
    return (
      <>
        <Tabs
          values={["MCP Servers", "Tools"]}
          current={tab}
          onChange={(v) => d.set({ tab: v, page: null })}
        />
        <Table
          title={tab === "Tools" ? "Governed tools" : "Registered MCP servers"}
          columns={
            tab === "Tools"
              ? [
                  ["name", "Tool name"],
                  ["server", "Server"],
                  ["scope", "Permission"],
                  ["calls", "Server calls"],
                  ["risk", "Risk"],
                  ["state", "Approval"],
                ]
              : [
                  ["name", "Server identity"],
                  ["transport", "Transport"],
                  ["endpoint", "Endpoint"],
                  ["connectedAgents", "Agents"],
                  ["tools", "Tools"],
                  ["scope", "Permissions"],
                  ["risk", "Risk"],
                  ["state", "Approval"],
                ]
          }
        />
      </>
    );
  }
  if (key === "ghost-orphan-agents") {
    const classification = d.params.get("classification") ?? "";
    return (
      <>
        <Tabs
          values={["All findings", "Ghost AI", "Orphan AI", "Shadow AI"]}
          current={
            classification === "Orphan"
              ? "Orphan AI"
              : classification === "Suspected ghost"
                ? "Ghost AI"
                : "All findings"
          }
          onChange={(t) =>
            t === "Shadow AI"
              ? d.go("shadow-ai")
              : d.set({
                  classification:
                    t === "All findings"
                      ? null
                      : t === "Ghost AI"
                        ? "Suspected ghost"
                        : "Orphan",
                  page: null,
                })
          }
        />
        <p className="inline-note">
          <I n="info" size={15} />
          Suspected ghost activity requires additional identity evidence. Orphan
          findings indicate missing ownership.
        </p>
        <Table
          title="Accountability findings"
          columns={[
            ["name", "Identity"],
            ["state", "Classification"],
            ["confidence", "Confidence"],
            ["owner", "Owner"],
            ["evidence", "Evidence basis"],
            ["at", "Last observed"],
          ]}
        />
      </>
    );
  }
  return (
    <>
      <Tabs
        values={[
          "All agents",
          "Registered",
          "Unregistered",
          "Inactive",
          "Suspended",
          "Unknown",
        ]}
        current={d.params.get("classification") ?? "All agents"}
        onChange={(v) =>
          d.set({
            classification: v === "All agents" ? null : v,
            page: null,
            tab: null,
          })
        }
      />
      <Table
        title="Agent inventory"
        columns={[
          ...d.page.columns.slice(0, -1),
          ["sensorCoverage", "Sensor coverage"],
          ...d.page.columns.slice(-1),
        ]}
      />
    </>
  );
}
function Analytics() {
  const d = useDesk(),
    b = d.data!,
    s = b.stats ?? {},
    m = b.summaries ?? {},
    selected =
      d.params.get("view") ??
      ({
        "data-analytics": "Data Protection",
        "risk-analysis": "Risk Analysis",
        "ai-adoption": "AI Adoption",
        roi: "ROI",
      }[d.page.slug] ||
        "Behavioral Activity");
  const [busy, B] = useState(false);
  return (
    <div className="analytics-layout">
      <aside className="card subnav">
        {analyticsTabs.map((t, i) => (
          <div key={t}>
            {(i === 0 || i === 6) && (
              <small>
                {i === 0 ? "Guardrail analytics" : "Platform analytics"}
              </small>
            )}
            <button
              className={selected === t ? "on" : ""}
              onClick={() => d.set({ view: t, page: null })}
            >
              {t}
            </button>
          </div>
        ))}
      </aside>
      <div className="stack">
        <div className="section-heading">
          <div>
            <h2>{selected}</h2>
            <p className="muted">
              {selected === "ROI"
                ? "Review the cost baseline and measured outcome inputs."
                : "Explore counts and event evidence for the selected window."}
            </p>
          </div>
          <div className="btn-group">
            <button
              className="btn small"
              disabled={busy}
              onClick={async () => {
                B(true);
                try {
                  await exportRows(
                    d.page.api,
                    d.mode,
                    d.params,
                    d.page.columns,
                    "analytics",
                  );
                } catch (e) {
                  d.toast((e as Error).message);
                } finally {
                  B(false);
                }
              }}
            >
              <I n="download" size={13} />
              CSV
            </button>
            <button className="btn small" onClick={() => window.print()}>
              Print / PDF
            </button>
          </div>
        </div>
        {selected === "ROI" && (
          <p className="notice">
            Realized ROI is unavailable. A customer-approved baseline and
            measured business outcome are required.
          </p>
        )}
        <MiniMetrics
          items={[
            ["Interactions", fmt(s.interactions)],
            ["Agent executions", fmt(s.agents)],
            ["Risk events", fmt(s.riskEvents)],
          ]}
        />
        <Card
          title="Activity trend"
          sub="Select a period to inspect its underlying events"
        >
          <TimeChart
            points={b.trend ?? []}
            onDay={(v) =>
              d.go(
                "runtime-activity?day=" +
                  v.slice(0, 10) +
                  (selected === "Data Protection"
                    ? "&guardrail=Data%20Protection"
                    : ""),
              )
            }
          />
        </Card>
        <div className="double">
          <Card title="Top intent categories">
            <Bars
              items={m.intents ?? []}
              limit={10}
              onClick={(v) =>
                d.go("conversations?intent=" + encodeURIComponent(v))
              }
            />
          </Card>
          <Card title="Application breakdown">
            <Bars
              items={m.apps ?? []}
              limit={10}
              onClick={(v) =>
                d.go("conversations?app=" + encodeURIComponent(v))
              }
            />
          </Card>
        </div>
        <Card title="User breakdown">
          <Bars
            items={m.users ?? []}
            onClick={(v) => d.go("conversations?user=" + encodeURIComponent(v))}
          />
        </Card>
        <Table title="Underlying events" />
      </div>
    </div>
  );
}
function Finops() {
  const d = useDesk(),
    b = d.data!,
    s = b.stats ?? {},
    summ = b.summaries ?? {};
  const [dim, D] = useState("Model"),
    [budget, Bu] = useState(""),
    [saving, Sa] = useState(false);
  const key = (
    {
      Model: "modelCost",
      Provider: "providerCost",
      Application: "appCost",
      User: "userCost",
      Department: "departmentCost",
      Agent: "agentCost",
    } as Record<string, string>
  )[dim];
  const r = summ[key] ?? [];
  const limit = Number(b.stats?.budget ?? 0);
  return (
    <div className="stack">
      <Tabs
        values={["Spending", "Token usage", "Cost optimization"]}
        current={
          d.page.slug === "ai-finops"
            ? "Spending"
            : d.page.slug === "token-usage"
              ? "Token usage"
              : "Cost optimization"
        }
        onChange={(v) =>
          d.go(
            v === "Spending"
              ? "ai-finops"
              : v === "Token usage"
                ? "token-usage"
                : "cost-optimization",
          )
        }
      />
      <MiniMetrics
        items={[
          ["Total allocated cost", money(s.cost), "USD · includes estimates"],
          [
            "Provider-metered costs",
            money(s.metered),
            d.mode === "demo" ? "Synthetic meter records" : "Provider records",
          ],
          ["Estimated costs", money(s.estimated), "Rate-card model"],
          ["Token consumption", fmt(s.tokens), "Input and output combined"],
        ]}
      />
      <Card
        title="Cost allocation"
        sub="Usage attributed to the selected dimension"
        action={
          <Select
            label="Cost dimension"
            value={dim}
            onChange={D}
            options={[
              "Model",
              "Provider",
              "Application",
              "User",
              "Department",
              "Agent",
            ]}
          />
        }
      >
        <CostChart items={r} />
      </Card>
      <div className="double">
        <Card title="Cost trend">
          <TimeChart
            spend
            points={b.trend ?? []}
            onDay={(v) => d.go("ai-finops?day=" + v.slice(0, 10))}
          />
        </Card>
        <Card title="Budget & optimization">
          <p>
            {limit
              ? money(s.cost) + " of " + money(limit) + " allocated budget"
              : "No spending budget configured for this group and period."}
          </p>
          {limit > 0 && (
            <Badge>
              {s.cost > limit ? "Budget exceeded" : "Within budget"}
            </Badge>
          )}
          {d.role === "Administrator" && d.mode === "demo" && (
            <form
              className="inline-form"
              onSubmit={async (e) => {
                e.preventDefault();
                Sa(true);
                try {
                  await request("finops/budget", d.mode, d.params, {
                    group: b.meta.group,
                    days: b.meta.days,
                    amount: Number(budget),
                    version: s.budgetVersion ?? 0,
                  });
                  d.refresh();
                  Bu("");
                  d.toast("Demo budget saved");
                } catch (e) {
                  d.toast((e as Error).message);
                } finally {
                  Sa(false);
                }
              }}
            >
              <input
                aria-label="Budget in USD"
                type="number"
                min=".01"
                step=".01"
                required
                value={budget}
                onChange={(e) => Bu(e.target.value)}
                placeholder="Budget in USD"
              />
              <button className="btn small" disabled={saving}>
                Set budget
              </button>
            </form>
          )}
          <p className="muted">
            {r[0]
              ? r[0].name +
                " has the largest allocation. Review its workload before changing model routing."
              : "No usage in this window."}
          </p>
          <small className="muted">
            Projected savings require an alternative price and workload
            benchmark. Realized savings unavailable.
          </small>
        </Card>
      </div>
      {d.page.slug === "cost-optimization" && <CostProjection />}
      <Table
        title={
          d.page.slug === "token-usage"
            ? "Token usage records"
            : "Cost allocation records"
        }
      />
    </div>
  );
}
function Accountability() {
  const d = useDesk(),
    b = d.data!,
    s = b.stats ?? {},
    isSniff = d.page.slug === "sniffer-dog",
    isId = d.page.slug === "identity-authorization";
  const [play, P] = useState(false),
    [step, S] = useState(0),
    [stream, St] = useState(false);
  const timeline = b.timeline ?? [];
  useEffect(() => {
    S(0);
    P(false);
  }, [d.params.get("trace"), d.params.get("group"), d.params.get("days")]);
  useEffect(() => {
    if (!play) return;
    const t = setInterval(
      () =>
        S((n) => {
          if (n >= timeline.length - 1) {
            P(false);
            return n;
          }
          return n + 1;
        }),
      1000,
    );
    return () => clearInterval(t);
  }, [play, timeline.length]);
  useEffect(() => {
    if (!stream || d.mode !== "live") return;
    const t = setInterval(d.refresh, 5000);
    return () => clearInterval(t);
  }, [stream, d.mode, d.refresh]);
  const graph = b.graph;
  const activeStep = timeline[Math.min(step, timeline.length - 1)];
  const graphExport = (visible: GraphExport) =>
    saveFile(
      "vanian-" + d.mode + "-topology.json",
      JSON.stringify(
        {
          meta: b.meta,
          graph: { ...graph, nodes: visible.nodes, edges: visible.edges },
          relationshipFilter: visible.relationshipFilter,
          timelineScope: "selected trace",
          timeline,
        },
        null,
        2,
      ),
    );
  return (
    <div className="stack">
      {isSniff && <RuntimeMasthead />}
      {isSniff && (
        <MiniMetrics
          items={[
            ["Healthy sensors", s.healthy + "/" + s.sensors],
            ["Observed executions", fmt((s.agents ?? 0) + (s.unknown ?? 0))],
            ["Attributed executions", fmt(s.agents)],
            ["Unattributed activity", fmt(s.unknown)],
            ["Policy violations", fmt(s.violations)],
            ["Signed batches", fmt(s.batches)],
          ]}
        />
      )}
      <div className="module-tools wrap">
        <div className="btn-group">
          <I n={isSniff ? "radar" : "lineage"} />
          <strong>
            {isSniff
              ? "Execution topology"
              : isId
                ? "Delegation chain"
                : "Lineage explorer"}
          </strong>
        </div>
        <div className="btn-group">
          {!!b.series?.length && (
            <Select
              label="Select execution trace"
              value={d.params.get("trace") ?? b.series[0]}
              options={b.series}
              onChange={(v) => d.set({ trace: v })}
            />
          )}
          <button className="btn small" onClick={d.toggleCommand}>
            <I n={d.command ? "sun" : "moon"} size={14} />{" "}
            {d.command ? "Light view" : "Command mode"}
          </button>
          {d.mode === "live" && (
            <button className="btn small" onClick={() => St(!stream)}>
              {stream ? "Pause refresh" : "Refresh every 5s"}
            </button>
          )}
        </div>
      </div>
      {graph ? (
        <Topology
          key={b.meta.group + d.page.slug}
          meta={b.meta}
          nodes={graph.nodes}
          edges={graph.edges}
          mode={d.command ? "command" : "light"}
          title={
            isSniff
              ? "Runtime execution topology"
              : isId
                ? "Human authorization chain"
                : "Parent–child agent lineage"
          }
          onExport={graphExport}
          onSelect={(n) => {
            if (n.kind === "agent") {
              const r = b.references?.find((r) => r.id === n.id);
              if (r) d.open(r, "ai-agents");
            }
          }}
        />
      ) : (
        <Empty
          title="No graph observations"
          message="The selected source supplied no relationships for this window."
        />
      )}
      {isSniff && (
        <>
          <Card
            title="Historical replay"
            sub="Step through the selected trace in event order"
            action={
              <button
                className="btn small"
                disabled={!timeline.length}
                onClick={() => {
                  if (step >= timeline.length - 1) S(0);
                  P(!play);
                }}
              >
                <I n={play ? "pause" : "play"} size={13} />
                {play ? "Pause" : "Play replay"}
              </button>
            }
          >
            {timeline.length > 0 && (
              <>
                <div
                  className="trace-sequence"
                  role="group"
                  aria-label="Execution replay events"
                >
                  {timeline.map((event, index) => (
                    <button
                      type="button"
                      className="trace-frame"
                      data-basis={event.basis.toLowerCase()}
                      key={event.id}
                      aria-pressed={step === index}
                      onClick={() => {
                        P(false);
                        S(index);
                      }}
                    >
                      <span className="trace-mark">
                        <I
                          n={
                            event.basis === "Observed"
                              ? "scan"
                              : event.basis === "Declared"
                                ? "key"
                                : "lineage"
                          }
                          size={13}
                        />
                        {event.basis}
                      </span>
                      <b>{event.label}</b>
                      <small>
                        +{Date.parse(event.at) - Date.parse(timeline[0].at)} ms
                      </small>
                    </button>
                  ))}
                </div>
                <input
                  className="range"
                  type="range"
                  aria-label="Replay position"
                  min={0}
                  max={timeline.length - 1}
                  value={Math.min(step, timeline.length - 1)}
                  onChange={(e) => {
                    P(false);
                    S(Number(e.target.value));
                  }}
                />
                <div className="replay-step">
                  <Badge>{timeline[step]?.basis}</Badge>
                  <b>{timeline[step]?.label}</b>
                  <span className="mono">{timeline[step]?.id}</span>
                  <small>
                    {timeline[step] && stamp(timeline[step].at, true)}
                  </small>
                </div>
                {activeStep && (
                  <div className="trace-meta">
                    <b>{activeStep.source}</b>
                    <code>{activeStep.identity}</code>
                    <button
                      type="button"
                      onClick={() =>
                        d.go(
                          "evidence-audit?q=" +
                            encodeURIComponent(activeStep.batch),
                        )
                      }
                    >
                      Inspect linked batch
                    </button>
                  </div>
                )}
              </>
            )}
          </Card>
          <Card
            title="Sensor health & coverage"
            sub={
              "Mean reported sensor overhead " +
              (s.overhead ?? 0).toFixed(2) +
              "% · fixture window"
            }
          >
            <div
              className={
                d.command
                  ? "runtime-fleet-layout has-map"
                  : "runtime-fleet-layout"
              }
            >
              {d.command && (
                <div className="runtime-fleet-map">
                  <OrbitalSensors
                    sensors={b.sensors ?? []}
                    onSelect={(id) => d.set({ sensor: id, page: null })}
                  />
                </div>
              )}
              <div className="sensors">
                {(b.sensors ?? []).map((r) => (
                  <button
                    key={r.id}
                    onClick={() => d.set({ sensor: r.id, page: null })}
                  >
                    <I n="radio" />
                    <span>
                      <b>{r.name}</b>
                      <small>
                        {r.group} · {r.id}
                      </small>
                    </span>
                    <Badge dot>{r.state}</Badge>
                  </button>
                ))}
              </div>
            </div>
          </Card>
        </>
      )}
      {isId && d.mode === "demo" && (
        <NativeResearchPanel initialSample="same-run" />
      )}
      <Table
        title={
          isSniff
            ? "Runtime observations"
            : isId
              ? "Identity registry"
              : "Agent inventory"
        }
      />
    </div>
  );
}
function Evidence() {
  const d = useDesk();
  return (
    <div className="stack">
      {d.page.slug === "verification" && d.mode === "demo" && (
        <NativeResearchPanel />
      )}
      <Tabs
        values={["Execution evidence", "Verification", "Audit trails"]}
        current={
          d.page.slug === "audit-trails"
            ? "Audit trails"
            : d.page.slug === "verification"
              ? "Verification"
              : "Execution evidence"
        }
        onChange={(v) =>
          d.go(
            v === "Verification"
              ? "verification"
              : v === "Audit trails"
                ? "audit-trails"
                : "evidence-audit",
          )
        }
      />
      {d.page.slug === "audit-trails" ? (
        <Table
          title="Workspace change log"
          columns={[
            ["at", "Recorded at"],
            ["name", "Action"],
            ["record", "Record"],
            ["actor", "Actor role"],
            ["detail", "Detail"],
            ["source", "Source"],
          ]}
        />
      ) : (
        <>
          <p className="inline-note">
            <I n="signed" />
            Select a batch to inspect its custody record, verify the signature
            and download the signed payload.
          </p>
          <Table title="Signed execution batches" />
        </>
      )}
    </div>
  );
}
function Administration() {
  const d = useDesk();
  if (d.page.slug === "settings")
    return (
      <div className="stack">
        <Card title="Workspace preferences">
          <div className="setting-row">
            <div>
              <b>Data environment</b>
              <p>Choose the source for every view in this console.</p>
            </div>
            <Select
              label="Data environment"
              value={d.mode}
              options={[
                ["demo", "Demo · synthetic"],
                ["live", "Live · authenticated"],
              ]}
              onChange={(v) => d.changeMode(v as "demo" | "live")}
            />
          </div>
          {d.mode === "demo" && (
            <div className="setting-row">
              <div>
                <b>Demo role</b>
                <p>Try the permissions available to an analyst or auditor.</p>
              </div>
              <Select
                label="Demo role"
                value={d.role}
                options={["Administrator", "Analyst", "Auditor"]}
                onChange={(v) => void d.changeRole(v as typeof d.role)}
              />
            </div>
          )}
          <div className="setting-row">
            <div>
              <b>Guided onboarding</b>
              <p>Explore the discovery-to-evidence workflow.</p>
            </div>
            <button className="btn" onClick={() => d.modal("tour")}>
              Start tour
            </button>
          </div>
        </Card>
        <Table
          title="Workspace configuration"
          columns={[
            ["name", "Setting"],
            ["value", "Configured value"],
            ["source", "Source"],
          ]}
        />
      </div>
    );
  return (
    <div className="stack">
      {d.page.slug === "integrations" && (
        <Card title="Source onboarding">
          <div className="setup-steps">
            {[
              "Authorize connector",
              "Install sensor",
              "Capture baseline",
              "Verify evidence",
            ].map((s, i) => (
              <button
                key={s}
                onClick={() =>
                  i === 3 ? d.go("verification") : d.modal("connection")
                }
              >
                <I n={["key", "radio", "activity", "filecheck"][i]} />
                {s}
              </button>
            ))}
          </div>
        </Card>
      )}
      {d.page.slug === "deployments" && (
        <Card title="Deployment architecture">
          <svg
            className="architecture"
            role="img"
            aria-label="Customer sensor submits evidence to the customer verifier. The console reads tenant-scoped projections."
            viewBox="0 0 760 100"
          >
            {[
              "Customer sensor",
              "Native verifier",
              "Scoped API",
              "VANIAN console",
            ].map((v, i) => (
              <g key={v}>
                {i > 0 && (
                  <path
                    d={"M" + (28 + (i - 1) * 190 + 141) + " 49h49"}
                    stroke="#9b78d3"
                    strokeWidth="2"
                  />
                )}
                <rect
                  x={20 + i * 190}
                  y="20"
                  width="143"
                  height="55"
                  rx="8"
                  fill="#f6f0fe"
                  stroke="#d5c2f2"
                />
                <text
                  x={91 + i * 190}
                  y="52"
                  textAnchor="middle"
                  fill="#542a8a"
                  fontSize="13"
                >
                  {v}
                </text>
              </g>
            ))}
          </svg>
        </Card>
      )}
      <Table
        title={d.page.title}
        columns={
          d.page.api.startsWith("admin/")
            ? [
                ["name", "Capability"],
                ["value", "Configuration"],
                ["source", "Source"],
              ]
            : undefined
        }
      />
    </div>
  );
}
export default function Module() {
  const d = useDesk(),
    k = d.page.slug,
    b = d.data!,
    s = b.stats ?? {},
    m = b.summaries ?? {};
  if (
    d.page.section === "Discovery" ||
    ["ghost-orphan-agents", "agent-inventory"].includes(k)
  )
    return <Discovery />;
  if (d.page.section === "Analytics") return <Analytics />;
  if (d.page.section === "AI FinOps") return <Finops />;
  if (d.page.section === "Administration") return <Administration />;
  if (["sniffer-dog", "agent-lineage", "identity-authorization"].includes(k))
    return <Accountability />;
  if (d.page.section === "Evidence") return <Evidence />;
  if (k === "policies") return <PolicyList />;
  const security = [
    "security-posture",
    "runtime-protection",
    "alerts",
    "investigations",
  ].includes(k);
  return (
    <div className="stack">
      {security && (
        <MiniMetrics
          items={[
            ["Security detections", fmt(s.riskEvents)],
            [
              "Critical detections",
              fmt(
                (m.alerts ?? []).find((v) => v.name === "Critical")?.value ?? 0,
              ),
            ],
            [
              "High severity",
              fmt((m.alerts ?? []).find((v) => v.name === "High")?.value ?? 0),
            ],
            [
              "Decision mode",
              d.mode === "demo" ? "Simulated" : "Source reported",
            ],
          ]}
        />
      )}
      {k === "runtime-protection" && (
        <Card title="Detection & response">
          <p>
            Inspect matched controls, decision records and evidence for each
            detection.
          </p>
          <div className="double">
            <div>
              <h3>Guardrail activity</h3>
              <Bars
                items={m.guards ?? []}
                onClick={(v) =>
                  d.go("runtime-activity?guardrail=" + encodeURIComponent(v))
                }
              />
            </div>
            <div>
              <h3>Decision outcomes</h3>
              <Bars
                items={m.decisions ?? []}
                onClick={(v) => d.go("conversations?state=" + v)}
              />
            </div>
          </div>
        </Card>
      )}
      {k === "attribution" && (
        <Card title="Attribution by evidence">
          <Donut
            items={m.actors ?? []}
            onClick={(v) => d.set({ kind: v, page: null })}
          />
        </Card>
      )}
      {k === "intent-classification" && (
        <Card title="Classified intent">
          <Bars
            items={m.intents ?? []}
            onClick={(v) => d.set({ intent: v, page: null })}
          />
        </Card>
      )}
      {k === "security-posture" && (
        <div className="double">
          <Card title="Risk distribution">
            <Donut
              items={m.risk ?? []}
              onClick={(v) => d.go("runtime-activity?risk=" + v)}
            />
          </Card>
          <Card title="Security outcomes">
            <Bars
              items={m.decisions ?? []}
              onClick={(v) => d.go("conversations?state=" + v)}
            />
          </Card>
        </div>
      )}
      {k === "compliance" && (
        <div className="inline-note">
          <I n="clipboard" />
          Draft control mappings for assessor review. Certification status
          requires an independent assessment.
          <button className="text-btn" onClick={() => window.print()}>
            Print report
          </button>
        </div>
      )}
      {k === "ai-red-teaming" && (
        <p className="inline-note">
          <I n="target" />
          Authorized assessment scope covers predefined policy conditions in the
          isolated simulator.
        </p>
      )}
      {k === "data-protection" && <DlpTest />}
      {k === "data-protection" && (
        <Card title="Data handling">
          <DataPairs
            items={[
              ["Default preview", "Masked"],
              ["Reveal authority", "Explicit administrator action · audited"],
              ["Secret and PII rules", "Configured in policy guardrails"],
              ["Tokenization", "Synthetic sample simulator"],
              ["Attachment inspection", "Connector capability required"],
            ]}
          />
        </Card>
      )}
      <Table
        title={
          k === "conversations"
            ? "Interactions"
            : k === "security-posture"
              ? "Exposure findings"
              : d.page.title
        }
      />
    </div>
  );
}
