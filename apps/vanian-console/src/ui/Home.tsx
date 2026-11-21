"use client";
import { type ReactNode } from "react";
import { useDesk } from "./context";
import { I, Badge, fmt, money, stamp, ProvenanceLine } from "./primitives";
import { Bars, Donut, Spark, TimeChart } from "./charts";
import { RuntimeMasthead } from "./visual/RuntimeMasthead";
import type { Metric, Entry } from "../types";
export function Card({
  title,
  sub,
  action,
  children,
  cls = "",
  anchor,
}: {
  title: string;
  sub?: string;
  action?: ReactNode;
  children: ReactNode;
  cls?: string;
  anchor?: string;
}) {
  return (
    <section className={"card " + cls} data-tour={anchor}>
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          {sub && <p>{sub}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
const styles: Record<string, [string, string, string]> = {
  agents: ["bot", "purple", "#8745eb"],
  shadow: ["scan", "amber", "#c18932"],
  alerts: ["danger", "red", "#d85c71"],
  verified: ["filecheck", "green", "#3c987e"],
};
export function Kpi({ m }: { m: Metric }) {
  const { go, data } = useDesk(),
    [icon, hue, color] = styles[m.key] ?? ["activity", "purple", "#7943d6"];
  const delta = m.value - m.prior;
  return (
    <button
      className="kpi"
      onClick={() => go(m.href)}
      title={
        m.info +
        " Source: " +
        m.source +
        " · " +
        stamp(data!.meta.asOf) +
        " · " +
        data!.meta.status
      }
    >
      <span className="kpi-label">
        <span className={"icon-tile " + hue}>
          <I n={icon} size={18} />
        </span>
        {m.label}
        <I n="open" size={13} className="kpi-open" />
      </span>
      <span className="kpi-center">
        <strong>
          {fmt(m.value)}
          {m.key === "verified" && <em>%</em>}
        </strong>
        <Spark values={m.series} color={color} />
      </span>
      <span className="kpi-period">
        <span
          className={
            "delta " +
            (delta === 0 || data!.meta.mode === "live"
              ? "steady"
              : (
                    m.key === "alerts" || m.key === "shadow"
                      ? delta < 0
                      : delta > 0
                  )
                ? "positive"
                : "negative")
          }
        >
          <I
            n={delta === 0 ? "minus" : delta > 0 ? "up" : "trenddown"}
            size={12}
          />
          {delta === 0
            ? "Stable"
            : (delta > 0 ? "+" : "") +
              fmt(delta) +
              (m.key === "verified" ? " pp" : "")}
        </span>{" "}
        vs prior {data!.meta.days}
        {data!.meta.days === 1 ? " day" : " days"}
      </span>
    </button>
  );
}
export function RecentList({ rows }: { rows: Entry[] }) {
  const { open } = useDesk();
  return (
    <div className="recent-list">
      <div className="recent-label">
        <span>Detection</span>
        <span>Severity</span>
        <span>Status</span>
      </div>
      {rows.map((r) => (
        <button key={r.id} onClick={() => open(r, "alerts")}>
          <span className="recent-name">
            <span
              className={
                "incident-icon " +
                (r.fields.risk === "Critical" ? "red" : "amber")
              }
            >
              <I n="outline" size={16} />
            </span>
            <span>
              <b>{r.name}</b>
              <small>
                {r.fields.app} <span>·</span> {r.fields.actor}
              </small>
            </span>
          </span>
          <span>
            <Badge>{r.fields.risk}</Badge>
          </span>
          <span>
            <Badge dot>{r.state}</Badge>
          </span>
        </button>
      ))}
    </div>
  );
}
export default function Home() {
  const { data, go, modal } = useDesk();
  if (!data) return null;
  const { metrics = [], stats = {}, summaries = {}, trend = [], meta } = data;
  return (
    <div className="dashboard">
      <div className="kpi-grid" data-tour="home">
        {metrics.slice(0, 4).map((m) => (
          <Kpi key={m.key} m={m} />
        ))}
      </div>
      <div className="runtime-focus">
        <Card
          title="AI activity over time"
          sub="Application interactions and attributed executions"
          cls="activity-card"
          action={
            <button
              className="subaction"
              onClick={() => go("analytics")}
              aria-label="Open activity analytics"
            >
              <I n="open" size={16} />
            </button>
          }
        >
          <div className="chart-summary">
            <strong>{fmt(stats.interactions ?? 0)}</strong>
            <span>total interactions</span>
          </div>
          <div className="legend">
            <span>
              <i />
              AI interactions
            </span>
            <span>
              <i className="dashed" />
              Agent executions
            </span>
          </div>
          <TimeChart
            points={trend}
            onDay={(d) => go("runtime-activity?day=" + d.slice(0, 10))}
          />
        </Card>
        <RuntimeMasthead compact />
      </div>
      <div className="main-grid">
        <Card
          title="Recent security alerts"
          sub={
            meta.mode === "demo"
              ? "Latest detections in the replay window"
              : "Latest detections in the selected window"
          }
          action={
            <button className="text-btn" onClick={() => go("alerts")}>
              View all <I n="right" size={13} />
            </button>
          }
          cls="table-card"
        >
          <RecentList rows={data.references ?? []} />
        </Card>
        <Card
          title="Risk distribution"
          sub="Interactions by classified severity"
        >
          <Donut
            items={summaries.risk ?? []}
            onClick={(k) => go("runtime-activity?risk=" + k)}
          />
          <button className="footlink" onClick={() => go("security-posture")}>
            Review security posture <I n="right" size={14} />
          </button>
        </Card>
      </div>
      <div className="section-heading">
        <h2>Discovery & accountability</h2>
        <ProvenanceLine meta={meta} onClick={() => modal("provenance")} />
      </div>
      <div className="small-kpis">
        {metrics.slice(4).map((m) => (
          <button
            key={m.key}
            onClick={() => go(m.href)}
            title={
              m.info +
              " · " +
              m.source +
              " · " +
              stamp(meta.asOf) +
              " · " +
              meta.status
            }
          >
            <span>{m.label}</span>
            <strong>{fmt(m.value)}</strong>
            <small>
              {m.value === m.prior
                ? "Stable"
                : (m.value > m.prior ? "+" : "") + fmt(m.value - m.prior)}{" "}
              vs prior {meta.days}d
            </small>
          </button>
        ))}
      </div>
      <div className="triple">
        <Card title="Top AI applications" action={<I n="apps" />}>
          <Bars
            items={summaries.apps ?? []}
            onClick={(s) => go("ai-applications?q=" + encodeURIComponent(s))}
          />
        </Card>
        <Card title="Human vs agent activity" action={<I n="fingerprint" />}>
          <Donut
            items={summaries.actors ?? []}
            onClick={(s) => go("attribution?kind=" + s)}
          />
        </Card>
        <Card title="Agent lineage health" action={<I n="lineage" />}>
          <Bars
            items={summaries.lineage ?? []}
            onClick={(s) =>
              go("ai-agents?classification=" + encodeURIComponent(s))
            }
          />
        </Card>
      </div>
      <div className="triple">
        <Card
          title="Policy decisions"
          sub={
            meta.mode === "demo"
              ? "Simulated outcomes"
              : "Source-reported outcomes"
          }
        >
          <Bars
            items={summaries.decisions ?? []}
            onClick={(s) => go("conversations?state=" + s)}
          />
        </Card>
        <Card title="AI spending" sub="Metered and estimated components">
          <div className="value-row">
            <b>{money(stats.cost ?? 0)}</b>
            <I n="wallet" />
          </div>
          <p className="muted">
            {money(stats.metered ?? 0)} metered · {money(stats.estimated ?? 0)}{" "}
            estimated
          </p>
          <button className="footlink" onClick={() => go("ai-finops")}>
            Inspect cost allocation <I n="right" size={14} />
          </button>
        </Card>
        <Card title="Security events by severity">
          <Bars
            items={summaries.alerts ?? []}
            onClick={(s) => go("alerts?risk=" + s)}
          />
        </Card>
      </div>
    </div>
  );
}
