"use client";
import { useState, useEffect } from "react";
import { useDesk } from "./context";
import { RuntimeMasthead } from "./visual/RuntimeMasthead";
import { Topology } from "./visual/Topology";
import { Bars, TimeChart } from "./charts";
import { Card, Kpi } from "./Home";
import { I, DataPairs, stamp, Badge } from "./primitives";
import { Table } from "./Table";
import type { Column } from "../types";
export default function LiveRecords() {
  const d = useDesk(),
    b = d.data!,
    [auto, A] = useState(false),
    [streamStatus, setStreamStatus] = useState("");
  const followArchives = d.page.slug === "sniffer-dog";
  const filters = d.params.toString();
  useEffect(() => {
    if (!auto) return;
    if (followArchives) {
      const query = new URLSearchParams(filters);
      query.set("mode", "live");
      const feed = new EventSource(
        "/api/snifferdog/stream?" + query.toString(),
      );
      feed.onopen = () => setStreamStatus("Following verified archive updates");
      feed.addEventListener("snapshot", d.refresh);
      feed.addEventListener("unavailable", () => {
        feed.close();
        A(false);
        setStreamStatus("Archive source unavailable. Follow again to retry.");
      });
      feed.onerror = () =>
        setStreamStatus("Reconnecting to the archive source");
      return () => feed.close();
    }
    const t = setInterval(d.refresh, 5000);
    return () => clearInterval(t);
  }, [auto, d.refresh, followArchives, filters]);
  const observer =
      [
        "sniffer-dog",
        "runtime-activity",
        "attribution",
        "agent-lineage",
      ].includes(d.page.slug) || !!b.summaries?.archiveActivity,
    authority = d.page.slug === "identity-authorization",
    evidence = ["evidence-audit", "verification"].includes(d.page.slug);
  const columns: Column[] = observer
    ? [
        ["name", "Observation"],
        ["workload", "Workload"],
        ["kind", "Actor type"],
        ["agent", "Agent binding"],
        ["verification", "Signature"],
        ["mechanism", "Mechanism"],
        ["at", "Collector attestation"],
      ]
    : authority
      ? [
          ["name", "Authority record"],
          ["authorization", "Authorization"],
          ["receipt", "Gateway receipt"],
          ["verdict", "Execution verdict"],
          ["reason", "Evidence limit"],
          ["at", "Assessment time"],
        ]
      : evidence
        ? [
            ["name", "Signed archive"],
            ["observer", "Observer"],
            ["items", "Signed items"],
            ["sensorHealth", "Health statement"],
            ["state", "Integrity"],
            ["at", "Attestation"],
          ]
        : d.page.columns;
  return (
    <div className="stack">
      {(d.page.slug === "sniffer-dog" ||
        (d.page.slug === "home" && b.summaries?.archiveActivity)) && (
        <RuntimeMasthead />
      )}
      <Card
        title="Connected evidence source"
        action={
          <button
            className="btn small"
            aria-pressed={auto}
            onClick={() => {
              setStreamStatus("");
              A(!auto);
            }}
          >
            <I n={auto ? "pause" : "refresh"} size={13} />
            {followArchives
              ? auto
                ? "Pause archive updates"
                : "Follow archive updates"
              : auto
                ? "Pause polling"
                : "Poll every 5 seconds"}
          </button>
        }
      >
        {streamStatus && (
          <p className="muted" role="status">
            {streamStatus}
          </p>
        )}
        <DataPairs
          items={[
            ["Source", b.meta.source],
            ["Processing", b.meta.status],
            ["Observation time", stamp(b.meta.asOf, true)],
            ["Verified at", stamp(b.meta.processedAt, true)],
            ["Tenant group", b.meta.group],
          ]}
        />
      </Card>
      {!!b.metrics?.length && (
        <div className="kpi-grid">
          {b.metrics.map((m) => (
            <Kpi key={m.key} m={m} />
          ))}
        </div>
      )}
      {b.summaries?.archiveActivity && (
        <div className="double">
          <Card
            title="Archive observations by day"
            sub="Collector attestation time · select a day to inspect the records"
          >
            <Bars
              items={b.summaries.archiveActivity}
              limit={b.meta.days}
              onClick={(date) => d.go("runtime-activity?day=" + date)}
            />
          </Card>
          <Card
            title="Observation types"
            sub="Counts in the selected signed archive and date range"
          >
            <Bars
              items={b.summaries.recordKinds ?? []}
              onClick={(kind) =>
                d.go("runtime-activity?recordKind=" + encodeURIComponent(kind))
              }
            />
          </Card>
        </div>
      )}
      {!!b.trend?.length && (
        <Card title="AI activity over time" sub={b.meta.source}>
          <TimeChart
            points={b.trend}
            onDay={(at) => d.go("runtime-activity?day=" + at.slice(0, 10))}
          />
        </Card>
      )}
      {b.graph && (
        <Topology
          nodes={b.graph.nodes}
          edges={b.graph.edges}
          title={
            d.page.slug === "agent-lineage"
              ? "Recorded process lineage"
              : "Signed process observations"
          }
          mode={d.command ? "command" : "light"}
        />
      )}
      <Table
        title={
          observer
            ? "Signed runtime observations"
            : authority
              ? "Signed authorizations"
              : evidence
                ? "Verified archive records"
                : d.page.title
        }
        columns={columns}
      />
    </div>
  );
}
