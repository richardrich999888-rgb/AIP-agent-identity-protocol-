"use client";
import "./records.css";
import { useMemo, useState, useEffect } from "react";
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from "@tanstack/react-table";
import { useDesk, request } from "./context";
import { type Bundle, type Column, type Entry } from "../types";
import { field, pretty } from "../product";
import {
  Badge,
  Empty,
  I,
  Select,
  Mark,
  csv,
  fmt,
  saveFile,
  stamp,
} from "./primitives";
const technical = [
  "id",
  "agent",
  "parent",
  "model",
  "endpoint",
  "sensor",
  "domain",
  "event",
  "tokens",
  "items",
];
const numeric = new Set([
  "count",
  "users",
  "cost",
  "tokens",
  "items",
  "confidence",
  "calls",
  "agents",
  "tools",
  "version",
  "priority",
  "events",
  "spend",
  "budget",
  "executions",
]);
const tagged = [
  "risk",
  "state",
  "decision",
  "classification",
  "verification",
  "costKind",
  "kind",
  "enforcement",
  "action",
];
function Cell({ k, row }: { k: string; row: Entry }) {
  const v = field(row, k);
  if (k === "name")
    return (
      <span className="record-name">
        {row.id.startsWith("APP-") ? <Mark row={row} /> : null}
        <span>
          <b>{v}</b>
          {row.id.startsWith("APP-") && <small>{row.fields.domain}</small>}
        </span>
      </span>
    );
  if (k === "at") return <span className="cell-time">{stamp(String(v))}</span>;
  if (tagged.includes(k) && v) return <Badge dot={k === "state"}>{v}</Badge>;
  if (k === "confidence")
    return <span className="mono">{typeof v === "number" ? v + "%" : v}</span>;
  return (
    <span
      className={
        technical.includes(k) ? "mono" : k === "preview" ? "preview-cell" : ""
      }
      title={String(v)}
    >
      {typeof v === "number"
        ? k === "cost"
          ? "$" + v.toFixed(4)
          : fmt(v)
        : String(v || "—")}
    </span>
  );
}
export async function exportRows(
  api: string,
  mode: "demo" | "live",
  query: URLSearchParams,
  columns: Column[],
  file: string,
) {
  let page = 1;
  const lines: (string | number | boolean)[][] = [
    [
      "Mode",
      "Source",
      "Snapshot UTC",
      "Processed UTC",
      "Processing status",
      ...columns.map((c) => c[1]),
    ],
  ];
  let total = 0;
  do {
    const p = new URLSearchParams(query);
    p.set("page", String(page));
    p.set("size", "100");
    const b = await request<Bundle>(api, mode, p);
    total = b.total;
    lines.push(
      ...b.rows.map((r) => [
        b.meta.mode,
        r.source,
        b.meta.asOf,
        b.meta.processedAt,
        b.meta.status,
        ...columns.map(([k]) => field(r, k)),
      ]),
    );
    if (!b.rows.length) break;
    page++;
  } while ((page - 1) * 100 < total);
  saveFile(
    "vanian-" + mode + "-" + file + ".csv",
    csv(lines),
    "text/csv;charset=utf-8",
  );
}
export function Table({
  title = "Records",
  columns,
  showExport = true,
  onRow,
  hideToolbar = false,
}: {
  title?: string;
  columns?: Column[];
  showExport?: boolean;
  onRow?: (row: Entry) => void;
  hideToolbar?: boolean;
}) {
  const d = useDesk(),
    b = d.data!;
  const [filters, F] = useState(false),
    [search, S] = useState(d.params.get("q") ?? ""),
    [busy, B] = useState(false);
  const [density, setDensity] = useState<"standard" | "compact">("standard");
  useEffect(() => {
    try {
      if (localStorage.getItem("vanian-table-density") === "compact")
        setDensity("compact");
    } catch {}
  }, []);
  function changeDensity(value: string) {
    const next = value === "compact" ? "compact" : "standard";
    setDensity(next);
    try {
      localStorage.setItem("vanian-table-density", next);
    } catch {}
  }
  const q = d.params.get("q") ?? "";
  useEffect(() => {
    S(q);
  }, [q, d.page.slug]);
  useEffect(() => {
    if (search === q) return;
    const t = setTimeout(() => d.set({ q: search || null, page: null }), 240);
    return () => clearTimeout(t);
  }, [search, q, d.set]);
  const pairs = columns ?? d.page.columns;
  const defs = useMemo<ColumnDef<Entry>[]>(
    () =>
      pairs.map(([key, label]) => ({
        id: key,
        header: label,
        accessorFn: (r) => field(r, key),
        cell: (c) => <Cell k={key} row={c.row.original} />,
      })),
    [pairs],
  );
  const model = useReactTable({
    data: b.rows,
    columns: defs,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (r) => r.id,
  });
  const keys = d.page.filters.filter(
    (k) => k !== "group" && (b.facets?.[k]?.length || d.params.has(k)),
  );
  const actual = keys.filter((k) => d.params.has(k)).length;
  return (
    <section
      className="table-shell card"
      data-tour="records"
      data-density={density}
    >
      <div className="table-title">
        <h2>
          {title}
          <span className="count-tag">{fmt(b.total)}</span>
        </h2>
        {showExport && (
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
                  pairs,
                  d.page.slug,
                );
              } catch (e) {
                d.toast((e as Error).message);
              } finally {
                B(false);
              }
            }}
          >
            <I n="download" size={14} />
            {busy ? "Exporting…" : "Export CSV"}
          </button>
        )}
      </div>
      {!hideToolbar && (
        <div className="table-toolbar">
          <label className="searchbox">
            <I n="search" size={15} />
            <input
              value={search}
              onChange={(e) => S(e.target.value)}
              placeholder="Search records…"
              aria-label="Search records"
            />
          </label>
          {keys.length > 0 && (
            <button
              className={"btn small " + (actual || filters ? "selected" : "")}
              onClick={() => F(!filters)}
              aria-expanded={filters}
            >
              <I n="filter" size={14} />
              Filters {actual || ""}
            </button>
          )}
          <div className="table-density">
            <Select
              label="Row density"
              value={density}
              onChange={changeDensity}
              options={[
                ["standard", "Standard rows"],
                ["compact", "Compact rows"],
              ]}
            />
          </div>
          {actual > 0 && (
            <button
              className="text-btn"
              onClick={() =>
                d.set(Object.fromEntries(keys.map((k) => [k, null])))
              }
            >
              Clear
            </button>
          )}
        </div>
      )}
      {(filters || actual > 0) && (
        <div className="filter-strip">
          {keys.map((k) => (
            <Select
              key={k}
              label={pretty(k)}
              value={d.params.get(k) ?? ""}
              onChange={(v) => d.set({ [k]: v || null, page: null })}
              options={[
                ["", "All " + pretty(k).toLowerCase()],
                ...(b.facets?.[k] ?? []),
              ]}
            />
          ))}
        </div>
      )}
      {b.rows.length ? (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label={title + " table"}
        >
          <table>
            <thead>
              {model.getHeaderGroups().map((h) => (
                <tr key={h.id}>
                  {h.headers.map((col) => (
                    <th
                      key={col.id}
                      scope="col"
                      data-number={numeric.has(col.id) || undefined}
                      aria-sort={
                        d.params.get("sort") === col.id
                          ? d.params.get("dir") === "asc"
                            ? "ascending"
                            : "descending"
                          : "none"
                      }
                    >
                      <button
                        onClick={() =>
                          d.set({
                            sort: col.id,
                            dir:
                              d.params.get("sort") === col.id &&
                              d.params.get("dir") === "asc"
                                ? "desc"
                                : "asc",
                            page: null,
                          })
                        }
                      >
                        {flexRender(
                          col.column.columnDef.header,
                          col.getContext(),
                        )}
                        <I n="sort" size={11} />
                      </button>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {model.getRowModel().rows.map((r) => (
                <tr
                  tabIndex={0}
                  aria-label={"Inspect " + r.original.name}
                  aria-current={
                    d.selectedRowId === r.original.id ? "true" : undefined
                  }
                  key={r.id}
                  onClick={() =>
                    onRow ? onRow(r.original) : d.open(r.original)
                  }
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onRow ? onRow(r.original) : d.open(r.original);
                    }
                  }}
                >
                  {r.getVisibleCells().map((c) => (
                    <td
                      key={c.id}
                      data-number={numeric.has(c.column.id) || undefined}
                    >
                      {flexRender(c.column.columnDef.cell, c.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty
          action={() => {
            d.go(d.page.slug);
          }}
        />
      )}
      <div className="pager">
        <span>
          {b.total
            ? fmt((b.page - 1) * b.pageSize + 1) +
              "–" +
              fmt(Math.min(b.page * b.pageSize, b.total)) +
              " of " +
              fmt(b.total)
            : "0 records"}
        </span>
        <div>
          <Select
            label="Rows per page"
            value={String(b.pageSize)}
            options={["12", "25", "50", "100"]}
            onChange={(v) => d.set({ size: v, page: null })}
          />
          <button
            className="icon-btn"
            aria-label="Previous page"
            disabled={b.page <= 1}
            onClick={() => d.set({ page: String(b.page - 1) })}
          >
            <I n="left" size={15} />
          </button>
          <button
            className="icon-btn"
            aria-label="Next page"
            disabled={b.page * b.pageSize >= b.total}
            onClick={() => d.set({ page: String(b.page + 1) })}
          >
            <I n="right" size={15} />
          </button>
        </div>
      </div>
    </section>
  );
}
