"use client";
import { useState, useId, useEffect, useRef } from "react";
import type { Count, Point } from "../types";
import { useDesk } from "./context";
import { I, fmt, money } from "./primitives";
const colors = [
  "#702ced",
  "#aa7af1",
  "#cbb4f1",
  "#e4d7f6",
  "#786e99",
  "#c8b9df",
];
const riskColors: Record<string, string> = {
  Critical: "#c62b49",
  High: "#e77468",
  Medium: "#e3a237",
  Low: "#52a595",
  Agent: "#7542e6",
  Human: "#baa5e9",
  Unknown: "#8992a6",
};
function path(points: number[][]) {
  return points.map(([x, y], i) => (i ? "L" : "M") + x + " " + y).join(" ");
}
export function Spark({ values, color }: { values: number[]; color: string }) {
  const id = useId().replaceAll(":", ""),
    lo = Math.min(...values),
    hi = Math.max(...values);
  const pts = values.map((v, i) => [
    2 + (i * 94) / Math.max(1, values.length - 1),
    24 - (hi === lo ? 9 : ((v - lo) / (hi - lo)) * 17),
  ]);
  const d = path(pts);
  return (
    <svg
      role="img"
      aria-label="Trend within selected period"
      className="spark"
      viewBox="0 0 100 31"
    >
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity=".18" />
          <stop offset="1" stopColor={color} stopOpacity=".01" />
        </linearGradient>
      </defs>
      <path d={d + " L96 31 L2 31Z"} fill={"url(#" + id + ")"} />
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth="2.1"
        strokeLinecap="round"
      />
    </svg>
  );
}
export function TimeChart({
  points,
  spend = false,
  onDay,
}: {
  points: Point[];
  spend?: boolean;
  onDay?: (at: string) => void;
}) {
  const [hover, H] = useState<number | null>(null);
  const id = useId().replaceAll(":", "");
  const vals = points.map((p) => (spend ? p.spend : p.interactions)),
    other = points.map((p) => p.executions);
  const footprint = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(612);
  useEffect(() => {
    if (!footprint.current) return;
    const resize = new ResizeObserver(([entry]) =>
      setWidth(Math.max(180, Math.round(entry.contentRect.width))),
    );
    resize.observe(footprint.current);
    return () => resize.disconnect();
  }, []);
  const high = Math.max(spend ? 0.01 : 1, ...vals, ...(spend ? [] : other));
  const rough = high / 3;
  const magnitude = 10 ** Math.floor(Math.log10(rough));
  const step = Math.max(
    spend ? 0.01 : 1,
    ([1, 2, 5, 10].find((n) => n * magnitude >= rough) ?? 10) * magnitude,
  );
  const ticks = Math.ceil(high / step);
  const max = ticks * step;
  const left = spend ? 48 : 32,
    right = width - 10;
  const x = (i: number) =>
    points.length === 1
      ? (left + right) / 2
      : left + (i * (right - left)) / Math.max(1, points.length - 1);
  const y = (v: number) => 133 - (v / max) * 108;
  const line = (v: number[]) => path(v.map((p, i) => [x(i), y(p)]));
  const a = line(vals);
  const selected = hover === null ? null : points[hover];
  return (
    <div className="chart-wrap" ref={footprint}>
      <svg
        className="timechart"
        viewBox={"0 0 " + width + " 161"}
        preserveAspectRatio="none"
        role="group"
        aria-label={
          spend
            ? "AI cost by time period"
            : "AI interactions and attributed agent executions by time period"
        }
        onMouseLeave={() => H(null)}
      >
        <defs>
          <linearGradient id={"area" + id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#8542ea" stopOpacity=".10" />
            <stop offset="1" stopColor="#a36add" stopOpacity=".015" />
          </linearGradient>
        </defs>
        {Array.from({ length: ticks + 1 }, (_, i) => {
          const n = step * i;
          return (
            <g key={i}>
              <line
                x1={left}
                x2={right}
                y1={y(n)}
                y2={y(n)}
                stroke="var(--plot-grid)"
                strokeDasharray="2 4"
              />
              <text x={left - 7} y={y(n) + 3} textAnchor="end">
                {spend ? "$" : ""}
                {spend && step < 1 ? n.toFixed(2) : fmt(n)}
              </text>
            </g>
          );
        })}
        {points.length > 0 && (
          <>
            <path
              d={a + " L" + x(points.length - 1) + " 133 L" + x(0) + " 133 Z"}
              fill={"url(#area" + id + ")"}
            />
            <path
              d={a}
              fill="none"
              stroke="#783be1"
              strokeWidth="2.4"
              vectorEffect="non-scaling-stroke"
              strokeLinejoin="round"
            />
            {!spend && (
              <path
                d={line(other)}
                fill="none"
                stroke="#ab8add"
                strokeDasharray="5 4"
                strokeWidth="2"
                vectorEffect="non-scaling-stroke"
              />
            )}
          </>
        )}
        {points.map((p, i) => (
          <g key={p.at}>
            {((points.length <= 8 && width > 420) ||
              i === 0 ||
              i === points.length - 1 ||
              i % Math.ceil(points.length / (width < 420 ? 3 : 6)) === 0) && (
              <text
                x={x(i)}
                y="154"
                textAnchor={
                  i === points.length - 1 ? "end" : i === 0 ? "start" : "middle"
                }
              >
                {p.label}
              </text>
            )}
            <rect
              x={Math.max(
                left,
                x(i) - (right - left) / Math.max(1, points.length - 1) / 2,
              )}
              y="13"
              width={
                points.length === 1
                  ? (right - left) / 2
                  : ((right - left) / (points.length - 1)) *
                    (i === 0 || i === points.length - 1 ? 0.5 : 1)
              }
              height="124"
              fill="transparent"
              tabIndex={0}
              role="button"
              aria-label={
                p.label +
                " · " +
                fmt(vals[i]) +
                " " +
                (spend ? "USD" : "interactions") +
                ". Open events"
              }
              onMouseEnter={() => H(i)}
              onFocus={() => H(i)}
              onBlur={() => H(null)}
              onClick={() => onDay?.(p.at)}
              onKeyDown={(e) => {
                if (e.key === "Enter") onDay?.(p.at);
              }}
            />
          </g>
        ))}
        {selected && hover !== null && (
          <g pointerEvents="none">
            <line
              x1={x(hover)}
              x2={x(hover)}
              y1="12"
              y2="132"
              stroke="#9474c6"
              strokeDasharray="3 3"
            />
            <circle
              cx={x(hover)}
              cy={y(vals[hover])}
              r="4"
              fill="#7637e2"
              stroke="white"
              strokeWidth="2"
            />
          </g>
        )}
      </svg>
      {selected && (
        <div className="chart-tooltip" role="status">
          {selected.label} ·{" "}
          {spend
            ? money(selected.spend)
            : fmt(selected.interactions) +
              " interactions · " +
              fmt(selected.executions) +
              " agent executions"}
        </div>
      )}
    </div>
  );
}
export function Bars({
  items,
  financial = false,
  onClick,
  limit = 5,
}: {
  items: Count[];
  financial?: boolean;
  onClick?: (s: string) => void;
  limit?: number;
}) {
  const max = Math.max(...items.map((r) => r.value), 1);
  return (
    <div className="bars">
      {items.slice(0, limit).map((r, i) => (
        <button
          key={r.name}
          disabled={!onClick}
          onClick={() => onClick?.(r.name)}
        >
          <span>{r.name}</span>
          <i>
            <b
              style={{
                width: (r.value / max) * 100 + "%",
                background: colors[i % colors.length],
              }}
            />
          </i>
          <strong>{financial ? money(r.value) : fmt(r.value)}</strong>
        </button>
      ))}
      {!items.length && (
        <p className="muted">No observations in this window.</p>
      )}
    </div>
  );
}
export function Donut({
  items,
  label = "events",
  onClick,
}: {
  items: Count[];
  label?: string;
  onClick?: (s: string) => void;
}) {
  const sum = items.reduce((n, r) => n + r.value, 0);
  let start = 0;
  return (
    <div className="donut-row">
      <div className="donut">
        <svg
          viewBox="0 0 120 120"
          role="img"
          aria-label={items.map((r) => r.name + " " + r.value).join(", ")}
        >
          <circle
            r="45"
            cx="60"
            cy="60"
            fill="none"
            stroke="var(--plot-grid)"
            strokeWidth="12"
          />
          {items.map((r, i) => {
            const frac = (r.value / Math.max(1, sum)) * 100,
              offset = -start;
            start += frac;
            return (
              <circle
                key={r.name}
                cx="60"
                cy="60"
                r="45"
                pathLength="100"
                fill="none"
                stroke={riskColors[r.name] ?? colors[i % colors.length]}
                strokeWidth="12"
                strokeDasharray={
                  Math.max(0, frac - 1.15) + " " + (100 - frac + 1.15)
                }
                strokeDashoffset={offset}
                transform="rotate(-90 60 60)"
              />
            );
          })}
        </svg>
        <span>
          <b>{fmt(sum)}</b>
          <small>{label}</small>
        </span>
      </div>
      <div className="donut-key">
        {items.map((r, i) => (
          <button
            key={r.name}
            onClick={() => onClick?.(r.name)}
            disabled={!onClick}
          >
            <i
              style={{
                background: riskColors[r.name] ?? colors[i % colors.length],
              }}
            />
            {r.name}
            <strong>{fmt(r.value)}</strong>
          </button>
        ))}
      </div>
    </div>
  );
}
export function CostChart({ items }: { items: Count[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const { go } = useDesk();
  useEffect(() => {
    let disposed = false;
    let instance: any, observer: ResizeObserver | undefined;
    (async () => {
      const [ec, charts, comp, render] = await Promise.all([
        import("echarts/core"),
        import("echarts/charts"),
        import("echarts/components"),
        import("echarts/renderers"),
      ]);
      if (disposed || !ref.current) return;
      ec.use([
        charts.BarChart,
        comp.GridComponent,
        comp.TooltipComponent,
        render.SVGRenderer,
      ]);
      instance = ec.init(ref.current, undefined, { renderer: "svg" });
      const data = items.slice(0, 8).reverse();
      instance.setOption({
        animation: false,
        textStyle: { fontFamily: "Inter Variable, sans-serif", fontSize: 11 },
        grid: { left: 115, right: 35, top: 10, bottom: 34 },
        tooltip: { trigger: "axis", valueFormatter: (n: number) => money(n) },
        xAxis: {
          type: "value",
          axisLabel: { formatter: "${value}" },
          splitLine: { lineStyle: { type: "dashed", color: "#e8e3f2" } },
        },
        yAxis: {
          type: "category",
          data: data.map((x) => x.name),
          axisLine: { show: false },
          axisTick: { show: false },
        },
        series: [
          {
            type: "bar",
            data: data.map((x) => x.value),
            barMaxWidth: 19,
            itemStyle: { color: "#8a50e9", borderRadius: [0, 4, 4, 0] },
          },
        ],
      });
      instance.on("click", (v: { name: string }) =>
        go("ai-finops?q=" + encodeURIComponent(v.name)),
      );
      observer = new ResizeObserver(() => instance?.resize());
      observer.observe(ref.current);
    })().catch(() => {});
    return () => {
      disposed = true;
      observer?.disconnect();
      instance?.dispose();
    };
  }, [items, go]);
  return (
    <div
      ref={ref}
      className="costchart"
      role="img"
      aria-label={items.map((x) => x.name + " " + money(x.value)).join(", ")}
    />
  );
}
