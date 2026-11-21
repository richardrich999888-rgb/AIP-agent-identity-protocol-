"use client";
import { useState } from "react";
import { Card } from "./Home";
import { useDesk, request } from "./context";
import { Field, Select, I, Badge, stamp, money, fmt } from "./primitives";
export function DlpTest() {
  const d = useDesk(),
    [sample, S] = useState("Customer contact"),
    [treatment, T] = useState("Mask"),
    [result, R] = useState<any>(null),
    [err, E] = useState(""),
    [busy, B] = useState(false);
  return (
    <Card
      title="Test a data protection control"
      sub="Apply a treatment to a predefined synthetic sample."
    >
      <div className="form-grid">
        <Field label="Test sample">
          <Select
            label="Test sample"
            value={sample}
            options={[
              "Customer contact",
              "Financial record",
              "Service token",
              "Public summary",
            ]}
            onChange={(v) => {
              S(v);
              R(null);
            }}
          />
        </Field>
        <Field label="Treatment">
          <Select
            label="Treatment"
            value={treatment}
            onChange={(v) => {
              T(v);
              R(null);
            }}
            options={["Mask", "Redact", "Tokenize"]}
          />
        </Field>
      </div>
      <button
        className="btn"
        disabled={busy}
        onClick={async () => {
          B(true);
          E("");
          try {
            R(
              await request("protection/data/test", d.mode, d.params, {
                sample,
                treatment,
              }),
            );
          } catch (e) {
            E((e as Error).message);
          } finally {
            B(false);
          }
        }}
      >
        <I n="play" size={13} />
        Test treatment
      </button>
      {result && (
        <div role="status">
          <blockquote>{result.output}</blockquote>
          <small>
            {result.findings.join(", ") || "No matching patterns"} ·{" "}
            {result.source} · {stamp(result.processedAt, true)} ·{" "}
            {result.status}
          </small>
        </div>
      )}
      {err && <p className="error-msg">{err}</p>}
    </Card>
  );
}
export function CostProjection() {
  const d = useDesk(),
    b = d.data!,
    [rate, R] = useState(""),
    [share, S] = useState("100");
  const s = b.stats ?? {},
    pct = Number(share) / 100,
    valid =
      rate.trim() !== "" &&
      Number.isFinite(Number(rate)) &&
      Number(rate) >= 0 &&
      pct > 0 &&
      pct <= 1;
  const forecast = (s.tokens * pct * Number(rate)) / 1e6,
    baseline = s.cost * pct;
  const daily = b.trend ?? [];
  const mean =
    daily.length > 1
      ? daily.slice(0, -1).reduce((n, x) => n + x.spend, 0) / (daily.length - 1)
      : null;
  const latest = daily.at(-1)?.spend;
  return (
    <div className="double">
      <Card
        title="Routing cost projection"
        sub="Apply an alternative price to the same token volume."
      >
        <div className="form-grid">
          <Field label="Alternative USD per million tokens">
            <input
              type="number"
              min="0"
              step=".01"
              placeholder="Enter benchmark rate"
              value={rate}
              onChange={(e) => R(e.target.value)}
            />
          </Field>
          <Field label="Eligible traffic (%)">
            <input
              type="number"
              min="1"
              max="100"
              value={share}
              onChange={(e) => S(e.target.value)}
            />
          </Field>
        </div>
        {valid ? (
          <p role="status">
            <b>{money(baseline - forecast)}</b> projected difference for{" "}
            {fmt(s.tokens * pct)} tokens. Alternative cost {money(forecast)}.{" "}
            <Badge kind="violet">Estimate</Badge>
          </p>
        ) : (
          <p className="muted">
            Enter a benchmark rate to estimate a routing change.
          </p>
        )}
      </Card>
      <Card
        title="Cost anomalies"
        sub="Latest reporting bucket against earlier buckets in this window."
      >
        {mean !== null && latest !== undefined ? (
          <>
            <p>
              <b>{money(latest)}</b> in the latest bucket · {money(mean)} prior
              average
            </p>
            <p className="notice">
              {latest > mean * 1.5
                ? "Review elevated spend"
                : "Within the 1.5× review threshold"}
            </p>
          </>
        ) : (
          <p className="muted">
            A comparison requires at least two reporting buckets.
          </p>
        )}
        <small>
          {b.meta.source} · {stamp(b.meta.asOf)}
        </small>
      </Card>
    </div>
  );
}
