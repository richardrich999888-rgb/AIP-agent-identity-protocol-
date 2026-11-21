const dayMs = 86_400_000;
const measures = [
  {
    key: "archiveRecords",
    label: "Signed observations",
    condition: () => true,
    href: "runtime-activity",
    info: "All process samples and kernel records in this signed archive.",
  },
  {
    key: "kernelRecords",
    label: "Kernel events",
    condition: (row) => row.fields.recordKind === "Kernel event",
    href: "runtime-activity?recordKind=Kernel+event",
    info: "Individual kernel events reported in the archive.",
  },
  {
    key: "processSamples",
    label: "Process samples",
    condition: (row) => row.fields.recordKind === "Process sample",
    href: "runtime-activity?recordKind=Process+sample",
    info: "Individual process observations collected by the observer.",
  },
  {
    key: "unboundRecords",
    label: "Unbound observations",
    condition: (row) => row.fields.agent === "Unbound",
    href: "attribution?agent=Unbound",
    info: "Observed records with unresolved logical agent identity.",
  },
];
export function observationSummary(rows, current, meta) {
  const start = Date.parse(meta.start);
  const previousStart = new Date(start - dayMs * meta.days).toISOString();
  const prior = rows.filter(
    (row) => row.at >= previousStart && row.at < meta.start,
  );
  const dates = Array.from({ length: meta.days }, (_, index) =>
    new Date(start + index * dayMs).toISOString().slice(0, 10),
  );
  const metrics = measures.map(({ key, label, condition, href, info }) => {
    const buckets = new Map(dates.map((date) => [date, 0]));
    let value = 0;
    for (const row of current) {
      if (!condition(row)) continue;
      const date = row.at.slice(0, 10);
      buckets.set(date, buckets.get(date) + 1);
      value++;
    }
    return {
      key,
      label,
      href,
      info:
        info +
        " Counts use collector attestation times. Missing archive observations do not establish absence on the host.",
      source: meta.source,
      value,
      prior: prior.filter(condition).length,
      series: Array.from(buckets.values()),
    };
  });
  const kinds = new Map();
  for (const row of current)
    kinds.set(
      row.fields.recordKind,
      (kinds.get(row.fields.recordKind) ?? 0) + 1,
    );
  return {
    metrics,
    summaries: {
      archiveActivity: dates.map((name, i) => ({
        name,
        value: metrics[0].series[i],
      })),
      recordKinds: [...kinds]
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value || a.name.localeCompare(b.name)),
    },
  };
}
