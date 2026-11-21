import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { verifyObserver, evaluateAuthority } from "./observer.mjs";

import { observationSummary } from "./overview.mjs";

class LabArchive extends Error {}
const sources = new Map([
  ["/v1/overview", "overview"],
  ["/v1/posture", "overview"],
  ["/v1/agents/lineage", "events"],
  ["/v1/snifferdog/events", "events"],
  ["/v1/runtime", "events"],
  ["/v1/attribution", "events"],
  ["/v1/evidence", "evidence"],
  ["/v1/verification", "evidence"],
  ["/v1/identity", "authority"],
]);
const roles = new Set(["Administrator", "Analyst", "Auditor"]);
const knownLabKeys = new Set([
  "db060311e2da56e4d864804d0bfaf5dfd6e236a686acc2c9a98afb1dfd5c1899",
  "1924827571fc8b903e00eda3ba9856c6135ea4559b6e67913190243f0deb5b43",
]);
const knownAIPBundles = new Set([
  "9ddb8e0d4b36782a5cd400dd7c30d5139183ff84ba43e943a42da9d97f33dd51",
  "c4efe4fd20f98acd91d23c26f7fe5c62e6b796bbb3e6ef991f92adf483d22d60",
]);
const knownAPIssuers = new Set([
  "936e51b085289310e60bdbf9652aec802f241d7fd0df0f66d61c17ec10372f99",
  "90f96e027f31bcd419e3d10b6b72a6d3e2e3107d3d843607a1b0341fa3dee30a",
]);
function sameSecret(left, right) {
  const hash = (value) => createHash("sha256").update(value).digest();
  return timingSafeEqual(hash(left), hash(right));
}
function response(status, body, tenant) {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "private, no-store",
      "x-content-type-options": "nosniff",
      ...(tenant ? { "X-Vanian-Tenant": tenant } : {}),
    },
  });
}
function error(status, code) {
  return response(status, { error: { code } });
}
function property(row, key) {
  return ["id", "name", "at", "group", "source", "state"].includes(key)
    ? row[key]
    : row.fields[key];
}

export function projectObserver(verified, group, view) {
  if (!verified.accepted || !verified.scope)
    throw Error("Archive verification failed.");
  const scope = verified.scope,
    source = "Sniffer Dog · aip-observe-verify";
  const id = "OBS-" + verified.inputSha256.batches;
  const fields = {
    observer: verified.observerId,
    keyVersion: verified.keyVersion,
    signature: "Verified",
    verification: "Verified",
    key: verified.publicKey,
    archiveSha256: verified.inputSha256.batches,
    healthSha256: verified.inputSha256.health,
    chainHead: scope.finalHead,
    scope: "Signed capture",
    coverageAssertions: scope.withCoverage,
    uncoveredReports: scope.withoutCoverage,
    sensorHealth: scope.health.join(", "),
    sensorConnection: "Offline · archive reader",
    collectorAttestedAt: scope.collectorAttestedAt,
    clockUnstated: scope.clockUnstated,
  };
  if (view === "evidence")
    return [
      {
        id,
        name: "Observer archive",
        at: scope.collectorAttestedAt,
        source,
        group,
        state: "Verified",
        fields: {
          ...fields,
          items: verified.events.length + verified.observations,
          itemsScope: "Entire signed archive",
          batches: scope.records,
          retention: "Operator-managed",
          signer: verified.observerId,
        },
      },
    ];
  return [...verified.events, ...(verified.processSamples ?? [])].map((e) => ({
    id: e.id,
    name: e.kind,
    at: e.collectorAttestedAt,
    group,
    source,
    state: "Observed",
    fields: {
      ...fields,
      actor:
        e.processId == null
          ? e.parentPid == null
            ? "Unbound process"
            : "PID " + e.parentPid
          : "PID " + e.processId,
      agent: "Unbound",
      owner: "Unresolved",
      kind: "Unknown",
      recordKind: e.source === "kernel" ? "Kernel event" : "Process sample",
      sensor: e.probeId,
      mechanism: e.mechanism,
      workload: e.processId == null ? "Unbound process" : "PID " + e.processId,
      parentPid: e.parentPid ?? "Unstated",
      childPid: e.childPid ?? "Unstated",
      monotonicNs: e.monotonicNs ?? "Unstated",
      processBound: e.processBound,
      timeBasis: "Collector attestation",
      batch: id,
      confidence: "Unestablished",
      authorization: "Unresolved",
      processAttribution: e.reportedProcessAttribution,
      executionVerdict: "Not evaluated",
      risk: "Unassessed",
    },
  }));
}
export function projectAuthority(result, group) {
  if (!result.accepted || !result.signedReconciliationVerified)
    throw Error("Reconciliation signature unavailable.");
  return [
    {
      id: result.runId || result.inputSha256.bundle,
      name: result.agentId || "Signed authority record",
      at: result.assessmentTime,
      group,
      source: "AIP · aip-execution-assurance",
      state: result.authorizationVerified
        ? "Authority verified"
        : "Authority unverified",
      fields: {
        agent: result.agentId || "Unbound",
        owner: "Unresolved",
        risk: "Unassessed",
        environment: "Operator archive",
        authorization: result.authorizationVerified ? "Verified" : "Unverified",
        verdict: result.verdict,
        reason: typeof result.reason === "string" ? result.reason : "Unstated",
        receipt: result.gatewayReceiptVerified ? "Verified" : "Unverified",
        disposition: result.gatewayDisposition || "Unstated",
        sourceDigest: result.inputSha256.bundle,
        trustDigest: result.inputSha256.trust,
        scope: "Signed run evaluation",
      },
    },
  ];
}
export function observedGraph(row) {
  if (!row) return { nodes: [], edges: [] };
  const evidence = String(row.fields.batch),
    at = row.at,
    nodes = [],
    edges = [];
  const node = (suffix, label, kind, scope) => {
    const id = row.id + "#" + suffix;
    nodes.push({ id, label, kind, scope, at, evidence, status: "Observed" });
    return id;
  };
  const link = (source, target, label) =>
    edges.push({ source, target, label, relation: "observed", at, evidence });
  if (
    row.name === "Fork" &&
    Number.isInteger(row.fields.parentPid) &&
    Number.isInteger(row.fields.childPid)
  ) {
    const a = node(
      "parent",
      "PID " + row.fields.parentPid,
      "process",
      "Parent PID at this kernel event",
    );
    const b = node(
      "child",
      "PID " + row.fields.childPid,
      "process",
      "Child PID at this kernel event",
    );
    link(a, b, "Kernel-reported fork");
  } else {
    const event = node(
      "record",
      row.name,
      "action",
      String(row.fields.recordKind),
    );
    if (String(row.fields.workload).startsWith("PID ")) {
      const proc = node(
        "process",
        String(row.fields.workload),
        "process",
        "PID at this signed record",
      );
      link(
        proc,
        event,
        row.fields.recordKind === "Process sample"
          ? "Measured in sample"
          : "Recorded in kernel event",
      );
    }
  }
  return { nodes, edges };
}
export function listing(
  rows,
  verified,
  params,
  group,
  role,
  source,
  includeSummary = false,
) {
  const days = Number(params.get("days") || 7),
    size = Number(params.get("size") || 25),
    page = Number(params.get("page") || 1);
  if (
    ![1, 7, 14, 30].includes(days) ||
    !Number.isInteger(page) ||
    page < 1 ||
    !Number.isInteger(size) ||
    size < 1 ||
    size > 100
  )
    throw RangeError("Invalid pagination.");
  const end = new Date(),
    start = new Date(end);
  start.setUTCHours(0, 0, 0, 0);
  start.setUTCDate(start.getUTCDate() - days + 1);
  const requested = params.get("group") || "All groups",
    inGroup =
      requested === "All groups" || requested === "all" || requested === group;
  let eligible = inGroup ? rows : [];
  const q = (params.get("q") || "").toLowerCase();
  if (q)
    eligible = eligible.filter((row) =>
      [row.name, row.id, row.state, ...Object.values(row.fields)].some((x) =>
        String(x).toLowerCase().includes(q),
      ),
    );
  const filters = [
    "state",
    "kind",
    "sensor",
    "verification",
    "risk",
    "app",
    "day",
    "guardrail",
    "classification",
    "agent",
    "recordKind",
  ];
  for (const key of filters) {
    const v = params.get(key);
    if (v)
      eligible = eligible.filter(
        (row) =>
          String(
            key === "day" ? row.at.slice(0, 10) : (property(row, key) ?? ""),
          ) === v,
      );
  }
  const from = start.toISOString(),
    to = end.toISOString();
  const subset = eligible.filter((row) => row.at >= from && row.at <= to);
  const sort = params.get("sort") || "at",
    dir = params.get("dir") === "asc" ? 1 : -1;
  subset.sort((a, b) => {
    const x = property(a, sort),
      y = property(b, sort);
    return (
      dir *
      (typeof x === "number" && typeof y === "number"
        ? x - y
        : String(x ?? "").localeCompare(String(y ?? "")) ||
          a.id.localeCompare(b.id))
    );
  });
  const id = params.get("id"),
    selected = id ? subset.find((row) => row.id === id) : undefined;
  const asOf = verified.scope?.collectorAttestedAt || verified.assessmentTime;
  const meta = {
    mode: "live",
    source,
    asOf,
    processedAt: verified.verifiedAt,
    status: "Verified archive · live sensor offline",
    start: from,
    end: to,
    group: requested,
    role,
    days,
  };
  return {
    meta,
    ...(includeSummary ? observationSummary(eligible, subset, meta) : {}),
    rows: subset.slice((page - 1) * size, page * size),
    total: subset.length,
    page,
    pageSize: size,
    groups: [group],
    ...(selected ? { selected } : {}),
    facets: Object.fromEntries(
      filters.map((key) => [
        key,
        [
          ...new Set(
            subset
              .map((row) => property(row, key))
              .filter((x) => x != null)
              .map(String),
          ),
        ],
      ]),
    ),
  };
}
export function createReader(config, token) {
  if (
    config?.sourceClassification !== "customer-runtime" ||
    !config.tenant ||
    !config.group ||
    !config.members ||
    typeof token !== "string" ||
    token.length < 32
  )
    throw Error(
      "Configure the tenant, group, membership, customer-runtime classification and service credential.",
    );
  if (Object.values(config.members).some((role) => !roles.has(role)))
    throw Error("Invalid membership configuration.");
  return async function handle(request) {
    if (
      !sameSecret(request.headers.get("authorization") || "", "Bearer " + token)
    )
      return error(401, "UNAUTHENTICATED");
    const tenant = request.headers.get("x-vanian-tenant"),
      subject = request.headers.get("x-vanian-subject"),
      role = request.headers.get("x-vanian-role");
    if (
      tenant !== config.tenant ||
      !subject ||
      !roles.has(role) ||
      !Object.hasOwn(config.members, subject) ||
      role !== config.members[subject]
    )
      return error(403, "ACCESS_DENIED");
    if (request.method !== "GET") return error(405, "READ_ONLY");
    const url = new URL(request.url),
      view = sources.get(url.pathname);
    if (!view) return error(501, "UNSUPPORTED_SOURCE");
    try {
      let verified, rows, source;
      if (view === "authority") {
        if (!config.authority) return error(503, "AUTHORITY_UNAVAILABLE");
        verified = await evaluateAuthority({
          ...config.authority,
          provenance: "Operator-owned customer archive",
          validateTrust: (context) => {
            if (knownAPIssuers.has(context.observer_public_key_hex))
              throw new LabArchive();
          },
        });
        if (
          knownAPIssuers.has(verified.trustObserverKey) ||
          knownAIPBundles.has(verified.inputSha256.bundle)
        )
          return error(422, "LAB_ARCHIVE");
        rows = projectAuthority(verified, config.group);
        source = "AIP signed run archive";
      } else {
        if (!config.observer) return error(503, "OBSERVER_UNAVAILABLE");
        if (knownLabKeys.has(String(config.observer.publicKey).toLowerCase()))
          return error(422, "LAB_ARCHIVE");
        verified = await verifyObserver({
          ...config.observer,
          provenance: "Operator-owned customer archive",
        });
        rows = projectObserver(verified, config.group, view);
        source = "Sniffer Dog signed observer archive";
      }
      const body = listing(
        rows,
        verified,
        url.searchParams,
        config.group,
        role,
        source,
        view === "overview",
      );
      if (view === "events")
        body.graph = observedGraph(
          url.searchParams.has("id") ? body.selected : body.rows[0],
        );
      return response(200, body, tenant);
    } catch (e) {
      if (e instanceof LabArchive) return error(422, "LAB_ARCHIVE");
      return error(
        e instanceof RangeError ? 400 : 503,
        e instanceof RangeError ? "INVALID_QUERY" : "VERIFICATION_UNAVAILABLE",
      );
    }
  };
}
async function main() {
  const config = JSON.parse(await readFile(process.argv[2], "utf8")),
    token = process.env.VANIAN_BRIDGE_TOKEN;
  const handle = createReader(config, token);
  const port = Number(config.port ?? 8874);
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw Error("Invalid bridge port.");
  const server = createServer(async (req, res) => {
    try {
      const route = new URL(req.url || "/", "http://127.0.0.1");
      const request = new Request(route, {
        method: req.method,
        headers: req.headers,
      });
      const result = await handle(request);
      res.writeHead(result.status, Object.fromEntries(result.headers));
      res.end(await result.text());
    } catch {
      res.writeHead(400, { "cache-control": "no-store" });
      res.end();
    }
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  server.listen(port, "127.0.0.1", () =>
    console.log(
      "VANIAN read-only archive bridge listening on local port " +
        server.address().port,
    ),
  );
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch((e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
