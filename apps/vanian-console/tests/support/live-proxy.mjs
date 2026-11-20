import assert from "node:assert/strict";
import { createServer } from "node:https";
import { once } from "node:events";
import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createReader } from "../../bridge/service.mjs";
const { live } = await import(pathToFileURL(process.env.VANIAN_LIVE_SOURCE));
const dir = process.argv[2],
  token = randomBytes(32).toString("hex");
const anchor = JSON.parse(await readFile(join(dir, "anchor.json")));
const source = createReader(
  {
    sourceClassification: "customer-runtime",
    tenant: "tenant-under-test",
    group: "Engineering",
    members: { "test-subject": "Analyst" },
    observer: {
      ...anchor,
      binary: process.env.OBSERVER_VERIFIER,
      batches: join(dir, "batches.jsonl"),
      health: join(dir, "health.jsonl"),
    },
  },
  token,
);
let followedRedirects = 0;
const server = createServer(
  {
    key: await readFile(join(dir, "key.pem")),
    cert: await readFile(join(dir, "cert.pem")),
  },
  async (req, res) => {
    if (req.url === "/forbidden-hop") followedRedirects++;
    if (req.url.endsWith("?q=redirect-test")) {
      res.writeHead(302, { Location: "/forbidden-hop" });
      res.end();
      return;
    }
    try {
      const output = await source(
        new Request(new URL(req.url, "https://127.0.0.1"), {
          headers: req.headers,
        }),
      );
      res.writeHead(output.status, Object.fromEntries(output.headers));
      res.end(await output.text());
    } catch {
      res.writeHead(500);
      res.end();
    }
  },
);
server.listen(0, "127.0.0.1");
await once(server, "listening");
try {
  const env = {
    VANIAN_API_ORIGIN: "https://127.0.0.1:" + server.address().port,
    VANIAN_API_TOKEN: token,
    VANIAN_LIVE_MEMBERS: JSON.stringify({
      "test-subject": { tenant: "tenant-under-test", role: "Analyst" },
    }),
  };
  const request = new Request("https://console.invalid/api/snifferdog/events", {
    headers: { "oai-authenticated-user-id": "test-subject" },
  });
  const call = (resource, query = "", override = {}) =>
    live(request, resource, new URLSearchParams(query), {
      ...env,
      ...override,
    });
  await assert.rejects(
    call("evidence", "q=redirect-test"),
    (error) => error.code === "SOURCE_REDIRECT",
  );
  assert.equal(followedRedirects, 0);
  const x = await call("snifferdog/events", "days=1&kind=Unknown");
  assert.equal(x.meta.mode, "live");
  assert.equal(x.total, 3);
  assert.equal(x.rows[0].fields.agent, "Unbound");
  assert.equal(x.meta.role, "Analyst");
  assert.match(x.meta.status, /sensor offline/);
  const summary = await call("overview", "days=1&size=1");
  assert.equal(summary.total, 3);
  assert.equal(summary.rows.length, 1);
  assert.deepEqual(
    summary.metrics.map((x) => x.value),
    [3, 0, 3, 3],
  );
  assert.equal(summary.summaries.archiveActivity[0].value, 3);
  assert.equal((await call("runtime", "recordKind=Process+sample")).total, 3);
  assert.equal((await call("runtime", "recordKind=Kernel+event")).total, 0);
  assert.equal((await call("overview", "group=Finance")).metrics[0].value, 0);
  const lineage = await call("agents/lineage", "days=1");
  assert.ok(lineage.graph.edges.every((edge) => edge.relation === "observed"));
  assert.ok(lineage.graph.nodes.every((node) => node.kind !== "agent"));
  const e = await call("evidence");
  assert.equal(e.rows[0].state, "Verified");
  const v = await call("verification");
  assert.equal(v.rows[0].fields.chainHead, e.rows[0].fields.chainHead);
  const g = await call("snifferdog/events", "group=NoSuchGroup");
  assert.equal(g.total, 0);
  await assert.rejects(
    call("evidence", "", {
      VANIAN_LIVE_MEMBERS: JSON.stringify({
        "test-subject": { tenant: "unrelated", role: "Analyst" },
      }),
    }),
  );
  await assert.rejects(call("evidence", "", { VANIAN_API_TOKEN: "incorrect" }));
  const { observationStream } = await import(
    new URL("stream.ts", pathToFileURL(process.env.VANIAN_LIVE_SOURCE))
  );
  const feed = await observationStream(
    request,
    new URLSearchParams("days=1"),
    env,
  );
  assert.match(feed.headers.get("Content-Type"), /text\/event-stream/);
  const reader = feed.body.getReader(),
    decode = new TextDecoder();
  const initial = decode.decode((await reader.read()).value);
  assert.match(initial, /event: snapshot/);
  assert.deepEqual(
    JSON.parse(initial.split("data: ")[1]).records,
    x.rows.map((record) => record.id),
  );
  await writeFile(join(dir, "health.jsonl"), "");
  const lost = decode.decode((await reader.read()).value);
  assert.match(lost, /event: unavailable/);
  assert.equal((await reader.read()).done, true);
  await assert.rejects(call("evidence"));
  console.log(
    "Authenticated HTTPS console-to-native round trip and rejection paths verified.",
  );
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
