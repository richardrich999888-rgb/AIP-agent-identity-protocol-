import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { promisify } from "node:util";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  createReader,
  listing,
  observedGraph,
  projectObserver,
} from "../bridge/service.mjs";
import { verifyObserver } from "../bridge/observer.mjs";
const call = promisify(execFile);
const token = randomBytes(32).toString("hex");
const config = {
  sourceClassification: "customer-runtime",
  tenant: "test-tenant",
  group: "Engineering",
  members: { operator: "Analyst" },
};
const headers = {
  authorization: "Bearer " + token,
  "x-vanian-tenant": config.tenant,
  "x-vanian-subject": "operator",
  "x-vanian-role": "Analyst",
};
function request(path, changes = {}, method = "GET") {
  return new Request("https://internal.invalid/v1/" + path, {
    method,
    headers: { ...headers, ...changes },
  });
}
test("bridge requires a complete service configuration", () => {
  assert.throws(() =>
    createReader({ ...config, sourceClassification: "archived-lab" }, token),
  );
  assert.throws(() => createReader(config, "test"));
  assert.throws(() =>
    createReader({ ...config, members: { operator: "root" } }, token),
  );
});
test("reader rejects wrong token, tenant, role, subject and mutation before opening archives", async () => {
  const handle = createReader(config, token);
  for (const [change, status] of [
    [{ authorization: "Bearer incorrect" }, 401],
    [{ "x-vanian-tenant": "different" }, 403],
    [{ "x-vanian-role": "Administrator" }, 403],
    [{ "x-vanian-subject": "unknown" }, 403],
    [{ "x-vanian-subject": "__proto__" }, 403],
  ]) {
    const r = await handle(request("snifferdog/events", change));
    assert.equal(r.status, status);
    assert.equal(r.headers.get("x-vanian-tenant"), null);
    assert.equal((await r.json()).rows, undefined);
  }
  assert.equal((await handle(request("evidence", {}, "POST"))).status, 405);
});
test("unconnected, unsupported and historical sources do not supply live metrics", async () => {
  const read = createReader(config, token);
  assert.equal((await read(request("snifferdog/events"))).status, 503);
  assert.equal((await read(request("identity"))).status, 503);
  assert.equal((await read(request("overview"))).status, 503);
  assert.equal((await read(request("discovery/apps"))).status, 501);
  const f = new URL("../public/upstream-replay/fixtures/", import.meta.url);
  const obs = JSON.parse(await readFile(new URL("t09-trust.json", f)));
  const gap = await createReader(
    { ...config, observer: obs },
    token,
  )(request("verification"));
  assert.equal(gap.status, 422);
  assert.equal((await gap.json()).error.code, "LAB_ARCHIVE");
  const directory = await mkdtemp(join(tmpdir(), "vanian-scope-"));
  try {
    const bundle = join(directory, "bundle.json");
    await writeFile(bundle, "{}");
    const aip = await createReader(
      {
        ...config,
        authority: {
          binary: "/unused",
          bundle,
          trust: fileURLToPath(new URL("same-run-trust.json", f)),
        },
      },
      token,
    )(request("identity"));
    assert.equal(aip.status, 422);
    assert.equal((await aip.json()).error.code, "LAB_ARCHIVE");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
test("time windows exclude older authenticated records", () => {
  const now = new Date(),
    old = new Date(now.getTime() - 9 * 864e5),
    verified = {
      verifiedAt: now.toISOString(),
      scope: { collectorAttestedAt: now.toISOString() },
    };
  const rows = [
    {
      id: "now",
      name: "Current",
      state: "Observed",
      at: now.toISOString(),
      group: "Engineering",
      source: "Observer",
      fields: {},
    },
    {
      id: "old",
      name: "Historical",
      state: "Observed",
      at: old.toISOString(),
      group: "Engineering",
      source: "Observer",
      fields: {},
    },
  ];
  assert.equal(
    listing(
      rows,
      verified,
      new URLSearchParams("days=1"),
      "Engineering",
      "Auditor",
      "Observer",
    ).total,
    1,
  );
  assert.equal(
    listing(
      rows,
      verified,
      new URLSearchParams("days=30"),
      "Engineering",
      "Auditor",
      "Observer",
    ).total,
    2,
  );
});
test(
  "native HTTP projection accepts fresh self-process samples, filters rows and withholds raw data",
  {
    skip: !process.env.OBSERVER_VERIFIER || !process.env.SELF_SAMPLE_GENERATOR,
  },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "vanian-service-test-"));
    try {
      await call(process.env.SELF_SAMPLE_GENERATOR, [dir]);
      const trust = JSON.parse(await readFile(join(dir, "anchor.json")));
      const observer = {
        ...trust,
        binary: process.env.OBSERVER_VERIFIER,
        batches: join(dir, "batches.jsonl"),
        health: join(dir, "health.jsonl"),
      };
      const read = createReader({ ...config, observer }, token);
      const get = async (path) => {
        const r = await read(request(path));
        assert.equal(r.status, 200);
        assert.equal(r.headers.get("x-vanian-tenant"), config.tenant);
        return r.json();
      };
      const collection = await get(
        "snifferdog/events?days=1&size=1&page=1&sort=id&dir=asc&group=Engineering",
      );
      assert.equal(collection.meta.mode, "live");
      assert.equal(collection.meta.role, "Analyst");
      assert.match(collection.meta.status, /live sensor offline/);
      assert.equal(collection.total, 3);
      assert.equal(collection.rows.length, 1);
      const first = collection.rows[0];
      assert.equal(first.name, "ProcessPresent");
      assert.equal(first.fields.kind, "Unknown");
      assert.equal(first.fields.recordKind, "Process sample");
      assert.equal(first.fields.agent, "Unbound");
      assert.equal(collection.graph.edges[0].label, "Measured in sample");
      assert.deepEqual(collection.graph.nodes.map((n) => n.kind).sort(), [
        "action",
        "process",
      ]);
      assert.equal(first.fields.verification, "Verified");
      assert.match(first.fields.sensorConnection, /Offline/);
      const raw = JSON.parse(await readFile(observer.batches, "utf8"));
      const exePath = raw.batch.observations[0].observed.exe_path;
      assert.ok(exePath);
      assert.ok(!JSON.stringify(collection).includes(exePath));
      assert.ok(!JSON.stringify(collection).includes("signature_bytes"));
      assert.equal((await get("snifferdog/events?group=Finance")).total, 0);
      assert.equal((await get("snifferdog/events?kind=Agent")).total, 0);
      assert.equal((await get("snifferdog/events?q=unmatched-query")).total, 0);
      assert.equal(
        (
          await get(
            "snifferdog/events?kind=Unknown&verification=Verified&sensor=probe-test",
          )
        ).total,
        3,
      );
      assert.notEqual(
        (await get("snifferdog/events?size=1&page=2&sort=id&dir=asc")).rows[0]
          .id,
        first.id,
      );
      assert.equal(
        (await get("snifferdog/events?id=" + encodeURIComponent(first.id)))
          .selected.id,
        first.id,
      );
      assert.equal(
        (
          await get(
            "snifferdog/events?group=Finance&id=" +
              encodeURIComponent(first.id),
          )
        ).selected,
        undefined,
      );
      const evidence = await get("evidence");
      assert.equal(evidence.rows[0].fields.items, 3);
      assert.equal(
        (await get("verification")).rows[0].fields.chainHead,
        evidence.rows[0].fields.chainHead,
      );
      assert.equal(
        (await read(request("snifferdog/events?size=0"))).status,
        400,
      );
      await writeFile(observer.health, "");
      const broken = await read(request("verification"));
      assert.equal(broken.status, 503);
      const error = await broken.json();
      assert.equal(error.rows, undefined);
      assert.equal(error.meta, undefined);
      await rm(observer.batches);
      assert.equal((await read(request("snifferdog/events"))).status, 503);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);
test(
  "runnable loopback HTTP adapter serves the checked v1 contract",
  {
    skip: !process.env.OBSERVER_VERIFIER || !process.env.SELF_SAMPLE_GENERATOR,
  },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "vanian-service-http-"));
    let child;
    try {
      await call(process.env.SELF_SAMPLE_GENERATOR, [dir]);
      const trust = JSON.parse(await readFile(join(dir, "anchor.json")));
      const observer = {
        ...trust,
        binary: process.env.OBSERVER_VERIFIER,
        batches: join(dir, "batches.jsonl"),
        health: join(dir, "health.jsonl"),
      };
      const configPath = join(dir, "service.json");
      await writeFile(
        configPath,
        JSON.stringify({ ...config, port: 0, observer }),
        { mode: 0o600 },
      );
      child = spawn(
        process.execPath,
        [
          fileURLToPath(new URL("../bridge/service.mjs", import.meta.url)),
          configPath,
        ],
        {
          env: { PATH: process.env.PATH, VANIAN_BRIDGE_TOKEN: token },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      const [ready] = await once(child.stdout, "data", {
        signal: AbortSignal.timeout(5000),
      });
      const port = Number(String(ready).match(/port (\d+)/)?.[1]);
      assert.ok(port > 0);
      const url = "http://127.0.0.1:" + port + "/v1/evidence?days=1";
      const unauthenticated = await fetch(url);
      assert.equal(unauthenticated.status, 401);
      const result = await fetch(url, {
        headers,
        signal: AbortSignal.timeout(5000),
      });
      assert.equal(result.status, 200);
      const body = await result.json();
      assert.equal(result.headers.get("X-Vanian-Tenant"), config.tenant);
      assert.equal(body.rows[0].fields.items, 3);
      assert.match(body.meta.status, /sensor offline/);
    } finally {
      if (child) {
        const stopped = once(child, "exit");
        child.kill();
        await stopped;
      }
      await rm(dir, { recursive: true, force: true });
    }
  },
);
test(
  "historical kernel graph uses directly recorded parent/child PID values and no agent nodes",
  { skip: !process.env.OBSERVER_VERIFIER },
  async () => {
    const base = new URL(
      "../public/upstream-replay/fixtures/",
      import.meta.url,
    );
    const anchor = JSON.parse(await readFile(new URL("t09-trust.json", base)));
    const original = await verifyObserver({
      ...anchor,
      binary: process.env.OBSERVER_VERIFIER,
      batches: fileURLToPath(new URL("t09-batches.jsonl", base)),
      health: fileURLToPath(new URL("t09-health.jsonl", base)),
      provenance: "Historical lab test",
    });
    const rows = projectObserver(original, "Research", "events");
    const fork = observedGraph(rows.find((r) => r.name === "Fork"));
    assert.deepEqual(
      fork.nodes.map((n) => n.label),
      ["PID 5251", "PID 5252"],
    );
    assert.ok(fork.nodes.every((n) => n.kind === "process"));
    assert.equal(fork.edges[0].label, "Kernel-reported fork");
    assert.equal(fork.edges[0].relation, "observed");
    assert.deepEqual(observedGraph(undefined), { nodes: [], edges: [] });
  },
);
