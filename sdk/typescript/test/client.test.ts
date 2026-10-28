import {test} from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {VanianClient, VanianError, type DeploymentDefinition} from "../src/index.ts";

test("secure origin and bounds", () => {
  for (const url of ["http://bank.internal", "https://user:secret@bank.internal", "https://bank.internal/path"]) {
    assert.throws(() => new VanianClient(url, () => "credential"));
  }
  assert.throws(() => new VanianClient("https://bank.internal", () => "credential", {retries: 4}));
});

test("configuration POST is bounded and never automatically retried", async () => {
  let calls = 0;
  const server = createServer((req, res) => {
    calls++; req.resume(); res.writeHead(503, {"Content-Type": "application/json"}); res.end('{"error":"unavailable"}');
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address !== "string");
  const client = new VanianClient(`http://127.0.0.1:${address.port}`, () => "admin-secret", {allowLoopbackHttp: true, retries: 3});
  try {
    const definition = {schema_version: "vanian.deployment.v1"} as DeploymentDefinition;
    await assert.rejects(client.registerDeployment(definition), (e: unknown) => e instanceof VanianError && e.status === 503 && !e.message.includes("admin-secret"));
    assert.equal(calls, 1);
    assert.throws(() => client.registerDeployment({deployment_name: "x".repeat(25000)} as DeploymentDefinition));
    assert.throws(() => client.listDeployments(101));
  } finally {await new Promise<void>(resolve => server.close(() => resolve()));}
});

test("auth rotation, bounded response, redirect refusal", async () => {
  const requests: string[] = [];
  const credentials: string[] = [];
  const server = createServer((req, res) => {
    requests.push(req.url!);
    credentials.push(req.headers.authorization!);
    if (req.url === "/v1/access") {res.writeHead(302, {Location: "/leak"}); res.end(); return;}
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({items: [], limit: 50, offset: 0, next_offset: null}));
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  let token = "first";
  const client = new VanianClient(base, () => token, {allowLoopbackHttp: true, retries: 0});
  try {
    assert.equal((await client.listAgents()).next_offset, null);
    token = "second";
    await client.listAgents();
    assert.deepEqual(credentials, ["Bearer first", "Bearer second"]);
    await assert.rejects(client.access(), VanianError);
    assert.ok(!requests.includes("/leak"));
    const small = new VanianClient(base, () => token, {allowLoopbackHttp: true, maxResponseBytes: 8});
    await assert.rejects(small.listAgents(), (e: unknown) => e instanceof VanianError && e.code === "response_too_large");
    assert.throws(() => client.listAgents(101));
    assert.throws(() => client.getAgent(".."));
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
