import { test as base, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { connectedSite } from "../support/connected.mjs";
import { testSite } from "../support/site.mjs";
import { pages } from "../../src/navigation";
const test = base.extend<{}, { instance: { url: string } }>({
  instance: [
    async ({}, use) => {
      const site = await testSite();
      try {
        await use(site);
      } finally {
        await site.mf.dispose();
      }
    },
    { scope: "worker" },
  ],
});
test("all workspace routes serve real records, empty filters and typed errors", async ({
  request,
  instance,
}) => {
  for (const p of pages) {
    const res = await request.get(instance.url + "/api/" + p.api);
    expect(res.status(), p.slug).toBe(200);
    const b = await res.json();
    expect(b.meta.mode).toBe("demo");
    expect(b.meta.asOf).toMatch(/Z$/);
    expect(Array.isArray(b.rows)).toBe(true);
    expect(typeof b.total).toBe("number");
  }
  const invalid = await request.post(instance.url + "/api/alerts", {
    headers: { "Content-Type": "application/json" },
    data: "null",
  });
  expect(invalid.status()).toBe(422);
  const large = await request.post(instance.url + "/api/alerts", {
    data: { note: "x".repeat(64_001) },
  });
  expect(large.status()).toBe(413);
  expect(
    (
      await request.get(instance.url + "/api/snifferdog/stream?mode=live")
    ).status(),
  ).toBe(503);
  const none = await request.get(
    instance.url + "/api/conversations?q=nonexistent_reference_78239",
  );
  expect((await none.json()).total).toBe(0);
  expect(
    (await request.get(instance.url + "/api/overview?mode=live")).status(),
  ).toBe(503);
  expect(
    (await request.get(instance.url + "/api/incorrect-route")).status(),
  ).toBe(404);
});
test("home drill-down counts and scoped filters agree", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url);
  await expect(
    page.getByText("AI activity over time", { exact: true }),
  ).toBeVisible();
  await page
    .getByLabel("Organization group", { exact: true })
    .selectOption("Finance");
  await page.getByLabel("Date range", { exact: true }).selectOption("1");
  const card = page.getByRole("button", { name: /High-risk alerts.*vs prior/ });
  await expect(card).toContainText("prior 1 day");
  const num = (await card.locator("strong").innerText()).replaceAll(",", "");
  await card.click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Alerts");
  await expect(page.locator(".count-tag")).toHaveText(num);
  expect(page.url()).toContain("group=Finance");
  expect(page.url()).toContain("priority=High%20risk".replace("%20", "+"));
});
test("investigation edits persist and content access follows the session role", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url + "/alerts");
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByLabel("Investigation status").selectOption("In review");
  await page.getByLabel("Assignee").selectOption("SOC queue");
  await page
    .getByLabel("Analyst note")
    .fill("Reviewed against the fixture batch.");
  await page.getByRole("button", { name: "Save investigation" }).click();
  await expect(
    page.getByText("Change saved to the demo workspace"),
  ).toBeVisible();
  await page.getByRole("button", { name: "Case notes" }).click();
  await expect(
    page.getByText("Reviewed against the fixture batch.", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Close dialog" }).click();
  await page.reload();
  await page.locator("tbody tr").first().click();
  await expect(page.getByLabel("Investigation status")).toHaveValue(
    "In review",
  );
  await page.getByRole("button", { name: "Close dialog" }).click();
  await page.getByRole("button", { name: "Workspace profile" }).click();
  await page.getByLabel("Demo role").selectOption("Auditor");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.locator("tbody tr").first().click();
  await expect(
    page.getByRole("button", { name: "Save investigation" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Reveal synthetic original" }),
  ).toHaveCount(0);
  const denied = await page.request.post(instance.url + "/api/content/reveal", {
    data: { id: "EV-900000" },
  });
  expect(denied.status()).toBe(403);
  expect(
    (await page.request.get(instance.url + "/api/admin/rbac")).status(),
  ).toBe(403);
});
test("policy editor persists rules, simulates and retains rollback history", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url + "/policies");
  await page
    .locator(".policy-row")
    .filter({ hasText: "Corporate AI usage" })
    .click();
  await page
    .getByLabel("Policy name", { exact: true })
    .fill("Reviewed corporate usage");
  await page.getByRole("button", { name: "Save policy", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.reload();
  await page
    .locator(".policy-row")
    .filter({ hasText: "Reviewed corporate usage" })
    .click();
  await page.getByRole("button", { name: "Simulation", exact: true }).click();
  await page
    .getByLabel("Test condition")
    .selectOption("Unapproved application");
  await page.getByRole("button", { name: "Simulate", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText(
    "Behavioral Activity · Simulated",
  );
  await page.getByRole("button", { name: "Version history" }).click();
  await page
    .getByRole("button", { name: "Restore this version" })
    .first()
    .click();
  await expect(
    page.locator(".policy-row").filter({ hasText: "Corporate AI usage" }),
  ).toBeVisible();
});
test("lineage has accessible records and native research verifies and rejects evidence", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url + "/agent-lineage");
  await expect(page.locator(".vgraph-node").first()).toBeVisible();
  await page.locator(".vgraph-node").first().click();
  await expect(page.locator(".vgraph-selection")).toBeVisible();
  await page.goto(instance.url + "/verification");
  const fingerprint = page.getByRole("group", {
    name: "Verifier output summary",
  });
  await expect(fingerprint.locator("samp")).toHaveCount(0);
  await page.getByRole("button", { name: "Run upstream verifier" }).click();
  await expect(
    page.getByText("Signature verified", { exact: true }),
  ).toBeVisible();
  await expect(fingerprint.locator("samp")).toHaveText(
    "695e33a5 847967b8 cc128232 9d2ff8bd 8f578951 29e598da 8aa8b025 f264b9e8",
  );
  await page.getByLabel("Integrity check").selectOption("tampered");
  await page.getByRole("button", { name: "Run upstream verifier" }).click();
  await expect(
    page.getByText("Evidence rejected", { exact: true }),
  ).toBeVisible();
  await expect(fingerprint.locator("samp")).toHaveCount(0);
});
test("guided tour and fail-closed live mode work on small screens", async ({
  page,
  instance,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(instance.url);
  await expect(
    page.getByText("AI activity over time", { exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("button", { name: "Product tour" }).click();
  await page.getByRole("button", { name: "Start tour" }).click();
  await expect(page.getByRole("dialog")).toContainText("1 OF");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("Application discovery");
  await page.getByRole("button", { name: "Close tour" }).click();
  await page.goto(instance.url + "/home?mode=live");
  await expect(page.getByText("Live telemetry unavailable")).toBeVisible();
  await expect(page.locator(".kpi")).toHaveCount(0);
  await page.getByRole("button", { name: "Open demo workspace" }).click();
  await expect(page.locator(".kpi")).toHaveCount(4);
});
test("home has no serious or critical automated accessibility findings", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url);
  await expect(page.locator(".kpi")).toHaveCount(4);
  const r = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(
    r.violations
      .filter((v) => v.impact === "critical" || v.impact === "serious")
      .map((v) => [v.id, v.nodes.slice(0, 4).map((n) => n.target)]),
  ).toEqual([]);
});

test("every navigation destination renders its data source and workspace", async ({
  page,
  instance,
}) => {
  test.setTimeout(180_000);
  const faults: string[] = [];
  page.on("pageerror", (error) => faults.push(error.message));
  for (const def of pages) {
    await page.goto(instance.url + "/" + def.slug, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      page.locator(".mode-row .source-line"),
      def.slug,
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { level: 1 }),
      def.slug,
    ).toBeVisible();
    await expect(page.locator(".error-panel"), def.slug).toHaveCount(0);
  }
  expect(faults).toEqual([]);
});

test("session-isolated investigations reject stale and cross-origin changes", async ({
  playwright,
  instance,
}) => {
  const first = await playwright.request.newContext({ baseURL: instance.url });
  const second = await playwright.request.newContext({ baseURL: instance.url });
  try {
    const a = await (await first.get("/api/alerts")).json();
    await second.get("/api/session");
    const r = a.rows[0];
    const body = {
      id: r.id,
      version: r.version ?? 1,
      state: "Resolved",
      assignee: "SOC queue",
      note: "Tenant-only investigation note",
    };
    const denied = await first.post("/api/alerts", {
      data: body,
      headers: { Origin: "https://unrelated.invalid" },
    });
    expect(denied.status()).toBe(403);
    expect((await first.post("/api/alerts", { data: body })).status()).toBe(
      200,
    );
    expect((await first.post("/api/alerts", { data: body })).status()).toBe(
      409,
    );
    const item = "/api/alerts?id=" + encodeURIComponent(r.id);
    const mine = await (await first.get(item)).json();
    const theirs = await (await second.get(item)).json();
    expect(mine.selected.notes.at(-1).text).toBe(body.note);
    expect(theirs.selected.notes ?? []).not.toContainEqual(
      expect.objectContaining({ text: body.note }),
    );
    const audit = await (await first.get("/api/audit")).json();
    expect(
      audit.rows.filter(
        (x: { fields: { record: string } }) => x.fields.record === r.id,
      ),
    ).toHaveLength(1);
  } finally {
    await first.dispose();
    await second.dispose();
  }
});

test("reordering policies persists and updates their priorities", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url + "/policies");
  const first = page.locator(".policy-row").first();
  await expect(first).toBeVisible();
  const name = await first.locator(".policy-copy > b").innerText();
  await page.getByRole("button", { name: "Move " + name + " down" }).click();
  await expect(page.locator(".policy-row").nth(1)).toContainText(name);
  await page.reload();
  const reordered = page.locator(".policy-row").nth(1);
  await expect(reordered.locator(".policy-copy > b")).toHaveText(name);
  await expect(reordered.locator(".order")).toHaveText("2");
});

test("exported synthetic evidence verifies independently and rejects edited bytes", async ({
  instance,
  request,
}, testInfo) => {
  const { writeFile } = await import("node:fs/promises");
  const { spawnSync } = await import("node:child_process");
  const b = await (await request.get(instance.url + "/api/evidence")).json();
  const id = b.rows[0].id;
  const value = await (
    await request.post(instance.url + "/api/evidence/export", { data: { id } })
  ).json();
  expect(value.verified).toBe(true);
  const packet = testInfo.outputPath("demo-batch.json");
  await writeFile(packet, JSON.stringify(value));
  const verify = () =>
    spawnSync(process.execPath, ["scripts/verify-export.mjs", packet], {
      encoding: "utf8",
    });
  const ok = verify();
  expect(ok.status, ok.stderr).toBe(0);
  value.events[0].owner = "Changed after export";
  await writeFile(packet, JSON.stringify(value));
  const altered = verify();
  expect(altered.status).toBe(1);
  expect(JSON.parse(altered.stdout).accepted).toBe(false);
});

test("relationship filters preserve graph positions and export only visible links", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url + "/agent-lineage");
  const diagram = page.locator(".vgraph").first();
  const filter = (type: string) =>
    diagram.getByRole("button", {
      name: "Show " + type + " links",
      exact: true,
    });
  const nodes = diagram.locator(".react-flow__node");
  await expect(nodes.first()).toBeVisible();
  const originalCount = await nodes.count();
  const positions = () =>
    nodes.evaluateAll((items) =>
      items.map((item) => (item as HTMLElement).style.transform),
    );
  const startingPositions = await positions();
  await filter("observed").click();
  await expect(filter("observed")).toHaveAttribute("aria-pressed", "true");
  await expect(diagram.locator(".vgraph-total")).toContainText(" of ");
  expect(await positions()).toEqual(startingPositions);
  const downloadPromise = page.waitForEvent("download");
  await diagram.getByRole("button", { name: "Export", exact: true }).click();
  const download = await downloadPromise;
  const { readFile } = await import("node:fs/promises");
  const exported = JSON.parse(await readFile((await download.path())!, "utf8"));
  expect(exported.meta.mode).toBe("demo");
  expect(exported.relationshipFilter).toBe("observed");
  expect(exported.graph.nodes).toHaveLength(originalCount);
  expect(exported.graph.edges.length).toBeGreaterThan(0);
  expect(
    exported.graph.edges.every(
      (edge: { relation: string }) => edge.relation === "observed",
    ),
  ).toBe(true);
  await diagram.getByRole("button", { name: "3D", exact: true }).click();
  const canvas = diagram.locator(".vgraph-three canvas");
  const fallback = diagram.getByRole("button", { name: "Open 2D graph" });
  await expect(canvas.or(fallback)).toBeVisible();
  if (await fallback.isVisible()) {
    await fallback.click();
    await expect(nodes.first()).toBeVisible();
  } else {
    const element = await canvas.elementHandle();
    await filter("declared").click();
    expect(
      await canvas.evaluate(
        (current, previous) => current === previous,
        element,
      ),
    ).toBe(true);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await diagram.getByRole("button", { name: "Records", exact: true }).click();
  await filter("inferred").click();
  await expect(filter("inferred")).toHaveAttribute("aria-pressed", "true");
  await expect(diagram.locator("tbody tr")).toHaveCount(originalCount);
  await filter("all").click();
  await expect(diagram.locator(".vgraph-total")).not.toContainText(" of ");
  await diagram.locator("tbody tr").first().getByRole("button").click();
  await diagram.locator(".vgraph-selection summary").click();
  const neighbor = diagram
    .getByRole("button", { name: /^Follow connection to / })
    .first();
  const name = (await neighbor.getAttribute("aria-label"))!.replace(
    "Follow connection to ",
    "",
  );
  await neighbor.click();
  await expect(diagram.locator(".vgraph-selection-head")).toContainText(name);
  expect(
    await diagram.evaluate((el) => el.scrollWidth <= el.clientWidth + 1),
  ).toBe(true);
});
test("data treatments and cost projections expose their evaluation basis", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url + "/data-protection");
  await page
    .getByLabel("Test sample", { exact: true })
    .selectOption("Service token");
  await page.getByLabel("Treatment", { exact: true }).selectOption("Redact");
  await page.getByRole("button", { name: "Test treatment" }).click();
  await expect(page.locator("blockquote")).toContainText("[REDACTED]");
  await expect(page.locator("blockquote")).not.toContainText("demo_secret");
  await page.goto(instance.url + "/cost-optimization");
  await page.getByPlaceholder("Enter benchmark rate").fill("0.75");
  await expect(page.getByText(/projected difference for/)).toContainText(
    "Estimate",
  );
});

test("native process observations drive the live home, inventory drill-down, lineage and archive feed", async ({
  page,
}) => {
  test.skip(
    !process.env.SELF_SAMPLE_GENERATOR || !process.env.OBSERVER_VERIFIER,
    "Requires the original native verifier and self-process sample generator",
  );
  const live = await connectedSite();
  try {
    await page.setExtraHTTPHeaders({
      "oai-authenticated-user-id": live.subject,
    });
    await page.goto(live.url + "/home?mode=live");
    const samples = page.getByRole("button", {
      name: /Process samples.*vs prior/,
    });
    await expect(samples.locator("strong")).toHaveText("3");
    await expect(
      page
        .getByRole("button", { name: /Kernel events.*vs prior/ })
        .locator("strong"),
    ).toHaveText("0");
    await samples.click();
    await expect(page.locator("tbody tr")).toHaveCount(3);
    expect(page.url()).toContain("mode=live");
    await expect(page.locator("tbody tr").first()).toContainText("Unbound");
    await page.goto(live.url + "/agent-lineage?mode=live");
    await expect(
      page.getByRole("heading", { name: "Recorded process lineage" }),
    ).toBeVisible();
    await expect(page.locator(".vgraph-node").first()).toBeVisible();
    const diagram = page.locator(".vgraph");
    await diagram.getByRole("button", { name: "Show observed links" }).click();
    const exportPromise = page.waitForEvent("download");
    await diagram.getByRole("button", { name: "Export", exact: true }).click();
    const { readFile } = await import("node:fs/promises");
    const file = await exportPromise;
    const exported = JSON.parse(await readFile((await file.path())!, "utf8"));
    expect(exported.meta.mode).toBe("live");
    expect(exported.meta.source).toBeTruthy();
    expect(exported.meta.asOf).toMatch(/Z$/);
    expect(exported.meta.status).toBeTruthy();
    expect(exported.relationshipFilter).toBe("observed");
    await page.goto(live.url + "/sniffer-dog?mode=live");
    await page.getByRole("button", { name: "Follow archive updates" }).click();
    await expect(
      page
        .getByRole("status")
        .filter({ hasText: "Following verified archive updates" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Pause archive updates" }).click();
  } finally {
    await page.goto("about:blank");
    await live.close();
  }
});

test("coverage matches scoped heartbeat records and preserves the sensor on drill-down", async ({
  page,
  request,
  instance,
}) => {
  await page.goto(instance.url + "/home?group=Operations&days=1");
  const source = await (
    await request.get(instance.url + "/api/overview?group=Operations&days=1")
  ).json();
  const matrix = page.getByRole("group", {
    name: "Sensors by organization group",
  });
  await expect(matrix.getByRole("button")).toHaveCount(source.sensors.length);
  const delayed = source.sensors.find(
    (s: { state: string }) => s.state === "Delayed",
  );
  expect(delayed).toBeTruthy();
  await matrix
    .getByRole("button", {
      name: "Inspect " + delayed.name + ", Delayed, Operations",
    })
    .click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Sniffer Dog",
  );
  const location = new URL(page.url());
  expect(location.searchParams.get("sensor")).toBe(delayed.id);
  expect(location.searchParams.get("group")).toBe("Operations");
  expect(location.searchParams.get("days")).toBe("1");
  await expect(
    page.getByRole("heading", { name: /Runtime observations/ }),
  ).toBeVisible();
});

test("inventory row density persists and keyboard inspection retains the selected row", async ({
  page,
  instance,
}) => {
  await page.goto(instance.url + "/alerts");
  await page.getByLabel("Row density").selectOption("compact");
  await page.reload();
  await expect(page.getByLabel("Row density")).toHaveValue("compact");
  await expect(page.locator(".table-shell")).toHaveAttribute(
    "data-density",
    "compact",
  );
  const row = page.locator("tbody tr").first();
  await row.focus();
  await row.press("Space");
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(row).toHaveAttribute("aria-current", "true");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("tbody tr[aria-current]")).toHaveCount(0);
});
