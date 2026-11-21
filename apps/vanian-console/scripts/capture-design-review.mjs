import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium } from "@playwright/test";
import { testSite } from "../tests/support/site.mjs";

const output = process.argv[2] || "docs/preview";
await mkdir(output, { recursive: true });
const site = await testSite();
let browser;
try {
  browser = await chromium.launch({
    executablePath: process.env.VANIAN_CHROMIUM || undefined,
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 950 },
    deviceScaleFactor: 1,
    timezoneId: "UTC",
    locale: "en-US",
    reducedMotion: "reduce",
  });
  async function capture(name) {
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({
      path: join(output, name + ".png"),
      animations: "disabled",
    });
  }
  await page.goto(site.url + "/home");
  await page
    .getByRole("button", { name: "Inspect ops-02, Delayed, Operations" })
    .waitFor();
  await capture("security-overview");
  await page.goto(site.url + "/alerts?risk=High");
  await page.locator("tbody tr").first().click();
  await page
    .getByRole("dialog")
    .getByRole("heading", { name: "Record context" })
    .waitFor();
  await page
    .getByRole("dialog")
    .getByRole("heading", { name: "Alert investigation" })
    .waitFor();
  await capture("alert-investigation");
  await page.goto(site.url + "/agent-lineage");
  await page.locator(".react-flow__node").first().waitFor();
  await page.locator(".react-flow__node").first().click();
  await page.locator(".vgraph-selection").waitFor();
  await capture("agent-lineage");
  await page.goto(site.url + "/verification");
  await page.getByRole("button", { name: "Run upstream verifier" }).click();
  await page.getByText("Signature verified", { exact: true }).waitFor();
  await capture("evidence-verification");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(site.url + "/home");
  await page
    .getByRole("heading", { name: "Sensor coverage", exact: true })
    .waitFor();
  await capture("mobile-overview");
} finally {
  await browser?.close();
  await site.mf.dispose();
}
