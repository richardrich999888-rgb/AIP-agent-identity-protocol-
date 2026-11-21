import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium } from "@playwright/test";
import { testSite } from "../tests/support/site.mjs";

const args = process.argv.slice(2);
const spatial = args.includes("--spatial");
const output = args.find((value) => !value.startsWith("--")) || "docs/preview";
await mkdir(output, { recursive: true });
const site = await testSite();
let browser;
try {
  browser = await chromium.launch({
    executablePath: process.env.VANIAN_CHROMIUM || undefined,
    args: spatial && process.env.VANIAN_SOFTWARE_WEBGL === "1"
      ? ["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--in-process-gpu"]
      : undefined,
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
  if (spatial) {
    await page.goto(site.url + "/agent-lineage");
    await page.getByRole("button", { name: "3D", exact: true }).click();
    const canvas = page.locator(".vgraph-three canvas");
    const fallback = page.getByRole("button", { name: "Open 2D graph" });
    await canvas.or(fallback).waitFor();
    if (await fallback.isVisible()) {
      throw Error("Spatial capture requires a WebGL2 renderer.");
    }
    await page.evaluate(() => new Promise((resolve) =>
      requestAnimationFrame(() => requestAnimationFrame(resolve))
    ));
    await capture("spatial-lineage");
    await page.getByRole("button", { name: "Command mode", exact: true }).click();
    await page.getByRole("button", { name: "Show observed links" }).click();
    await page.locator(".vgraph--command .vgraph-three canvas").waitFor();
    await page.locator(".vgraph-total").filter({ hasText: " of " }).waitFor();
    await page.evaluate(() => new Promise((resolve) =>
      requestAnimationFrame(() => requestAnimationFrame(resolve))
    ));
    await capture("spatial-observed-links");
  } else {
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
    await page.goto(site.url + "/agent-lineage");
    await page.getByRole("button", { name: "Records", exact: true }).click();
    await page.getByRole("button", { name: "Show inferred links" }).click();
    await page.locator(".vgraph-total").filter({ hasText: " of " }).waitFor();
    await capture("mobile-lineage-records");
  }
} finally {
  await browser?.close();
  await site.mf.dispose();
}
