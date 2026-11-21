import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests/ui",
  timeout: 90000,
  workers: 1,
  retries: 0,
  reporter: "line",
  outputDir: ".sites-runtime/ui-results",
  use: {
    browserName: "chromium",
    viewport: { width: 1440, height: 900 },
    headless: true,
    launchOptions: process.env.VANIAN_CHROMIUM
      ? { executablePath: process.env.VANIAN_CHROMIUM }
      : {},
  },
  fullyParallel: false,
});
