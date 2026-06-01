import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.CREDTRAIL_DEV_BASE_URL || "http://127.0.0.1:8787";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  reporter: [["list"], ["html", { outputFolder: "output/playwright-report", open: "never" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "setup",
      testMatch: /global\.setup\.ts/,
    },
    {
      name: "chromium",
      dependencies: ["setup"],
      testIgnore: /global\.setup\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        storageState: ".auth/admin.json",
      },
    },
    {
      name: "guided-demo",
      dependencies: ["setup"],
      grep: /@demo/,
      testIgnore: /global\.setup\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        headless: false,
        launchOptions: {
          slowMo: 250,
        },
        storageState: ".auth/admin.json",
      },
    },
  ],
});
