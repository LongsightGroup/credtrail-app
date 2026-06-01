import { mkdir } from "node:fs/promises";

import { test as setup } from "@playwright/test";

import { adminEmail, demoRoutes, tenantId } from "./helpers/demo-routes";

setup("authenticate seeded admin", async ({ page, baseURL }) => {
  if (baseURL === undefined) {
    throw new Error("Playwright baseURL is required.");
  }

  const loginUrl = new URL("/v1/dev/auth/login-as", baseURL);
  loginUrl.searchParams.set("tenantId", tenantId);
  loginUrl.searchParams.set("email", adminEmail);
  loginUrl.searchParams.set("next", demoRoutes.admin);

  await page.goto(loginUrl.toString());
  await page.waitForURL(/\/tenants\/[^/]+\/admin/);
  await mkdir(".auth", { recursive: true });
  await page.context().storageState({ path: ".auth/admin.json" });
});
