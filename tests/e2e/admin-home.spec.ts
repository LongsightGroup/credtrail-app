import { expect, test } from "@playwright/test";

import { demoRoutes, tenantId } from "./helpers/demo-routes";

test("admin home exposes the workspace tiles aligned with the side nav", async ({ page }) => {
  await page.goto(demoRoutes.admin);

  await expect(page.getByRole("link", { name: "Open Issuance workspace" })).toHaveAttribute(
    "href",
    `/tenants/${tenantId}/admin/operations/issue`,
  );
  await expect(page.getByRole("link", { name: "Open Learner Records workspace" })).toHaveAttribute(
    "href",
    `/tenants/${tenantId}/admin/operations/learner-records`,
  );
  await expect(page.getByRole("link", { name: "Open Badge Program workspace" })).toHaveAttribute(
    "href",
    `/tenants/${tenantId}/admin/rules`,
  );
  await expect(page.getByRole("link", { name: "Open Reporting workspace" })).toHaveAttribute(
    "href",
    `/tenants/${tenantId}/admin/reporting`,
  );
  await expect(page.getByRole("link", { name: "Open People & Access workspace" })).toHaveAttribute(
    "href",
    `/tenants/${tenantId}/admin/access/members`,
  );

  await expect(page.getByRole("heading", { name: "Issue & Inspect" })).toHaveCount(0);
  await expect(page.getByText("Operations", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Analytics", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Management", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Configuration", { exact: true })).toHaveCount(0);
});
