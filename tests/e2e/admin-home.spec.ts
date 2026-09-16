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

test("Home shows bounded work and a keyboard-accessible exact version at mobile width", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(demoRoutes.admin);
  const tasks = page.locator(".ct-admin__workflow-task-list > li");
  const count = await tasks.count();
  expect(count).toBeGreaterThan(0);
  expect(count).toBeLessThanOrEqual(5);
  await expect(tasks.first().getByText(/Badge owner:/)).toBeVisible();
  const action = tasks.first().getByRole("link");
  await action.focus();
  await expect(action).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/rules\/[^/]+\/versions\/[^/]+$/);
  await expect(page.getByRole("heading", { name: "Who does what" })).toBeVisible();
  await expect(page.getByText("Who awards the badge", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
});
