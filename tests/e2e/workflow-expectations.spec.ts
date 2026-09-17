import { expect, test } from "@playwright/test";
import {
  completeFirstDayWorkflow,
  createFirstDayWorkflowIdentity,
} from "./helpers/first-day-workflow";

test("status changes explain filtered results and learner records show useful labels", async ({
  page,
}) => {
  const identity = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, identity);
  const url = new URL(page.url());
  url.searchParams.set("state", "active");
  await page.goto(url.toString());
  await expect(page.getByRole("region", { name: "CSV export" })).toContainText(
    "all 1 matching record across every page",
  );
  await page
    .locator('[data-issued-badge-row="true"]')
    .getByRole("link", { name: "View record", exact: true })
    .click();
  await page.getByRole("link", { name: "Manage status", exact: true }).click();
  await page.getByRole("link", { name: "Mark badge expired", exact: true }).click();
  await page.getByRole("button", { name: "Mark badge expired", exact: true }).click();
  await expect(
    page.getByText("It no longer matches your status filter.", { exact: false }),
  ).toBeVisible();
  await expect(page.locator('[data-issued-badge-row="true"]')).toHaveCount(0);
  await page.getByRole("link", { name: "View updated record" }).click();
  await expect(page.locator(".assertion-evidence__status-row")).toContainText("Expired");
  await page.getByRole("link", { name: "View learner record", exact: true }).click();
  await expect(
    page.getByText(`Reviewing ${identity.recipientEmail}.`, { exact: false }),
  ).toBeVisible();
  await expect(page.getByText("Learner profile ID:", { exact: false })).toBeHidden();
  await expect(page.getByRole("link", { name: "Download learner record (JSON)" })).toBeVisible();
  await expect(page.getByText("Phase 27", { exact: false })).toHaveCount(0);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.screenshot({ path: "/tmp/credtrail-next-learner-desktop.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: "/tmp/credtrail-next-learner-mobile.png", fullPage: true });
});

test("receipt carries the learner into a different badge without issuing on navigation", async ({
  page,
}) => {
  const otherBadge = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, otherBadge);
  const identity = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, identity);
  const href = await page
    .locator('[data-issued-badge-row="true"]')
    .getByRole("link", { name: "View record", exact: true })
    .getAttribute("href");
  const assertionId = href?.match(/issued-badges\/([^/]+)\/evidence/)?.[1];
  expect(assertionId).toBeTruthy();
  await page.goto(`/tenants/tenant_123/admin/operations/issue/${assertionId}/receipt`);
  await page.getByRole("link", { name: "Award another badge to this learner" }).click();
  await expect(page.getByLabel("Recipient email")).toHaveValue(identity.recipientEmail);
  await expect(page.getByRole("heading", { name: "Badge issued", exact: true })).toHaveCount(0);
  await page
    .getByRole("combobox", { name: "Badge template", exact: true })
    .selectOption({ label: otherBadge.templateName });
  await expect(page.getByLabel("Recipient email")).toHaveValue(identity.recipientEmail);
  await page
    .getByRole("button", {
      name: "Issue badge",
      exact: true,
    })
    .click();
  await expect(page.getByRole("region", { name: "Issuance receipt" })).toContainText(
    identity.recipientEmail,
  );
  await expect(
    page.getByRole("heading", { name: otherBadge.templateName, exact: true }),
  ).toBeVisible();
});
