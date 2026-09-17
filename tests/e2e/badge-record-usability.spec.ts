import { expect, test } from "@playwright/test";
import {
  completeFirstDayWorkflow,
  createFirstDayWorkflowIdentity,
} from "./helpers/first-day-workflow";

test("record search, learner navigation, expiration, and mobile actions stay connected", async ({
  page,
}) => {
  const identity = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, identity);
  const row = page.locator('[data-issued-badge-row="true"]');
  await expect(page.getByLabel("Recipient or record")).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Status", exact: true })).toBeHidden();
  await row.getByRole("link", { name: "View learner record", exact: true }).click();
  await expect(page.getByLabel("LMS learner ID or email")).toHaveValue(identity.recipientEmail);
  await expect(
    page.getByRole("heading", { name: identity.templateName, exact: true }),
  ).toBeVisible();
  await page.goBack();
  await expect(page.getByLabel("Recipient or record")).toHaveValue(identity.recipientEmail);
  await row.getByRole("link", { name: "View record", exact: true }).click();
  const notification = page.getByRole("region", { name: "Email notification" });
  await expect(notification).toContainText("Share this link with the learner.");
  await expect(notification.getByRole("button", { name: "Copy public badge link" })).toBeVisible();
  await expect(page.getByRole("link", { name: "View learner record", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Manage status", exact: true }).click();
  await page.getByRole("link", { name: "Mark badge expired", exact: true }).click();
  await page
    .getByRole("combobox", { name: "Reason", exact: true })
    .selectOption("credential_expired");
  await page.getByRole("button", { name: "Mark badge expired", exact: true }).click();
  await expect(row.locator('[data-label="Status"]')).toHaveText("Expired");
  await page.locator("summary").filter({ hasText: "More filters" }).click();
  await page.getByRole("combobox", { name: "Status", exact: true }).selectOption("expired");
  await page.getByRole("button", { name: "Apply filters", exact: true }).click();
  await expect(page.getByRole("region", { name: "Active filters" })).toContainText(
    "Status: Expired",
  );
  await expect(row).toHaveCount(1);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.screenshot({ path: "/tmp/credtrail-records-desktop.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await page.locator("summary").filter({ hasText: "More filters" }).click();
  await row.scrollIntoViewIfNeeded();
  for (const name of ["View record", "View public badge", "View learner record"]) {
    const box = await row.getByRole("link", { name, exact: true }).boundingBox();
    expect(box).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: "/tmp/credtrail-records-mobile.png", fullPage: true });
  await row.getByRole("link", { name: "View record", exact: true }).click();
  await expect(page.locator(".assertion-evidence__status-row")).toContainText("Expired");
});
