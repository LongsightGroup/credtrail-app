import { expect, test } from "@playwright/test";
import {
  completeFirstDayWorkflow,
  createFirstDayWorkflowIdentity,
} from "./helpers/first-day-workflow";
import { demoRoutes } from "./helpers/demo-routes";

test("changing a badge keeps the recipient and repeated awards require review", async ({
  page,
}) => {
  const identity = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, identity);
  const row = page.locator('[data-issued-badge-row="true"]');
  await expect(row.locator("td")).toHaveCount(5);
  await expect(row.locator("td").first().locator("strong")).toHaveText(identity.recipientEmail);
  await expect(row).not.toContainText("default_active");
  await expect(row.getByRole("link", { name: "View record", exact: true })).toHaveClass(
    /--primary/,
  );
  await expect(row.getByRole("link", { name: "View public badge", exact: true })).toHaveAttribute(
    "target",
    "_blank",
  );
  await page.goto(demoRoutes.badgeTemplates + "?q=" + encodeURIComponent(identity.templateName));
  await page.getByRole("link", { name: "Issue this badge", exact: true }).click();
  const selected = page.locator('[name="badgeTemplateId"]');
  const templateId = await selected.inputValue();
  await page.getByLabel("Recipient email").fill(identity.recipientEmail);
  const initialUrl = page.url();
  await page.locator("summary").filter({ hasText: "Change badge" }).click();
  await page
    .getByRole("combobox", { name: "Badge template", exact: true })
    .selectOption("badge_template_trusted_demo");
  await expect(page.getByLabel("Recipient email")).toHaveValue(identity.recipientEmail);
  expect(page.url()).toBe(initialUrl);
  await expect(page.locator("#manual-issue-badge-title")).toHaveText(
    "Applied Analytics TrustEd Credential",
  );
  await selected.selectOption(templateId);
  await page.getByRole("button", { name: "Issue badge", exact: true }).click();
  const warning = page.getByRole("region", { name: "Previous award" });
  await expect(warning).toBeVisible();
  await expect(warning).toBeFocused();
  await expect(page.getByLabel("Recipient email")).toHaveValue(identity.recipientEmail);
  await expect(warning.getByRole("link", { name: "View existing record" })).toHaveAttribute(
    "href",
    /\/evidence$/,
  );
  await page.getByRole("button", { name: "Issue another badge", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Badge issued", exact: true })).toBeVisible();
  await page.goto(
    demoRoutes.issuedBadges + "?recipientQuery=" + encodeURIComponent(identity.recipientEmail),
  );
  await expect(page.locator('[data-issued-badge-row="true"]')).toHaveCount(2);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.screenshot({ path: "/tmp/credtrail-clarity-records-desktop.png", fullPage: true });
});

test("archive explains its consequences and leaves restore directly available", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const identity = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, identity);
  await page.goto(demoRoutes.badgeTemplates + "?q=" + encodeURIComponent(identity.templateName));
  const row = page.locator("tr[data-template-row-id]").filter({ hasText: identity.templateName });
  await expect(row.getByRole("button", { name: "Archive template", exact: true })).toBeHidden();
  await row.locator("summary").filter({ hasText: "Archive template" }).click();
  await expect(row).toContainText("Published rules can still issue badges");
  await expect(row).toContainText("Existing credentials and their public pages stay unchanged");
  await row.getByRole("button", { name: "Archive template", exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: "/tmp/credtrail-clarity-archive-mobile.png", fullPage: true });
  await row.getByRole("button", { name: "Archive template", exact: true }).click();
  await expect(row).toContainText("Archived");
  await expect(page).toHaveURL(/includeArchived=1/);
  await expect(row.getByRole("link", { name: "Issue this badge", exact: true })).toHaveCount(0);
  await row.getByRole("button", { name: "Restore template", exact: true }).click();
  await expect(row).toContainText("Ready to award");
  await expect(row.getByRole("link", { name: "Issue this badge", exact: true })).toBeVisible();
});
