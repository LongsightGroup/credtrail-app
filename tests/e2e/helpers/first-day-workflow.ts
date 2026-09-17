import { expect, type Page } from "@playwright/test";

import { demoRoutes } from "./demo-routes";

const TINY_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64",
);

export interface FirstDayWorkflowIdentity {
  readonly templateName: string;
  readonly recipientEmail: string;
}

/** Creates unique user-facing values so repeated local runs do not collide. */
export const createFirstDayWorkflowIdentity = (
  recipientEmail?: string,
): FirstDayWorkflowIdentity => {
  const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 12);

  return {
    templateName: `First Day Demo ${suffix}`,
    recipientEmail: recipientEmail ?? `first-day-${suffix}@example.edu`,
  };
};

/** Completes the real create, artwork, issue, and issued-record browser journey. */
export const completeFirstDayWorkflow = async (
  page: Page,
  identity: FirstDayWorkflowIdentity,
  verifyCorrections = false,
): Promise<void> => {
  await page.goto(
    demoRoutes.badgeTemplates +
      "?q=" +
      encodeURIComponent(identity.templateName) +
      "&includeArchived=1",
  );
  await page.getByRole("button", { name: "New badge template" }).click();
  await page.getByLabel("Badge name").fill(identity.templateName);
  await page
    .getByLabel("Description")
    .fill("Created by the browser acceptance flow so developers can inspect real data.");
  await page.getByRole("button", { name: "Create and add artwork" }).click();
  await expect(page.getByLabel("Badge name")).toHaveValue(identity.templateName);

  const backToTemplates = page.getByRole("link", { name: "Back to filtered templates" });
  await expect(backToTemplates).toHaveAttribute(
    "href",
    demoRoutes.badgeTemplates +
      "?q=" +
      encodeURIComponent(identity.templateName).replaceAll("%20", "+") +
      "&includeArchived=1",
  );
  if (verifyCorrections) {
    const tooLongName = "X".repeat(201);
    await page.getByLabel("Badge name").evaluate((input: HTMLInputElement) => {
      input.maxLength = 500;
    });
    await page.getByLabel("Badge name").fill(tooLongName);
    await page.locator("#badge-template-edit-form").evaluate((form: HTMLFormElement) => {
      form.noValidate = true;
    });
    await page.getByRole("button", { name: "Save template details" }).click();
    await expect(page.locator("#badge-template-edit-status")).toContainText(
      "Check the template fields",
    );
    await expect(page.getByLabel("Badge name")).toHaveValue(tooLongName);
    await expect(page.locator("#badge-template-edit-status")).toBeFocused();
    await page.getByLabel("Badge name").fill(identity.templateName);
    await page.getByRole("button", { name: "Save template details" }).click();
    await expect(page.locator("#badge-template-details-notice")).toHaveText(
      "Template details saved.",
    );
    await expect(backToTemplates).toHaveAttribute("href", /includeArchived=1/);
  }

  await page.getByLabel("Image file").setInputFiles({
    name: "first-day-badge.png",
    mimeType: "image/png",
    buffer: TINY_PNG,
  });
  await expect(page.getByRole("img", { name: "Selected artwork preview" })).toBeVisible();
  await expect(
    page.getByText("1 × 1 pixels. Full image shown; proportions preserved."),
  ).toBeVisible();
  await page.getByRole("button", { name: "Upload and use image" }).click();
  await expect(page.getByText("Image uploaded and set as this template’s artwork.")).toBeVisible();

  await backToTemplates.click();
  const templateRow = page.locator("tbody tr").filter({ hasText: identity.templateName });
  await expect(templateRow).toContainText("Ready to award");
  await page.goto(demoRoutes.manualIssue);
  await page.getByLabel(/recipient email/i).fill(identity.recipientEmail);
  const templateSelect = page.getByLabel(/badge template/i);
  const templateOption = templateSelect
    .locator("option")
    .filter({ hasText: identity.templateName });
  await expect(templateOption).toHaveCount(1);

  const templateId = await templateOption.getAttribute("value");
  if (templateId === null || templateId.length === 0) {
    throw new Error(`Badge template ${identity.templateName} has no selectable value.`);
  }
  await templateSelect.selectOption(templateId);
  if (verifyCorrections) {
    await page.getByLabel(/recipient email/i).fill("learner@");
    await page.locator("#manual-issue-form").evaluate((form: HTMLFormElement) => {
      form.noValidate = true;
    });
    await page.getByRole("button", { name: "Issue badge", exact: true }).click();
    await expect(page.locator("#manual-issue-error")).toBeVisible();
    await expect(page.locator("#manual-issue-error")).toBeFocused();
    await expect(page.getByLabel(/recipient email/i)).toHaveValue("learner@");
    await expect(page.locator('[name="badgeTemplateId"]')).toHaveValue(templateId);
    await page.getByLabel(/recipient email/i).fill(identity.recipientEmail);
  }

  await expect(page.locator("#manual-issue-consequence")).toContainText(
    "Issue " + identity.templateName + " to " + identity.recipientEmail,
  );

  await expect(page.getByRole("region", { name: "Email notification expectations" })).toContainText(
    "No email will be sent",
  );
  await page.getByRole("button", { name: "Issue badge", exact: true }).click();
  await expect(page).toHaveURL(/\/operations\/issue\/[^/]+\/receipt$/);
  await expect(page.getByRole("heading", { name: "Badge issued", exact: true })).toBeVisible();
  const receipt = page.getByRole("region", { name: "Issuance receipt" });
  await expect(receipt.getByRole("heading", { name: identity.templateName })).toBeVisible();
  await expect(receipt).toContainText(identity.recipientEmail);
  await expect(receipt.getByRole("link", { name: "View badge record" })).toHaveAttribute(
    "href",
    /\/issued-badges\/[^/]+\/evidence$/,
  );
  await expect(
    receipt.getByRole("link", { name: "Open public badge", exact: true }),
  ).toHaveAttribute("href", /^\/badges\/[^/]+$/);
  await expect(receipt.getByRole("region", { name: "Email notification" })).toContainText(
    "Email notifications are turned off",
  );
  await page.reload();
  await expect(receipt.getByRole("heading", { name: identity.templateName })).toBeVisible();
  await expect(receipt).toContainText(identity.recipientEmail);

  await page.goto(demoRoutes.issuedBadges);
  await page.getByLabel(/recipient/i).fill(identity.recipientEmail);
  await page.getByRole("button", { name: /search issued badges/i }).click();
  const issuedBadge = page
    .locator("tbody tr")
    .filter({ hasText: identity.recipientEmail })
    .filter({ hasText: identity.templateName });
  await expect(issuedBadge).toHaveCount(1);
  await expect(issuedBadge).toContainText(identity.templateName);
};
