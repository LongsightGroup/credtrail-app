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
): Promise<void> => {
  await page.goto(demoRoutes.badgeTemplates);
  await page.getByRole("button", { name: "New badge template" }).click();
  await page.getByLabel("Badge name").fill(identity.templateName);
  await page
    .getByLabel("Description")
    .fill("Created by the browser acceptance flow so developers can inspect real data.");
  await page.getByRole("button", { name: "Create and add artwork" }).click();
  await expect(page.getByLabel("Badge name")).toHaveValue(identity.templateName);

  await page.getByLabel("Image file").setInputFiles({
    name: "first-day-badge.png",
    mimeType: "image/png",
    buffer: TINY_PNG,
  });
  await page.getByRole("button", { name: "Upload approved image" }).click();
  await expect(page.getByText("Approved artwork uploaded.")).toBeVisible();

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
  await page.getByRole("button", { name: /issue/i }).click();
  await expect(page.getByText(`Badge issued for ${identity.recipientEmail}.`)).toBeVisible();

  await page.goto(demoRoutes.issuedBadges);
  await page.getByLabel(/recipient/i).fill(identity.recipientEmail);
  await page.getByRole("button", { name: /search issued badges/i }).click();
  await expect(page.getByText(identity.recipientEmail).first()).toBeVisible();
};
