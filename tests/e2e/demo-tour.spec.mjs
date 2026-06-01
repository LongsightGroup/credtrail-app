import { expect, test } from "@playwright/test";

import { demoRoutes, firstDayTemplateName, learnerEmail } from "./helpers/demo-routes.mjs";

test("seeded admin can inspect the local demo world", async ({ page }) => {
  await page.goto(demoRoutes.admin);
  await expect(page.getByRole("heading", { name: /admin/i }).first()).toBeVisible();

  await page.goto(demoRoutes.badgeTemplates);
  await expect(page.getByText("Applied Analytics TrustEd Credential")).toBeVisible();
  await expect(page.getByText("Workforce Readiness Credential")).toBeVisible();
  await expect(page.getByText("Foundations Badge")).toBeVisible();

  await page.goto(demoRoutes.rules);
  await expect(page.getByText("Local Demo: Applied Analytics Completion")).toBeVisible();
});

test("@demo guided first-day workflow creates data through normal admin routes", async ({
  page,
}) => {
  const templateName = firstDayTemplateName();

  await page.goto(demoRoutes.badgeTemplates);
  await page.locator("#template-create-panel").evaluate((element) => {
    if (element instanceof HTMLDetailsElement) {
      element.open = true;
    }
  });
  await page.getByLabel("Badge name").fill(templateName);
  await page
    .getByLabel("Description")
    .fill("Created by the local guided browser demo so new developers can inspect real data.");
  await page.getByRole("button", { name: "Create and add artwork" }).click();
  await expect(page.getByDisplayValue(templateName)).toBeVisible();

  await page.goto(demoRoutes.manualIssue);
  await page.getByLabel(/recipient email/i).fill(learnerEmail);
  await page.getByLabel(/badge template/i).selectOption({ label: "Applied Analytics TrustEd Credential" });
  await page.getByRole("button", { name: /issue/i }).click();
  await expect(page.getByText(new RegExp(`Badge issued for ${learnerEmail}`, "i"))).toBeVisible();

  await page.goto(demoRoutes.issuedBadges);
  await page.getByLabel(/recipient/i).fill(learnerEmail);
  await page.getByRole("button", { name: /search issued badges/i }).click();
  await expect(page.getByText(learnerEmail)).toBeVisible();

  console.log(
    JSON.stringify(
      {
        createdTemplate: templateName,
        issuedTo: learnerEmail,
        continueExploring: {
          badgeTemplates: demoRoutes.badgeTemplates,
          issuedBadges: demoRoutes.issuedBadges,
        },
      },
      null,
      2,
    ),
  );
});
