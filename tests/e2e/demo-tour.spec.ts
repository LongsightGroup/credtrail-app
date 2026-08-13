import { expect, test } from "@playwright/test";

import { demoRoutes, learnerEmail } from "./helpers/demo-routes";
import {
  completeFirstDayWorkflow,
  createFirstDayWorkflowIdentity,
} from "./helpers/first-day-workflow";

test("seeded admin can inspect the local demo world", async ({ page }) => {
  await page.goto(demoRoutes.admin);
  await expect(page.getByRole("heading", { name: /admin/i }).first()).toBeVisible();

  await page.goto(demoRoutes.badgeTemplates);
  await expect(page.getByText("Applied Analytics TrustEd Credential")).toBeVisible();
  await expect(page.getByText("Workforce Readiness Credential")).toBeVisible();
  await expect(page.getByText("Foundations Badge")).toBeVisible();

  await page.goto(demoRoutes.rules);
  await expect(
    page.getByText("Local Demo: Applied Analytics Completion", { exact: true }),
  ).toBeVisible();
});

test("@demo guided first-day workflow creates data through normal admin routes", async ({
  page,
}) => {
  const identity = createFirstDayWorkflowIdentity(learnerEmail);

  await completeFirstDayWorkflow(page, identity);

  console.log(
    JSON.stringify(
      {
        createdTemplate: identity.templateName,
        issuedTo: identity.recipientEmail,
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
