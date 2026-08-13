import { expect, test } from "@playwright/test";

import { demoRoutes, learnerEmail } from "./helpers/demo-routes";

test("an administrator can define, publish, and evaluate a governed learner pathway", async ({
  page,
}) => {
  const pathwayTitle = `E2E Evidence Pathway ${String(Date.now())}`;

  await page.goto(`${demoRoutes.admin}/operations/pathways`);
  await expect(page.getByRole("heading", { name: "Learner pathways" })).toBeVisible();
  await page.getByRole("link", { name: "New pathway" }).click();

  await page.getByLabel("Pathway name").fill(pathwayTitle);
  await page
    .getByLabel("What learners are working toward")
    .fill("Complete verified evidence without turning institutional progress into a game.");
  await page.getByLabel("Program owner").selectOption({ index: 1 });
  await page.getByLabel("Requirement 1").selectOption({ index: 1 });
  await page.getByRole("button", { name: "Create pathway draft" }).click();

  await expect(page.getByRole("heading", { name: pathwayTitle })).toBeVisible();
  await expect(page.getByText("Version 1 · 1 ordered requirements")).toBeVisible();
  await page.getByRole("button", { name: "Publish version" }).click();
  await expect(page.getByText("Pathway version published")).toBeVisible();

  await page.getByLabel("Learner email").fill(learnerEmail);
  await page.getByRole("button", { name: "Enroll learner" }).click();
  await expect(page.getByText("Learner enrolled and evaluated")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Learner progress" })).toBeVisible();
  await expect(page.getByText(/In progress|Complete|Needs review/).first()).toBeVisible();
  await expect(page.getByText("Evaluation history (1)")).toBeVisible();
});
