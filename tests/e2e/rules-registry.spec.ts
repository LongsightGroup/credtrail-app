import { expect, test } from "@playwright/test";

import { demoRoutes } from "./helpers/demo-routes";

test("an administrator can search, filter, and sort the governed rules registry", async ({
  page,
}) => {
  await page.goto(demoRoutes.rules);

  const search = page.getByLabel("Search rules");
  await expect(search).toBeVisible();
  await search.fill("Local Demo: Applied Analytics Completion");
  await page.getByLabel("Latest status").selectOption("draft");
  await page.getByRole("button", { name: "Apply filters" }).click();

  await expect(page).toHaveURL(/q=Local(\+|%20)Demo/);
  await expect(page).toHaveURL(/status=draft/);
  await expect(
    page.getByRole("link", { name: "Local Demo: Applied Analytics Completion" }),
  ).toBeVisible();
  await expect(page.getByText("1 shown · 1 matching rule").first()).toBeVisible();

  await page.getByRole("link", { name: "Sort by Rule, ascending" }).click();
  await expect(page).toHaveURL(/sort=rule/);
  await expect(page).toHaveURL(/direction=asc/);
  await expect(
    page.getByRole("columnheader", { name: "Sort by Rule, descending" }),
  ).toHaveAttribute("aria-sort", "ascending");
});
