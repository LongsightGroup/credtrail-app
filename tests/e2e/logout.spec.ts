import { expect, test } from "@playwright/test";

import { demoRoutes } from "./helpers/demo-routes";

test("an administrator can sign out and cannot reopen the protected workspace", async ({
  page,
}) => {
  await page.goto(demoRoutes.admin);
  await page.getByRole("button", { name: "Sign out" }).click();

  await expect(page).toHaveURL(/\/login\?reason=signed_out$/);
  await expect(page.getByText("You are signed out.", { exact: true })).toBeVisible();

  await page.goto(demoRoutes.admin);

  await expect(page).toHaveURL(/\/login\?.*reason=auth_required$/);
});
