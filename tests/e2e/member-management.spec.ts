import { expect, test } from "@playwright/test";

import { tenantId } from "./helpers/demo-routes";

const membersPath = `/tenants/${tenantId}/admin/access/members`;
const removableMemberEmail = "removal-e2e@credtrail.local";

test("an administrator can remove a tenant member", async ({ page }) => {
  await page.goto(membersPath);
  await page.getByRole("button", { name: "Add member" }).click();
  const createForm = page.locator(`form[action="${membersPath}/create"]`);
  await createForm.getByLabel("Institution email").fill(removableMemberEmail);
  await createForm.getByLabel("Tenant role").selectOption("admin");
  await createForm.getByRole("checkbox", { name: "Email sign-in invite now" }).uncheck();
  await createForm.getByRole("button", {
    name: "Add member",
  }).click();

  const memberRow = page.getByRole("row", { name: new RegExp(removableMemberEmail) });
  await expect(memberRow).toBeVisible();

  const dialogPromise = page.waitForEvent("dialog");
  const removeClickPromise = memberRow.getByRole("button", { name: "Remove" }).click();
  const dialog = await dialogPromise;
  const dialogMessage = dialog.message();
  await dialog.accept();
  await removeClickPromise;
  expect(dialogMessage).toBe(`Remove tenant access for ${removableMemberEmail}?`);

  await expect(page.getByText(`Removed tenant access for ${removableMemberEmail}.`)).toBeVisible();
  await expect(memberRow).toHaveCount(0);
});
