import { expect, test } from "@playwright/test";

import { tenantId } from "./helpers/demo-routes";

const membersPath = `/tenants/${tenantId}/admin/access/members`;
const managedMemberEmail = "member-management-e2e@credtrail.local";

test("an administrator can change a tenant role and remove the member", async ({ page }) => {
  await page.goto(membersPath);
  await page.getByRole("button", { name: "Add member" }).click();
  const createForm = page.locator(`form[action="${membersPath}/create"]`);
  await createForm.getByLabel("Institution email").fill(managedMemberEmail);
  await createForm.getByLabel("Tenant role").selectOption("admin");
  await createForm.getByRole("checkbox", { name: "Email sign-in invite now" }).uncheck();
  await createForm.getByRole("button", {
    name: "Add member",
  }).click();

  const memberRow = page.getByRole("row", { name: new RegExp(managedMemberEmail) });
  await expect(memberRow).toBeVisible();

  const roleSelect = memberRow.getByLabel(`Tenant role for ${managedMemberEmail}`);
  await roleSelect.selectOption("viewer");
  await memberRow
    .getByRole("button", { name: `Save role for ${managedMemberEmail}`, exact: true })
    .click();

  await expect(page.getByText(`Updated ${managedMemberEmail} to viewer.`)).toBeVisible();
  await expect(roleSelect).toHaveValue("viewer");
  await page.reload();
  await expect(roleSelect).toHaveValue("viewer");

  const dialogPromise = page.waitForEvent("dialog");
  const removeClickPromise = memberRow.getByRole("button", { name: "Remove" }).click();
  const dialog = await dialogPromise;
  const dialogMessage = dialog.message();
  await dialog.accept();
  await removeClickPromise;
  expect(dialogMessage).toBe(`Remove tenant access for ${managedMemberEmail}?`);

  await expect(page.getByText(`Removed tenant access for ${managedMemberEmail}.`)).toBeVisible();
  await expect(memberRow).toHaveCount(0);
});
