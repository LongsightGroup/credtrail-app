import { expect, test } from "@playwright/test";

import { tenantId } from "./helpers/demo-routes";

const membersPath = `/tenants/${tenantId}/admin/access/members`;
const managedMemberEmail = "member-management-e2e@credtrail.local";

test("an administrator can change a tenant role and remove the member", async ({ page }) => {
  await page.goto(membersPath);
  const createForm = page.locator(`form[action="${membersPath}/create"]`);
  const addMemberTrigger = page.locator(
    '[data-admin-inline-panel-trigger="tenant-member-panel"]',
  );
  await addMemberTrigger.click();
  await expect(addMemberTrigger).toHaveAttribute("aria-expanded", "true");
  await expect(createForm).toBeVisible();
  await createForm.getByLabel("Institution email").fill(managedMemberEmail);
  await createForm.getByLabel("Tenant role").selectOption("admin");
  await createForm.getByRole("checkbox", { name: "Email sign-in invite now" }).uncheck();
  await createForm.getByRole("button", {
    name: "Add member",
  }).click();

  const memberRow = page.getByRole("row", { name: new RegExp(managedMemberEmail) });
  await expect(memberRow).toBeVisible();

  const roleSelect = memberRow.getByLabel(`Tenant role for ${managedMemberEmail}`);
  await expect(
    memberRow.getByRole("button", {
      name: `Save role for ${managedMemberEmail}`,
      exact: true,
    }),
  ).toBeHidden();
  await expect(
    page.getByText("Role changes take effect as soon as you select a new role."),
  ).toBeVisible();
  await roleSelect.selectOption("viewer");

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
