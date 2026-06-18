import { expect, test } from "@playwright/test";

test("public criteria registry shows seeded badge details and qualification context", async ({
  page,
}) => {
  await page.goto("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_trusted_demo");

  await expect(
    page.getByRole("heading", { name: "Applied Analytics TrustEd Credential" }),
  ).toBeVisible();
  await expect(page.getByText("Published criteria", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "How someone qualifies" })).toBeVisible();
  await expect(page.getByText("Local Demo: Applied Analytics Completion")).toBeVisible();
  await expect(
    page.getByRole("img", { name: /Applied Analytics TrustEd Credential/i }),
  ).toBeVisible();
});
