import { expect, test } from "@playwright/test";

test("public trusted demo credential route resolves when local credential storage is populated", async ({
  page,
}) => {
  const response = await page.goto("/badges/trusted-demo-credential");

  expect(response?.ok()).toBe(true);
  await expect(page.getByText(/Applied Analytics TrustEd Credential/i)).toBeVisible();
});
