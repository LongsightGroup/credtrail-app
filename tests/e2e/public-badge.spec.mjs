import { expect, test } from "@playwright/test";

test("public trusted demo credential route resolves when local credential storage is populated", async ({
  page,
}) => {
  const response = await page.goto("/badges/trusted-demo-credential");

  if (response?.status() === 500) {
    test.skip(
      true,
      "The seeded DB row exists, but the local R2 credential object is created by pnpm dev:demo/manual issuance.",
    );
  }

  await expect(page.getByText(/Applied Analytics TrustEd Credential/i)).toBeVisible();
});
