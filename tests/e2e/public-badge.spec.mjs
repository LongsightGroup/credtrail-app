import { expect, test } from "@playwright/test";

test("public trusted demo credential route resolves when local credential storage is populated", async ({
  page,
}) => {
  const response = await page.goto("/badges/trusted-demo-credential");

  if (
    response?.status() === 500 &&
    process.env.CREDTRAIL_DEV_SEED_R2?.trim().toLowerCase() === "false"
  ) {
    test.skip(
      true,
      "CREDTRAIL_DEV_SEED_R2=false skips the local R2 credential object required by this route.",
    );
  }

  expect(response?.ok()).toBe(true);
  await expect(page.getByText(/Applied Analytics TrustEd Credential/i)).toBeVisible();
});
