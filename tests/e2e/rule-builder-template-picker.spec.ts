import { expect, test } from "@playwright/test";

import { demoRoutes } from "./helpers/demo-routes";

test("an administrator can search and choose a badge template in one combobox", async ({
  page,
}) => {
  await page.goto(demoRoutes.ruleBuilder);

  const combobox = page.getByRole("combobox", { name: "Badge template" });
  const nativeSelect = page.locator('select[name="badgeTemplateId"]');
  const listbox = page.getByRole("listbox", { name: "Badge templates" });
  const searchStatus = page.locator("#rule-builder-badge-template-search-status");
  const ruleName = page.locator("#rule-builder-name");

  await expect(ruleName).toBeHidden();
  await expect(ruleName).toHaveValue("");

  await expect(combobox).toHaveCount(1);
  await expect(combobox).toBeVisible();
  await expect(page.locator("#rule-builder-badge-template-fallback-field")).toBeHidden();
  await expect(nativeSelect).toBeHidden();

  await combobox.focus();
  await expect(listbox).toBeVisible();
  const templateOption = listbox.getByRole("option", {
    name: /Applied Analytics TrustEd Credential/,
  });
  await expect(templateOption).toBeVisible();

  await combobox.fill("analytics");
  await expect(listbox.getByRole("option")).toHaveCount(1);
  await expect(templateOption).toBeVisible();

  await combobox.press("ArrowDown");
  await combobox.press("Enter");
  await expect(listbox).toBeHidden();
  await expect(combobox).toHaveValue("Applied Analytics TrustEd Credential");
  await expect(ruleName).toHaveValue("");
  await page.locator("#rule-builder-template-preset").selectOption("course_completion");
  await expect(ruleName).toHaveValue("");
  await page.getByText("Add a custom label", { exact: true }).click();
  await ruleName.fill("Final exam distinction");
  await page.locator("#rule-builder-template-preset").selectOption("course_and_grade");
  await expect(ruleName).toHaveValue("Final exam distinction");
  await ruleName.fill("");
  await page.locator("#rule-builder-template-preset").selectOption("course_completion");
  await expect(ruleName).toHaveValue("");
  await expect(page.locator("#rule-builder-summary-rule-name")).toHaveText(
    "Complete all gradebook items",
  );
  const reuse = page.getByLabel("I confirm this rule is another valid way to earn the same badge.");
  if (await reuse.isVisible()) await reuse.check();
  await expect(page.getByRole("button", { name: "Continue to Requirements" })).toBeEnabled();
  await ruleName.fill("Final exam distinction");
  const committedValue = await nativeSelect.inputValue();
  expect(committedValue).not.toBe("");

  await combobox.click();
  await combobox.fill("no matching badge template");
  await expect(listbox).toBeVisible();
  await expect(listbox.getByText("No badge templates match this search.")).toBeVisible();
  await combobox.press("Escape");
  await expect(listbox).toBeHidden();
  await expect(combobox).toHaveValue("Applied Analytics TrustEd Credential");
  await expect(nativeSelect).toHaveValue(committedValue);
  await expect(searchStatus).toHaveText("Applied Analytics TrustEd Credential selected.");

  await combobox.click();
  await expect(templateOption).toBeVisible();
  await templateOption.click();
  await expect(listbox).toBeHidden();
  await expect(combobox).toHaveValue("Applied Analytics TrustEd Credential");
  await expect(nativeSelect).toHaveValue(committedValue);
  await expect(ruleName).toHaveValue("Final exam distinction");
});
