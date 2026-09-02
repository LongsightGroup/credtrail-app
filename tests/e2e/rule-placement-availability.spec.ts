import { expect, test } from "@playwright/test";

import { createLiveRulePlacementAvailabilityFixture } from "./helpers/live-rule-placement-availability-fixture";

test("an administrator can govern where a rule is offered to courses", async ({
  browser,
  baseURL,
}) => {
  if (baseURL === undefined) {
    throw new Error("Playwright baseURL is required.");
  }

  const fixture = await createLiveRulePlacementAvailabilityFixture();
  const context = await browser.newContext();

  try {
    const page = await context.newPage();
    const loginUrl = new URL("/v1/dev/auth/login-as", baseURL);
    loginUrl.searchParams.set("tenantId", fixture.tenantId);
    loginUrl.searchParams.set("email", fixture.adminEmail);
    loginUrl.searchParams.set("next", fixture.rulesPath);
    await page.goto(loginUrl.toString());

    const ruleRow = page.locator("tbody tr").filter({ hasText: fixture.ruleName });
    await expect(ruleRow).toBeVisible();
    await ruleRow
      .getByRole("link", { name: `Set course availability for ${fixture.ruleName}` })
      .click();

    await expect(page.getByRole("heading", { name: fixture.ruleName })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Current availability" })).toBeVisible();
    await expect(page.getByText("Not offered", { exact: true })).toBeVisible();

    await page.getByLabel("Course name or code").fill("Community Data");
    await page.getByRole("button", { name: "Search courses" }).click();
    await expect(page.getByText(fixture.courseTitle, { exact: true })).toBeVisible();
    await page
      .getByRole("button", { name: `Add ${fixture.courseTitle} to selected courses` })
      .click();

    await expect(page.getByText(`Added ${fixture.courseTitle} to selected courses.`)).toBeVisible();
    await expect(page.getByText("1 selected course", { exact: true })).toBeVisible();
    await page.reload();
    await expect(page.getByText("1 selected course", { exact: true })).toBeVisible();

    await page.getByLabel("Course name or code").fill("Community Data");
    await page.getByRole("button", { name: "Search courses" }).click();
    await page
      .getByRole("button", { name: `Add ${fixture.secondCourseTitle} to selected courses` })
      .click();
    await expect(page.getByText("2 selected courses", { exact: true })).toBeVisible();
    await page
      .getByRole("button", {
        name: `Remove ${fixture.secondCourseTitle} from selected courses`,
      })
      .click();
    await expect(page.getByText("Course removed from the selected list.")).toBeVisible();
    await expect(page.getByText("1 selected course", { exact: true })).toBeVisible();

    await page.getByLabel("Course name or code").fill("Community Data");
    await page.getByRole("button", { name: "Search courses" }).click();
    await page
      .getByLabel(`Map ${fixture.courseTitle} to an organizational area`)
      .locator("xpath=ancestor::form")
      .getByLabel("Department or program")
      .selectOption(fixture.departmentId);
    await page
      .getByRole("button", { name: `Map ${fixture.courseTitle} to an organizational area` })
      .click();
    await expect(
      page.getByText(`Mapped ${fixture.courseTitle} to ${fixture.departmentName}.`),
    ).toBeVisible();

    await page.getByRole("radio", { name: /An organizational area/ }).check();
    await page.locator('select[name="rootOrgUnitId"]').selectOption(fixture.departmentId);
    await page.getByLabel("I have reviewed which mapped courses will receive this rule.").check();
    await page.getByRole("button", { name: "Update course availability" }).click();
    await expect(page.getByText(`Organizational area: ${fixture.departmentName}`)).toBeVisible();
    await page.reload();
    await expect(page.getByText(`Organizational area: ${fixture.departmentName}`)).toBeVisible();

    await page.getByRole("radio", { name: /Every course in this institution/ }).check();
    await page.getByLabel("I have reviewed the institution-wide impact.").check();
    await page.getByRole("button", { name: "Update course availability" }).click();
    await expect(
      page.getByText("Every course in this institution", { exact: true }).first(),
    ).toBeVisible();

    await page.setViewportSize({ width: 390, height: 844 });
    const viewportWidths = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(viewportWidths.scrollWidth).toBe(viewportWidths.clientWidth);
    await expect(page.getByRole("button", { name: "Stop offering in courses" })).toBeVisible();

    await page
      .getByLabel("I understand faculty will no longer be able to add this rule to courses.")
      .check();
    await page.getByRole("button", { name: "Stop offering in courses" }).click();
    await expect(page.getByText("The rule is no longer offered in courses.")).toBeVisible();
    await expect(page.getByText("Not offered", { exact: true })).toBeVisible();
    const visibleText = await page.locator("body").innerText();
    expect(visibleText).not.toContain(fixture.tenantId);
    expect(visibleText).not.toContain(fixture.departmentId);
    expect(visibleText).not.toMatch(/\b(?:brl|lctx|ou)_[A-Za-z0-9_-]+\b/);
    await expect(fixture.readRuleState()).resolves.toEqual(fixture.initialRuleState);
  } finally {
    await context.close();
    await fixture.dispose();
  }
});
