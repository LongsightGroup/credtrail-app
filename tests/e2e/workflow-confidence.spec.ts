import { expect, test } from "@playwright/test";
import {
  completeFirstDayWorkflow,
  createFirstDayWorkflowIdentity,
} from "./helpers/first-day-workflow";
import { demoRoutes } from "./helpers/demo-routes";

test("sharing and notification status stay available from filtered badge records", async ({
  page,
  context,
}) => {
  const identity = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, identity);
  await expect(page.getByRole("region", { name: "Active filters" })).toContainText(
    identity.recipientEmail,
  );
  await expect(page.getByRole("status")).toContainText("1 matching record.");
  await expect(page.getByLabel("Results to show")).toHaveValue("100");
  await page.getByRole("link", { name: "View record", exact: true }).click();
  await expect(page.getByRole("region", { name: "Email notification" })).toContainText(
    "Email notifications are turned off",
  );
  const copy = page.getByRole("button", { name: "Copy public badge link" });
  const publicUrl = await copy.getAttribute("data-public-badge-url");
  expect(publicUrl).toMatch(/^http:\/\/(localhost|127\.0\.0\.1):8787\/badges\//);
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await copy.click();
  await expect(page.getByRole("status")).toHaveText("Copied");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(publicUrl);
  await context.clearPermissions();
  await context.grantPermissions([]);
  // Exercise the denied-clipboard path through the browser permission boundary.
  const session = await context.newCDPSession(page);
  await session.send("Browser.setPermission", {
    permission: { name: "clipboard-write" },
    setting: "denied",
    origin: new URL(page.url()).origin,
  });
  await copy.click();
  await expect(page.getByLabel("Public badge link", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Public badge link", { exact: true })).toHaveValue(publicUrl ?? "");
  await session.detach();
  await page.getByRole("link", { name: "Back to badge records" }).click();
  await expect(page.getByLabel("Recipient or record")).toHaveValue(identity.recipientEmail);
  await page.getByRole("link", { name: "Clear filters" }).click();
  await expect(page.getByLabel("Recipient or record")).toHaveValue("");
  await expect(page.getByRole("region", { name: "Active filters" })).toHaveCount(0);
});

test("template editors warn only while details differ from the saved record", async ({ page }) => {
  const identity = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, identity);
  await page.goto(demoRoutes.badgeTemplates + "?q=" + encodeURIComponent(identity.templateName));
  await page.getByRole("link", { name: "Edit template", exact: true }).click();
  const name = page.getByLabel("Badge name", { exact: true });
  await name.fill(identity.templateName + " revised");
  await expect(page.locator("#badge-template-edit-status")).toHaveText("Unsaved changes");
  const warnings: string[] = [];
  page.on("dialog", async (dialog) => {
    warnings.push(dialog.type());
    await dialog.dismiss();
  });
  await page.getByRole("link", { name: "Back to filtered templates" }).click({ noWaitAfter: true });
  await expect.poll(() => warnings).toEqual(["beforeunload"]);
  await expect(name).toHaveValue(identity.templateName + " revised");
  await name.fill(identity.templateName);
  await expect(page.locator("#badge-template-edit-status")).toHaveText("No unsaved changes");
  await page.getByRole("link", { name: "Back to filtered templates" }).click();
  await expect(page).toHaveURL(/templates\?q=/);
  await page.getByRole("link", { name: "Edit template", exact: true }).click();
  await page
    .getByRole("textbox", { name: "Description", exact: true })
    .fill("Saved by the workflow confidence test.");
  await page.getByRole("button", { name: "Save template details" }).click();
  await expect(page.locator("#badge-template-details-notice")).toHaveText(
    "Template details saved.",
  );
  await page.getByRole("link", { name: "Back to filtered templates" }).click();
  await expect(page).toHaveURL(/templates\?q=/);
  expect(warnings).toEqual(["beforeunload"]);
});

test("repeated issuance submissions converge on one receipt and one record", async ({ page }) => {
  const recipient = `retry-${crypto.randomUUID()}@example.edu`;
  await page.goto(demoRoutes.manualIssue + "?badgeTemplateId=badge_template_trusted_demo");
  await page.getByLabel("Recipient email").fill(recipient);
  const requestId = await page.locator('input[name="issuanceRequestId"]').inputValue();
  const form = {
    issuanceRequestId: requestId,
    badgeTemplateId: "badge_template_trusted_demo",
    recipientIdentity: recipient,
  };
  const submit = () =>
    page.request.post(demoRoutes.manualIssue, {
      form,
      maxRedirects: 0,
      headers: { Origin: new URL(page.url()).origin },
    });
  const responses = await Promise.all([submit(), submit()]);
  expect(responses.map((response) => response.status())).toEqual([303, 303]);
  const receiptPath = responses[0]?.headers()["location"];
  expect(receiptPath).toMatch(/\/receipt$/);
  expect(responses[1]?.headers()["location"]).toBe(receiptPath);
  let requests = 0;
  let release: () => void = () => {
    throw new Error("Request gate not initialized");
  };
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/admin/operations/issue", async (route) => {
    requests += 1;
    await gate;
    await route.continue();
  });
  const busy = await page.evaluate(() => {
    const form = document.querySelector("#manual-issue-form");
    if (!(form instanceof HTMLFormElement)) throw new Error("Missing issuance form");
    form.requestSubmit();
    const button = form.querySelector('button[type="submit"]');
    const state = {
      label: button?.textContent,
      disabled: button instanceof HTMLButtonElement && button.disabled,
    };
    form.requestSubmit();
    return state;
  });
  expect(busy).toEqual({ label: "Issuing…", disabled: true });
  await expect.poll(() => requests).toBe(1);
  release();
  await expect(page).toHaveURL(new RegExp("/receipt$"));
  expect(new URL(page.url()).pathname).toBe(receiptPath);
  expect(requests).toBe(1);
  await page.goto(demoRoutes.issuedBadges + "?recipientQuery=" + encodeURIComponent(recipient));
  await expect(page.locator("tbody tr").filter({ hasText: recipient })).toHaveCount(1);
});
