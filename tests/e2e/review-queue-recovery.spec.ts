import { expect, test } from "@playwright/test";
import { createBadgeIssuanceRuleEvaluation, createAuditLog } from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { createLiveBadgeRuleApprovalFixture } from "./helpers/live-badge-rule-approval-fixture";
import { loadLocalDevEnv, requireEnv } from "../../scripts/local-dev-env.mjs";
import {
  completeFirstDayWorkflow,
  createFirstDayWorkflowIdentity,
} from "./helpers/first-day-workflow";

test("review notes survive errors and warn before leaving, then become searchable history", async ({
  page,
  baseURL,
}) => {
  const f = await createLiveBadgeRuleApprovalFixture();
  loadLocalDevEnv();
  const db = createPostgresDatabase({
    databaseUrl: requireEnv("DATABASE_URL"),
    connectionMode: "single-use",
  });
  const recipient = `review-${crypto.randomUUID()}@example.edu`;
  try {
    const evaluation = await createBadgeIssuanceRuleEvaluation(db, {
      tenantId: f.tenantId,
      ruleId: f.ruleId,
      versionId: f.versionId,
      learnerId: recipient,
      recipientIdentity: recipient,
      recipientIdentityType: "email",
      matched: false,
      issuanceStatus: "review_required",
      reviewStatus: "pending",
      evaluationJson: "{}",
    });
    const path = `/tenants/${f.tenantId}/admin/operations/review-queue`;
    const login = new URL("/v1/dev/auth/login-as", baseURL);
    login.search = new URLSearchParams({
      tenantId: f.tenantId,
      email: f.authorEmail,
      next: `${path}?review=${evaluation.id}`,
    }).toString();
    await page.goto(login.toString());
    const note = page.getByLabel("Decision note (optional)");
    await note.fill("Keep the registrar's decision note intact.");
    const dialog = page.waitForEvent("dialog");
    const navigation = page.getByRole("link", { name: "Resolved", exact: true }).click();
    await (await dialog).dismiss();
    await navigation;
    await expect(note).toHaveValue("Keep the registrar's decision note intact.");
    const dismiss = page.getByRole("button", { name: "Dismiss review", exact: true });
    await dismiss.evaluate((button: HTMLButtonElement) => {
      button.value = "invalid";
    });
    await dismiss.click();
    await expect(page.getByRole("alert")).toContainText("Choose Issue badge or Dismiss review");
    await expect(note).toHaveValue("Keep the registrar's decision note intact.");
    await expect(page.locator('#review-decision-form input[name="evaluationId"]')).toHaveValue(
      evaluation.id,
    );
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({ path: "/tmp/credtrail-review-recovery-desktop.png", fullPage: true });
    await page.getByRole("button", { name: "Dismiss review", exact: true }).click();
    await page.getByRole("link", { name: "Resolved", exact: true }).click();
    await page.getByLabel("Learner or badge").fill(recipient);
    await page.getByRole("button", { name: "Search reviews", exact: true }).click();
    await page.getByRole("link", { name: "View decision", exact: true }).click();
    await expect(page.getByRole("region", { name: "Decision details" })).toContainText(
      "Keep the registrar's decision note intact.",
    );
    await page.setViewportSize({ width: 390, height: 844 });
    await page.reload();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.screenshot({ path: "/tmp/credtrail-review-history-mobile.png", fullPage: true });
  } finally {
    await f.dispose();
  }
});

test("email attention filter opens retry and clears after a successful notification", async ({
  page,
}) => {
  const identity = createFirstDayWorkflowIdentity();
  await completeFirstDayWorkflow(page, identity);
  const href = await page
    .locator('[data-issued-badge-row="true"]')
    .getByRole("link", { name: "View record", exact: true })
    .getAttribute("href");
  const encodedId = href?.match(/issued-badges\/([^/]+)\/evidence/)?.[1];
  if (!encodedId) throw new Error("Missing assertion record link");
  const assertionId = decodeURIComponent(encodedId);
  loadLocalDevEnv();
  const db = createPostgresDatabase({
    databaseUrl: requireEnv("DATABASE_URL"),
    connectionMode: "single-use",
  });
  await createAuditLog(db, {
    tenantId: "tenant_123",
    action: "assertion.issuance_email",
    targetType: "assertion",
    targetId: assertionId,
    metadata: { status: "failed" },
    occurredAt: "2090-01-01T00:00:00.000Z",
  });
  const url = new URL(page.url());
  url.searchParams.set("notificationStatus", "failed");
  await page.goto(url.toString());
  await expect(page.locator('[data-issued-badge-row="true"]')).toHaveCount(1);
  await expect(page.getByRole("region", { name: "CSV export" })).toContainText(
    "all 1 matching record",
  );
  await page.getByRole("link", { name: "Retry notification email", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Retry notification email", exact: true }),
  ).toBeVisible();
  await createAuditLog(db, {
    tenantId: "tenant_123",
    action: "assertion.issuance_email",
    targetType: "assertion",
    targetId: assertionId,
    metadata: { status: "accepted" },
    occurredAt: "2090-01-02T00:00:00.000Z",
  });
  await page.goto(url.toString());
  await expect(page.locator('[data-issued-badge-row="true"]')).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Export matching CSV" })).toHaveCount(0);
});
