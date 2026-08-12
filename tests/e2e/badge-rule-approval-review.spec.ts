import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PAGE_ASSET_MANIFEST } from "../../apps/api-worker/src/ui/page-assets/generated/page-assets-manifest";
import { createLiveBadgeRuleApprovalFixture } from "./helpers/live-badge-rule-approval-fixture";

const readBuiltPageAsset = (path: string): string => {
  return readFileSync(
    join(process.cwd(), "apps/api-worker/public", path.replace(/^\//, "")),
    "utf8",
  );
};

const REVIEW_PAGE_CSS = [
  readBuiltPageAsset(PAGE_ASSET_MANIFEST.foundationCss.path),
  readBuiltPageAsset(PAGE_ASSET_MANIFEST.institutionAdminCss.path),
  readBuiltPageAsset(PAGE_ASSET_MANIFEST.institutionAdminRuleVersionCss.path),
  readBuiltPageAsset(PAGE_ASSET_MANIFEST.institutionAdminRuleApprovalReviewCss.path),
].join("\n");
const REVIEW_PAGE_SCRIPT = readBuiltPageAsset(
  PAGE_ASSET_MANIFEST.institutionAdminRuleApprovalReviewJs.path,
);
const REVIEW_DOCUMENT = execFileSync(
  "pnpm",
  [
    "exec",
    "tsx",
    "-e",
    'import { renderBadgeRuleApprovalReviewPageFixture } from "./apps/api-worker/src/test-support/badge-rule-approval-review-page-fixture"; process.stdout.write(renderBadgeRuleApprovalReviewPageFixture());',
  ],
  { cwd: process.cwd(), encoding: "utf8" },
);

const loadReviewPage = async (page: Page): Promise<void> => {
  await page.setContent(REVIEW_DOCUMENT);
  await page.addStyleTag({ content: REVIEW_PAGE_CSS });
  await page.addScriptTag({ content: REVIEW_PAGE_SCRIPT });
  await page.evaluate(() => document.dispatchEvent(new Event("DOMContentLoaded")));
};

test("approval review keeps the decision rail visible on desktop", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await loadReviewPage(page);

  await expect(page.getByRole("heading", { name: "What changed" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Record your decision" })).toBeVisible();
  await expect(page.locator(".ct-admin__review-decision-panel")).toHaveCSS("position", "sticky");

  const columns = await page
    .locator(".ct-admin__review-layout")
    .evaluate((element) => getComputedStyle(element).gridTemplateColumns);
  expect(columns.split(" ")).toHaveLength(2);
});

test("approval review validates reviewer decisions with native controls", async ({ page }) => {
  await loadReviewPage(page);

  await page.getByLabel("Return for changes").check();
  const comment = page.getByLabel("Reviewer comment");
  await expect(comment).toHaveAttribute("required", "");
  await expect(page.locator("[data-rule-review-comment-hint]")).toHaveText(
    "Required. Describe what the author must change before resubmitting.",
  );

  await page.getByRole("button", { name: "Record decision" }).click();
  await expect(comment).toBeFocused();

  await page.getByLabel("Approve version").check();
  await expect(comment).not.toHaveAttribute("required", "");
});

test("approval review becomes a single ordered flow on a narrow screen", async ({ page }) => {
  await page.setViewportSize({ width: 540, height: 900 });
  await loadReviewPage(page);

  await expect(page.locator(".ct-admin__review-decision-panel")).toHaveCSS("position", "static");

  const verticalPositions = await page.locator(".ct-admin__review-layout").evaluate((layout) => {
    const primary = layout.querySelector(".ct-admin__review-primary");
    const decision = layout.querySelector(".ct-admin__review-decision-rail");
    const supporting = layout.querySelector(".ct-admin__review-supporting");

    if (!(primary instanceof HTMLElement)) throw new Error("Primary review content is missing");
    if (!(decision instanceof HTMLElement)) throw new Error("Decision content is missing");
    if (!(supporting instanceof HTMLElement)) throw new Error("Supporting content is missing");

    return [
      primary.getBoundingClientRect().top,
      decision.getBoundingClientRect().top,
      supporting.getBoundingClientRect().top,
    ];
  });

  expect(verticalPositions[0]).toBeLessThan(verticalPositions[1] ?? 0);
  expect(verticalPositions[1]).toBeLessThan(verticalPositions[2] ?? 0);

  const auditHistory = page.locator(".ct-admin__review-audit-history");
  await auditHistory.getByText("Show full audit history (1 event)").click();
  await expect(auditHistory.getByText("submitted")).toBeVisible();
});

test("a distinct reviewer can approve a submitted rule and reload the persisted decision", async ({
  browser,
  baseURL,
}) => {
  if (baseURL === undefined) {
    throw new Error("Playwright baseURL is required.");
  }

  const fixture = await createLiveBadgeRuleApprovalFixture();
  const authorContext = await browser.newContext();
  const reviewerContext = await browser.newContext();

  try {
    const authorPage = await authorContext.newPage();
    const authorLoginUrl = new URL("/v1/dev/auth/login-as", baseURL);
    authorLoginUrl.searchParams.set("tenantId", fixture.tenantId);
    authorLoginUrl.searchParams.set("email", fixture.authorEmail);
    authorLoginUrl.searchParams.set("next", fixture.rulesPath);
    await authorPage.goto(authorLoginUrl.toString());

    const ruleRow = authorPage.locator("tr").filter({ hasText: fixture.ruleName });
    await expect(ruleRow).toBeVisible();
    await authorPage
      .getByRole("button", { name: `More actions for ${fixture.ruleName}` })
      .click();
    authorPage.once("dialog", (dialog) => dialog.accept());
    await ruleRow.getByRole("button", { name: "Submit for approval" }).click();
    await expect(authorPage.getByText("Rule version submitted for approval.")).toBeVisible();

    const reviewerPage = await reviewerContext.newPage();
    const reviewerLoginUrl = new URL("/v1/dev/auth/login-as", baseURL);
    reviewerLoginUrl.searchParams.set("tenantId", fixture.tenantId);
    reviewerLoginUrl.searchParams.set("email", fixture.reviewerEmail);
    reviewerLoginUrl.searchParams.set("next", fixture.approvalsPath);
    await reviewerPage.goto(reviewerLoginUrl.toString());

    const approvalRow = reviewerPage.locator("tr").filter({ hasText: fixture.ruleName });
    await expect(approvalRow).toBeVisible();
    await approvalRow.getByRole("link", { name: "Review" }).click();
    await expect(reviewerPage.getByRole("heading", { name: fixture.ruleName })).toBeVisible();
    await reviewerPage.getByLabel("Approve version").check();
    await reviewerPage.getByLabel("Reviewer comment").fill("Approved in the live browser flow.");
    await reviewerPage.getByRole("button", { name: "Record decision" }).click();

    await expect(reviewerPage.getByText("Rule version approved.")).toBeVisible();
    await reviewerPage.reload();
    await expect(reviewerPage.getByRole("heading", { name: "Correct this approval" })).toBeVisible();
    await expect(
      reviewerPage
        .locator(".ct-admin__review-approval-chain")
        .getByText("Approved in the live browser flow.")
    ).toBeVisible();
  } finally {
    await Promise.all([authorContext.close(), reviewerContext.close()]);
    await fixture.dispose();
  }
});
