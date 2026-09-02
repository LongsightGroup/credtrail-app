import { upsertTenantLmsConnection } from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { expect, test, type Page, type Route } from "@playwright/test";
import { createServer } from "node:http";

import { createTestBadgeIssuanceRule } from "../../packages/db/src/badge-issuance-rule-test-fixtures";
import { loadLocalDevEnv, requireEnv } from "../../scripts/local-dev-env.mjs";
import { demoRoutes, tenantId } from "./helpers/demo-routes";

const sourceDescription = "Source settings must survive the copy workflow.";
const copiedBadgeTemplateId = "badge_template_trusted_demo";
const sourceCourseId = "course-copy-source";

const startMockSakai = async (): Promise<{
  readonly apiBaseUrl: string;
  readonly close: () => Promise<void>;
}> => {
  const course = {
    id: sourceCourseId,
    title: "Rule Copy Source Course",
    type: "course",
    maintainRole: "Instructor",
    shortDescription: "COPY101",
    published: true,
  };
  const server = createServer((request, response) => {
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    const body =
      requestUrl.pathname === "/direct/site.json"
        ? { site_collection: requestUrl.searchParams.has("_start") ? [] : [course] }
        : requestUrl.pathname === `/direct/site/${sourceCourseId}.json`
          ? course
          : { error: `No mock route configured for ${requestUrl.pathname}` };
    const statusCode = "error" in body ? 404 : 200;
    response.writeHead(statusCode, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();

  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("Mock Sakai server did not bind to a TCP port");
  }

  return {
    apiBaseUrl: `http://127.0.0.1:${String(address.port)}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) {
            resolve();
          } else {
            reject(error);
          }
        });
      }),
  };
};

const fulfillRulePreview = async (route: Route): Promise<void> => {
  await route.fulfill({
    json: {
      dryRun: true,
      outcome: "matched",
      evaluation: {
        matched: true,
        tree: {
          children: [
            { matched: true, detail: "The learner completed the course." },
            { matched: true, detail: "The learner met the score threshold." },
          ],
        },
      },
      evaluationSummary: { missingDataCount: 0 },
      facts: {},
    },
  });
};

const setHiddenRuleName = async (page: Page, name: string): Promise<void> => {
  await page.locator("#rule-builder-name").evaluate((field, value) => {
    if (!(field instanceof HTMLInputElement)) {
      throw new TypeError("Rule name field must be an input");
    }

    field.value = value;
    field.dispatchEvent(new Event("input", { bubbles: true }));
  }, name);
};

const createCopySource = async (input: {
  readonly apiBaseUrl: string;
  readonly lmsConnectionId: string;
  readonly sourceRuleName: string;
}): Promise<string> => {
  loadLocalDevEnv();
  const db = createPostgresDatabase({
    databaseUrl: requireEnv("DATABASE_URL"),
    connectionMode: "single-use",
  });

  await upsertTenantLmsConnection(db, {
    id: input.lmsConnectionId,
    tenantId,
    displayName: "Rule copy test LMS",
    providerKind: "sakai",
    apiBaseUrl: input.apiBaseUrl,
    accessToken: "SAKAIID=rule-copy-test-session",
  });
  const created = await createTestBadgeIssuanceRule(db, {
    tenantId,
    name: input.sourceRuleName,
    description: sourceDescription,
    badgeTemplateId: copiedBadgeTemplateId,
    lmsProviderKind: "sakai",
    lmsConnectionId: input.lmsConnectionId,
    ruleJson: JSON.stringify({
      conditions: {
        all: [
          {
            type: "course_completion",
            courseId: sourceCourseId,
            minCompletionPercent: 100,
          },
          {
            type: "grade_threshold",
            courseId: sourceCourseId,
            scoreField: "final_score",
            minScore: 85,
          },
        ],
      },
      options: { issuanceTiming: "manual", reviewOnMissingFacts: true },
    }),
    changeSummary: "Create rule-copy browser fixture",
  });

  return created.rule.id;
};

const cleanupCopiedRule = async (input: {
  readonly copiedRuleName: string;
  readonly lmsConnectionId: string;
  readonly sourceRuleId: string | undefined;
}): Promise<void> => {
  loadLocalDevEnv();
  const db = createPostgresDatabase({
    databaseUrl: requireEnv("DATABASE_URL"),
    connectionMode: "single-use",
  });

  await db
    .prepare(
      "DELETE FROM badge_issuance_rule_builder_drafts WHERE tenant_id = ? AND draft_json::jsonb ->> 'name' = ?",
    )
    .bind(tenantId, input.copiedRuleName)
    .run();
  await db
    .prepare("DELETE FROM badge_issuance_rules WHERE tenant_id = ? AND name = ?")
    .bind(tenantId, input.copiedRuleName)
    .run();
  if (input.sourceRuleId !== undefined) {
    await db
      .prepare("DELETE FROM badge_issuance_rules WHERE tenant_id = ? AND id = ?")
      .bind(tenantId, input.sourceRuleId)
      .run();
  }
  await db
    .prepare("DELETE FROM tenant_lms_connections WHERE tenant_id = ? AND id = ?")
    .bind(tenantId, input.lmsConnectionId)
    .run();
};

test("a copied rule keeps its settings and starts a separate lifecycle", async ({ page }) => {
  await page.route("**/v1/tenants/**/badge-rules/preview-evaluate", fulfillRulePreview);
  const fixtureSuffix = crypto.randomUUID().replaceAll("-", "");
  const sourceRuleName = `Copy source ${fixtureSuffix.slice(0, 8)}`;
  const copiedRuleName = `Copied analytics ${crypto.randomUUID().slice(0, 8)}`;
  const lmsConnectionId = `lms_rule_copy_${fixtureSuffix}`;
  const mockSakai = await startMockSakai();
  let sourceRuleId: string | undefined;

  try {
    sourceRuleId = await createCopySource({
      apiBaseUrl: mockSakai.apiBaseUrl,
      lmsConnectionId,
      sourceRuleName,
    });
    await page.goto(demoRoutes.rules);
    const sourceRow = page.locator("tbody tr").filter({ hasText: sourceRuleName });
    const sourceDetailHref = await sourceRow
      .getByRole("link", { name: sourceRuleName, exact: true })
      .getAttribute("href");

    await sourceRow.getByRole("link", { name: `Copy ${sourceRuleName}`, exact: true }).click();
    await expect(page).toHaveURL(/\/admin\/rules\/new\?copyRuleId=/);
    await expect(page.getByRole("heading", { name: "Copy Badge Awarding Rule" })).toBeVisible();
    await expect(page.locator("#rule-builder-name")).toHaveValue(`Copy of ${sourceRuleName}`);
    await expect(page.getByLabel("Description (optional)")).toHaveValue(sourceDescription);
    await expect(page.getByRole("combobox", { name: "Badge template" })).toHaveValue(
      "Applied Analytics TrustEd Credential",
    );
    await expect(page.getByLabel("LMS connection")).toHaveValue(lmsConnectionId);

    await setHiddenRuleName(page, copiedRuleName);
    const reuseConfirmation = page.getByLabel(
      "I confirm this rule is another valid way to earn the same badge.",
    );
    if (await reuseConfirmation.isVisible()) {
      await reuseConfirmation.check();
    }

    await page.getByRole("button", { name: "Continue to Requirements" }).click();
    const conditionCards = page.locator(".ct-admin__condition-card");
    await expect(conditionCards).toHaveCount(2);
    const scoreField = conditionCards.nth(1).locator('[data-field="minScore"]');
    await expect(scoreField).toHaveValue("85");
    await scoreField.fill("88");

    const unfinishedSave = page.waitForResponse((response) => {
      return (
        response.request().method() === "PUT" &&
        new URL(response.url()).pathname.includes("/badge-rule-builder-drafts/")
      );
    });
    await page.getByRole("button", { name: "Save unfinished work" }).click();
    await unfinishedSave;
    await expect(page).toHaveURL(/\/admin\/rules\/drafts\/.+\/edit$/);

    await page.reload();
    await expect(page.locator("#rule-builder-name")).toHaveValue(copiedRuleName);
    await expect(page.locator(".ct-admin__condition-card")).toHaveCount(2);
    await expect(
      page.locator(".ct-admin__condition-card").nth(1).locator('[data-field="minScore"]'),
    ).toHaveValue("88");

    await page.getByRole("button", { name: /Awarding pattern/ }).click();
    const restoredReuseConfirmation = page.getByLabel(
      "I confirm this rule is another valid way to earn the same badge.",
    );
    if (
      (await restoredReuseConfirmation.isVisible()) &&
      !(await restoredReuseConfirmation.isChecked())
    ) {
      await restoredReuseConfirmation.check();
    }
    await page.getByRole("button", { name: "Continue to Requirements" }).click();
    await page.getByRole("button", { name: "Continue to Test and submit" }).click();
    await page.getByLabel("Generated example data").check();
    await page.getByRole("button", { name: "Test example data" }).click();
    await expect(page.locator("#rule-builder-test-result")).toContainText("qualifies");
    const submitButton = page.getByRole("button", { name: "Create and submit for approval" });
    await expect(submitButton).toBeEnabled();
    const createResponse = page.waitForResponse((response) => {
      return (
        response.request().method() === "POST" &&
        new URL(response.url()).pathname === `/v1/tenants/${tenantId}/badge-rules`
      );
    });
    await submitButton.click();
    await expect((await createResponse).ok()).toBe(true);
    await expect(page).toHaveURL(demoRoutes.rules);

    const copiedRow = page.locator("tbody tr").filter({ hasText: copiedRuleName });
    await expect(copiedRow).toBeVisible();
    await expect(copiedRow.getByText(/Draft|Awaiting approval|Approved/)).toBeVisible();
    const copiedDetailHref = await copiedRow
      .getByRole("link", { name: copiedRuleName, exact: true })
      .getAttribute("href");
    expect(copiedDetailHref).not.toBe(sourceDetailHref);

    const unchangedSourceRow = page.locator("tbody tr").filter({ hasText: sourceRuleName });
    await expect(
      unchangedSourceRow.getByRole("link", { name: sourceRuleName, exact: true }),
    ).toHaveAttribute("href", sourceDetailHref ?? "");
  } finally {
    await cleanupCopiedRule({ copiedRuleName, lmsConnectionId, sourceRuleId });
    await mockSakai.close();
  }
});
