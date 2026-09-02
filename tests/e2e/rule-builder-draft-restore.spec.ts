import { upsertTenantLmsConnection } from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { expect, test, type Page, type Route } from "@playwright/test";

import { createTestBadgeIssuanceRule } from "../../packages/db/src/badge-issuance-rule-test-fixtures";
import { loadLocalDevEnv, requireEnv } from "../../scripts/local-dev-env.mjs";
import { demoRoutes, tenantId } from "./helpers/demo-routes";

const savedCourseId = "course-draft-restore";
const savedAssignmentId = "assignment-outside-picker-page";
const savedBadgeTemplateId = "badge_template_trusted_demo";

const fulfillLmsPickerRoute = async (route: Route): Promise<void> => {
  const request = route.request();
  const path = new URL(request.url()).pathname;

  if (path.endsWith("/courses/resolve")) {
    await route.fulfill({
      json: {
        courses: [{ courseId: savedCourseId, title: "Draft Restore Course", courseCode: "DR101" }],
      },
    });
    return;
  }

  if (path.endsWith("/gradebook-items/resolve")) {
    await route.fulfill({
      json: {
        items: [
          {
            assignmentId: savedAssignmentId,
            title: "Saved capstone",
            pointsPossible: 100,
          },
        ],
      },
    });
    return;
  }

  if (path.endsWith(`/gradebook-items/${savedAssignmentId}/workflow-states`)) {
    await route.fulfill({ json: { states: [] } });
    return;
  }

  if (path.endsWith("/gradebook-items")) {
    await route.fulfill({
      json: {
        items: [{ assignmentId: "first-page-item", title: "First-page assignment" }],
      },
    });
    return;
  }

  if (path.endsWith("/courses")) {
    await route.fulfill({
      json: {
        courses: [{ courseId: savedCourseId, title: "Draft Restore Course", courseCode: "DR101" }],
        hasMore: false,
      },
    });
    return;
  }

  await route.fallback();
};

const installLmsPickerRoutes = async (page: Page): Promise<void> => {
  await page.route("**/v1/tenants/**/lms/connections/**", fulfillLmsPickerRoute);
  await page.route("**/v1/tenants/**/badge-rules/preview-evaluate", async (route) => {
    await route.fulfill({
      json: {
        dryRun: true,
        outcome: "matched",
        evaluation: {
          matched: true,
          tree: {
            children: [{ matched: true, detail: "Generated example meets the requirement." }],
          },
        },
        evaluationSummary: { missingDataCount: 0 },
        facts: {},
      },
    });
  });
};

const applyDefinitionJson = async (page: Page, definition: unknown): Promise<void> => {
  const definitionField = page.locator("#rule-builder-definition-json");
  if (!(await definitionField.isVisible())) {
    await page.getByText("Generated rule JSON", { exact: true }).click();
  }
  await definitionField.fill(JSON.stringify(definition));
  await page.getByRole("button", { name: "Apply JSON" }).click();
};

const createReadyLmsConnection = async (): Promise<string> => {
  loadLocalDevEnv();
  const db = createPostgresDatabase({
    databaseUrl: requireEnv("DATABASE_URL"),
    connectionMode: "single-use",
  });
  const connectionId = `lms_draft_restore_${crypto.randomUUID().replaceAll("-", "")}`;

  await upsertTenantLmsConnection(db, {
    id: connectionId,
    tenantId,
    displayName: "Draft Restore LMS",
    providerKind: "sakai",
    apiBaseUrl: "https://sakai.example.edu",
    accessToken: "SAKAIID=draft-restore-session",
  });
  return connectionId;
};

const createFormalAssignmentRule = async (input: {
  readonly lmsConnectionId: string;
  readonly ruleName: string;
}): Promise<string> => {
  loadLocalDevEnv();
  const db = createPostgresDatabase({
    databaseUrl: requireEnv("DATABASE_URL"),
    connectionMode: "single-use",
  });
  const created = await createTestBadgeIssuanceRule(db, {
    tenantId,
    name: input.ruleName,
    badgeTemplateId: savedBadgeTemplateId,
    lmsProviderKind: "sakai",
    lmsConnectionId: input.lmsConnectionId,
    ruleJson: JSON.stringify({
      conditions: {
        all: [
          {
            type: "assignment_submission",
            courseId: savedCourseId,
            assignmentId: savedAssignmentId,
            requireSubmitted: true,
          },
        ],
      },
      options: { issuanceTiming: "manual", reviewOnMissingFacts: true },
    }),
    changeSummary: "Create draft-restore browser fixture",
  });
  return created.rule.id;
};

const configureAssignmentRule = async (
  page: Page,
  ruleName: string,
  lmsConnectionId: string,
): Promise<void> => {
  const badgeTemplateCombobox = page.getByRole("combobox", { name: "Badge template" });
  await badgeTemplateCombobox.click();
  await page.getByRole("listbox", { name: "Badge templates" }).getByRole("option").first().click();

  const reuseConfirmation = page.getByLabel(
    "I confirm this rule is another valid way to earn the same badge.",
  );
  if (await reuseConfirmation.isVisible()) {
    await reuseConfirmation.check();
  }

  const lmsConnection = page.getByLabel("LMS connection");
  await lmsConnection.selectOption(lmsConnectionId);

  await page.getByLabel("Awarding pattern").selectOption("assignment_submission");
  await page.locator("#rule-builder-name").evaluate((field, value) => {
    if (!(field instanceof HTMLInputElement)) {
      throw new TypeError("Rule name field must be an input");
    }
    field.value = value;
    field.dispatchEvent(new Event("input", { bubbles: true }));
  }, ruleName);
  await page.getByRole("button", { name: "Continue to Requirements" }).click();

  const conditionCard = page.locator(".ct-admin__condition-card").first();
  const courseSelect = conditionCard.locator("select[data-lms-course-select]");
  await expect(courseSelect.locator(`option[value="${savedCourseId}"]`)).toHaveCount(1);
  await courseSelect.selectOption(savedCourseId);

  const gradebookItemSelect = conditionCard.locator("select[data-lms-gradebook-item-select]");
  await expect(gradebookItemSelect.locator('option[value="first-page-item"]')).toHaveCount(1);
  await gradebookItemSelect.selectOption("first-page-item");
  await applyDefinitionJson(page, {
    conditions: {
      all: [
        {
          type: "assignment_submission",
          courseId: savedCourseId,
          assignmentId: savedAssignmentId,
          requireSubmitted: true,
        },
      ],
    },
    options: { issuanceTiming: "immediate", reviewOnMissingFacts: false },
  });
  await expect(gradebookItemSelect).toHaveValue(savedAssignmentId);
};

const openTestStep = async (page: Page): Promise<void> => {
  await page.getByRole("button", { name: "Continue to Test and submit" }).click();
};

const runPassingExample = async (page: Page): Promise<void> => {
  await page.getByLabel("Generated example data").check();
  await page.getByRole("button", { name: "Test example data" }).click();
  await expect(page.locator("#rule-builder-test-result")).toContainText("qualifies");
};

const readGeneratedDefinition = async (page: Page): Promise<unknown> => {
  const rawDefinition = await page.locator("#rule-builder-definition-json").inputValue();
  return JSON.parse(rawDefinition) as unknown;
};

const waitForBuilderDraftSave = (page: Page): ReturnType<Page["waitForResponse"]> => {
  return page.waitForResponse((response) => {
    return (
      response.request().method() === "PUT" &&
      new URL(response.url()).pathname.includes("/badge-rule-builder-drafts/")
    );
  });
};

const cleanupDraftRestoreRecords = async (input: {
  readonly builderDraftId?: string;
  readonly lmsConnectionId: string;
  readonly ruleId?: string;
}): Promise<void> => {
  loadLocalDevEnv();
  const db = createPostgresDatabase({
    databaseUrl: requireEnv("DATABASE_URL"),
    connectionMode: "single-use",
  });

  if (input.builderDraftId !== undefined) {
    await db
      .prepare("DELETE FROM badge_issuance_rule_builder_drafts WHERE tenant_id = ? AND id = ?")
      .bind(tenantId, input.builderDraftId)
      .run();
  }

  if (input.ruleId !== undefined) {
    await db
      .prepare("DELETE FROM badge_issuance_rules WHERE tenant_id = ? AND id = ?")
      .bind(tenantId, input.ruleId)
      .run();
  }

  await db
    .prepare("DELETE FROM tenant_lms_connections WHERE tenant_id = ? AND id = ?")
    .bind(tenantId, input.lmsConnectionId)
    .run();
};

test("a formal assignment-rule draft restores every visible and submitted setting", async ({
  page,
}) => {
  await installLmsPickerRoutes(page);
  const ruleName = `Draft restore ${crypto.randomUUID().slice(0, 8)}`;
  const lmsConnectionId = await createReadyLmsConnection();
  let ruleId: string | undefined;

  try {
    ruleId = await createFormalAssignmentRule({ lmsConnectionId, ruleName });
    await page.goto(`${demoRoutes.rules}/${encodeURIComponent(ruleId)}/edit`);

    await expect(page.getByLabel("Awarding pattern")).toHaveValue("assignment_submission");
    await expect(page.getByLabel("Issuance timing")).toHaveValue("manual");
    await expect(page.getByLabel("Send missing-data cases to human review")).toBeChecked();
    const restoredCard = page.locator(".ct-admin__condition-card").first();
    await expect(restoredCard.locator("select[data-lms-course-select]")).toHaveValue(savedCourseId);
    await expect(restoredCard.locator("select[data-lms-gradebook-item-select]")).toHaveValue(
      savedAssignmentId,
    );
    await expect(readGeneratedDefinition(page)).resolves.toMatchObject({
      conditions: {
        all: [
          expect.objectContaining({
            type: "assignment_submission",
            courseId: savedCourseId,
            assignmentId: savedAssignmentId,
          }),
        ],
      },
      options: { issuanceTiming: "manual", reviewOnMissingFacts: true },
    });

    const reuseConfirmation = page.getByLabel(
      "I confirm this rule is another valid way to earn the same badge.",
    );
    if ((await reuseConfirmation.isVisible()) && !(await reuseConfirmation.isChecked())) {
      await reuseConfirmation.check();
    }

    const conditionsDraftSave = waitForBuilderDraftSave(page);
    await page.getByRole("button", { name: "Continue to Requirements" }).click();
    await conditionsDraftSave;
    const testDraftSave = waitForBuilderDraftSave(page);
    await openTestStep(page);
    await testDraftSave;
    await runPassingExample(page);
    const updatePath = `/v1/tenants/${tenantId}/badge-rules/${encodeURIComponent(ruleId)}/draft`;
    const updateRequestPromise = page.waitForRequest((request) => {
      return request.method() === "POST" && new URL(request.url()).pathname === updatePath;
    });
    const updateResponsePromise = page.waitForResponse((response) => {
      return (
        response.request().method() === "POST" && new URL(response.url()).pathname === updatePath
      );
    });
    await page.getByRole("button", { name: "Save draft version" }).click();
    const updateRequest = await updateRequestPromise;
    await updateResponsePromise;
    const updatePayload = JSON.parse(updateRequest.postData() ?? "null") as unknown;

    expect(updatePayload).toMatchObject({
      definition: {
        conditions: {
          all: [
            expect.objectContaining({
              type: "assignment_submission",
              courseId: savedCourseId,
              assignmentId: savedAssignmentId,
            }),
          ],
        },
        options: { issuanceTiming: "manual", reviewOnMissingFacts: true },
      },
    });
  } finally {
    await cleanupDraftRestoreRecords({
      lmsConnectionId,
      ...(ruleId === undefined ? {} : { ruleId }),
    });
  }
});

test("unfinished custom requirements restore without being replaced by a starter", async ({
  page,
}) => {
  await installLmsPickerRoutes(page);
  const ruleName = `Unfinished restore ${crypto.randomUUID().slice(0, 8)}`;
  const lmsConnectionId = await createReadyLmsConnection();
  let builderDraftId: string | undefined;

  try {
    await page.goto(demoRoutes.ruleBuilder);
    await configureAssignmentRule(page, ruleName, lmsConnectionId);
    const customDefinition = {
      conditions: {
        all: [
          { type: "course_completion", courseId: savedCourseId, minCompletionPercent: 100 },
          {
            any: [
              { type: "survey_completion", surveyId: "exit-survey", requireCompleted: true },
              { type: "prerequisite_badge", badgeTemplateId: savedBadgeTemplateId },
            ],
          },
        ],
      },
      options: { issuanceTiming: "manual", reviewOnMissingFacts: true },
    };
    await applyDefinitionJson(page, customDefinition);
    await expect(page.getByLabel("Awarding pattern")).toHaveValue("custom");

    const saveResponsePromise = page.waitForResponse((response) => {
      const request = response.request();
      return request.method() === "PUT" && new URL(request.url()).pathname.includes("drafts");
    });
    await page.getByRole("button", { name: "Save unfinished work" }).click();
    const saveResponse = await saveResponsePromise;
    const savePayload: unknown = await saveResponse.json();
    const draft =
      savePayload !== null && typeof savePayload === "object"
        ? Reflect.get(savePayload, "draft")
        : null;
    const savedDraftId =
      draft !== null && typeof draft === "object" ? Reflect.get(draft, "id") : undefined;

    if (typeof savedDraftId !== "string") {
      throw new Error("Saved builder draft response did not include a draft ID");
    }

    builderDraftId = savedDraftId;
    const restoredDraftSave = waitForBuilderDraftSave(page);
    await page.reload();
    await restoredDraftSave;

    await expect(page.getByLabel("Awarding pattern")).toHaveValue("custom");
    await expect(page.getByLabel("Issuance timing")).toHaveValue("manual");
    await expect(page.getByLabel("Send missing-data cases to human review")).toBeChecked();
    await expect(readGeneratedDefinition(page)).resolves.toEqual(customDefinition);
  } finally {
    await cleanupDraftRestoreRecords({
      lmsConnectionId,
      ...(builderDraftId === undefined ? {} : { builderDraftId }),
    });
  }
});
