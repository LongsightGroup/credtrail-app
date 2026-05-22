import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import {
  AdminButton,
  AdminCheckboxRow,
  AdminEmptyTableRow,
  AdminField,
  AdminFieldset,
  AdminForm,
  AdminShell,
  AdminSidebar,
  AdminStatus,
  AdminTable,
  AdminTopbar,
  type AdminSidebarFooterLink,
  type AdminSidebarSection,
} from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const serializeJsonScriptContent = (value: unknown): string => {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
};

const inferCourseCodeFromText = (text: string): string | null => {
  const match = text.match(/\b([A-Z]{2,4}\d{2,4}[A-Z]?)\b/i);

  return match?.[1]?.toUpperCase() ?? null;
};

const parseGovernanceCourseId = (
  governanceMetadataJson: string | null | undefined,
): string | null => {
  if (governanceMetadataJson === null || governanceMetadataJson === undefined) {
    return null;
  }

  const trimmed = governanceMetadataJson.trim();

  if (trimmed.length === 0) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(trimmed);

    if (parsed !== null && typeof parsed === "object" && "courseId" in parsed) {
      const courseId = (parsed as { courseId?: unknown }).courseId;

      if (typeof courseId === "string" && courseId.trim().length > 0) {
        return courseId.trim();
      }
    }
  } catch {
    return null;
  }

  return null;
};

const extractCourseIdsFromRuleJson = (ruleJson: string): readonly string[] => {
  const courseIds: string[] = [];

  const walk = (node: unknown): void => {
    if (node === null || typeof node !== "object") {
      return;
    }

    if (Array.isArray(node)) {
      node.forEach((entry) => {
        walk(entry);
      });
      return;
    }

    const record = node as Record<string, unknown>;

    if (typeof record.courseId === "string" && record.courseId.trim().length > 0) {
      courseIds.push(record.courseId.trim());
    }

    if (Array.isArray(record.courseIds)) {
      for (const entry of record.courseIds) {
        if (typeof entry === "string" && entry.trim().length > 0) {
          courseIds.push(entry.trim());
        }
      }
    }

    for (const value of Object.values(record)) {
      walk(value);
    }
  };

  try {
    const parsed: unknown = JSON.parse(ruleJson);

    if (parsed !== null && typeof parsed === "object" && "conditions" in parsed) {
      walk((parsed as { conditions?: unknown }).conditions);
    }
  } catch {
    return courseIds;
  }

  return courseIds;
};

type RuleBuilderStepTarget = "metadata" | "conditions" | "test";

const ruleBuilderConditionTypes = [
  { value: "course_completion", label: "Course completion" },
  { value: "grade_threshold", label: "Grade threshold" },
  { value: "program_completion", label: "Program completion" },
  { value: "assignment_submission", label: "Assignment submission" },
  { value: "survey_completion", label: "Survey completion" },
  { value: "time_window", label: "Time window" },
  { value: "prerequisite_badge", label: "Prerequisite badge" },
  { value: "custom_field", label: "Custom field" },
] as const;

const RuleBuilderStepButton = (props: {
  stepNumber: number;
  target: RuleBuilderStepTarget;
  title: string;
  description: string;
}): HonoElement => {
  return (
    <button type="button" class="ct-admin__step-button" data-rule-step-target={props.target}>
      <span class="ct-admin__step-number">{props.stepNumber}</span>
      <span class="ct-admin__step-copy">
        <strong>{props.title}</strong>
        <small>{props.description}</small>
      </span>
    </button>
  );
};

const RuleBuilderConditionCardTemplate = (): HonoElement => {
  return (
    <template id="rule-builder-condition-card-template">
      <article class="ct-admin__condition-card ct-stack" draggable={true}>
        <header class="ct-admin__condition-header ct-stack">
          <div class="ct-admin__condition-header-row ct-cluster">
            <span class="ct-admin__condition-index" data-condition-index="">
              Requirement
            </span>
            <span class="ct-admin__condition-drag" title="Drag to reorder" aria-hidden="true">
              Move
            </span>
            <div class="ct-admin__condition-actions ct-cluster">
              <AdminButton
                type="button"
                size="tiny"
                variant="ghost"
                ariaLabel="Move requirement up"
                dataAttributes={{ "data-condition-move": "up" }}
              >
                Up
              </AdminButton>
              <AdminButton
                type="button"
                size="tiny"
                variant="ghost"
                ariaLabel="Move requirement down"
                dataAttributes={{ "data-condition-move": "down" }}
              >
                Down
              </AdminButton>
              <AdminButton
                type="button"
                size="tiny"
                variant="danger"
                className="ct-admin__condition-remove"
              >
                Remove
              </AdminButton>
            </div>
          </div>
          <p class="ct-admin__condition-summary">Requirement details will appear here.</p>
        </header>
        <details class="ct-admin__condition-details" open>
          <summary>Edit requirement details</summary>
          <div class="ct-admin__condition-header-fields ct-admin__builder-grid ct-grid">
            <AdminField label="Requirement type">
              <select class="ct-admin__condition-type">
                {ruleBuilderConditionTypes.map((conditionType) => (
                  <option value={conditionType.value}>{conditionType.label}</option>
                ))}
              </select>
            </AdminField>
            <details class="ct-admin__condition-advanced">
              <summary>Advanced</summary>
              <AdminCheckboxRow>
                <input type="checkbox" data-field="negate" />
                Exclude learners who match this requirement
              </AdminCheckboxRow>
            </details>
          </div>
          <div class="ct-admin__condition-fields ct-admin__builder-grid ct-grid"></div>
        </details>
        <p class="ct-admin__condition-result" data-state="idle" aria-live="polite">
          Not evaluated yet.
        </p>
      </article>
    </template>
  );
};

export const institutionAdminRuleBuilderPage = (input: {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string;
  membershipRole: TenantMembershipRole;
  badgeTemplates: readonly BadgeTemplateRecord[];
  badgeRules: readonly BadgeIssuanceRuleRecord[];
  badgeRuleVersions: readonly BadgeIssuanceRuleVersionRecord[];
  switchOrganizationPath?: string | null;
}): AppPage => {
  const versionsByRuleId = new Map<string, BadgeIssuanceRuleVersionRecord[]>();

  for (const version of input.badgeRuleVersions) {
    const versions = versionsByRuleId.get(version.ruleId);

    if (versions === undefined) {
      versionsByRuleId.set(version.ruleId, [version]);
      continue;
    }

    versions.push(version);
  }

  for (const versions of versionsByRuleId.values()) {
    versions.sort((left, right) => right.versionNumber - left.versionNumber);
  }

  const tenantAdminPath = `/tenants/${encodeURIComponent(input.tenant.id)}/admin`;
  const ruleBuilderPath = `${tenantAdminPath}/rules/new`;
  const manualIssueApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions/manual-issue`;
  const createApiKeyPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/api-keys`;
  const createOrgUnitPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/org-units`;
  const badgeTemplateApiPathPrefix = `/v1/tenants/${encodeURIComponent(
    input.tenant.id,
  )}/badge-templates`;
  const badgeRuleApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules`;
  const badgeRuleValueListApiPath = `/v1/tenants/${encodeURIComponent(
    input.tenant.id,
  )}/badge-rule-value-lists`;
  const badgeRulePreviewSimulationApiPath = `${badgeRuleApiPath}/preview-simulate`;
  const badgeRuleReviewQueueApiPath = `${badgeRuleApiPath}/review-queue`;
  const assertionsApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions`;
  const tenantMembersApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/members`;
  const tenantUsersApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/users`;
  const showcasePath = `/showcase/${encodeURIComponent(input.tenant.id)}`;
  const adminAuditLogPath = `/admin/audit-logs?tenantId=${encodeURIComponent(input.tenant.id)}`;
  const switchOrganizationPath = input.switchOrganizationPath?.trim() ?? "";
  const userLabel = input.userEmail ?? input.userId;

  const templateOptions = input.badgeTemplates.map((template, index) => ({
    template,
    isSelected: index === 0,
  }));

  const lmsProviderOptions = [
    { value: "canvas", label: "Canvas" },
    { value: "sakai", label: "Sakai" },
    { value: "moodle", label: "Moodle" },
    { value: "blackboard_ultra", label: "Blackboard Ultra" },
    { value: "d2l_brightspace", label: "D2L Brightspace" },
  ] as const;

  const inferDefaultLmsProviderKind = (): (typeof lmsProviderOptions)[number]["value"] => {
    const counts = new Map<string, number>();

    for (const rule of input.badgeRules) {
      const kind = rule.lmsProviderKind;

      if (typeof kind === "string" && kind.length > 0) {
        counts.set(kind, (counts.get(kind) ?? 0) + 1);
      }
    }

    if (counts.size > 0) {
      const mostUsedKind = [...counts.entries()].sort((left, right) => right[1] - left[1])[0]?.[0];

      if (
        mostUsedKind !== undefined &&
        lmsProviderOptions.some((option) => option.value === mostUsedKind)
      ) {
        return mostUsedKind as (typeof lmsProviderOptions)[number]["value"];
      }
    }

    const tenantKey = `${input.tenant.slug ?? ""} ${input.tenant.id}`.toLowerCase();

    if (tenantKey.includes("sakai")) {
      return "sakai";
    }

    return "canvas";
  };

  const defaultLmsProviderKind = inferDefaultLmsProviderKind();

  const ruleCloneOptions = input.badgeRules.map((rule) => {
    const versions = versionsByRuleId.get(rule.id) ?? [];
    const latestVersion = versions[0] ?? null;
    const latestLabel =
      latestVersion === null
        ? "none"
        : `v${String(latestVersion.versionNumber)} ${latestVersion.status}`;

    return {
      rule,
      label: `${rule.name} (${rule.id}) · latest ${latestLabel}`,
    };
  });

  const courseIdByBadgeTemplateId = new Map<string, string>();

  for (const rule of input.badgeRules) {
    const versions = versionsByRuleId.get(rule.id) ?? [];
    const latestVersion = versions[0] ?? null;

    if (latestVersion === null || typeof latestVersion.ruleJson !== "string") {
      continue;
    }

    const courseIds = extractCourseIdsFromRuleJson(latestVersion.ruleJson);

    if (courseIds.length > 0 && typeof rule.badgeTemplateId === "string") {
      courseIdByBadgeTemplateId.set(rule.badgeTemplateId, courseIds[0] ?? "");
    }
  }

  const badgeTemplateCourseContext = input.badgeTemplates.map((template) => {
    const fromExistingRule = courseIdByBadgeTemplateId.get(template.id);
    const fromMetadata = parseGovernanceCourseId(template.governanceMetadataJson);
    const fromText = inferCourseCodeFromText(`${template.slug} ${template.title}`);
    const defaultCourseId = fromExistingRule ?? fromMetadata ?? fromText ?? null;

    return {
      id: template.id,
      title: template.title,
      slug: template.slug,
      defaultCourseId,
    };
  });

  const selectedTemplateOption =
    templateOptions.find((option) => option.isSelected) ?? templateOptions[0];
  const initialTestCourseId =
    selectedTemplateOption === undefined
      ? ""
      : (badgeTemplateCourseContext.find((entry) => entry.id === selectedTemplateOption.template.id)
          ?.defaultCourseId ?? "");

  const adminPageContextJson = serializeJsonScriptContent({
    tenantAdminPath,
    manualIssueApiPath,
    createApiKeyPath,
    createOrgUnitPath,
    badgeTemplateApiPathPrefix,
    badgeRuleApiPath,
    badgeRuleValueListApiPath,
    badgeRulePreviewSimulationApiPath,
    badgeRuleReviewQueueApiPath,
    assertionsApiPathPrefix,
    tenantMembersApiPath,
    tenantUsersApiPathPrefix,
    ruleBuilderContext: {
      badgeTemplates: badgeTemplateCourseContext,
      fallbackCourseId: initialTestCourseId,
    },
  });

  const rulesWorkspacePath = `${tenantAdminPath}/rules`;
  const rulesTemplatesPath = `${rulesWorkspacePath}/templates`;
  const operationsPath = `${tenantAdminPath}/operations`;
  const operationsLearnerRecordsPath = `${operationsPath}/learner-records`;
  const operationsLearnerRecordImportsPath = `${operationsPath}/learner-record-imports`;
  const operationsReviewQueuePath = `${operationsPath}/review-queue`;
  const operationsIssuedBadgesPath = `${operationsPath}/issued-badges`;
  const operationsBadgeStatusPath = `${operationsPath}/badge-status`;
  const reportingPath = `${tenantAdminPath}/reporting`;
  const reportingExplorePath = `${reportingPath}/explore`;
  const reportingTrendsPath = `${reportingPath}/trends`;
  const reportingReportsPath = `${reportingPath}/reports`;
  const accessPath = `${tenantAdminPath}/access`;
  const accessMembersPath = `${accessPath}/members`;
  const accessGovernancePath = `${accessPath}/governance`;
  const accessApiKeysPath = `${accessPath}/api-keys`;
  const accessOrgUnitsPath = `${accessPath}/org-units`;
  const sidebarSections: readonly AdminSidebarSection[] = [
    {
      links: [{ href: tenantAdminPath, label: "Home" }],
    },
    {
      label: "Operations",
      links: [
        { href: operationsPath, label: "Issue & Inspect" },
        { href: operationsLearnerRecordsPath, label: "Learner Records", isSub: true },
        {
          href: operationsLearnerRecordImportsPath,
          label: "Learner Record Imports",
          isSub: true,
        },
        { href: operationsReviewQueuePath, label: "Review Queue", isSub: true },
        { href: operationsIssuedBadgesPath, label: "Issued Badges", isSub: true },
        { href: operationsBadgeStatusPath, label: "Badge Status", isSub: true },
      ],
    },
    {
      label: "Analytics",
      links: [
        { href: reportingPath, label: "Reporting" },
        { href: reportingExplorePath, label: "Explore", isSub: true },
        { href: reportingTrendsPath, label: "Trends", isSub: true },
        { href: reportingReportsPath, label: "Reports", isSub: true },
      ],
    },
    {
      label: "Management",
      links: [
        { href: rulesWorkspacePath, label: "Rules" },
        { href: rulesTemplatesPath, label: "Badge Templates", isSub: true },
        { href: ruleBuilderPath, label: "Rule Builder", isCurrent: true, isSub: true },
      ],
    },
    {
      label: "Configuration",
      links: [
        { href: accessPath, label: "Access" },
        { href: accessMembersPath, label: "Members", isSub: true },
        { href: accessGovernancePath, label: "Governance", isSub: true },
        { href: accessApiKeysPath, label: "API Keys", isSub: true },
        { href: accessOrgUnitsPath, label: "Org Units", isSub: true },
      ],
    },
  ];
  const sidebarFooterLinks: readonly AdminSidebarFooterLink[] = [
    { href: adminAuditLogPath, label: "Audit logs", isExternal: true },
    {
      href: showcasePath,
      label: "Public showcase",
      isExternal: true,
      target: "_blank",
      rel: "noopener noreferrer",
    },
    ...(switchOrganizationPath.length === 0
      ? []
      : [{ href: switchOrganizationPath, label: "Switch organization" }]),
  ];

  return appPage({
    title: `Rule Builder · ${input.tenant.displayName}`,
    assets: ["institutionAdminCss", "institutionAdminJs"],
    variant: "admin",
    body: (
      <AdminShell
        sidebar={
          <AdminSidebar
            brandHref={tenantAdminPath}
            sections={sidebarSections}
            footerLinks={sidebarFooterLinks}
          />
        }
        topbar={
          <AdminTopbar
            title={input.tenant.displayName}
            chips={[{ label: input.membershipRole }]}
            userLabel={userLabel}
            userTitle={`User ID: ${input.userId}`}
          />
        }
        contentClassName="ct-admin-content ct-admin-content--rule-builder"
      >
        <div class="ct-admin-page-header ct-admin-page-header--compact">
          <h1>Badge Awarding Rule</h1>
          <p>
            Define when learners earn this badge. Complete each step, then save a draft for review.
          </p>
        </div>

        <section class="ct-admin__builder-shell ct-stack">
          <section
            class="ct-admin__panel ct-admin__builder-stepper-panel ct-stack"
            aria-label="Rule builder workflow"
          >
            <h2 class="ct-admin__builder-flow-title">Follow these steps in order</h2>
            <ol
              id="rule-builder-stepper"
              class="ct-admin__builder-steps"
              aria-label="Rule builder steps"
            >
              <li>
                <RuleBuilderStepButton
                  stepNumber={1}
                  target="metadata"
                  title="Awarding pattern"
                  description="Choose the badge and how learners qualify."
                />
              </li>
              <li>
                <RuleBuilderStepButton
                  stepNumber={2}
                  target="conditions"
                  title="Requirements"
                  description="Confirm what learners must complete."
                />
              </li>
              <li>
                <RuleBuilderStepButton
                  stepNumber={3}
                  target="test"
                  title="Test and submit"
                  description="Try the rule, then save the draft."
                />
              </li>
            </ol>
            <p
              id="rule-builder-step-progress"
              class="ct-admin__meta ct-admin__builder-progress"
              aria-live="polite"
            >
              Step 1 of 3 · Awarding pattern
            </p>
          </section>

          <div class="ct-admin__builder-main ct-stack">
            <section class="ct-admin__panel ct-admin__builder-workbench-panel ct-stack">
              <AdminForm id="rule-create-form">
                <section
                  id="builder-step-metadata"
                  class="ct-admin__builder-step"
                  data-rule-step="metadata"
                >
                  <section class="ct-admin__step-panel ct-admin__pattern-panel ct-stack">
                    <p class="ct-admin__step-kicker">Step 1 of 3</p>
                    <h3>Set up this rule</h3>
                    <p class="ct-admin__step-panel-lead">
                      Choose the badge, LMS, and how learners earn it.
                    </p>
                    <div class="ct-admin__builder-grid ct-grid">
                      <AdminField label="Badge template">
                        <select name="badgeTemplateId" required>
                          {templateOptions.length === 0 ? (
                            <option value="">No badge templates available</option>
                          ) : (
                            templateOptions.map(({ template, isSelected }) => (
                              <option key={template.id} value={template.id} selected={isSelected}>
                                {template.title} ({template.id})
                              </option>
                            ))
                          )}
                        </select>
                      </AdminField>
                      <p class="ct-admin__hint ct-admin__builder-field-span">
                        Need a new template?{" "}
                        <a href={rulesTemplatesPath}>Create one in Badge Templates</a>, then return
                        here.
                      </p>
                      <AdminField label="LMS provider">
                        <select name="lmsProviderKind" required>
                          {lmsProviderOptions.map((option) => (
                            <option
                              key={option.value}
                              value={option.value}
                              selected={option.value === defaultLmsProviderKind}
                            >
                              {option.label}
                            </option>
                          ))}
                        </select>
                      </AdminField>
                      <AdminField label="Awarding pattern" className="ct-admin__builder-field-span">
                        <select id="rule-builder-template-preset" name="templatePreset">
                          <option value="course_completion">Course completed</option>
                          <option value="course_and_grade" selected>
                            Course completed + minimum score
                          </option>
                          <option value="program_completion">Program or pathway completed</option>
                          <option value="assignment_submission">
                            Assignment or evidence submitted
                          </option>
                          <option value="survey_completion">Survey completed</option>
                          <option value="prerequisite_chain">Prerequisite badge required</option>
                          <option value="time_limited">Date-limited earning window</option>
                          <option value="custom_field">Custom institutional field</option>
                          <option value="blank">Blank requirements</option>
                        </select>
                      </AdminField>
                      <AdminField
                        label="Description (optional)"
                        className="ct-admin__builder-field-span"
                      >
                        <input
                          name="description"
                          type="text"
                          placeholder="Award when learner completes the course with strong performance."
                        />
                      </AdminField>
                    </div>
                    <p class="ct-admin__hint">
                      Requirements update automatically when you change the awarding pattern.
                    </p>
                    {ruleCloneOptions.length > 0 ? (
                      <section class="ct-admin__builder-clone ct-stack">
                        <h4>Start from an existing rule</h4>
                        <p class="ct-admin__hint">
                          Load requirements from a rule you already use for this badge or a similar
                          one.
                        </p>
                        <AdminField label="Existing rule">
                          <div class="ct-admin__builder-inline ct-cluster">
                            <select id="rule-builder-clone-rule" name="cloneRuleId">
                              <option value="">Select rule to clone</option>
                              {ruleCloneOptions.map((option) => (
                                <option key={option.rule.id} value={option.rule.id}>
                                  {option.label}
                                </option>
                              ))}
                            </select>
                            <AdminButton
                              id="rule-builder-clone-load"
                              type="button"
                              size="tiny"
                              variant="secondary"
                            >
                              Load rule
                            </AdminButton>
                          </div>
                        </AdminField>
                      </section>
                    ) : null}
                    <input type="hidden" name="name" id="rule-builder-name" value="" />
                    <details class="ct-admin__builder-advanced">
                      <summary>Customize internal rule name</summary>
                      <AdminField label="Internal rule name">
                        <input
                          id="rule-builder-name-visible"
                          type="text"
                          autocomplete="off"
                          placeholder="Generated automatically from badge and pattern"
                        />
                      </AdminField>
                      <p class="ct-admin__hint">
                        CredTrail names this rule automatically. Change it only if your team uses a
                        specific naming convention.
                      </p>
                    </details>
                  </section>
                </section>

                <section
                  id="builder-step-conditions"
                  class="ct-admin__builder-step"
                  data-rule-step="conditions"
                  hidden
                >
                  <header class="ct-admin__step-head ct-stack">
                    <p class="ct-admin__step-kicker">Step 2 of 3</p>
                    <h3>Awarding requirements</h3>
                    <p>Review each requirement learners must meet before the badge is awarded.</p>
                  </header>
                  <div class="ct-admin__builder-workbench ct-stack">
                    <div class="ct-admin__builder-workbench-main ct-stack">
                      <div class="ct-admin__builder-toolbar ct-cluster">
                        <AdminButton type="button" id="rule-builder-add-condition" size="tiny">
                          Add requirement
                        </AdminButton>
                        <details class="ct-admin__builder-advanced ct-admin__builder-advanced--inline">
                          <summary>Advanced logic</summary>
                          <div class="ct-admin__builder-inline ct-cluster">
                            <div class="ct-admin__inline-control">
                              <span
                                id="rule-builder-root-logic-label"
                                class="ct-admin__field-label"
                              >
                                Earning path
                              </span>
                              <input
                                id="rule-builder-root-logic"
                                name="rootLogic"
                                type="hidden"
                                value="all"
                              />
                              <div
                                class="ct-admin__segmented-control"
                                role="radiogroup"
                                aria-labelledby="rule-builder-root-logic-label"
                              >
                                <label>
                                  <input
                                    type="radio"
                                    name="rootLogicChoice"
                                    value="all"
                                    data-rule-builder-root-logic-option="all"
                                    checked
                                  />
                                  <span>All requirements</span>
                                </label>
                                <label>
                                  <input
                                    type="radio"
                                    name="rootLogicChoice"
                                    value="any"
                                    data-rule-builder-root-logic-option="any"
                                  />
                                  <span>Any requirement</span>
                                </label>
                              </div>
                            </div>
                            <AdminButton
                              type="button"
                              id="rule-builder-add-alternative-path"
                              size="tiny"
                              variant="secondary"
                            >
                              Add alternative way
                            </AdminButton>
                          </div>
                        </details>
                      </div>
                      <section class="ct-admin__builder-canvas ct-stack">
                        <header class="ct-admin__builder-canvas-header ct-cluster">
                          <strong>Requirements</strong>
                          <span class="ct-admin__meta">
                            Each row describes one fact CredTrail checks.
                          </span>
                        </header>
                        <div class="ct-admin__builder-canvas-meta ct-cluster">
                          <span id="rule-builder-canvas-count" class="ct-admin__status-pill">
                            0 requirements
                          </span>
                          <span id="rule-builder-canvas-logic" class="ct-admin__status-pill">
                            All requirements
                          </span>
                        </div>
                        <div
                          id="rule-builder-condition-empty"
                          class="ct-admin__builder-empty-state ct-stack"
                          role="status"
                        >
                          <p class="ct-admin__builder-empty-state__title">No requirements yet</p>
                          <p class="ct-admin__builder-empty-state__body">
                            Go back to Step 1 and choose an awarding pattern, or add a requirement
                            below.
                          </p>
                          <AdminButton
                            type="button"
                            id="rule-builder-return-to-pattern"
                            size="tiny"
                            variant="secondary"
                          >
                            Back to Step 1
                          </AdminButton>
                        </div>
                        <div
                          id="rule-builder-condition-list"
                          class="ct-admin__builder-condition-list ct-stack"
                        ></div>
                      </section>
                      <section
                        class="ct-admin__builder-flow ct-stack"
                        aria-labelledby="rule-builder-flow-title"
                      >
                        <header class="ct-admin__builder-canvas-header ct-cluster">
                          <strong id="rule-builder-flow-title">Rule flow preview</strong>
                          <span id="rule-builder-flow-mode" class="ct-admin__meta">
                            Waiting for requirements.
                          </span>
                        </header>
                        <p id="rule-builder-flow-empty" class="ct-admin__builder-canvas-empty">
                          Add requirements to preview the earning path.
                        </p>
                        <ol
                          id="rule-builder-flow-list"
                          class="ct-admin__builder-flow-list"
                          aria-label="Generated rule flow"
                        ></ol>
                      </section>
                    </div>

                    <details class="ct-admin__builder-guide">
                      <summary>Requirement catalog</summary>
                      <div class="ct-admin__builder-patterns-head ct-stack">
                        <p class="ct-admin__hint">
                          These are the requirement rows available in the visual builder.
                        </p>
                      </div>
                      <dl class="ct-admin__builder-guide-list">
                        <div>
                          <dt>Course completion</dt>
                          <dd>
                            Matches when course completion facts show learner completion and
                            optional minimum percent.
                          </dd>
                        </div>
                        <div>
                          <dt>Grade threshold</dt>
                          <dd>
                            Matches when a learner score is within configured min/max thresholds.
                          </dd>
                        </div>
                        <div>
                          <dt>Program completion</dt>
                          <dd>
                            Matches when enough required courses are completed for a program path.
                          </dd>
                        </div>
                        <div>
                          <dt>Assignment submission</dt>
                          <dd>
                            Matches when assignment submission, score, and workflow-state
                            constraints pass.
                          </dd>
                        </div>
                        <div>
                          <dt>Survey completion</dt>
                          <dd>
                            Matches when completion facts show that a learner finished a required
                            survey.
                          </dd>
                        </div>
                        <div>
                          <dt>Time window</dt>
                          <dd>Matches only inside optional not-before / not-after timestamps.</dd>
                        </div>
                        <div>
                          <dt>Prerequisite badge</dt>
                          <dd>
                            Matches when learner already has an earned prerequisite badge template.
                          </dd>
                        </div>
                        <div>
                          <dt>Custom field</dt>
                          <dd>
                            Matches institution-specific learner attributes such as cohort, pathway,
                            or standing.
                          </dd>
                        </div>
                      </dl>
                    </details>
                  </div>

                  <details class="ct-admin__builder-advanced ct-stack">
                    <summary>Generated rule JSON</summary>
                    <AdminField label="Rule JSON (expert override)">
                      <textarea
                        id="rule-builder-definition-json"
                        name="definitionJson"
                        rows={12}
                        spellcheck={false}
                      ></textarea>
                    </AdminField>
                    <div class="ct-admin__builder-inline ct-cluster">
                      <AdminButton id="rule-builder-apply-json" type="button" size="tiny">
                        Apply JSON
                      </AdminButton>
                    </div>
                  </details>
                </section>

                <section
                  id="builder-step-test"
                  class="ct-admin__builder-step"
                  data-rule-step="test"
                  hidden
                >
                  <header class="ct-admin__step-head ct-stack">
                    <p class="ct-admin__step-kicker">Step 3 of 3</p>
                    <h3>Test and submit</h3>
                    <p>Try the rule with a sample learner, then save the draft for review.</p>
                  </header>
                  <div class="ct-admin__builder-test-layout ct-stack">
                    <AdminFieldset legend="Test with learner">
                      <p class="ct-admin__hint">
                        CredTrail fills in a sample learner. Adjust if needed, then run the test.
                      </p>
                      <AdminField label="Learner ID">
                        <input name="testLearnerId" type="text" value="canvas:12345" />
                      </AdminField>
                      <AdminField label="Recipient email">
                        <input
                          name="testRecipientIdentity"
                          type="email"
                          value="learner@example.edu"
                        />
                      </AdminField>
                      <AdminField label="Sample course ID">
                        <input
                          name="testCourseId"
                          type="text"
                          value={initialTestCourseId}
                          placeholder="Course ID from your LMS"
                        />
                      </AdminField>
                      <AdminField label="Sample final score">
                        <input
                          name="testFinalScore"
                          type="number"
                          min={0}
                          max={100}
                          step="0.01"
                          value="92"
                        />
                      </AdminField>
                      <AdminCheckboxRow>
                        <input name="testCompleted" type="checkbox" checked />
                        Learner completed course
                      </AdminCheckboxRow>
                      <select id="rule-builder-test-preset" name="testPreset" hidden>
                        <option value="canvas_course_grade" selected>
                          Canvas course + grade
                        </option>
                        <option value="program_completion">Program completion</option>
                        <option value="assignment_submission">Assignment submission</option>
                        <option value="survey_completion">Survey completion</option>
                        <option value="prerequisite_badge">Prerequisite badge</option>
                        <option value="custom_field">Custom field</option>
                      </select>
                      <div class="ct-admin__builder-test-actions">
                        <AdminButton id="rule-builder-test" type="button" size="tiny">
                          Test with learner
                        </AdminButton>
                      </div>
                      <p
                        id="rule-builder-test-result"
                        class="ct-admin__status ct-admin__builder-test-result"
                        aria-live="polite"
                      >
                        CredTrail runs a test automatically when you reach this step.
                      </p>
                    </AdminFieldset>

                    <details class="ct-admin__builder-advanced ct-stack">
                      <summary>Advanced test facts</summary>
                      <AdminField label="Advanced facts JSON (optional)">
                        <textarea
                          name="testFactsJson"
                          rows={6}
                          spellcheck={false}
                          placeholder='{"grades":[{"courseId":"CS101","learnerId":"canvas:12345","finalScore":92}]}'
                        ></textarea>
                      </AdminField>
                    </details>
                  </div>
                  <pre id="rule-builder-test-output" class="ct-admin__code-output" hidden></pre>

                  <details class="ct-admin__builder-advanced ct-stack">
                    <summary>Governance and release settings</summary>
                    <p class="ct-admin__hint">
                      Defaults work for most drafts. Open this only if approvers need a specific
                      chain or issuance timing.
                    </p>
                    <div class="ct-admin__builder-review-layout ct-grid">
                      <div class="ct-stack">
                        <AdminField label="Approval roles (comma separated)">
                          <input name="approvalRoles" type="text" value="admin,owner" />
                        </AdminField>
                        <AdminField label="Issuance timing">
                          <select name="issuanceTiming">
                            <option value="immediate">Immediate</option>
                            <option value="manual">Manual review trigger</option>
                            <option value="end_of_term">End of term batch</option>
                          </select>
                        </AdminField>
                        <AdminField label="Change summary (optional)">
                          <input
                            name="changeSummary"
                            type="text"
                            placeholder="Initial draft for committee review."
                          />
                        </AdminField>
                        <AdminCheckboxRow>
                          <input name="reviewOnMissingFacts" type="checkbox" />
                          Send missing-data cases to human review
                        </AdminCheckboxRow>
                      </div>
                    </div>
                  </details>

                  <details class="ct-admin__builder-simulation ct-stack">
                    <summary>Historical simulation</summary>
                    <header class="ct-admin__step-head ct-stack">
                      <h4>Project impact before activation</h4>
                      <p>
                        Replay this draft against recent rule evaluations for the same badge
                        template.
                      </p>
                    </header>
                    <div class="ct-admin__builder-inline ct-cluster">
                      <AdminField label="Sample limit" className="ct-admin__inline-control">
                        <input
                          id="rule-builder-simulate-limit"
                          type="number"
                          min={1}
                          max={100}
                          step={1}
                          value="25"
                        />
                      </AdminField>
                      <AdminButton
                        id="rule-builder-simulate"
                        type="button"
                        size="tiny"
                        variant="secondary"
                      >
                        Run simulation
                      </AdminButton>
                    </div>
                    <AdminStatus id="rule-builder-simulate-status">
                      No historical simulation has been run yet.
                    </AdminStatus>
                    <pre
                      id="rule-builder-simulate-output"
                      class="ct-admin__code-output"
                      hidden
                    ></pre>
                  </details>
                </section>
              </AdminForm>

              <footer class="ct-admin__builder-step-footer ct-stack">
                <p
                  id="rule-builder-step-callout"
                  class="ct-admin__builder-step-callout"
                  aria-live="polite"
                >
                  Choose an awarding pattern, badge, and LMS source, then select Continue.
                </p>
                <div class="ct-admin__builder-draft-actions ct-cluster">
                  <AdminButton
                    type="button"
                    id="rule-builder-save-draft"
                    size="tiny"
                    variant="secondary"
                  >
                    Save progress
                  </AdminButton>
                  <AdminButton
                    type="button"
                    id="rule-builder-load-draft"
                    size="tiny"
                    variant="secondary"
                  >
                    Resume saved progress
                  </AdminButton>
                </div>
                <div class="ct-admin__builder-step-nav ct-cluster">
                  <AdminButton
                    id="rule-builder-step-prev"
                    type="button"
                    size="tiny"
                    variant="secondary"
                  >
                    Back
                  </AdminButton>
                  <AdminButton id="rule-builder-step-next" type="button" size="tiny">
                    Continue to Requirements
                  </AdminButton>
                  <AdminButton id="rule-builder-submit" type="submit" form="rule-create-form">
                    Create rule draft
                  </AdminButton>
                </div>
                <AdminStatus id="rule-create-status"></AdminStatus>
              </footer>
            </section>
          </div>

          <details class="ct-admin__panel ct-admin__builder-guide ct-admin__builder-support">
            <summary>Advanced tools and reusable lists</summary>
            <div class="ct-admin__builder-support-grid ct-grid">
              <section class="ct-admin__builder-support-section ct-stack">
                <h3>Import and export</h3>
                <div class="ct-admin__builder-toolbar ct-cluster">
                  <AdminButton
                    type="button"
                    id="rule-builder-export-json"
                    size="tiny"
                    variant="secondary"
                  >
                    Export JSON
                  </AdminButton>
                  <AdminButton
                    type="button"
                    id="rule-builder-import-json"
                    size="tiny"
                    variant="secondary"
                  >
                    Import JSON
                  </AdminButton>
                  <input
                    id="rule-builder-import-file"
                    type="file"
                    accept="application/json"
                    hidden
                  />
                </div>
                <p class="ct-admin__hint">
                  Export JSON to move the rule definition between sessions, or import a saved
                  definition.
                </p>
              </section>

              <section class="ct-admin__builder-support-section ct-stack">
                <h3>Reusable lists</h3>
                <p class="ct-admin__hint">
                  Course and badge-template lists appear here and can be used inside requirement
                  rows.
                </p>
                <AdminTable
                  headers={["Label", "Kind", "Values"]}
                  tbodyId="rule-builder-value-list-body"
                >
                  <AdminEmptyTableRow colSpan={3}>No reusable lists loaded yet.</AdminEmptyTableRow>
                </AdminTable>
              </section>
            </div>
          </details>
        </section>

        <RuleBuilderConditionCardTemplate />
        <div id="ct-admin-context" hidden data-context-json={adminPageContextJson}></div>
      </AdminShell>
    ),
  });
};
