import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  TenantLmsConnectionRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { RuleValueListBuilderContextEntry } from "./rule-value-lists-presentation";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import {
  AdminButton,
  AdminCheckboxRow,
  AdminField,
  AdminFieldset,
  AdminForm,
  AdminShell,
  AdminSidebar,
  AdminStatus,
  AdminTopbar,
  type AdminSidebarFooterLink,
} from "./components";
import { buildInstitutionAdminSidebarSectionsForTenant } from "./institution-admin-sidebar";

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
  { value: "program_completion", label: "Course pathway completion" },
  { value: "assignment_submission", label: "Gradebook item submitted" },
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
            <AdminCheckboxRow>
              <input type="checkbox" data-field="negate" />
              Exclude learners who match this requirement
            </AdminCheckboxRow>
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
  lmsConnections: readonly TenantLmsConnectionRecord[];
  valueLists: readonly RuleValueListBuilderContextEntry[];
  selectedBadgeTemplateId?: string;
  editRule?: {
    rule: BadgeIssuanceRuleRecord;
    latestVersion: BadgeIssuanceRuleVersionRecord;
  };
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
  const rulesListPath = `${tenantAdminPath}/rules`;
  const badgeRuleApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules`;
  const lmsConnectionsApiPath = `/v1/tenants/${encodeURIComponent(
    input.tenant.id,
  )}/lms/connections`;
  const showcasePath = `/showcase/${encodeURIComponent(input.tenant.id)}`;
  const switchOrganizationPath = input.switchOrganizationPath?.trim() ?? "";
  const userLabel = input.userEmail ?? input.userId;
  const editRule = input.editRule ?? null;
  const isEditMode = editRule !== null;

  const editDefinition = (() => {
    if (editRule === null) {
      return null;
    }

    try {
      return JSON.parse(editRule.latestVersion.ruleJson) as unknown;
    } catch {
      return null;
    }
  })();

  const selectedBadgeTemplateId =
    editRule?.rule.badgeTemplateId ?? input.selectedBadgeTemplateId ?? null;
  const hasSelectedBadgeTemplate =
    selectedBadgeTemplateId !== null &&
    input.badgeTemplates.some((template) => template.id === selectedBadgeTemplateId);
  const templateOptions = input.badgeTemplates.map((template, index) => ({
    template,
    isSelected: hasSelectedBadgeTemplate ? template.id === selectedBadgeTemplateId : index === 0,
  }));

  const supportedLmsConnections = input.lmsConnections.filter(
    (connection) => connection.providerKind === "canvas" || connection.providerKind === "sakai",
  );
  const connectedLmsConnections = supportedLmsConnections.filter(
    (connection) => connection.accessToken !== null && connection.accessToken.length > 0,
  );
  const hasUnusableLmsConnections =
    supportedLmsConnections.length > 0 && connectedLmsConnections.length === 0;
  const formatLmsConnectionProvider = (
    providerKind: TenantLmsConnectionRecord["providerKind"],
  ): string => {
    return providerKind === "sakai" ? "Sakai" : "Canvas";
  };

  const inferDefaultLmsConnectionId = (): string => {
    const counts = new Map<string, number>();

    for (const rule of input.badgeRules) {
      const connectionId = rule.lmsConnectionId;

      if (typeof connectionId === "string" && connectionId.length > 0) {
        counts.set(connectionId, (counts.get(connectionId) ?? 0) + 1);
      }
    }

    if (counts.size > 0) {
      const mostUsedConnectionId = [...counts.entries()].sort(
        (left, right) => right[1] - left[1],
      )[0]?.[0];

      if (
        mostUsedConnectionId !== undefined &&
        connectedLmsConnections.some((connection) => connection.id === mostUsedConnectionId)
      ) {
        return mostUsedConnectionId;
      }
    }

    return connectedLmsConnections[0]?.id ?? "";
  };

  const editLmsConnectionId =
    editRule?.rule.lmsConnectionId !== null &&
    editRule?.rule.lmsConnectionId !== undefined &&
    connectedLmsConnections.some((connection) => connection.id === editRule.rule.lmsConnectionId)
      ? editRule.rule.lmsConnectionId
      : null;
  const defaultLmsConnectionId = editLmsConnectionId ?? inferDefaultLmsConnectionId();
  const defaultLmsConnection =
    connectedLmsConnections.find((connection) => connection.id === defaultLmsConnectionId) ??
    connectedLmsConnections[0] ??
    null;

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
    rulesListPath,
    badgeRuleApiPath,
    lmsConnectionsApiPath,
    ruleBuilderContext: {
      badgeTemplates: badgeTemplateCourseContext,
      fallbackCourseId: initialTestCourseId,
      valueLists: input.valueLists,
      editRule:
        editRule === null
          ? null
          : {
              id: editRule.rule.id,
              name: editRule.rule.name,
              description: editRule.rule.description,
              badgeTemplateId: editRule.rule.badgeTemplateId,
              lmsConnectionId: editRule.rule.lmsConnectionId,
              latestVersionId: editRule.latestVersion.id,
              latestVersionNumber: editRule.latestVersion.versionNumber,
              latestVersionStatus: editRule.latestVersion.status,
              definition: editDefinition,
            },
      lmsConnections: connectedLmsConnections.map((connection) => ({
        id: connection.id,
        displayName: connection.displayName,
        providerKind: connection.providerKind,
        apiBaseUrl: connection.apiBaseUrl,
      })),
    },
  });

  const rulesWorkspacePath = `${tenantAdminPath}/rules`;
  const rulesTemplatesPath = `${rulesWorkspacePath}/templates`;
  const createTemplateForRulePath = `${rulesTemplatesPath}?returnTo=rule-builder`;
  const accessLmsConnectionsPath = `${tenantAdminPath}/access/lms-connections`;
  const sidebarSections = buildInstitutionAdminSidebarSectionsForTenant(
    input.tenant.id,
    "rulesBuilder",
    input.tenant.planTier,
  );
  const sidebarFooterLinks: readonly AdminSidebarFooterLink[] = [
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
    assets: ["institutionAdminCss", "institutionAdminShellJs", "institutionAdminRuleBuilderJs"],
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
          <h1>{isEditMode ? "Edit Badge Awarding Rule" : "Badge Awarding Rule"}</h1>
          <p>
            {isEditMode
              ? "Review the current settings, test changes, then save a new draft version."
              : "Define when learners earn this badge. Complete each step, then save a draft for review."}
          </p>
        </div>

        <section class="ct-admin__builder-shell ct-stack">
          {!isEditMode && ruleCloneOptions.length > 0 ? (
            <details class="ct-admin__builder-clone ct-stack">
              <summary>Copy existing rule settings</summary>
              <p class="ct-admin__hint">
                Preload settings from a rule you already use, then review the badge, source, and
                requirements before submitting.
              </p>
              <div class="ct-admin__builder-inline ct-cluster">
                <select
                  id="rule-builder-clone-rule"
                  name="cloneRuleId"
                  aria-label="Rule to copy settings from"
                >
                  <option value="">Select rule to copy</option>
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
                  Copy settings
                </AdminButton>
              </div>
            </details>
          ) : null}
          <section class="ct-admin__panel ct-admin__builder-workbench-panel ct-stack">
            <header class="ct-admin__builder-workflow-head">
              <h2 class="ct-admin__builder-steps-title">Build this rule</h2>
              <p
                id="rule-builder-step-progress"
                class="ct-admin__meta ct-admin__builder-progress"
                aria-live="polite"
              >
                Step 1 of 3 · Awarding pattern
              </p>
            </header>
            <AdminForm id="rule-create-form">
              <ol
                id="rule-builder-steps"
                class="ct-admin__builder-steps ct-admin__builder-steps--vertical-stepper"
                aria-label="Rule builder steps"
              >
                <li class="ct-admin__stepper-step" data-rule-step-row="metadata">
                  <div class="ct-admin__stepper-header">
                    <RuleBuilderStepButton
                      stepNumber={1}
                      target="metadata"
                      title="Awarding pattern"
                      description="Choose the badge and how learners qualify."
                    />
                  </div>
                  <div class="ct-admin__stepper-content">
                    <section
                      id="builder-step-metadata"
                      class="ct-admin__builder-step"
                      data-rule-step="metadata"
                    >
                      <section class="ct-admin__step-panel ct-admin__pattern-panel ct-stack">
                        <h3 tabindex={-1}>Set up this rule</h3>
                        <p class="ct-admin__step-panel-lead">
                          Choose the badge, LMS connection, and how learners earn it.
                        </p>
                        <div class="ct-admin__builder-grid ct-grid">
                          <AdminField label="Badge template">
                            <select name="badgeTemplateId" required>
                              {templateOptions.length === 0 ? (
                                <option value="">No badge templates available</option>
                              ) : (
                                templateOptions.map(({ template, isSelected }) => (
                                  <option
                                    key={template.id}
                                    value={template.id}
                                    selected={isSelected}
                                  >
                                    {template.title} ({template.id})
                                  </option>
                                ))
                              )}
                            </select>
                          </AdminField>
                          <p class="ct-admin__hint ct-admin__builder-field-span">
                            Need a new template?{" "}
                            <a href={createTemplateForRulePath}>
                              Create one in Badge Templates and continue here
                            </a>
                            .
                          </p>
                          <AdminField label="LMS connection">
                            <select
                              id="rule-builder-lms-connection"
                              name="lmsConnectionId"
                              required
                              disabled={connectedLmsConnections.length === 0}
                            >
                              {connectedLmsConnections.length === 0 ? (
                                <option value="">
                                  {hasUnusableLmsConnections
                                    ? "LMS connection needs a session or token"
                                    : "No LMS connection configured"}
                                </option>
                              ) : (
                                connectedLmsConnections.map((connection) => (
                                  <option
                                    key={connection.id}
                                    value={connection.id}
                                    data-provider-kind={connection.providerKind}
                                    selected={connection.id === defaultLmsConnectionId}
                                  >
                                    {`${connection.displayName} (${formatLmsConnectionProvider(
                                      connection.providerKind,
                                    )})`}
                                  </option>
                                ))
                              )}
                            </select>
                            <input
                              id="rule-builder-lms-provider-kind"
                              name="lmsProviderKind"
                              type="hidden"
                              value={defaultLmsConnection?.providerKind ?? ""}
                            />
                          </AdminField>
                          {connectedLmsConnections.length === 0 ? (
                            <div class="ct-admin__builder-prereq ct-admin__builder-field-span">
                              <span>
                                {hasUnusableLmsConnections
                                  ? "The saved LMS connection is not usable yet. Add a Canvas access token or Sakai SAKAIID session value before building rules."
                                  : "Create an LMS connection before building rules."}
                              </span>
                              <a class="ct-admin__text-action" href={accessLmsConnectionsPath}>
                                {hasUnusableLmsConnections
                                  ? "Update LMS connection"
                                  : "Create LMS connection"}
                              </a>
                            </div>
                          ) : null}
                          <div
                            id="rule-builder-lms-status"
                            class="ct-admin__builder-lms-status ct-admin__builder-field-span"
                            data-tone="info"
                            role="alert"
                            hidden={true}
                          >
                            <span data-rule-builder-lms-status-message="true"></span>
                            <a class="ct-admin__text-action" href={accessLmsConnectionsPath}>
                              Update LMS connection
                            </a>
                          </div>
                          <AdminField
                            label="Awarding pattern"
                            className="ct-admin__builder-field-span"
                          >
                            <select id="rule-builder-template-preset" name="templatePreset">
                              <option value="course_completion">Course completed</option>
                              <option value="course_and_grade" selected>
                                Course completed + minimum score
                              </option>
                              <option value="program_completion">Course pathway completed</option>
                              <option value="assignment_submission">
                                Assignment, assessment, or gradebook item submitted
                              </option>
                              <option value="survey_completion">Survey completed</option>
                              <option value="prerequisite_chain">
                                Prerequisite badge required
                              </option>
                              <option value="time_limited">Date-limited earning window</option>
                            </select>
                          </AdminField>
                          <AdminField
                            label="Description (optional)"
                            className="ct-admin__builder-field-span"
                          >
                            <input
                              name="description"
                              type="text"
                              value={editRule?.rule.description ?? ""}
                              placeholder="Award when learner completes the course with strong performance."
                            />
                          </AdminField>
                        </div>
                        <input
                          type="hidden"
                          name="name"
                          id="rule-builder-name"
                          value={editRule?.rule.name ?? ""}
                          data-rule-builder-preserve-name={isEditMode ? "true" : "false"}
                        />
                      </section>
                      <footer id="rule-builder-step-footer" class="ct-admin__builder-step-footer">
                        <p
                          id="rule-builder-step-callout"
                          class="ct-admin__builder-step-callout"
                          aria-live="polite"
                        >
                          Choose an awarding pattern, badge, and LMS connection, then select
                          Continue.
                        </p>
                        <div class="ct-admin__builder-step-nav ct-cluster">
                          <AdminButton id="rule-builder-step-next" type="button" size="tiny">
                            Continue to Requirements
                          </AdminButton>
                          <AdminButton
                            id="rule-builder-submit"
                            type="submit"
                            form="rule-create-form"
                            hidden={true}
                          >
                            {isEditMode ? "Save changes as draft" : "Create rule draft"}
                          </AdminButton>
                        </div>
                        <AdminStatus id="rule-create-status"></AdminStatus>
                      </footer>
                    </section>
                  </div>
                </li>
                <li class="ct-admin__stepper-step" data-rule-step-row="conditions">
                  <div class="ct-admin__stepper-header">
                    <RuleBuilderStepButton
                      stepNumber={2}
                      target="conditions"
                      title="Requirements"
                      description="Confirm what learners must complete."
                    />
                  </div>
                  <div class="ct-admin__stepper-content">
                    <section
                      id="builder-step-conditions"
                      class="ct-admin__builder-step"
                      data-rule-step="conditions"
                      hidden
                    >
                      <header class="ct-admin__step-head ct-stack">
                        <h3 tabindex={-1}>Awarding requirements</h3>
                        <p>Review what a learner needs to do before CredTrail awards the badge.</p>
                      </header>
                      <div class="ct-admin__builder-workbench ct-stack">
                        <div class="ct-admin__builder-workbench-main ct-stack">
                          <div class="ct-admin__builder-toolbar ct-cluster">
                            <input
                              id="rule-builder-root-logic"
                              name="rootLogic"
                              type="hidden"
                              value="all"
                            />
                            <AdminButton type="button" id="rule-builder-add-condition" size="tiny">
                              Add requirement
                            </AdminButton>
                            <AdminButton
                              type="button"
                              id="rule-builder-add-alternative-path"
                              size="tiny"
                              variant="secondary"
                            >
                              Add another way to earn it
                            </AdminButton>
                            <AdminButton
                              type="button"
                              id="rule-builder-require-every-requirement"
                              size="tiny"
                              variant="secondary"
                              hidden
                            >
                              Require every requirement
                            </AdminButton>
                          </div>
                          <section class="ct-admin__builder-canvas ct-stack">
                            <header class="ct-admin__builder-canvas-header ct-cluster">
                              <strong>Requirements</strong>
                              <span class="ct-admin__meta">
                                Each requirement describes what a learner must do.
                              </span>
                            </header>
                            <p class="ct-admin__hint">
                              Reusable course or template lists are managed on the{" "}
                              <a href={rulesListPath}>Rules page</a>. Reload this builder after
                              creating a new list there.
                            </p>
                            <div class="ct-admin__builder-canvas-meta ct-cluster">
                              <span id="rule-builder-canvas-count" class="ct-admin__status-pill">
                                0 requirements
                              </span>
                              <span id="rule-builder-canvas-logic" class="ct-admin__status-pill">
                                Learner must meet every requirement
                              </span>
                            </div>
                            <div
                              id="rule-builder-condition-empty"
                              class="ct-admin__builder-empty-state ct-stack"
                              role="status"
                            >
                              <p class="ct-admin__builder-empty-state__title">
                                No requirements yet
                              </p>
                              <p class="ct-admin__builder-empty-state__body">
                                Choose an awarding pattern in Step 1, or add a requirement below.
                              </p>
                              <AdminButton
                                type="button"
                                id="rule-builder-return-to-pattern"
                                size="tiny"
                                variant="secondary"
                              >
                                Change pattern
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
                                Matches when a learner score is within configured min/max
                                thresholds.
                              </dd>
                            </div>
                            <div>
                              <dt>Course pathway completion</dt>
                              <dd>
                                Matches when enough required courses are completed for a course
                                path.
                              </dd>
                            </div>
                            <div>
                              <dt>Assignment, assessment, or gradebook item submitted</dt>
                              <dd>
                                Matches when gradebook item submission, score, and workflow-state
                                constraints pass.
                              </dd>
                            </div>
                            <div>
                              <dt>Survey completion</dt>
                              <dd>
                                Matches when completion facts show that a learner finished a
                                required survey.
                              </dd>
                            </div>
                            <div>
                              <dt>Time window</dt>
                              <dd>
                                Matches only inside optional not-before / not-after timestamps.
                              </dd>
                            </div>
                            <div>
                              <dt>Prerequisite badge</dt>
                              <dd>
                                Matches when learner already has an earned prerequisite badge
                                template.
                              </dd>
                            </div>
                            <div>
                              <dt>Custom field</dt>
                              <dd>
                                Matches institution-specific learner attributes such as cohort,
                                pathway, or standing.
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
                  </div>
                </li>
                <li class="ct-admin__stepper-step" data-rule-step-row="test">
                  <div class="ct-admin__stepper-header">
                    <RuleBuilderStepButton
                      stepNumber={3}
                      target="test"
                      title="Test and submit"
                      description={
                        isEditMode
                          ? "Try the rule, then save a new draft version."
                          : "Try the rule, then save the draft."
                      }
                    />
                  </div>
                  <div class="ct-admin__stepper-content">
                    <section
                      id="builder-step-test"
                      class="ct-admin__builder-step"
                      data-rule-step="test"
                      hidden
                    >
                      <header class="ct-admin__step-head ct-stack">
                        <h3 tabindex={-1}>Test and submit</h3>
                        <p>
                          {isEditMode
                            ? "Try the rule with a sample learner, then save a new draft version for review."
                            : "Try the rule with a sample learner, then save the draft for review."}
                        </p>
                      </header>
                      <div class="ct-admin__builder-test-layout ct-stack">
                        <AdminFieldset legend="Test with learner">
                          <p class="ct-admin__hint">
                            CredTrail fills in a sample learner. Adjust if needed, then run the
                            test.
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
                            <option value="program_completion">Course pathway completion</option>
                            <option value="assignment_submission">Gradebook item submitted</option>
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
                          Defaults work for most drafts. Open this only if a rule needs a specific
                          reviewer role or issuance timing.
                        </p>
                        <div class="ct-admin__builder-review-layout ct-grid">
                          <div class="ct-stack">
                            <AdminField label="Reviewer roles (optional)">
                              <input
                                name="approvalRoles"
                                type="text"
                                placeholder="Leave blank for admin review"
                              />
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
                    </section>
                  </div>
                </li>
              </ol>
            </AdminForm>
          </section>

          <details class="ct-admin__panel ct-admin__builder-guide ct-admin__builder-support">
            <summary>Advanced JSON tools</summary>
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
                <h3>Advanced requirement tools</h3>
                <p class="ct-admin__hint">
                  Use generated JSON for custom institutional fields or blank rule drafts. LMS
                  course and gradebook item references still need to validate against the selected
                  connection when you create the draft.
                </p>
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
