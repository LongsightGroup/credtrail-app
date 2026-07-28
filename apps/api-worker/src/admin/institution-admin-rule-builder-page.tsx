import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleBuilderDraftRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  TenantLmsConnectionRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { RuleValueListBuilderContextEntry } from "./rule-value-lists-presentation";
import { buildInstitutionAdminRuleBuilderPageContext } from "./institution-admin-rule-builder-context";
import { appPage, type AppPage } from "../ui/render-page";
import {
  AdminForm,
  AdminShell,
  AdminSidebar,
  AdminTopbar,
  type AdminSidebarFooterLink,
} from "./components";
import { buildInstitutionAdminSidebarSectionsForTenant } from "./institution-admin-sidebar";
import { isLmsConnectionReady } from "./lms-connection-admin-helpers";
import {
  RuleBuilderAdvancedJsonTools,
  RuleBuilderCloneSettings,
  RuleBuilderConditionCardTemplate,
  RuleBuilderConditionsStep,
  RuleBuilderMetadataStep,
  RuleBuilderReviewStep,
  RuleBuilderSaveDraftFooter,
  RuleBuilderTestStep,
} from "./institution-admin-rule-builder-sections";

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
  builderDraftId: string;
  builderDraft?: BadgeIssuanceRuleBuilderDraftRecord | null;
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
  const builderDraft = input.builderDraft ?? null;

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
  const connectedLmsConnections = supportedLmsConnections.filter((connection) =>
    isLmsConnectionReady(connection),
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
    ruleBuilderContext: buildInstitutionAdminRuleBuilderPageContext({
      tenantId: input.tenant.id,
      builderDraftId: input.builderDraftId,
      builderDraft,
      badgeTemplateCourseContext,
      initialTestCourseId,
      valueLists: input.valueLists,
      editRule:
        editRule === null
          ? null
          : {
              rule: editRule.rule,
              latestVersion: editRule.latestVersion,
              definition: editDefinition,
            },
      connectedLmsConnections,
    }),
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
              ? "Review the current settings, test your changes, then submit a new version for approval."
              : "Define when learners earn this badge. Complete each step, then submit the rule for approval."}
          </p>
        </div>

        <section class="ct-admin__builder-shell ct-stack">
          {!isEditMode ? <RuleBuilderCloneSettings ruleCloneOptions={ruleCloneOptions} /> : null}
          <section class="ct-admin__panel ct-admin__builder-workbench-panel ct-stack">
            <header class="ct-admin__builder-workflow-head">
              <h2 class="ct-admin__builder-steps-title">Build this rule</h2>
              <p
                id="rule-builder-step-progress"
                class="ct-admin__meta ct-admin__builder-progress"
                aria-live="polite"
              >
                Step 1 of 4 · Awarding pattern
              </p>
            </header>
            <AdminForm id="rule-create-form">
              <ol
                id="rule-builder-steps"
                class="ct-admin__builder-steps ct-admin__builder-steps--vertical-stepper"
                aria-label="Rule builder steps"
              >
                <RuleBuilderMetadataStep
                  isEditMode={isEditMode}
                  templateOptions={templateOptions}
                  connectedLmsConnections={connectedLmsConnections}
                  defaultLmsConnectionId={defaultLmsConnectionId}
                  defaultLmsConnection={defaultLmsConnection}
                  hasUnusableLmsConnections={hasUnusableLmsConnections}
                  createTemplateForRulePath={createTemplateForRulePath}
                  accessLmsConnectionsPath={accessLmsConnectionsPath}
                  editRule={editRule}
                  formatLmsConnectionProvider={formatLmsConnectionProvider}
                />
                <RuleBuilderConditionsStep rulesListPath={rulesListPath} />
                <RuleBuilderTestStep />
                <RuleBuilderReviewStep />
              </ol>
              <RuleBuilderSaveDraftFooter />
            </AdminForm>
          </section>

          <RuleBuilderAdvancedJsonTools />
        </section>

        <RuleBuilderConditionCardTemplate />
        <div id="ct-admin-context" hidden data-context-json={adminPageContextJson}></div>
      </AdminShell>
    ),
  });
};
