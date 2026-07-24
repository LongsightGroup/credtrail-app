import type {
  BadgeIssuanceRuleBuilderDraftRecord,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  TenantLmsConnectionRecord,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleBuilderDraftJson,
  type BadgeIssuanceRuleBuilderDraftPayload,
} from "@credtrail/validation";
import type { RuleValueListBuilderContextEntry } from "./rule-value-lists-presentation";

export interface InstitutionAdminRuleBuilderEditContext {
  id: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
  lmsConnectionId: string | null;
  latestVersionId: string;
  latestVersionNumber: number;
  latestVersionStatus: BadgeIssuanceRuleVersionRecord["status"];
  latestVersionUpdatedAt: string;
  definition: unknown;
}

export interface InstitutionAdminRuleBuilderPageContext {
  badgeRuleBuilderDraftApiPath: string;
  builderDraftId: string;
  builderDraft: {
    ruleId: string | null;
    versionId: string | null;
    currentStep: BadgeIssuanceRuleBuilderDraftRecord["currentStep"];
    updatedAt: string;
    payload: BadgeIssuanceRuleBuilderDraftPayload | null;
    restoreStatus: "restorable" | "invalid_payload" | "version_mismatch" | "stale";
  } | null;
  badgeTemplates: readonly {
    id: string;
    title: string;
    slug: string;
    defaultCourseId: string | null;
  }[];
  fallbackCourseId: string;
  valueLists: readonly RuleValueListBuilderContextEntry[];
  editRule: InstitutionAdminRuleBuilderEditContext | null;
  lmsConnections: readonly {
    id: string;
    displayName: string;
    providerKind: string;
    apiBaseUrl: string;
  }[];
}

export const buildInstitutionAdminRuleBuilderDraftContext = (
  builderDraft: BadgeIssuanceRuleBuilderDraftRecord | null,
  editRule: InstitutionAdminRuleBuilderEditContext | null,
): InstitutionAdminRuleBuilderPageContext["builderDraft"] => {
  if (builderDraft === null) {
    return null;
  }

  const payload = parseBadgeIssuanceRuleBuilderDraftJson(builderDraft.draftJson);
  const restoreStatus = (() => {
    if (payload === null) {
      return "invalid_payload";
    }

    if (editRule === null) {
      return "restorable";
    }

    if (builderDraft.versionId === null || builderDraft.versionId !== editRule.latestVersionId) {
      return "version_mismatch";
    }

    const draftUpdatedAt = Date.parse(builderDraft.updatedAt);
    const versionUpdatedAt = Date.parse(editRule.latestVersionUpdatedAt);

    if (!Number.isFinite(draftUpdatedAt) || !Number.isFinite(versionUpdatedAt)) {
      return "restorable";
    }

    return draftUpdatedAt > versionUpdatedAt ? "restorable" : "stale";
  })();

  return {
    ruleId: builderDraft.ruleId,
    versionId: builderDraft.versionId,
    currentStep: builderDraft.currentStep,
    updatedAt: builderDraft.updatedAt,
    payload,
    restoreStatus,
  };
};

export const buildInstitutionAdminRuleBuilderEditContext = (input: {
  rule: BadgeIssuanceRuleRecord;
  latestVersion: BadgeIssuanceRuleVersionRecord;
  definition: unknown;
}): InstitutionAdminRuleBuilderEditContext => {
  return {
    id: input.rule.id,
    name: input.rule.name,
    description: input.rule.description,
    badgeTemplateId: input.rule.badgeTemplateId,
    lmsConnectionId: input.rule.lmsConnectionId,
    latestVersionId: input.latestVersion.id,
    latestVersionNumber: input.latestVersion.versionNumber,
    latestVersionStatus: input.latestVersion.status,
    latestVersionUpdatedAt: input.latestVersion.updatedAt,
    definition: input.definition,
  };
};

export const buildInstitutionAdminRuleBuilderPageContext = (input: {
  tenantId: string;
  builderDraftId: string;
  builderDraft: BadgeIssuanceRuleBuilderDraftRecord | null;
  badgeTemplateCourseContext: readonly {
    id: string;
    title: string;
    slug: string;
    defaultCourseId: string | null;
  }[];
  initialTestCourseId: string;
  valueLists: readonly RuleValueListBuilderContextEntry[];
  editRule: {
    rule: BadgeIssuanceRuleRecord;
    latestVersion: BadgeIssuanceRuleVersionRecord;
    definition: unknown;
  } | null;
  connectedLmsConnections: readonly TenantLmsConnectionRecord[];
}): InstitutionAdminRuleBuilderPageContext => {
  const editRule =
    input.editRule === null
      ? null
      : buildInstitutionAdminRuleBuilderEditContext({
          rule: input.editRule.rule,
          latestVersion: input.editRule.latestVersion,
          definition: input.editRule.definition,
        });

  return {
    badgeRuleBuilderDraftApiPath: `/v1/tenants/${encodeURIComponent(
      input.tenantId,
    )}/badge-rule-builder-drafts/${encodeURIComponent(input.builderDraftId)}`,
    builderDraftId: input.builderDraftId,
    builderDraft: buildInstitutionAdminRuleBuilderDraftContext(input.builderDraft, editRule),
    badgeTemplates: input.badgeTemplateCourseContext,
    fallbackCourseId: input.initialTestCourseId,
    valueLists: input.valueLists,
    editRule,
    lmsConnections: input.connectedLmsConnections.map((connection) => ({
      id: connection.id,
      displayName: connection.displayName,
      providerKind: connection.providerKind,
      apiBaseUrl: connection.apiBaseUrl,
    })),
  };
};
