import {
  resolveBadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
} from "@credtrail/db";
import { badgeRuleLmsProviderLabel } from "./badge-rule-lms-provider-label";
import { parseBadgeIssuanceRuleDefinitionJson } from "@credtrail/validation";
import { describeBadgeRuleCondition } from "./badge-rule-description";

/** Current rule naming alongside the requirements of one immutable version. */
export interface BadgeRuleVersionDisplayFields {
  readonly displayName: string;
  readonly customLabel: string | null;
  readonly requirementSummary: string;
  readonly courseLabels: readonly string[];
  readonly badgeTitle: string;
  readonly lmsProviderLabel: string;
  readonly updatedAt: string;
}

/** Projects the shared display fields used across admin, audit, and public rule surfaces. */
export const badgeRuleVersionDisplayFields = (
  version: BadgeIssuanceRuleVersionRecord,
  rule: Pick<BadgeIssuanceRuleRecord, "customLabel">,
): BadgeRuleVersionDisplayFields => {
  let definition;
  try {
    definition = parseBadgeIssuanceRuleDefinitionJson(version.ruleJson);
  } catch {
    return {
      displayName: "Requirements unavailable",
      customLabel: null,
      requirementSummary: "Requirements unavailable",
      courseLabels: [],
      badgeTitle: version.snapshot.badgeTemplateTitle,
      lmsProviderLabel: badgeRuleLmsProviderLabel(version.snapshot.lmsProviderKind),
      updatedAt: version.updatedAt,
    };
  }
  const customLabel = rule.customLabel;
  const requirementSummary = describeBadgeRuleCondition(
    definition.conditions,
    definition.referenceLabels,
  );
  return {
    displayName: customLabel ?? requirementSummary,
    customLabel,
    requirementSummary,
    courseLabels: definition.referenceLabels?.courses.map((course) => course.title) ?? [],
    badgeTitle: version.snapshot.badgeTemplateTitle,
    lmsProviderLabel: badgeRuleLmsProviderLabel(version.snapshot.lmsProviderKind),
    updatedAt: version.updatedAt,
  };
};

/** Returns the current label or the default version’s requirement description. */
export const badgeRuleDisplayName = (
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): string => {
  const versionSelection = resolveBadgeIssuanceRuleVersionSelection({ rule, versions });
  const defaultVersion = versionSelection.defaultVersion;

  return defaultVersion === null
    ? "Rule version unavailable"
    : badgeRuleVersionDisplayFields(defaultVersion, rule).displayName;
};

/** Formats a persisted badge-rule version status for product UI. */
export const badgeRuleVersionStatusLabel = (
  status: BadgeIssuanceRuleVersionRecord["status"],
): string => {
  switch (status) {
    case "draft":
      return "Draft";
    case "pending_approval":
      return "Awaiting approval";
    case "approved":
      return "Approved";
    case "active":
      return "Active";
    case "suspended":
      return "Suspended";
    case "expired":
      return "Expired";
    case "rejected":
      return "Needs changes";
    case "deprecated":
      return "Previous";
  }
};

/** Describes one version relative to the rule's active and latest versions. */
export const badgeRuleVersionStateLabel = (input: {
  readonly rule: BadgeIssuanceRuleRecord;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
}): string => {
  if (input.rule.activeVersionId === input.version.id) {
    return input.version.status === "active"
      ? "Active now"
      : `${badgeRuleVersionStatusLabel(input.version.status)} · current version`;
  }

  const label = badgeRuleVersionStatusLabel(input.version.status);
  return input.version.id === input.latestVersion.id ? `${label} · latest version` : label;
};
