import {
  resolveBadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
} from "@credtrail/db";
import { badgeRuleLmsProviderLabel } from "./badge-rule-lms-provider-label";

/** Stable product-facing fields projected from one immutable badge-rule version. */
export interface BadgeRuleVersionDisplayFields {
  readonly displayName: string;
  readonly badgeTitle: string;
  readonly lmsProviderLabel: string;
  readonly updatedAt: string;
}

/** Projects the shared display fields used across admin, audit, and public rule surfaces. */
export const badgeRuleVersionDisplayFields = (
  version: BadgeIssuanceRuleVersionRecord,
): BadgeRuleVersionDisplayFields => {
  return {
    displayName: version.snapshot.name,
    badgeTitle: version.snapshot.badgeTemplateTitle,
    lmsProviderLabel: badgeRuleLmsProviderLabel(version.snapshot.lmsProviderKind),
    updatedAt: version.updatedAt,
  };
};

/** Returns the immutable version-backed name product surfaces should show for a rule. */
export const badgeRuleDisplayName = (
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): string => {
  const versionSelection = resolveBadgeIssuanceRuleVersionSelection({ rule, versions });
  const defaultVersion = versionSelection.defaultVersion;

  return defaultVersion === null
    ? "Rule version unavailable"
    : badgeRuleVersionDisplayFields(defaultVersion).displayName;
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
