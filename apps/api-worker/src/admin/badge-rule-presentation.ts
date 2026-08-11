import {
  resolveBadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
} from "@credtrail/db";

/** Returns the immutable version-backed name administrators should see for a rule. */
export const badgeRuleDisplayName = (
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): string => {
  const versionSelection = resolveBadgeIssuanceRuleVersionSelection({ rule, versions });
  return versionSelection.defaultVersion?.snapshot.name ?? "Rule version unavailable";
};

/** Formats a persisted badge-rule version status for administrator-facing UI. */
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

/** Returns the administrator-facing product name for a rule's LMS provider. */
export const badgeRuleLmsProviderLabel = (
  providerKind: BadgeIssuanceRuleRecord["lmsProviderKind"],
): string => {
  switch (providerKind) {
    case "canvas":
      return "Canvas";
    case "moodle":
      return "Moodle";
    case "blackboard_ultra":
      return "Blackboard Ultra";
    case "d2l_brightspace":
      return "D2L Brightspace";
    case "sakai":
      return "Sakai";
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
