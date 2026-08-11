import type { BadgeIssuanceRuleVersionSnapshot } from "@credtrail/db";

/** Complete immutable rule metadata for application tests that do not vary the snapshot. */
export const sampleBadgeRuleVersionSnapshot: BadgeIssuanceRuleVersionSnapshot = {
  name: "Sample badge rule",
  description: "Sample badge rule description",
  badgeTemplateId: "badge_template_001",
  badgeTemplateTitle: "Sample badge",
  badgeTemplateImageUri: null,
  orgUnitId: "tenant_123:org:institution",
  ownerOrgUnitId: "tenant_123:org:institution",
  lmsProviderKind: "canvas",
  lmsConnectionId: "lms_123",
};
