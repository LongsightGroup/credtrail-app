import type {
  BadgeIssuanceRuleVersionRecord,
  BadgeIssuanceRuleVersionSnapshot,
} from "@credtrail/db";
import type { BadgeAchievementSnapshot } from "@credtrail/validation";

/** Complete immutable rule metadata for application tests that do not vary the snapshot. */
export const sampleBadgeRuleVersionSnapshot: BadgeIssuanceRuleVersionSnapshot = {
  name: "Sample badge rule",
  description: "Sample badge rule description",
  badgeTemplateId: "badge_template_001",
  badgeTemplateTitle: "Sample badge",
  badgeTemplateDescription: "Sample badge description",
  badgeTemplateCriteriaUri: "https://example.edu/criteria/sample-badge",
  badgeTemplateImageUri: null,
  badgeTemplateTrustedCredentialMetadataJson: null,
  orgUnitId: "tenant_123:org:institution",
  ownerOrgUnitId: "tenant_123:org:institution",
  lmsProviderKind: "canvas",
  lmsConnectionId: "lms_123",
};

/** Complete immutable achievement content for issuance-path tests. */
export const sampleBadgeAchievementSnapshot: BadgeAchievementSnapshot = {
  badgeTemplateId: sampleBadgeRuleVersionSnapshot.badgeTemplateId,
  title: sampleBadgeRuleVersionSnapshot.badgeTemplateTitle,
  description: sampleBadgeRuleVersionSnapshot.badgeTemplateDescription,
  criteriaUri: sampleBadgeRuleVersionSnapshot.badgeTemplateCriteriaUri,
  imageUri: sampleBadgeRuleVersionSnapshot.badgeTemplateImageUri,
  trustedCredentialMetadataJson:
    sampleBadgeRuleVersionSnapshot.badgeTemplateTrustedCredentialMetadataJson,
};

/** Partial version fixture input with independently overridable snapshot fields. */
export type BadgeRuleVersionRecordOverrides = Partial<
  Omit<BadgeIssuanceRuleVersionRecord, "snapshot">
> & {
  readonly snapshot?: Partial<BadgeIssuanceRuleVersionSnapshot> | undefined;
};

/** Builds a complete badge-rule version while preserving valid snapshot defaults. */
export const buildBadgeRuleVersionRecord = (
  overrides: BadgeRuleVersionRecordOverrides = {},
): BadgeIssuanceRuleVersionRecord => {
  const { snapshot, ...recordOverrides } = overrides;

  return {
    id: "brv_123",
    tenantId: "tenant_123",
    ruleId: "brl_123",
    versionNumber: 1,
    status: "draft",
    ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
    changeSummary: "Initial version",
    createdByUserId: "usr_admin",
    submittedByUserId: null,
    submittedAt: null,
    approvedByUserId: null,
    approvedAt: null,
    activatedByUserId: null,
    activatedAt: null,
    effectiveStartsAt: null,
    expiresAt: null,
    expiredAt: null,
    suspendedAt: null,
    suspendedByUserId: null,
    suspensionReason: null,
    recertifiedAt: null,
    recertificationDueAt: null,
    expiryReminderSentAt: null,
    recertificationReminderSentAt: null,
    snapshot: {
      ...sampleBadgeRuleVersionSnapshot,
      ...snapshot,
    },
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
    ...recordOverrides,
  };
};
