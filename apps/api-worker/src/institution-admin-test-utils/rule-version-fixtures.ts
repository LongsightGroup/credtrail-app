import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
} from "@credtrail/db";
import { buildBadgeRuleVersionRecord } from "../test-support/badge-rule-version";

/** Badge template used by institution-admin rule-version behavior tests. */
export const sampleRuleBadgeTemplate: BadgeTemplateRecord = {
  id: "badge_template_001",
  tenantId: "tenant_123",
  slug: "typescript-foundations",
  title: "TypeScript Foundations",
  description: "Awarded for TypeScript basics.",
  criteriaUri: "https://example.edu/criteria",
  imageUri: "https://example.edu/badges/typescript.png",
  createdByUserId: "usr_admin",
  ownerOrgUnitId: "tenant_123:org:institution",
  governanceMetadataJson: null,
  isArchived: false,
  createdAt: "2026-02-18T12:00:00.000Z",
  updatedAt: "2026-02-18T12:00:00.000Z",
};

/** Creates the governed rule used by the dedicated version-page tests. */
export const sampleDetailRule = (activeVersionId: string | null): BadgeIssuanceRuleRecord => ({
  id: "brl_detail",
  tenantId: "tenant_123",
  name: "Mutable rule head name",
  description: "Award the badge after the learner completes the final project.",
  badgeTemplateId: sampleRuleBadgeTemplate.id,
  orgUnitId: "tenant_123:org:cs",
  ownerOrgUnitId: "tenant_123:org:cs",
  lmsProviderKind: "canvas",
  lmsConnectionId: "lms_canvas",
  activeVersionId,
  createdByUserId: "usr_admin",
  createdAt: "2026-02-18T12:00:00.000Z",
  updatedAt: "2026-02-18T12:20:00.000Z",
});

/** Creates a governed version used by the dedicated version-page tests. */
export const sampleDetailVersion = (
  id: string,
  versionNumber: number,
  status: BadgeIssuanceRuleVersionRecord["status"],
): BadgeIssuanceRuleVersionRecord =>
  buildBadgeRuleVersionRecord({
    id,
    ruleId: "brl_detail",
    versionNumber,
    status,
    ruleJson:
      '{"conditions":{"type":"assignment_submission","courseId":"course_101","assignmentId":"assignment_7","requireSubmitted":true,"minScore":80}}',
    changeSummary: versionNumber === 1 ? "Initial version" : "Raised the project score.",
    submittedByUserId: status === "draft" ? null : "usr_admin",
    submittedAt: status === "draft" ? null : "2026-02-18T12:05:00.000Z",
    approvedByUserId: status === "active" ? "usr_admin" : null,
    approvedAt: status === "active" ? "2026-02-18T12:10:00.000Z" : null,
    activatedByUserId: status === "active" ? "usr_admin" : null,
    activatedAt: status === "active" ? "2026-02-18T12:12:00.000Z" : null,
    snapshot: {
      name: "Advanced TypeScript Rule",
      description: "Award the badge after the learner completes the final project.",
      badgeTemplateId: sampleRuleBadgeTemplate.id,
      badgeTemplateTitle: sampleRuleBadgeTemplate.title,
      badgeTemplateImageUri: sampleRuleBadgeTemplate.imageUri,
      orgUnitId: "tenant_123:org:cs",
      ownerOrgUnitId: "tenant_123:org:cs",
      lmsConnectionId: "lms_canvas",
    },
    updatedAt: "2026-02-18T12:20:00.000Z",
  });
