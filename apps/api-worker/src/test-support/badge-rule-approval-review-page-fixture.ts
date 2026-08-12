import type {
  BadgeIssuanceRuleApprovalEventRecord,
  BadgeIssuanceRuleApprovalStepRecord,
  TenantOrgUnitRecord,
  TenantRecord,
} from "@credtrail/db";
import { parseBadgeIssuanceRuleDefinitionJson } from "@credtrail/validation";
import { badgeRuleApprovalReviewPage } from "../admin/badge-rule-approval-review-page";
import { buildBadgeRuleVersionNavigationModel } from "../admin/badge-rule-version-navigator";
import {
  sampleDetailRule,
  sampleDetailVersion,
} from "../institution-admin-test-utils/rule-version-fixtures";
import { renderAppPageToString } from "../ui/render-page";

const tenant: TenantRecord = {
  id: "tenant_123",
  slug: "tenant-123",
  displayName: "Tenant 123",
  planTier: "enterprise",
  issuerDomain: "tenant-123.credtrail.test",
  didWeb: "did:web:credtrail.test:tenant_123",
  isActive: true,
  createdAt: "2026-02-18T12:00:00.000Z",
  updatedAt: "2026-02-18T12:00:00.000Z",
};

const orgUnit: TenantOrgUnitRecord = {
  id: "tenant_123:org:cs",
  tenantId: "tenant_123",
  unitType: "department",
  slug: "computer-science",
  displayName: "Computer Science",
  parentOrgUnitId: "tenant_123:org:institution",
  createdByUserId: "usr_admin",
  isActive: true,
  createdAt: "2026-02-18T12:00:00.000Z",
  updatedAt: "2026-02-18T12:00:00.000Z",
};

const approvalStep: BadgeIssuanceRuleApprovalStepRecord = {
  id: "bras_review",
  tenantId: tenant.id,
  versionId: "brv_review",
  stepNumber: 1,
  targetType: "role_threshold",
  requiredRole: "admin",
  targetUserId: null,
  targetApproverGroupId: null,
  orgUnitId: orgUnit.id,
  label: "Department approval",
  status: "pending",
  decidedByUserId: null,
  decidedAt: null,
  decisionComment: null,
  createdAt: "2026-02-18T12:15:00.000Z",
  updatedAt: "2026-02-18T12:15:00.000Z",
};

const approvalEvent: BadgeIssuanceRuleApprovalEventRecord = {
  id: "brae_submitted",
  tenantId: tenant.id,
  versionId: "brv_review",
  stepNumber: 1,
  action: "submitted",
  actorUserId: "usr_author",
  actorRole: "issuer",
  comment: "Ready for review.",
  occurredAt: "2026-02-18T12:15:00.000Z",
  createdAt: "2026-02-18T12:15:00.000Z",
};

/** Renders the production review page with deterministic browser-test records. */
export const renderBadgeRuleApprovalReviewPageFixture = (): string => {
  const baseVersion = sampleDetailVersion("brv_base", 1, "active");
  const selectedVersion = {
    ...sampleDetailVersion("brv_review", 2, "pending_approval"),
    ruleJson:
      '{"conditions":{"type":"assignment_submission","courseId":"course_101","assignmentId":"assignment_7","requireSubmitted":true,"minScore":90}}',
    submittedByUserId: "usr_author",
  };
  const rule = sampleDetailRule(baseVersion.id);
  const navigation = buildBadgeRuleVersionNavigationModel({
    rule,
    selectedVersion,
    versions: [selectedVersion, baseVersion],
  });

  return renderAppPageToString(
    badgeRuleApprovalReviewPage(
      {
        tenant,
        userId: "usr_admin",
        userEmail: "reviewer@example.edu",
        membershipRole: "admin",
      },
      {
        rule,
        navigation,
        definition: parseBadgeIssuanceRuleDefinitionJson(selectedVersion.ruleJson),
        orgUnit,
        submittedByEmail: "author@example.edu",
        impactPreview: { status: "not_requested" },
        approvalSteps: [approvalStep],
        approvalEvents: [approvalEvent],
        action: { kind: "decide" },
        listNotice: null,
        listError: null,
      },
    ),
  );
};
