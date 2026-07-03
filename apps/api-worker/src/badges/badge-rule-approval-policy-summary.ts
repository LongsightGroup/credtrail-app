import type { BadgeRuleApprovalPolicyRecord } from "@credtrail/db";
import { tenantMembershipRoleLabel } from "../admin/tenant-membership-role-labels";

export const describeBadgeRuleApprovalSummary = (
  policy: BadgeRuleApprovalPolicyRecord | null,
): string => {
  const recertificationSummary =
    policy?.recertificationIntervalMonths === null ||
    policy?.recertificationIntervalMonths === undefined
      ? ""
      : ` Recertification every ${String(policy.recertificationIntervalMonths)} months.`;

  if (policy === null || policy.approvalRequirement !== "never") {
    const firstStep = policy?.approvalSteps[0] ?? null;

    if (firstStep !== null && firstStep.targetType !== "role_threshold") {
      return `Submitted badge rule versions require named approver review.${recertificationSummary}`;
    }

    const requiredRole = firstStep?.requiredRole ?? "admin";
    return `Submitted badge rule versions require ${tenantMembershipRoleLabel(
      requiredRole,
    ).toLowerCase()} approval.${recertificationSummary}`;
  }

  if (policy.allowSelfCertification) {
    return `Submitted badge rule versions are approved automatically.${recertificationSummary}`;
  }

  return `Automatic approval is disabled until self-certification is explicitly allowed.${recertificationSummary}`;
};
