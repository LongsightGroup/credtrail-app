import type { BadgeRuleApprovalPolicyRecord, TenantMembershipRole } from "@credtrail/db";
import { tenantMembershipRoleLabel } from "../admin/tenant-membership-role-labels";
import { formatIsoTimestamp } from "../utils/display-format";

export interface BadgeRuleApprovalPolicyFormState {
  readonly orgUnitId: string;
  readonly approvalRequirement: "always" | "never";
  readonly stepTargetType: "role_threshold" | "user" | "approver_group";
  readonly requiredRole: TenantMembershipRole | "";
  readonly targetUserId: string;
  readonly targetApproverGroupId: string;
  readonly recertificationIntervalMonths: number | null;
}

/** Projects a stored approval policy into the admin form's selected values. */
export const badgeRuleApprovalPolicyFormState = (
  policy: BadgeRuleApprovalPolicyRecord | null,
): BadgeRuleApprovalPolicyFormState => {
  const firstStep = policy?.approvalSteps[0] ?? null;

  return {
    orgUnitId: policy?.orgUnitId ?? "",
    approvalRequirement: policy?.approvalRequirement === "never" ? "never" : "always",
    stepTargetType: firstStep?.targetType ?? "role_threshold",
    requiredRole:
      firstStep?.targetType === "role_threshold"
        ? firstStep.requiredRole
        : (firstStep?.requiredRole ?? ""),
    targetUserId: firstStep?.targetType === "user" ? firstStep.targetUserId : "",
    targetApproverGroupId:
      firstStep?.targetType === "approver_group" ? firstStep.targetApproverGroupId : "",
    recertificationIntervalMonths: policy?.recertificationIntervalMonths ?? null,
  };
};

export const describeBadgeRuleApprovalScopeLabel = (
  policy: BadgeRuleApprovalPolicyRecord | null,
): string => {
  if (policy?.orgUnitId === null || policy?.orgUnitId === undefined) {
    return "Tenant default";
  }

  return "Org-unit override";
};

export const describeBadgeRuleApprovalRequirement = (
  policy: BadgeRuleApprovalPolicyRecord | null,
): string => {
  if (policy?.approvalRequirement === "never") {
    return policy.allowSelfCertification ? "Automatic approval" : "Automatic approval disabled";
  }

  return "Approval required";
};

export const describeBadgeRuleApprovalReviewer = (
  policy: BadgeRuleApprovalPolicyRecord | null,
): string => {
  if (policy?.approvalRequirement === "never") {
    return policy.allowSelfCertification ? "Self-certification" : "No active approval path";
  }

  const firstStep = policy?.approvalSteps[0] ?? null;

  if (firstStep === null || firstStep.targetType === "role_threshold") {
    const requiredRole = firstStep?.requiredRole ?? "admin";
    return `${tenantMembershipRoleLabel(requiredRole)} role`;
  }

  if (firstStep.targetType === "user") {
    return "Named reviewer";
  }

  return "Approver group";
};

export const describeBadgeRuleApprovalUpdatedAt = (
  policy: BadgeRuleApprovalPolicyRecord | null,
): string => {
  if (policy?.updatedAt === undefined) {
    return "Not saved";
  }

  return formatIsoTimestamp(policy.updatedAt);
};

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
