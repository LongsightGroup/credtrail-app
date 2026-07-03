import type { BadgeRuleApprovalPolicyRecord, TenantMembershipRole } from "@credtrail/db";
import { tenantMembershipRoleLabel } from "../admin/tenant-membership-role-labels";

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
