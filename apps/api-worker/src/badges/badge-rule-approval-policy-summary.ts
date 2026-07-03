import type { BadgeRuleApprovalPolicyRecord, TenantMembershipRole } from "@credtrail/db";

const ruleApprovalPolicyRoleLabel = (role: TenantMembershipRole): string => {
  switch (role) {
    case "owner":
      return "Owner";
    case "admin":
      return "Admin";
    case "issuer":
      return "Issuer";
    case "viewer":
      return "Viewer";
  }
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
    return `Submitted badge rule versions require ${ruleApprovalPolicyRoleLabel(
      requiredRole,
    ).toLowerCase()} approval.${recertificationSummary}`;
  }

  if (policy.allowSelfCertification) {
    return `Submitted badge rule versions are approved automatically.${recertificationSummary}`;
  }

  return `Automatic approval is disabled until self-certification is explicitly allowed.${recertificationSummary}`;
};
