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
  if (policy === null || policy.approvalRequirement !== "never") {
    const firstStep = policy?.approvalSteps[0] ?? null;

    if (firstStep !== null && firstStep.targetType !== "role_threshold") {
      return "Submitted badge rule versions require named approver review.";
    }

    const requiredRole = firstStep?.requiredRole ?? "admin";
    return `Submitted badge rule versions require ${ruleApprovalPolicyRoleLabel(
      requiredRole,
    ).toLowerCase()} approval.`;
  }

  if (policy.allowSelfCertification) {
    return "Submitted badge rule versions are approved automatically.";
  }

  return "Automatic approval is disabled until self-certification is explicitly allowed.";
};
