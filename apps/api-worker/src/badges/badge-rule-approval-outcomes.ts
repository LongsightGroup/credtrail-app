import type {
  BadgeIssuanceRuleApprovalDecision,
  DecideBadgeIssuanceRuleVersionForbiddenStep,
  DecideBadgeIssuanceRuleVersionResult,
  SubmitBadgeIssuanceRuleVersionForApprovalResult,
} from "@credtrail/db";

export const approvalDecisionForbiddenMessage = (
  step: DecideBadgeIssuanceRuleVersionForbiddenStep,
): string => {
  if (step.targetType === "role_threshold" && step.requiredRole !== null) {
    return `Current approval step requires role ${step.requiredRole}`;
  }

  return "Actor is not authorized to decide this approval step";
};

const adminApprovalDecisionVerb = (decision: BadgeIssuanceRuleApprovalDecision): string => {
  switch (decision) {
    case "approved":
      return "approve";
    case "rejected":
      return "reject";
    case "changes_requested":
      return "request changes on";
  }
};

export const adminApprovalDecisionForbiddenMessage = (
  decision: BadgeIssuanceRuleApprovalDecision,
  step: DecideBadgeIssuanceRuleVersionForbiddenStep,
): string => {
  if (step.targetType === "role_threshold" && step.requiredRole !== null) {
    return `This approval step requires ${step.requiredRole} access before you can ${adminApprovalDecisionVerb(decision)} it.`;
  }

  return "You are not authorized to decide this approval step.";
};

export const adminApprovalDecisionFailureMessage = (
  decision: BadgeIssuanceRuleApprovalDecision,
  result: Exclude<DecideBadgeIssuanceRuleVersionResult, { status: "decided" }>,
): string => {
  switch (result.status) {
    case "not_found":
      return "That rule version was not found.";
    case "not_pending":
      return "Only versions waiting for approval can be approved, sent back, or rejected.";
    case "no_pending_step":
      return "No pending approval step exists for this rule version.";
    case "stale":
      return "That rule version is no longer waiting for approval.";
    case "separation_of_duties":
      return "You cannot decide approval on a rule version you created or submitted.";
    case "forbidden":
      return adminApprovalDecisionForbiddenMessage(decision, result.step);
    case "comment_required":
      return "Add a comment explaining what needs to change before sending this version back.";
  }
};

export const submitBadgeRuleVersionForApprovalFailureMessage = (
  result: Exclude<SubmitBadgeIssuanceRuleVersionForApprovalResult, { status: "submitted" }>,
): string => {
  switch (result.status) {
    case "not_found":
      return "That rule version was not found.";
    case "not_submittable":
      return "Only draft or rejected versions can be submitted from this action.";
    case "self_certification_required":
      return "Automatic approval is disabled until self-certification is explicitly allowed.";
    case "policy_missing_steps":
      return "Badge rule approval policy did not provide any approval steps.";
  }
};

export const apiSubmitBadgeRuleVersionStatusCode = (
  result: Exclude<SubmitBadgeIssuanceRuleVersionForApprovalResult, { status: "submitted" }>,
): 404 | 409 | 500 => {
  switch (result.status) {
    case "not_found":
      return 404;
    case "not_submittable":
    case "self_certification_required":
      return 409;
    case "policy_missing_steps":
      return 500;
  }
};

export const apiDecideBadgeRuleVersionStatusCode = (
  result: Exclude<DecideBadgeIssuanceRuleVersionResult, { status: "decided" }>,
): 400 | 403 | 404 | 409 => {
  switch (result.status) {
    case "not_found":
      return 404;
    case "not_pending":
    case "no_pending_step":
    case "stale":
      return 409;
    case "separation_of_duties":
    case "forbidden":
      return 403;
    case "comment_required":
      return 400;
  }
};

export const apiDecideBadgeRuleVersionErrorMessage = (
  result: Exclude<DecideBadgeIssuanceRuleVersionResult, { status: "decided" }>,
): string => {
  switch (result.status) {
    case "not_found":
      return "Badge rule version not found";
    case "not_pending":
      return "Only pending_approval versions can be decided";
    case "no_pending_step":
      return "No pending approval step exists for this rule version";
    case "stale":
      return "Badge rule version is no longer pending approval";
    case "separation_of_duties":
      return "Rule version submitters and creators cannot decide approval steps";
    case "forbidden":
      return approvalDecisionForbiddenMessage(result.step);
    case "comment_required":
      return "comment is required when requesting changes";
  }
};
