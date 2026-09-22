import {
  tenantMembershipRoleSatisfiesMinimumRole,
  type BadgeIssuanceRuleApprovalStepRecord,
  type BadgeIssuanceRuleApprovalStepTarget,
  type BadgeIssuanceRuleVersionRecord,
  type BadgeRuleApprovalPolicyRecord,
  type BadgeRuleApproverGroupWithMembersRecord,
  type TenantMemberRecord,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinitionJson,
  resolveAutomatedBadgeRuleIssuanceTiming,
} from "@credtrail/validation";
import { tenantMembershipRoleLabel } from "./tenant-membership-role-labels";

/** Tenant-resolved identities used for workflow copy, never sent wholesale to the browser. */
export interface BadgeWorkflowDirectory {
  readonly members: readonly TenantMemberRecord[];
  readonly groups: readonly BadgeRuleApproverGroupWithMembersRecord[];
  readonly orgUnits: readonly TenantOrgUnitRecord[];
}

/** Names and policy for the badge selected in a rule builder. */
export interface BadgeTemplateWorkflow {
  readonly badgeOwner: string;
  readonly badgeCreator: string;
  readonly ruleAuthor: string;
  readonly approval: BadgeWorkflowApproval;
}

/** Approval truth for a draft policy or a submitted version's recorded decisions. */
export interface BadgeWorkflowApproval {
  readonly kind: "automatic" | "review" | "blocked" | "recorded" | "changes_requested";
  readonly label: string;
  readonly detail: string;
  readonly submissionNotice: string;
  readonly canReview: boolean;
}

/** Plain-language responsibility for one exact rule version. */
export interface BadgeWorkflowResponsibility {
  readonly badgeOwner: string;
  readonly ruleAuthor: string;
  readonly approval: BadgeWorkflowApproval;
  readonly awarding: string;
  readonly awardingDetail: string;
}

const reviewerLabel = (
  target: BadgeIssuanceRuleApprovalStepTarget,
  directory: BadgeWorkflowDirectory,
): string => {
  switch (target.targetType) {
    case "user":
      return (
        directory.members.find((member) => member.userId === target.targetUserId)?.email ??
        "Assigned reviewer (no longer a member)"
      );
    case "approver_group":
      return (
        directory.groups.find((group) => group.id === target.targetApproverGroupId)?.name ??
        "Assigned review group (unavailable)"
      );
    case "role_threshold":
      return `${tenantMembershipRoleLabel(target.requiredRole)} or higher`;
  }
};

const eligibleReviewers = (
  target: BadgeIssuanceRuleApprovalStepTarget,
  directory: BadgeWorkflowDirectory,
  excluded: readonly (string | null)[],
): readonly TenantMemberRecord[] =>
  directory.members.filter((member) => {
    if (excluded.includes(member.userId)) return false;
    switch (target.targetType) {
      case "user":
        return member.userId === target.targetUserId;
      case "role_threshold":
        return tenantMembershipRoleSatisfiesMinimumRole(member.role, target.requiredRole);
      case "approver_group":
        return (
          tenantMembershipRoleSatisfiesMinimumRole(member.role, target.requiredRole ?? "viewer") &&
          (directory.groups
            .find((group) => group.id === target.targetApproverGroupId)
            ?.members.some((entry) => entry.userId === member.userId) ??
            false)
        );
    }
  });

/** Describes the effective approval policy before a new rule is submitted. */
export const describeBadgeWorkflowPolicy = (
  policy: BadgeRuleApprovalPolicyRecord,
  directory: BadgeWorkflowDirectory,
  excludedUserIds: readonly (string | null)[],
): BadgeWorkflowApproval => {
  if (policy.approvalRequirement === "never") {
    return policy.allowSelfCertification
      ? {
          kind: "automatic",
          label: "Automatic approval under institution policy",
          detail:
            "Submitting approves the rule immediately. An administrator must then activate it.",
          submissionNotice:
            "Institution policy approves this submission automatically. It will still need activation.",
          canReview: false,
        }
      : {
          kind: "blocked",
          label: "Approval policy needs attention",
          detail: "An administrator must enable automatic approval or choose a reviewer.",
          submissionNotice: "Ask an administrator to configure an approval path before submitting.",
          canReview: false,
        };
  }
  const labels = policy.approvalSteps.map((step) => reviewerLabel(step, directory));
  const missingReviewer =
    policy.approvalSteps.length === 0 ||
    policy.approvalSteps.some(
      (step) => eligibleReviewers(step, directory, excludedUserIds).length === 0,
    );
  return {
    kind: missingReviewer ? "blocked" : "review",
    label: labels.join(" → ") || "No reviewer configured",
    detail: missingReviewer
      ? "No eligible independent reviewer is available for an approval step. An administrator must update Rule Approval or membership."
      : "Another eligible reviewer must approve this rule before an administrator can activate it.",
    submissionNotice: missingReviewer
      ? "This rule has an approval step without an eligible reviewer. Check Rule Approval before submitting."
      : `Approval goes to ${labels.join(" → ")}. You cannot approve a version you create or submit.`,
    canReview: false,
  };
};

/** Projects current policy or immutable submission history into honest approval copy. */
export const describeBadgeWorkflowApproval = (input: {
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly policy: BadgeRuleApprovalPolicyRecord;
  readonly steps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  readonly directory: BadgeWorkflowDirectory;
  readonly actorUserId: string;
}): BadgeWorkflowApproval => {
  const { version, steps, directory, actorUserId } = input;
  const returnedStep = steps.find((step) => step.status === "changes_requested");
  if (version.status === "draft" && returnedStep !== undefined) {
    const reviewer = directory.members.find(
      (member) => member.userId === returnedStep.decidedByUserId,
    )?.email;
    const instruction = "Review the feedback, revise this rule, and resubmit it for approval.";
    return {
      kind: "changes_requested",
      label: "Changes requested",
      detail: returnedStep.decisionComment?.trim()
        ? `${reviewer ?? "Reviewer"}: ${returnedStep.decisionComment}`
        : "The reviewer did not leave a comment. Ask them what needs to change before resubmitting.",
      submissionNotice: instruction,
      canReview: false,
    };
  }
  if (version.status === "draft" || version.status === "rejected") {
    return describeBadgeWorkflowPolicy(input.policy, directory, [
      version.createdByUserId,
      actorUserId,
    ]);
  }
  if (version.status === "pending_approval") {
    const pending = steps.find((step) => step.status === "pending");
    const reviewers =
      pending === undefined
        ? []
        : eligibleReviewers(pending, directory, [
            version.createdByUserId,
            version.submittedByUserId,
          ]);
    return {
      kind: reviewers.length === 0 ? "blocked" : "review",
      label:
        pending === undefined
          ? "Approval needs attention"
          : `Waiting for ${reviewerLabel(pending, directory)}`,
      detail:
        reviewers.length === 0
          ? "No eligible independent reviewer is available. An administrator must check Rule Approval and membership."
          : `Step ${String(pending?.stepNumber)} of ${String(steps.length)}. Approval does not start awarding badges.`,
      submissionNotice: "",
      canReview: reviewers.some((member) => member.userId === actorUserId),
    };
  }
  if (version.approvedAt !== null && steps.length === 0) {
    return {
      kind: "automatic",
      label: "Automatically approved under institution policy",
      detail: "No separate reviewer decision was required for this version.",
      submissionNotice: "",
      canReview: false,
    };
  }
  const decisions = steps
    .filter((step) => step.status === "approved")
    .map((step) => {
      const person = directory.members.find(
        (member) => member.userId === step.decidedByUserId,
      )?.email;
      return person === undefined ? reviewerLabel(step, directory) : person;
    });
  return {
    kind: "recorded",
    label:
      decisions.length === 0
        ? "Approval history available in the version record"
        : `Approved by ${[...new Set(decisions)].join(", ")}`,
    detail: "Approval applies to this version's saved badge and requirements.",
    submissionNotice: "",
    canReview: false,
  };
};

/** Describes who awards a badge even before activation or LMS placement. */
export const badgeWorkflowAwarding = (
  ruleJson: string,
  current: boolean,
): Pick<BadgeWorkflowResponsibility, "awarding" | "awardingDetail"> => {
  let definition;
  try {
    definition = parseBadgeIssuanceRuleDefinitionJson(ruleJson);
  } catch {
    return {
      awarding: "Awarding settings need attention",
      awardingDetail: "Open the rule to repair its saved requirements.",
    };
  }
  return describeBadgeWorkflowAwardingTiming(
    resolveAutomatedBadgeRuleIssuanceTiming(definition),
    current,
    definition.options?.reviewOnMissingFacts ?? false,
  );
};

/** Shared awarding copy for a saved definition or the builder's selected timing. */
export const describeBadgeWorkflowAwardingTiming = (
  timing: ReturnType<typeof resolveAutomatedBadgeRuleIssuanceTiming>,
  current: boolean,
  reviewOnMissingFacts: boolean,
): Pick<BadgeWorkflowResponsibility, "awarding" | "awardingDetail"> => {
  const prefix = current ? "" : "Once activated, ";
  const review = reviewOnMissingFacts
    ? " Learners are flagged for review if missing information prevents CredTrail from confirming eligibility."
    : "";
  switch (timing) {
    case "immediate":
      return {
        awarding: "CredTrail awards automatically",
        awardingDetail: `${prefix}CredTrail checks learners against the requirements and repeats the check every hour. Eligible learners receive the badge automatically.${review}`,
      };
    case null:
      return {
        awarding: "Instructor confirms the award",
        awardingDetail: `${current ? "An instructor" : "Once activated, an instructor"} selects eligible learners from the course roster and confirms who receives the badge.${review}`,
      };
    case "end_of_term":
      return {
        awarding: "CredTrail awards at term end",
        awardingDetail: `${prefix}CredTrail waits until the scheduled term end date, then checks the requirements and automatically awards badges to eligible learners.${review}`,
      };
  }
};

/** Builds the responsibility summary for one version without database or rendering concerns. */
export const buildBadgeWorkflowResponsibility = (input: {
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly current: boolean;
  readonly policy: BadgeRuleApprovalPolicyRecord;
  readonly steps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  readonly directory: BadgeWorkflowDirectory;
  readonly actorUserId: string;
}): BadgeWorkflowResponsibility => {
  const awarding = badgeWorkflowAwarding(input.version.ruleJson, input.current);
  const inactiveDetail =
    input.version.status === "suspended"
      ? "Awarding is paused. An administrator must resume this version before it can award badges again."
      : input.version.status === "expired" || input.version.status === "deprecated"
        ? "This version no longer awards badges. Its saved awarding method is shown for reference."
        : null;
  return {
    badgeOwner:
      input.directory.orgUnits.find((unit) => unit.id === input.version.snapshot.ownerOrgUnitId)
        ?.displayName ?? "Owning department not available",
    ruleAuthor:
      input.directory.members.find((member) => member.userId === input.version.createdByUserId)
        ?.email ??
      (input.version.createdByUserId === null
        ? "Creator not recorded"
        : "Creator no longer a member"),
    approval: describeBadgeWorkflowApproval(input),
    ...awarding,
    awardingDetail: inactiveDetail ?? awarding.awardingDetail,
  };
};
