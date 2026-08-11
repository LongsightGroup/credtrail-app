import {
  actorCanDecideApprovalStep,
  type BadgeIssuanceRuleApprovalStepRecord,
  type BadgeIssuanceRuleVersionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";

interface BadgeRuleApprovalActorInput {
  readonly tenantId: string;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
}

/** Decides whether an actor may record the next decision for a governed rule version. */
export const actorCanDecideBadgeRuleVersionApproval = async (
  db: SqlDatabase,
  input: BadgeRuleApprovalActorInput,
): Promise<boolean> => {
  if (input.version.status !== "pending_approval") {
    return false;
  }

  if (
    input.version.createdByUserId === input.actorUserId ||
    input.version.submittedByUserId === input.actorUserId
  ) {
    return false;
  }

  const pendingStep = input.approvalSteps.find((step) => step.status === "pending");

  if (pendingStep === undefined) {
    return false;
  }

  return actorCanDecideApprovalStep(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    step: pendingStep,
  });
};

/** Decides whether an actor may inspect a version through the approval workspace. */
export const actorCanViewBadgeRuleVersionApproval = async (
  db: SqlDatabase,
  input: BadgeRuleApprovalActorInput,
): Promise<boolean> => {
  if (input.actorRole === "owner" || input.actorRole === "admin") {
    return true;
  }

  if (input.version.status === "approved" && input.version.approvedByUserId === input.actorUserId) {
    return true;
  }

  if (input.version.status !== "pending_approval") {
    return false;
  }

  for (const step of input.approvalSteps) {
    if (
      await actorCanDecideApprovalStep(db, {
        tenantId: input.tenantId,
        actorUserId: input.actorUserId,
        actorRole: input.actorRole,
        step,
      })
    ) {
      return true;
    }
  }

  return false;
};
