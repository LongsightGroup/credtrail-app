import type { SqlDatabase } from "./tenant-scope";
import {
  tenantMembershipRoleSatisfiesMinimumRole,
  type TenantMembershipRole,
} from "./tenant-memberships";
import type {
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleVersionRecord,
} from "./badge-issuance-rule-types.js";

/** Returns whether an actor may reopen an approved badge-rule version before activation. */
export const canReopenApprovedBadgeIssuanceRuleVersion = (input: {
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
}): boolean => {
  return (
    input.version.status === "approved" &&
    (input.version.approvedByUserId === input.actorUserId ||
      input.actorRole === "admin" ||
      input.actorRole === "owner")
  );
};

export const checkActorIsApproverGroupMember = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    groupId: string;
    actorUserId: string;
  },
): Promise<boolean> => {
  const row = await db
    .prepare(
      `
      SELECT user_id AS userId
      FROM badge_rule_approver_group_members
      WHERE tenant_id = ?
        AND group_id = ?
        AND user_id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.groupId, input.actorUserId)
    .first<{ userId: string }>();

  return row !== null;
};

export const actorCanDecideApprovalStep = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    actorUserId: string;
    actorRole: TenantMembershipRole;
    step: BadgeIssuanceRuleApprovalStepRecord;
  },
): Promise<boolean> => {
  if (input.step.targetType === "user") {
    return input.step.targetUserId === input.actorUserId;
  }

  if (input.step.targetType === "approver_group") {
    if (
      !tenantMembershipRoleSatisfiesMinimumRole(
        input.actorRole,
        input.step.requiredRole ?? "viewer",
      )
    ) {
      return false;
    }

    return checkActorIsApproverGroupMember(db, {
      tenantId: input.tenantId,
      groupId: input.step.targetApproverGroupId,
      actorUserId: input.actorUserId,
    });
  }

  return tenantMembershipRoleSatisfiesMinimumRole(input.actorRole, input.step.requiredRole);
};
