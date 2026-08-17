import {
  countTenantMembershipsByRole,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { AppContext } from "../app/types";

export type MembershipAuditAction =
  | "membership.role_assigned"
  | "membership.role_changed"
  | "membership.role_reasserted";

export const membershipAuditAction = (
  previousRole: TenantMembershipRole | null,
  nextRole: TenantMembershipRole,
): MembershipAuditAction => {
  if (previousRole === null) {
    return "membership.role_assigned";
  }

  return previousRole === nextRole ? "membership.role_reasserted" : "membership.role_changed";
};

export const canManageTenantRole = (
  actorRole: TenantMembershipRole,
  targetRole: TenantMembershipRole,
): boolean => {
  return actorRole === "owner" || targetRole !== "owner";
};

export const assertRoleChangeAllowed = async (
  c: AppContext,
  input: {
    db: SqlDatabase;
    tenantId: string;
    actorUserId: string;
    actorRole: TenantMembershipRole;
    targetUserId: string;
    previousRole: TenantMembershipRole | null;
    nextRole: TenantMembershipRole;
  },
): Promise<Response | null> => {
  if (!canManageTenantRole(input.actorRole, input.nextRole)) {
    return c.json(
      {
        error: "Only tenant owners can assign the owner role.",
      },
      403,
    );
  }

  if (input.previousRole === "owner" && input.actorRole !== "owner") {
    return c.json(
      {
        error: "Only tenant owners can change an owner membership.",
      },
      403,
    );
  }

  if (
    input.targetUserId === input.actorUserId &&
    (input.previousRole === "owner" || input.previousRole === "admin") &&
    input.nextRole !== input.previousRole
  ) {
    return c.json(
      {
        error: "You cannot change your own tenant admin role.",
      },
      409,
    );
  }

  if (input.previousRole === "owner" && input.nextRole !== "owner") {
    const counts = await countTenantMembershipsByRole(input.db, input.tenantId);

    if (counts.owner <= 1) {
      return c.json(
        {
          error: "At least one tenant owner must remain.",
        },
        409,
      );
    }
  }

  return null;
};
