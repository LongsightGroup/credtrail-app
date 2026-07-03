import type { TenantMembershipRole } from "@credtrail/db";

export const ADMIN_ROLES: TenantMembershipRole[] = ["owner", "admin"];
export const ISSUER_ROLES: TenantMembershipRole[] = ["owner", "admin", "issuer"];
export const APPROVAL_WORKSPACE_ROLES: TenantMembershipRole[] = ["owner", "admin", "approver"];

export const membershipHasRole = (
  membershipRole: TenantMembershipRole,
  allowedRoles: readonly TenantMembershipRole[],
): boolean => {
  return allowedRoles.includes(membershipRole);
};

export const isTenantAdminRole = (membershipRole: TenantMembershipRole): boolean => {
  return membershipHasRole(membershipRole, ADMIN_ROLES);
};

export const canIssueBadgesAsTenantMember = (membershipRole: TenantMembershipRole): boolean => {
  return membershipHasRole(membershipRole, ISSUER_ROLES);
};
