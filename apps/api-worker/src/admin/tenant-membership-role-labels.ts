import type { TenantMembershipRole } from "@credtrail/db";

export const tenantMembershipRoleLabel = (role: TenantMembershipRole): string => {
  switch (role) {
    case "owner":
      return "Owner";
    case "admin":
      return "Admin";
    case "issuer":
      return "Issuer";
    case "approver":
      return "Approver";
    case "viewer":
      return "Viewer";
  }
};
