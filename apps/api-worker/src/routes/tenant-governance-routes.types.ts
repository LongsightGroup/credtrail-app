import type { TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import type {
  RequireDelegatedIssuingAuthorityPermission,
  RequireScopedOrgUnitPermission,
  RequireTenantRole,
  ResolveDatabase,
} from "../app/route-deps";
import type { IssueBadgeForTenant } from "./badge-rule-evaluation-types";

export interface RegisterTenantGovernanceRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  defaultInstitutionOrgUnitId: (tenantId: string) => string;
  requestTenantMemberInvite?: (
    c: AppContext,
    input: {
      tenantId: string;
      email: string;
      role: TenantMembershipRole;
    },
  ) => Promise<{
    deliveryStatus: "sent" | "skipped" | "failed";
    inviteKind: "magic_link" | "sso_notice";
  }>;
  requestBreakGlassPasswordReset?: (
    c: AppContext,
    input: {
      tenantId: string;
      email: string;
    },
  ) => Promise<"sent" | "unavailable">;
  generateOpaqueToken: () => string;
  sha256Hex: (value: string) => Promise<string>;
  requireTenantRole: RequireTenantRole;
  requireScopedOrgUnitPermission: RequireScopedOrgUnitPermission;
  requireDelegatedIssuingAuthorityPermission: RequireDelegatedIssuingAuthorityPermission;
  assertionBelongsToTenant: (tenantId: string, assertionId: string) => boolean;
  issueBadgeForTenant: IssueBadgeForTenant;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
  APPROVAL_WORKSPACE_ROLES: readonly TenantMembershipRole[];
}
