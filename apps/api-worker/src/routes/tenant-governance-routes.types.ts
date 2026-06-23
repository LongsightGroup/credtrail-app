import type {
  DelegatedIssuingAuthorityAction,
  SessionRecord,
  SqlDatabase,
  TenantMembershipOrgUnitScopeRole,
  TenantMembershipRole,
} from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { IssueBadgeForTenant } from "./badge-rule-evaluation-types";

export interface RegisterTenantGovernanceRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
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
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  requireScopedOrgUnitPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      orgUnitId: string;
      requiredRole: TenantMembershipOrgUnitScopeRole;
      allowWhenNoScopes?: boolean;
    },
  ) => Promise<Response | null>;
  requireDelegatedIssuingAuthorityPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      ownerOrgUnitId: string;
      badgeTemplateId: string;
      requiredAction: DelegatedIssuingAuthorityAction;
    },
  ) => Promise<Response | null>;
  assertionBelongsToTenant: (tenantId: string, assertionId: string) => boolean;
  issueBadgeForTenant: IssueBadgeForTenant;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
}
