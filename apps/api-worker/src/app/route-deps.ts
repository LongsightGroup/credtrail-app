import type {
  DelegatedIssuingAuthorityAction,
  SessionRecord,
  SqlDatabase,
  TenantMembershipOrgUnitScopeRole,
  TenantMembershipRole,
} from "@credtrail/db";
import type { AuthenticatedPrincipal, RequestedTenantContext } from "../auth/auth-context";
import type { DirectIssueBadgeResult } from "../badges/direct-issue";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import type { AppBindings, AppContext } from "./types";

export type ResolveDatabase = (bindings: AppBindings) => SqlDatabase;

/** Issues a badge within the current application and tenant context. */
export type IssueBadgeForTenant = (
  c: AppContext,
  tenantId: string,
  request: DirectIssueBadgeRequest,
  issuedByUserId?: string,
) => Promise<DirectIssueBadgeResult>;

export interface TenantRoleAccessResult {
  principal: AuthenticatedPrincipal;
  requestedTenant: RequestedTenantContext;
  session: SessionRecord;
  membershipRole: TenantMembershipRole;
}

export type RequireTenantRole = (
  c: AppContext,
  tenantId: string,
  allowedRoles: readonly TenantMembershipRole[],
) => Promise<TenantRoleAccessResult | Response>;

export interface ScopedOrgUnitPermissionInput {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  orgUnitId: string;
  requiredRole: TenantMembershipOrgUnitScopeRole;
  allowWhenNoScopes?: boolean;
}

export type RequireScopedOrgUnitPermission = (
  c: AppContext,
  input: ScopedOrgUnitPermissionInput,
) => Promise<Response | null>;

export interface DelegatedIssuingAuthorityPermissionInput {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  ownerOrgUnitId: string;
  badgeTemplateId: string;
  requiredAction: DelegatedIssuingAuthorityAction;
}

export type RequireDelegatedIssuingAuthorityPermission = (
  c: AppContext,
  input: DelegatedIssuingAuthorityPermissionInput,
) => Promise<Response | null>;

export interface DatabaseRouteDeps {
  resolveDatabase: ResolveDatabase;
}

export interface TenantAccessDeps {
  requireTenantRole: RequireTenantRole;
  requireScopedOrgUnitPermission: RequireScopedOrgUnitPermission;
  requireDelegatedIssuingAuthorityPermission: RequireDelegatedIssuingAuthorityPermission;
}
