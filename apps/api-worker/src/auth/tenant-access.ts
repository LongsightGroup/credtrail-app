import {
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findTenantMembership,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listTenantMembershipOrgUnitScopes,
  type DelegatedIssuingAuthorityAction,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { AuthenticatedPrincipal, RequestedTenantContext } from "./auth-context";
import { isTenantAdminRole, membershipHasRole } from "./tenant-role-policy";

export { ADMIN_ROLES, ISSUER_ROLES } from "./tenant-role-policy";

export const TENANT_MEMBER_ROLES: TenantMembershipRole[] = ["owner", "admin", "issuer", "viewer"];
export const REPORTING_SCOPE_ROLES: TenantMembershipOrgUnitScopeRole[] = ["admin", "issuer"];
export const EXECUTIVE_SCOPE_ROLES: TenantMembershipOrgUnitScopeRole[] = [
  "admin",
  "issuer",
  "viewer",
];

export const defaultInstitutionOrgUnitId = (tenantId: string): string => {
  return `${tenantId}:org:institution`;
};

export interface TenantAccessContext<BindingsType> {
  env: BindingsType;
  req: {
    header(name: string): string | undefined;
  };
  json(payload: unknown, status?: number): Response;
}

export interface PrincipalTenantRoleResult {
  principal: AuthenticatedPrincipal;
  requestedTenant: RequestedTenantContext;
  membershipRole: TenantMembershipRole;
}

export interface TenantReportingAccessResult {
  tenantId: string;
  membershipRole: TenantMembershipRole;
  visibility: "tenant" | "scoped";
  scopedOrgUnitIds: string[];
}

export interface TenantExecutiveAccessResult {
  tenantId: string;
  membershipRole: TenantMembershipRole;
  visibility: "tenant" | "scoped";
  scopedOrgUnitIds: string[];
}

interface CreateTenantAccessHelpersInput<
  ContextType extends TenantAccessContext<BindingsType>,
  BindingsType,
> {
  resolveAuthenticatedPrincipal: (context: ContextType) => Promise<AuthenticatedPrincipal | null>;
  resolvePendingBreakGlassTenantId?: (context: ContextType) => string | null;
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
}

interface TenantAccessHelpers<ContextType extends TenantAccessContext<BindingsType>, BindingsType> {
  requireTenantRole: (
    context: ContextType,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        principal: AuthenticatedPrincipal;
        requestedTenant: RequestedTenantContext;
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  requireScopedOrgUnitPermission: (
    context: ContextType,
    request: {
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
    context: ContextType,
    request: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      ownerOrgUnitId: string;
      badgeTemplateId: string;
      requiredAction: DelegatedIssuingAuthorityAction;
    },
  ) => Promise<Response | null>;
}

export const resolveTenantReportingAccess = async (input: {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
}): Promise<TenantReportingAccessResult | null> => {
  if (input.membershipRole === "owner" || input.membershipRole === "admin") {
    return {
      tenantId: input.tenantId,
      membershipRole: input.membershipRole,
      visibility: "tenant",
      scopedOrgUnitIds: [],
    };
  }

  if (input.membershipRole !== "issuer") {
    return null;
  }

  const scopes = await listTenantMembershipOrgUnitScopes(input.db, {
    tenantId: input.tenantId,
    userId: input.userId,
  });

  if (scopes.length === 0) {
    return {
      tenantId: input.tenantId,
      membershipRole: input.membershipRole,
      visibility: "tenant",
      scopedOrgUnitIds: [],
    };
  }

  const scopedOrgUnitIds = Array.from(
    new Set(
      scopes
        .filter((scope) => REPORTING_SCOPE_ROLES.includes(scope.role))
        .map((scope) => scope.orgUnitId),
    ),
  ).sort((left, right) => left.localeCompare(right));

  if (scopedOrgUnitIds.length === 0) {
    return null;
  }

  return {
    tenantId: input.tenantId,
    membershipRole: input.membershipRole,
    visibility: "scoped",
    scopedOrgUnitIds,
  };
};

export const resolveTenantExecutiveAccess = async (input: {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
}): Promise<TenantExecutiveAccessResult | null> => {
  if (input.membershipRole === "owner" || input.membershipRole === "admin") {
    return {
      tenantId: input.tenantId,
      membershipRole: input.membershipRole,
      visibility: "tenant",
      scopedOrgUnitIds: [],
    };
  }

  if (input.membershipRole !== "issuer" && input.membershipRole !== "viewer") {
    return null;
  }

  const scopes = await listTenantMembershipOrgUnitScopes(input.db, {
    tenantId: input.tenantId,
    userId: input.userId,
  });

  const scopedOrgUnitIds = Array.from(
    new Set(
      scopes
        .filter((scope) => EXECUTIVE_SCOPE_ROLES.includes(scope.role))
        .map((scope) => scope.orgUnitId),
    ),
  ).sort((left, right) => left.localeCompare(right));

  if (scopedOrgUnitIds.length === 0) {
    return null;
  }

  return {
    tenantId: input.tenantId,
    membershipRole: input.membershipRole,
    visibility: "scoped",
    scopedOrgUnitIds,
  };
};

export const requirePrincipalTenantRole = async <
  ContextType extends TenantAccessContext<BindingsType>,
  BindingsType,
>(input: {
  context: ContextType;
  principal: AuthenticatedPrincipal | null;
  requestedTenant: RequestedTenantContext;
  allowedRoles: readonly TenantMembershipRole[];
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
}): Promise<PrincipalTenantRoleResult | Response> => {
  if (input.principal === null) {
    return input.context.json(
      {
        error: "Not authenticated",
      },
      401,
    );
  }

  const membership = await findTenantMembership(
    input.resolveDatabase(input.context.env),
    input.requestedTenant.tenantId,
    input.principal.userId,
  );

  if (membership === null) {
    return input.context.json(
      {
        error: "Membership not found for requested tenant",
      },
      403,
    );
  }

  if (!membershipHasRole(membership.role, input.allowedRoles)) {
    return input.context.json(
      {
        error: "Insufficient role for requested action",
      },
      403,
    );
  }

  return {
    principal: input.principal,
    requestedTenant: input.requestedTenant,
    membershipRole: membership.role,
  };
};

const canBypassOrgScopeChecks = (membershipRole: TenantMembershipRole): boolean => {
  return isTenantAdminRole(membershipRole);
};

const sessionCompatibilityFromPrincipal = (
  principal: AuthenticatedPrincipal,
  requestedTenant: RequestedTenantContext,
): SessionRecord => {
  return {
    id: principal.authSessionId,
    tenantId: requestedTenant.tenantId,
    userId: principal.userId,
    sessionTokenHash: "",
    expiresAt: principal.expiresAt,
    lastSeenAt: principal.expiresAt,
    revokedAt: null,
    createdAt: principal.expiresAt,
  };
};

const hasScopedOrgUnitPermission = async (input: {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  orgUnitId: string;
  requiredRole: TenantMembershipOrgUnitScopeRole;
  allowWhenNoScopes: boolean;
}): Promise<boolean> => {
  if (canBypassOrgScopeChecks(input.membershipRole)) {
    return true;
  }

  if (input.membershipRole !== "issuer") {
    return false;
  }

  const hasScopedAssignments = await hasTenantMembershipOrgUnitScopeAssignments(
    input.db,
    input.tenantId,
    input.userId,
  );

  if (!hasScopedAssignments) {
    return input.allowWhenNoScopes;
  }

  return hasTenantMembershipOrgUnitAccess(input.db, {
    tenantId: input.tenantId,
    userId: input.userId,
    orgUnitId: input.orgUnitId,
    requiredRole: input.requiredRole,
  });
};

export const createTenantAccessHelpers = <
  ContextType extends TenantAccessContext<BindingsType>,
  BindingsType,
>(
  input: CreateTenantAccessHelpersInput<ContextType, BindingsType>,
): TenantAccessHelpers<ContextType, BindingsType> => {
  const requireTenantRole = async (
    context: ContextType,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ): Promise<
    | {
        principal: AuthenticatedPrincipal;
        requestedTenant: RequestedTenantContext;
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  > => {
    const requestedTenant: RequestedTenantContext = {
      tenantId,
      source: "route",
      authoritative: true,
    };
    const pendingBreakGlassTenantId = input.resolvePendingBreakGlassTenantId?.(context);

    if (pendingBreakGlassTenantId === tenantId) {
      return context.json(
        {
          error: "Local MFA enrollment must be completed before tenant access is granted",
          reason: "break_glass_mfa_setup_pending",
        },
        423,
      );
    }

    const result = await requirePrincipalTenantRole({
      context,
      principal: await input.resolveAuthenticatedPrincipal(context),
      requestedTenant,
      allowedRoles,
      resolveDatabase: input.resolveDatabase,
    });

    if (result instanceof Response) {
      return result;
    }

    return {
      principal: result.principal,
      requestedTenant: result.requestedTenant,
      session: sessionCompatibilityFromPrincipal(result.principal, requestedTenant),
      membershipRole: result.membershipRole,
    };
  };

  const requireScopedOrgUnitPermission = async (
    context: ContextType,
    request: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      orgUnitId: string;
      requiredRole: TenantMembershipOrgUnitScopeRole;
      allowWhenNoScopes?: boolean;
    },
  ): Promise<Response | null> => {
    const allowed = await hasScopedOrgUnitPermission({
      db: request.db,
      tenantId: request.tenantId,
      userId: request.userId,
      membershipRole: request.membershipRole,
      orgUnitId: request.orgUnitId,
      requiredRole: request.requiredRole,
      allowWhenNoScopes: request.allowWhenNoScopes === true,
    });

    if (allowed) {
      return null;
    }

    return context.json(
      {
        error: "Insufficient org-unit scope for requested action",
      },
      403,
    );
  };

  const requireDelegatedIssuingAuthorityPermission = async (
    context: ContextType,
    request: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      ownerOrgUnitId: string;
      badgeTemplateId: string;
      requiredAction: DelegatedIssuingAuthorityAction;
    },
  ): Promise<Response | null> => {
    if (canBypassOrgScopeChecks(request.membershipRole)) {
      return null;
    }

    const delegatedGrant = await findActiveDelegatedIssuingAuthorityGrantForAction(request.db, {
      tenantId: request.tenantId,
      userId: request.userId,
      orgUnitId: request.ownerOrgUnitId,
      badgeTemplateId: request.badgeTemplateId,
      requiredAction: request.requiredAction,
    });

    if (delegatedGrant !== null) {
      return null;
    }

    if (request.membershipRole === "issuer") {
      return requireScopedOrgUnitPermission(context, {
        db: request.db,
        tenantId: request.tenantId,
        userId: request.userId,
        membershipRole: request.membershipRole,
        orgUnitId: request.ownerOrgUnitId,
        requiredRole: "issuer",
        allowWhenNoScopes: true,
      });
    }

    return context.json(
      {
        error: "Insufficient role for requested action",
      },
      403,
    );
  };

  return {
    requireTenantRole,
    requireScopedOrgUnitPermission,
    requireDelegatedIssuingAuthorityPermission,
  };
};
