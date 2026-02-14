import {
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findTenantMembership,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  type DelegatedIssuingAuthorityAction,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from '@credtrail/db';

export const ISSUER_ROLES: TenantMembershipRole[] = ['owner', 'admin', 'issuer'];
export const TENANT_MEMBER_ROLES: TenantMembershipRole[] = ['owner', 'admin', 'issuer', 'viewer'];
export const ADMIN_ROLES: TenantMembershipRole[] = ['owner', 'admin'];

export const isUniqueConstraintError = (error: unknown): boolean => {
  return (
    error instanceof Error &&
    (error.message.includes('UNIQUE constraint failed') ||
      error.message.includes('duplicate key value violates unique constraint'))
  );
};

export const defaultInstitutionOrgUnitId = (tenantId: string): string => {
  return `${tenantId}:org:institution`;
};

interface TenantAccessContext<BindingsType extends { BOOTSTRAP_ADMIN_TOKEN?: string | undefined }> {
  env: BindingsType;
  req: {
    header(name: string): string | undefined;
  };
  json(payload: unknown, status?: number): Response;
}

interface CreateTenantAccessHelpersInput<
  ContextType extends TenantAccessContext<BindingsType>,
  BindingsType extends { BOOTSTRAP_ADMIN_TOKEN?: string | undefined },
> {
  resolveSessionFromCookie: (context: ContextType) => Promise<SessionRecord | null>;
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
}

interface TenantAccessHelpers<
  ContextType extends TenantAccessContext<BindingsType>,
  BindingsType extends { BOOTSTRAP_ADMIN_TOKEN?: string | undefined },
> {
  requireBootstrapAdmin: (context: ContextType) => Response | null;
  requireBootstrapAdminUiToken: (context: ContextType, token: string | null) => Response | null;
  requireTenantRole: (
    context: ContextType,
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
    context: ContextType,
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
    context: ContextType,
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
}

const hasRequiredRole = (
  membershipRole: TenantMembershipRole,
  allowedRoles: readonly TenantMembershipRole[],
): boolean => {
  return allowedRoles.includes(membershipRole);
};

const canBypassOrgScopeChecks = (membershipRole: TenantMembershipRole): boolean => {
  return membershipRole === 'owner' || membershipRole === 'admin';
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

  if (input.membershipRole !== 'issuer') {
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
  BindingsType extends { BOOTSTRAP_ADMIN_TOKEN?: string | undefined },
>(
  input: CreateTenantAccessHelpersInput<ContextType, BindingsType>,
): TenantAccessHelpers<ContextType, BindingsType> => {
  const requireBootstrapAdmin = (context: ContextType): Response | null => {
    const configuredToken = context.env.BOOTSTRAP_ADMIN_TOKEN?.trim();

    if (configuredToken === undefined || configuredToken.length === 0) {
      return context.json(
        {
          error: 'Bootstrap admin API is not configured',
        },
        503,
      );
    }

    const authorizationHeader = context.req.header('authorization');
    const expectedAuthorization = `Bearer ${configuredToken}`;

    if (authorizationHeader !== expectedAuthorization) {
      return context.json(
        {
          error: 'Unauthorized',
        },
        401,
      );
    }

    return null;
  };

  const requireBootstrapAdminUiToken = (
    context: ContextType,
    token: string | null,
  ): Response | null => {
    const configuredToken = context.env.BOOTSTRAP_ADMIN_TOKEN?.trim();

    if (configuredToken === undefined || configuredToken.length === 0) {
      return context.json(
        {
          error: 'Bootstrap admin API is not configured',
        },
        503,
      );
    }

    if (token === null || token !== configuredToken) {
      return context.json(
        {
          error: 'Unauthorized',
        },
        401,
      );
    }

    return null;
  };

  const requireTenantRole = async (
    context: ContextType,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ): Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  > => {
    const session = await input.resolveSessionFromCookie(context);

    if (session === null) {
      return context.json(
        {
          error: 'Not authenticated',
        },
        401,
      );
    }

    if (session.tenantId !== tenantId) {
      return context.json(
        {
          error: 'Forbidden for requested tenant',
        },
        403,
      );
    }

    const membership = await findTenantMembership(
      input.resolveDatabase(context.env),
      tenantId,
      session.userId,
    );

    if (membership === null) {
      return context.json(
        {
          error: 'Membership not found for requested tenant',
        },
        403,
      );
    }

    if (!hasRequiredRole(membership.role, allowedRoles)) {
      return context.json(
        {
          error: 'Insufficient role for requested action',
        },
        403,
      );
    }

    return {
      session,
      membershipRole: membership.role,
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
        error: 'Insufficient org-unit scope for requested action',
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

    if (request.membershipRole === 'issuer') {
      return requireScopedOrgUnitPermission(context, {
        db: request.db,
        tenantId: request.tenantId,
        userId: request.userId,
        membershipRole: request.membershipRole,
        orgUnitId: request.ownerOrgUnitId,
        requiredRole: 'issuer',
        allowWhenNoScopes: true,
      });
    }

    return context.json(
      {
        error: 'Insufficient role for requested action',
      },
      403,
    );
  };

  return {
    requireBootstrapAdmin,
    requireBootstrapAdminUiToken,
    requireTenantRole,
    requireScopedOrgUnitPermission,
    requireDelegatedIssuingAuthorityPermission,
  };
};
