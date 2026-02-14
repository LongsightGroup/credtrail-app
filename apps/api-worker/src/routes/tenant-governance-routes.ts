import {
  createAuditLog,
  createDelegatedIssuingAuthorityGrant,
  createTenantOrgUnit,
  findDelegatedIssuingAuthorityGrantById,
  listDelegatedIssuingAuthorityGrantEvents,
  listDelegatedIssuingAuthorityGrants,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  removeTenantMembershipOrgUnitScope,
  revokeDelegatedIssuingAuthorityGrant,
  upsertTenantMembershipOrgUnitScope,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from '@credtrail/db';
import type { Hono } from 'hono';
import {
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseCreateTenantOrgUnitRequest,
  parseDelegatedIssuingAuthorityGrantListQuery,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseTenantOrgUnitListQuery,
  parseTenantPathParams,
  parseTenantUserDelegatedGrantPathParams,
  parseTenantUserOrgUnitPathParams,
  parseTenantUserPathParams,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
} from '@credtrail/validation';
import type { AppBindings, AppContext, AppEnv } from '../app';

interface RegisterTenantGovernanceRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
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
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerTenantGovernanceRoutes = (
  input: RegisterTenantGovernanceRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, ADMIN_ROLES, ISSUER_ROLES } = input;

  app.get('/v1/tenants/:tenantId/org-units', async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const query = parseTenantOrgUnitListQuery({
      includeInactive: c.req.query('includeInactive'),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const orgUnits = await listTenantOrgUnits(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      includeInactive: query.includeInactive,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      orgUnits,
    });
  });

  app.post('/v1/tenants/:tenantId/org-units', async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantOrgUnitRequest>;

    try {
      request = parseCreateTenantOrgUnitRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: 'Invalid org unit request payload',
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;

    try {
      const orgUnit = await createTenantOrgUnit(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        unitType: request.unitType,
        slug: request.slug,
        displayName: request.displayName,
        parentOrgUnitId: request.parentOrgUnitId,
        createdByUserId: session.userId,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: 'tenant.org_unit_created',
        targetType: 'org_unit',
        targetId: orgUnit.id,
        metadata: {
          role: membershipRole,
          unitType: orgUnit.unitType,
          slug: orgUnit.slug,
          parentOrgUnitId: orgUnit.parentOrgUnitId,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          orgUnit,
        },
        201,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes('UNIQUE constraint failed')) {
          return c.json(
            {
              error: 'Org unit slug already exists for tenant',
            },
            409,
          );
        }

        if (
          (error.message.includes('Parent org unit') &&
            error.message.includes('not found for tenant')) ||
          error.message.includes('cannot have a parent org unit') ||
          error.message.includes('requires parent org unit type') ||
          error.message.includes('is inactive for tenant')
        ) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  });

  app.get('/v1/tenants/:tenantId/users/:userId/org-unit-scopes', async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const scopes = await listTenantMembershipOrgUnitScopes(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      scopes,
    });
  });

  app.put('/v1/tenants/:tenantId/users/:userId/org-unit-scopes/:orgUnitId', async (c) => {
    const pathParams = parseTenantUserOrgUnitPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantMembershipOrgUnitScopeRequest>;

    try {
      request = parseUpsertTenantMembershipOrgUnitScopeRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: 'Invalid org-unit scope payload',
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;

    try {
      const result = await upsertTenantMembershipOrgUnitScope(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        orgUnitId: pathParams.orgUnitId,
        role: request.role,
        createdByUserId: session.userId,
      });

      const action =
        result.previousRole === null
          ? 'membership.org_scope_assigned'
          : result.previousRole === result.scope.role
            ? 'membership.org_scope_reasserted'
            : 'membership.org_scope_changed';

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action,
        targetType: 'membership_org_scope',
        targetId: `${pathParams.tenantId}:${pathParams.userId}:${pathParams.orgUnitId}`,
        metadata: {
          role: membershipRole,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
          previousRole: result.previousRole,
          scopeRole: result.scope.role,
          changed: result.changed,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
          scope: result.scope,
          previousRole: result.previousRole,
          changed: result.changed,
        },
        result.previousRole === null ? 201 : 200,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes('Membership not found for tenant')) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }

        if (error.message.includes('Org unit') && error.message.includes('not found for tenant')) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  });

  app.delete('/v1/tenants/:tenantId/users/:userId/org-unit-scopes/:orgUnitId', async (c) => {
    const pathParams = parseTenantUserOrgUnitPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const removed = await removeTenantMembershipOrgUnitScope(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      orgUnitId: pathParams.orgUnitId,
    });

    if (removed) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: 'membership.org_scope_removed',
        targetType: 'membership_org_scope',
        targetId: `${pathParams.tenantId}:${pathParams.userId}:${pathParams.orgUnitId}`,
        metadata: {
          role: membershipRole,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      orgUnitId: pathParams.orgUnitId,
      removed,
    });
  });

  app.get('/v1/tenants/:tenantId/users/:userId/issuing-authority-grants', async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    const query = parseDelegatedIssuingAuthorityGrantListQuery({
      includeRevoked: c.req.query('includeRevoked'),
      includeExpired: c.req.query('includeExpired'),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const grants = await listDelegatedIssuingAuthorityGrants(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      delegateUserId: pathParams.userId,
      includeRevoked: query.includeRevoked,
      includeExpired: query.includeExpired,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      grants,
    });
  });

  app.post('/v1/tenants/:tenantId/users/:userId/issuing-authority-grants', async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateDelegatedIssuingAuthorityGrantRequest>;

    try {
      request = parseCreateDelegatedIssuingAuthorityGrantRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: 'Invalid delegated authority grant payload',
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const startsAt = request.startsAt ?? new Date().toISOString();

    try {
      const grant = await createDelegatedIssuingAuthorityGrant(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        delegateUserId: pathParams.userId,
        delegatedByUserId: session.userId,
        orgUnitId: request.orgUnitId,
        allowedActions: request.allowedActions,
        badgeTemplateIds: request.badgeTemplateIds,
        startsAt,
        endsAt: request.endsAt,
        reason: request.reason,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: 'delegated_issuing_authority.granted',
        targetType: 'delegated_issuing_authority_grant',
        targetId: grant.id,
        metadata: {
          role: membershipRole,
          delegateUserId: pathParams.userId,
          orgUnitId: request.orgUnitId,
          allowedActions: request.allowedActions,
          badgeTemplateIds: request.badgeTemplateIds ?? [],
          startsAt,
          endsAt: request.endsAt,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          userId: pathParams.userId,
          grant,
        },
        201,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes('conflicts with existing grant')) {
          return c.json(
            {
              error: error.message,
            },
            409,
          );
        }

        if (
          error.message.includes('Membership not found for tenant') ||
          (error.message.includes('Org unit') && error.message.includes('not found for tenant')) ||
          (error.message.includes('Badge template') &&
            error.message.includes('not found for tenant')) ||
          error.message.includes('outside delegated org-unit scope') ||
          error.message.includes('is inactive for tenant') ||
          error.message.includes('must be after') ||
          error.message.includes('must be a valid ISO timestamp')
        ) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  });

  app.post('/v1/tenants/:tenantId/users/:userId/issuing-authority-grants/:grantId/revoke', async (c) => {
    const pathParams = parseTenantUserDelegatedGrantPathParams(c.req.param());
    let request: ReturnType<typeof parseRevokeDelegatedIssuingAuthorityGrantRequest>;

    try {
      let payload: unknown = {};

      try {
        payload = await c.req.json<unknown>();
      } catch {
        payload = {};
      }

      request = parseRevokeDelegatedIssuingAuthorityGrantRequest(payload);
    } catch {
      return c.json(
        {
          error: 'Invalid delegated authority revoke payload',
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const existingGrant = await findDelegatedIssuingAuthorityGrantById(
      db,
      pathParams.tenantId,
      pathParams.grantId,
    );

    if (existingGrant?.delegateUserId !== pathParams.userId) {
      return c.json(
        {
          error: 'Delegated issuing authority grant not found',
        },
        404,
      );
    }

    const revokedAt = request.revokedAt ?? new Date().toISOString();

    try {
      const result = await revokeDelegatedIssuingAuthorityGrant(db, {
        tenantId: pathParams.tenantId,
        grantId: pathParams.grantId,
        revokedByUserId: session.userId,
        revokedReason: request.reason,
        revokedAt,
      });

      if (result.status === 'revoked') {
        await createAuditLog(db, {
          tenantId: pathParams.tenantId,
          actorUserId: session.userId,
          action: 'delegated_issuing_authority.revoked',
          targetType: 'delegated_issuing_authority_grant',
          targetId: pathParams.grantId,
          metadata: {
            role: membershipRole,
            delegateUserId: pathParams.userId,
            revokedAt,
            reason: request.reason,
          },
        });
      }

      return c.json({
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        status: result.status,
        grant: result.grant,
      });
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (
          error.message.includes('not found for tenant') ||
          error.message.includes('must be a valid ISO timestamp')
        ) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  });

  app.get('/v1/tenants/:tenantId/users/:userId/issuing-authority-grants/:grantId/events', async (c) => {
    const pathParams = parseTenantUserDelegatedGrantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const limitRaw = c.req.query('limit');
    let limit: number | undefined;

    if (limitRaw !== undefined) {
      const parsed = Number.parseInt(limitRaw, 10);

      if (!Number.isFinite(parsed) || parsed < 1) {
        return c.json(
          {
            error: 'limit must be a positive integer',
          },
          400,
        );
      }

      limit = parsed;
    }

    const db = resolveDatabase(c.env);
    const grant = await findDelegatedIssuingAuthorityGrantById(
      db,
      pathParams.tenantId,
      pathParams.grantId,
    );

    if (grant?.delegateUserId !== pathParams.userId) {
      return c.json(
        {
          error: 'Delegated issuing authority grant not found',
        },
        404,
      );
    }

    const events = await listDelegatedIssuingAuthorityGrantEvents(db, {
      tenantId: pathParams.tenantId,
      grantId: pathParams.grantId,
      ...(limit === undefined ? {} : { limit }),
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      grant,
      events,
    });
  });
};
