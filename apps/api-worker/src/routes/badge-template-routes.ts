import {
  createAuditLog,
  createBadgeTemplate,
  findBadgeTemplateById,
  findTenantMembership,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listBadgeTemplateOwnershipEvents,
  listBadgeTemplates,
  setBadgeTemplateArchivedState,
  transferBadgeTemplateOwnership,
  updateBadgeTemplate,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from '@credtrail/db';
import type { Hono } from 'hono';
import {
  parseBadgeTemplateListQuery,
  parseBadgeTemplatePathParams,
  parseCreateBadgeTemplateRequest,
  parseTenantPathParams,
  parseTransferBadgeTemplateOwnershipRequest,
  parseUpdateBadgeTemplateRequest,
} from '@credtrail/validation';
import type { AppBindings, AppContext, AppEnv } from '../app';

interface RegisterBadgeTemplateRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveSessionFromCookie: (c: AppContext) => Promise<SessionRecord | null>;
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
  defaultInstitutionOrgUnitId: (tenantId: string) => string;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeTemplateRoutes = (input: RegisterBadgeTemplateRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    resolveSessionFromCookie,
    requireTenantRole,
    requireScopedOrgUnitPermission,
    defaultInstitutionOrgUnitId,
    ADMIN_ROLES,
    ISSUER_ROLES,
  } = input;

  app.get('/v1/tenants/:tenantId/badge-templates', async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const query = parseBadgeTemplateListQuery({
      includeArchived: c.req.query('includeArchived'),
    });
    const session = await resolveSessionFromCookie(c);

    if (session === null) {
      return c.json(
        {
          error: 'Not authenticated',
        },
        401,
      );
    }

    if (session.tenantId !== pathParams.tenantId) {
      return c.json(
        {
          error: 'Forbidden for requested tenant',
        },
        403,
      );
    }

    const db = resolveDatabase(c.env);
    const membership = await findTenantMembership(db, pathParams.tenantId, session.userId);

    if (membership === null) {
      return c.json(
        {
          error: 'Membership not found for requested tenant',
        },
        403,
      );
    }

    let templates = await listBadgeTemplates(db, {
      tenantId: pathParams.tenantId,
      includeArchived: query.includeArchived,
    });

    if (membership.role === 'issuer') {
      const hasScopedAssignments = await hasTenantMembershipOrgUnitScopeAssignments(
        db,
        pathParams.tenantId,
        session.userId,
      );

      if (hasScopedAssignments) {
        const scopedTemplates: typeof templates = [];

        for (const template of templates) {
          const canViewTemplate = await hasTenantMembershipOrgUnitAccess(db, {
            tenantId: pathParams.tenantId,
            userId: session.userId,
            orgUnitId: template.ownerOrgUnitId,
            requiredRole: 'viewer',
          });

          if (canViewTemplate) {
            scopedTemplates.push(template);
          }
        }

        templates = scopedTemplates;
      }
    }

    return c.json({
      tenantId: pathParams.tenantId,
      templates,
    });
  });

  app.post('/v1/tenants/:tenantId/badge-templates', async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseCreateBadgeTemplateRequest(payload);
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const targetOwnerOrgUnitId =
      request.ownerOrgUnitId ?? defaultInstitutionOrgUnitId(pathParams.tenantId);

    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      orgUnitId: targetOwnerOrgUnitId,
      requiredRole: 'issuer',
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    try {
      const template = await createBadgeTemplate(db, {
        tenantId: pathParams.tenantId,
        slug: request.slug,
        title: request.title,
        description: request.description,
        criteriaUri: request.criteriaUri,
        imageUri: request.imageUri,
        ownerOrgUnitId: request.ownerOrgUnitId,
        createdByUserId: session.userId,
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: 'badge_template.created',
        targetType: 'badge_template',
        targetId: template.id,
        metadata: {
          role: membershipRole,
          slug: template.slug,
          title: template.title,
          ownerOrgUnitId: template.ownerOrgUnitId,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          template,
        },
        201,
      );
    } catch (error: unknown) {
      if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
        return c.json(
          {
            error: 'Badge template slug already exists for tenant',
          },
          409,
        );
      }

      if (
        error instanceof Error &&
        error.message.includes('Org unit') &&
        error.message.includes('not found for tenant')
      ) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }

      throw error;
    }
  });

  app.get('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId', async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const session = await resolveSessionFromCookie(c);

    if (session === null) {
      return c.json(
        {
          error: 'Not authenticated',
        },
        401,
      );
    }

    if (session.tenantId !== pathParams.tenantId) {
      return c.json(
        {
          error: 'Forbidden for requested tenant',
        },
        403,
      );
    }

    const db = resolveDatabase(c.env);
    const membership = await findTenantMembership(db, pathParams.tenantId, session.userId);

    if (membership === null) {
      return c.json(
        {
          error: 'Membership not found for requested tenant',
        },
        403,
      );
    }

    const template = await findBadgeTemplateById(db, pathParams.tenantId, pathParams.badgeTemplateId);

    if (template === null) {
      return c.json(
        {
          error: 'Badge template not found',
        },
        404,
      );
    }

    if (membership.role === 'issuer') {
      const hasScopedAssignments = await hasTenantMembershipOrgUnitScopeAssignments(
        db,
        pathParams.tenantId,
        session.userId,
      );

      if (hasScopedAssignments) {
        const canViewTemplate = await hasTenantMembershipOrgUnitAccess(db, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          orgUnitId: template.ownerOrgUnitId,
          requiredRole: 'viewer',
        });

        if (!canViewTemplate) {
          return c.json(
            {
              error: 'Insufficient org-unit scope for requested action',
            },
            403,
          );
        }
      }
    }

    return c.json({
      tenantId: pathParams.tenantId,
      template,
    });
  });

  app.get('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/ownership-history', async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(db, pathParams.tenantId, pathParams.badgeTemplateId);

    if (template === null) {
      return c.json(
        {
          error: 'Badge template not found',
        },
        404,
      );
    }

    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      orgUnitId: template.ownerOrgUnitId,
      requiredRole: 'viewer',
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    const events = await listBadgeTemplateOwnershipEvents(db, {
      tenantId: pathParams.tenantId,
      badgeTemplateId: pathParams.badgeTemplateId,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      template,
      events,
    });
  });

  app.post('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/ownership-transfer', async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    let request: ReturnType<typeof parseTransferBadgeTemplateOwnershipRequest>;

    try {
      request = parseTransferBadgeTemplateOwnershipRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: 'Invalid ownership transfer request payload',
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
      const transition = await transferBadgeTemplateOwnership(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        toOrgUnitId: request.toOrgUnitId,
        reasonCode: request.reasonCode,
        reason: request.reason,
        governanceMetadataJson:
          request.governanceMetadata === undefined
            ? undefined
            : JSON.stringify(request.governanceMetadata),
        transferredByUserId: session.userId,
        transferredAt: request.transferredAt ?? new Date().toISOString(),
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: 'badge_template.ownership_transferred',
        targetType: 'badge_template',
        targetId: pathParams.badgeTemplateId,
        metadata: {
          role: membershipRole,
          status: transition.status,
          fromOrgUnitId: transition.event?.fromOrgUnitId ?? transition.template.ownerOrgUnitId,
          toOrgUnitId: transition.template.ownerOrgUnitId,
          reasonCode: request.reasonCode,
          reason: request.reason,
          eventId: transition.event?.id ?? null,
        },
      });

      return c.json({
        tenantId: pathParams.tenantId,
        status: transition.status,
        template: transition.template,
        event: transition.event,
      });
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes('not found for tenant') && error.message.includes('Badge template')) {
          return c.json(
            {
              error: 'Badge template not found',
            },
            404,
          );
        }

        if (
          error.message.includes('transferredAt must be a valid ISO timestamp') ||
          error.message.includes('Unsupported badge template ownership reason code') ||
          error.message.includes('initial_assignment is reserved') ||
          (error.message.includes('Org unit') && error.message.includes('not found for tenant'))
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

  app.patch('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId', async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseUpdateBadgeTemplateRequest(payload);
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const existingTemplate = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      pathParams.badgeTemplateId,
    );

    if (existingTemplate === null) {
      return c.json(
        {
          error: 'Badge template not found',
        },
        404,
      );
    }

    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      orgUnitId: existingTemplate.ownerOrgUnitId,
      requiredRole: 'issuer',
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    try {
      const template = await updateBadgeTemplate(db, {
        tenantId: pathParams.tenantId,
        id: pathParams.badgeTemplateId,
        slug: request.slug,
        title: request.title,
        description: request.description,
        criteriaUri: request.criteriaUri,
        imageUri: request.imageUri,
      });

      if (template === null) {
        return c.json(
          {
            error: 'Badge template not found',
          },
          404,
        );
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: 'badge_template.updated',
        targetType: 'badge_template',
        targetId: template.id,
        metadata: {
          role: membershipRole,
          slug: template.slug,
          title: template.title,
        },
      });

      return c.json({
        tenantId: pathParams.tenantId,
        template,
      });
    } catch (error: unknown) {
      if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
        return c.json(
          {
            error: 'Badge template slug already exists for tenant',
          },
          409,
        );
      }

      throw error;
    }
  });

  app.post('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/archive', async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;

    const template = await setBadgeTemplateArchivedState(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      id: pathParams.badgeTemplateId,
      isArchived: true,
    });

    if (template === null) {
      return c.json(
        {
          error: 'Badge template not found',
        },
        404,
      );
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: 'badge_template.archived_state_changed',
      targetType: 'badge_template',
      targetId: template.id,
      metadata: {
        role: membershipRole,
        isArchived: template.isArchived,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      template,
    });
  });

  app.post('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/unarchive', async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;

    const template = await setBadgeTemplateArchivedState(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      id: pathParams.badgeTemplateId,
      isArchived: false,
    });

    if (template === null) {
      return c.json(
        {
          error: 'Badge template not found',
        },
        404,
      );
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: 'badge_template.archived_state_changed',
      targetType: 'badge_template',
      targetId: template.id,
      metadata: {
        role: membershipRole,
        isArchived: template.isArchived,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      template,
    });
  });
};
