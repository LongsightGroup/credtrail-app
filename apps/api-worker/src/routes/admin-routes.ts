import { createDidWeb } from '@credtrail/core-domain';
import {
  createDedicatedDbProvisioningRequest,
  createAuditLog,
  deleteLtiIssuerRegistrationByIssuer,
  listAuditLogs,
  listDedicatedDbProvisioningRequests,
  listLtiIssuerRegistrations,
  resolveDedicatedDbProvisioningRequest,
  upsertBadgeTemplateById,
  upsertLtiIssuerRegistration,
  upsertTenant,
  upsertTenantMembershipRole,
  upsertTenantSigningRegistration,
  type AuditLogRecord,
  type SqlDatabase,
} from '@credtrail/db';
import type { Hono } from 'hono';
import {
  type AdminAuditLogListQuery,
  parseCreateDedicatedDbProvisioningRequest,
  parseAdminAuditLogListQuery,
  parseAdminDeleteLtiIssuerRegistrationRequest,
  parseAdminUpsertBadgeTemplateByIdRequest,
  parseAdminUpsertLtiIssuerRegistrationRequest,
  parseAdminUpsertTenantMembershipRoleRequest,
  parseAdminUpsertTenantRequest,
  parseAdminUpsertTenantSigningRegistrationRequest,
  parseResolveDedicatedDbProvisioningRequest,
  parseBadgeTemplatePathParams,
  parseTenantDedicatedDbProvisioningRequestPathParams,
  parseTenantPathParams,
  parseTenantUserPathParams,
} from '@credtrail/validation';
import type { AppBindings, AppContext, AppEnv } from '../app';
import { auditLogAdminPage, type AuditLogAdminPageFilterState } from '../admin/pages';
import { normalizeLtiIssuer } from '../lti/lti-helpers';
import {
  ltiIssuerRegistrationAdminPage,
  type LtiIssuerRegistrationFormState,
} from '../lti/pages';

interface RegisterAdminRoutesInput {
  app: Hono<AppEnv>;
  requireBootstrapAdmin: (c: AppContext) => Response | null;
  requireBootstrapAdminUiToken: (c: AppContext, token: string | null) => Response | null;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  isUniqueConstraintError: (error: unknown) => boolean;
}

export const registerAdminRoutes = (input: RegisterAdminRoutesInput): void => {
  const {
    app,
    requireBootstrapAdmin,
    requireBootstrapAdminUiToken,
    resolveDatabase,
    isUniqueConstraintError,
  } = input;

  const ltiIssuerRegistrationAdminPageResponse = async (
    c: AppContext,
    input: {
      token: string;
      submissionError?: string;
      formState?: LtiIssuerRegistrationFormState;
      status?: 200 | 400;
    },
  ): Promise<Response> => {
    const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
    const pageHtml = ltiIssuerRegistrationAdminPage({
      token: input.token,
      registrations,
      ...(input.submissionError === undefined ? {} : { submissionError: input.submissionError }),
      ...(input.formState === undefined ? {} : { formState: input.formState }),
    });
    return c.html(pageHtml, input.status ?? 200);
  };

  const auditLogAdminPageResponse = (
    c: AppContext,
    input: {
      token: string;
      filterState: AuditLogAdminPageFilterState;
      logs: readonly AuditLogRecord[];
      status?: 200 | 400;
      submissionError?: string;
    },
  ): Response => {
    const pageHtml = auditLogAdminPage({
      token: input.token,
      filterState: input.filterState,
      logs: input.logs,
      ...(input.submissionError === undefined ? {} : { submissionError: input.submissionError }),
    });
    return c.html(pageHtml, input.status ?? 200);
  };

  app.put('/v1/admin/tenants/:tenantId', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertTenantRequest(payload);
    const issuerDomain = request.issuerDomain ?? `${request.slug}.${c.env.PLATFORM_DOMAIN}`;
    const didWeb = createDidWeb({
      host: c.env.PLATFORM_DOMAIN,
      pathSegments: [pathParams.tenantId],
    });

    try {
      const tenant = await upsertTenant(resolveDatabase(c.env), {
        id: pathParams.tenantId,
        slug: request.slug,
        displayName: request.displayName,
        planTier: request.planTier ?? 'team',
        issuerDomain,
        didWeb,
        isActive: request.isActive,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        action: 'tenant.upserted',
        targetType: 'tenant',
        targetId: pathParams.tenantId,
        metadata: {
          slug: tenant.slug,
          displayName: tenant.displayName,
          planTier: tenant.planTier,
          issuerDomain: tenant.issuerDomain,
          didWeb: tenant.didWeb,
          isActive: tenant.isActive,
        },
      });

      return c.json(
        {
          tenant,
        },
        201,
      );
    } catch (error: unknown) {
      if (isUniqueConstraintError(error)) {
        return c.json(
          {
            error: 'Tenant slug or issuer domain is already in use',
          },
          409,
        );
      }

      throw error;
    }
  });

  app.put('/v1/admin/tenants/:tenantId/signing-registration', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertTenantSigningRegistrationRequest(payload);
    const did = createDidWeb({
      host: c.env.PLATFORM_DOMAIN,
      pathSegments: [pathParams.tenantId],
    });

    try {
      const registration = await upsertTenantSigningRegistration(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        did,
        keyId: request.keyId,
        publicJwkJson: JSON.stringify(request.publicJwk),
        ...(request.privateJwk === undefined
          ? {}
          : {
              privateJwkJson: JSON.stringify(request.privateJwk),
            }),
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        action: 'tenant.signing_registration_upserted',
        targetType: 'tenant_signing_registration',
        targetId: pathParams.tenantId,
        metadata: {
          did: registration.did,
          keyId: registration.keyId,
          hasPrivateKey: registration.privateJwkJson !== null,
        },
      });

      return c.json(
        {
          tenantId: registration.tenantId,
          did: registration.did,
          keyId: registration.keyId,
          hasPrivateKey: registration.privateJwkJson !== null,
        },
        201,
      );
    } catch (error: unknown) {
      if (isUniqueConstraintError(error)) {
        return c.json(
          {
            error: 'Signing registration conflicts with another tenant DID',
          },
          409,
        );
      }

      throw error;
    }
  });

  app.put('/v1/admin/tenants/:tenantId/badge-templates/:badgeTemplateId', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertBadgeTemplateByIdRequest(payload);

    try {
      const template = await upsertBadgeTemplateById(resolveDatabase(c.env), {
        id: pathParams.badgeTemplateId,
        tenantId: pathParams.tenantId,
        slug: request.slug,
        title: request.title,
        description: request.description,
        criteriaUri: request.criteriaUri,
        imageUri: request.imageUri,
        ownerOrgUnitId: request.ownerOrgUnitId,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        action: 'badge_template.upserted',
        targetType: 'badge_template',
        targetId: pathParams.badgeTemplateId,
        metadata: {
          slug: template.slug,
          title: template.title,
          description: template.description,
          criteriaUri: template.criteriaUri,
          imageUri: template.imageUri,
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
      if (isUniqueConstraintError(error)) {
        return c.json(
          {
            error: 'Badge template slug already exists for tenant',
          },
          409,
        );
      }

      if (
        error instanceof Error &&
        ((error.message.includes('Org unit') && error.message.includes('not found for tenant')) ||
          error.message.includes('ownership changes must use transferBadgeTemplateOwnership'))
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

  app.put('/v1/admin/tenants/:tenantId/users/:userId/role', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantUserPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertTenantMembershipRoleRequest(payload);
    const roleResult = await upsertTenantMembershipRole(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      role: request.role,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action:
        roleResult.previousRole === null
          ? 'membership.role_assigned'
          : roleResult.previousRole === roleResult.membership.role
            ? 'membership.role_reasserted'
            : 'membership.role_changed',
      targetType: 'membership',
      targetId: `${pathParams.tenantId}:${pathParams.userId}`,
      metadata: {
        userId: pathParams.userId,
        previousRole: roleResult.previousRole,
        role: roleResult.membership.role,
        changed: roleResult.changed,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        role: roleResult.membership.role,
        previousRole: roleResult.previousRole,
        changed: roleResult.changed,
      },
      201,
    );
  });

  app.get('/v1/admin/lti/issuer-registrations', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));

    return c.json({
      registrations,
    });
  });

  app.get('/v1/admin/audit-logs', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    let query: AdminAuditLogListQuery;

    try {
      query = parseAdminAuditLogListQuery({
        tenantId: c.req.query('tenantId'),
        action: c.req.query('action'),
        limit: c.req.query('limit'),
      });
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : 'Invalid audit log query parameters',
        },
        400,
      );
    }

    const logs = await listAuditLogs(resolveDatabase(c.env), query);

    return c.json({
      tenantId: query.tenantId,
      action: query.action ?? null,
      limit: query.limit,
      logs,
    });
  });

  app.get('/v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    const statusCandidate = c.req.query('status');
    const status =
      statusCandidate === 'pending' ||
      statusCandidate === 'provisioned' ||
      statusCandidate === 'failed' ||
      statusCandidate === 'canceled'
        ? statusCandidate
        : undefined;

    if (statusCandidate !== undefined && status === undefined) {
      return c.json(
        {
          error: 'status must be one of pending, provisioned, failed, canceled',
        },
        400,
      );
    }

    const requests = await listDedicatedDbProvisioningRequests(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ...(status === undefined ? {} : { status }),
    });

    return c.json({
      tenantId: pathParams.tenantId,
      requests,
    });
  });

  app.post('/v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseCreateDedicatedDbProvisioningRequest(await c.req.json<unknown>());
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : 'Invalid provisioning request payload',
        },
        400,
      );
    }

    const provisioningRequest = await createDedicatedDbProvisioningRequest(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      targetRegion: request.targetRegion,
      notes: request.notes,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action: 'tenant.dedicated_db_provisioning_requested',
      targetType: 'tenant_dedicated_db_provisioning_request',
      targetId: provisioningRequest.id,
      metadata: {
        targetRegion: provisioningRequest.targetRegion,
        notes: provisioningRequest.notes,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        request: provisioningRequest,
      },
      201,
    );
  });

  app.post(
    '/v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests/:requestId/resolve',
    async (c) => {
      const unauthorizedResponse = requireBootstrapAdmin(c);

      if (unauthorizedResponse !== null) {
        return unauthorizedResponse;
      }

      const pathParams = parseTenantDedicatedDbProvisioningRequestPathParams(c.req.param());
      let request;

      try {
        request = parseResolveDedicatedDbProvisioningRequest(await c.req.json<unknown>());
      } catch (error) {
        return c.json(
          {
            error: error instanceof Error ? error.message : 'Invalid provisioning resolve payload',
          },
          400,
        );
      }

      const resolved = await resolveDedicatedDbProvisioningRequest(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        requestId: pathParams.requestId,
        status: request.status,
        dedicatedDatabaseUrl: request.dedicatedDatabaseUrl,
        notes: request.notes,
        resolvedAt: request.resolvedAt,
      });

      if (resolved === null) {
        return c.json(
          {
            error: 'Provisioning request not found',
          },
          404,
        );
      }

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        action: 'tenant.dedicated_db_provisioning_resolved',
        targetType: 'tenant_dedicated_db_provisioning_request',
        targetId: resolved.id,
        metadata: {
          status: resolved.status,
          targetRegion: resolved.targetRegion,
          dedicatedDatabaseUrl: resolved.dedicatedDatabaseUrl,
          resolvedAt: resolved.resolvedAt,
          notes: resolved.notes,
        },
      });

      return c.json({
        tenantId: pathParams.tenantId,
        request: resolved,
      });
    },
  );

  app.get('/admin/audit-logs', async (c) => {
    const token = c.req.query('token') ?? null;
    const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    if (token === null) {
      return c.json(
        {
          error: 'Unauthorized',
        },
        401,
      );
    }

    const tenantId = c.req.query('tenantId');
    const action = c.req.query('action');
    const limitRaw = c.req.query('limit');
    const limitParsed = limitRaw === undefined ? undefined : Number(limitRaw);
    const filterState: AuditLogAdminPageFilterState = {
      ...(tenantId === undefined ? {} : { tenantId }),
      ...(action === undefined ? {} : { action }),
      ...(typeof limitParsed === 'number' && Number.isFinite(limitParsed)
        ? {
            limit: Math.trunc(limitParsed),
          }
        : {}),
    };
    const hasAnyFilter = tenantId !== undefined || action !== undefined || limitRaw !== undefined;

    if (!hasAnyFilter) {
      return auditLogAdminPageResponse(c, {
        token,
        filterState: {},
        logs: [],
      });
    }

    let query: AdminAuditLogListQuery;

    try {
      query = parseAdminAuditLogListQuery({
        tenantId,
        action,
        limit: limitRaw,
      });
    } catch (error) {
      return auditLogAdminPageResponse(c, {
        token,
        filterState,
        logs: [],
        status: 400,
        submissionError: error instanceof Error ? error.message : 'Invalid audit log filters',
      });
    }

    const logs = await listAuditLogs(resolveDatabase(c.env), query);

    return auditLogAdminPageResponse(c, {
      token,
      filterState,
      logs,
    });
  });

  app.put('/v1/admin/lti/issuer-registrations', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertLtiIssuerRegistrationRequest(payload);
    const registration = await upsertLtiIssuerRegistration(resolveDatabase(c.env), {
      issuer: request.issuer,
      tenantId: request.tenantId,
      authorizationEndpoint: request.authorizationEndpoint,
      clientId: request.clientId,
      allowUnsignedIdToken: request.allowUnsignedIdToken,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: registration.tenantId,
      action: 'lti.issuer_registration_upserted',
      targetType: 'lti_issuer_registration',
      targetId: registration.issuer,
      metadata: {
        issuer: registration.issuer,
        tenantId: registration.tenantId,
        clientId: registration.clientId,
        authorizationEndpoint: registration.authorizationEndpoint,
        allowUnsignedIdToken: registration.allowUnsignedIdToken,
      },
    });

    return c.json(
      {
        registration,
      },
      201,
    );
  });

  app.delete('/v1/admin/lti/issuer-registrations', async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const payload = await c.req.json<unknown>();
    const request = parseAdminDeleteLtiIssuerRegistrationRequest(payload);
    const normalizedIssuer = normalizeLtiIssuer(request.issuer);
    const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
    const existingRegistration =
      registrations.find(
        (registration) => normalizeLtiIssuer(registration.issuer) === normalizedIssuer,
      ) ?? null;
    const deleted = await deleteLtiIssuerRegistrationByIssuer(resolveDatabase(c.env), request.issuer);

    if (deleted && existingRegistration !== null) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: existingRegistration.tenantId,
        action: 'lti.issuer_registration_deleted',
        targetType: 'lti_issuer_registration',
        targetId: normalizedIssuer,
        metadata: {
          issuer: normalizedIssuer,
          tenantId: existingRegistration.tenantId,
        },
      });
    }

    return c.json({
      status: deleted ? 'deleted' : 'not_found',
      issuer: normalizedIssuer,
    });
  });

  app.get('/admin/lti/issuer-registrations', async (c) => {
    const token = c.req.query('token') ?? null;
    const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    if (token === null) {
      return c.json(
        {
          error: 'Unauthorized',
        },
        401,
      );
    }

    return ltiIssuerRegistrationAdminPageResponse(c, {
      token,
    });
  });

  app.post('/admin/lti/issuer-registrations', async (c) => {
    const contentType = c.req.header('content-type') ?? '';

    if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
      return c.json(
        {
          error: 'Content-Type must be application/x-www-form-urlencoded',
        },
        400,
      );
    }

    const rawBody = await c.req.text();
    const formData = new URLSearchParams(rawBody);
    const token = formData.get('token');
    const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    if (token === null) {
      return c.json(
        {
          error: 'Unauthorized',
        },
        401,
      );
    }

    const formState: LtiIssuerRegistrationFormState = {
      issuer: formData.get('issuer') ?? '',
      tenantId: formData.get('tenantId') ?? '',
      authorizationEndpoint: formData.get('authorizationEndpoint') ?? '',
      clientId: formData.get('clientId') ?? '',
      allowUnsignedIdToken: formData.get('allowUnsignedIdToken') !== null,
    };

    let request;

    try {
      request = parseAdminUpsertLtiIssuerRegistrationRequest({
        issuer: formState.issuer,
        tenantId: formState.tenantId,
        authorizationEndpoint: formState.authorizationEndpoint,
        clientId: formState.clientId,
        allowUnsignedIdToken: formState.allowUnsignedIdToken,
      });
    } catch (error) {
      return ltiIssuerRegistrationAdminPageResponse(c, {
        token,
        status: 400,
        submissionError: error instanceof Error ? error.message : 'Invalid LTI registration payload',
        formState,
      });
    }

    const registration = await upsertLtiIssuerRegistration(resolveDatabase(c.env), {
      issuer: request.issuer,
      tenantId: request.tenantId,
      authorizationEndpoint: request.authorizationEndpoint,
      clientId: request.clientId,
      allowUnsignedIdToken: request.allowUnsignedIdToken,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: registration.tenantId,
      action: 'lti.issuer_registration_upserted',
      targetType: 'lti_issuer_registration',
      targetId: registration.issuer,
      metadata: {
        issuer: registration.issuer,
        tenantId: registration.tenantId,
        clientId: registration.clientId,
        authorizationEndpoint: registration.authorizationEndpoint,
        allowUnsignedIdToken: registration.allowUnsignedIdToken,
      },
    });

    return c.redirect(`/admin/lti/issuer-registrations?token=${encodeURIComponent(token)}`, 303);
  });

  app.post('/admin/lti/issuer-registrations/delete', async (c) => {
    const contentType = c.req.header('content-type') ?? '';

    if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
      return c.json(
        {
          error: 'Content-Type must be application/x-www-form-urlencoded',
        },
        400,
      );
    }

    const rawBody = await c.req.text();
    const formData = new URLSearchParams(rawBody);
    const token = formData.get('token');
    const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    if (token === null) {
      return c.json(
        {
          error: 'Unauthorized',
        },
        401,
      );
    }

    const issuerCandidate = formData.get('issuer');

    if (issuerCandidate === null) {
      return ltiIssuerRegistrationAdminPageResponse(c, {
        token,
        status: 400,
        submissionError: 'issuer is required',
      });
    }

    let request;

    try {
      request = parseAdminDeleteLtiIssuerRegistrationRequest({
        issuer: issuerCandidate,
      });
    } catch (error) {
      return ltiIssuerRegistrationAdminPageResponse(c, {
        token,
        status: 400,
        submissionError: error instanceof Error ? error.message : 'Invalid issuer value',
      });
    }

    const normalizedIssuer = normalizeLtiIssuer(request.issuer);
    const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
    const existingRegistration =
      registrations.find(
        (registration) => normalizeLtiIssuer(registration.issuer) === normalizedIssuer,
      ) ?? null;
    const deleted = await deleteLtiIssuerRegistrationByIssuer(resolveDatabase(c.env), request.issuer);

    if (deleted && existingRegistration !== null) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: existingRegistration.tenantId,
        action: 'lti.issuer_registration_deleted',
        targetType: 'lti_issuer_registration',
        targetId: normalizedIssuer,
        metadata: {
          issuer: normalizedIssuer,
          tenantId: existingRegistration.tenantId,
        },
      });
    }

    return c.redirect(`/admin/lti/issuer-registrations?token=${encodeURIComponent(token)}`, 303);
  });
};
