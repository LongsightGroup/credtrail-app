import {
  createAuditLog,
  createTenantAuthProvider,
  deleteTenantAuthProvider,
  findTenantAuthProviderById,
  listTenantAuthProviders,
  resolveTenantAuthPolicy,
  updateTenantAuthProvider,
  upsertTenantAuthPolicy,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseTenantAuthProviderPathParams,
  parseTenantPathParams,
  parseUpsertTenantAuthPolicyRequest,
  parseUpsertTenantAuthProviderRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";

interface RegisterTenantAuthManagementRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireEnterpriseTenant: (
    c: AppContext,
    tenantId: string,
    db: SqlDatabase,
  ) => Promise<Response | null>;
  requireTenantRole: RequireTenantRole;
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

const serializeTenantAuthPolicy = (
  policy: Awaited<ReturnType<typeof resolveTenantAuthPolicy>>,
): Record<string, unknown> => {
  return {
    tenantId: policy.tenantId,
    loginMode: policy.loginMode,
    breakGlassEnabled: policy.breakGlassEnabled,
    localMfaRequired: policy.localMfaRequired,
    defaultProviderId: policy.defaultProviderId,
    createdAt: policy.createdAt,
    updatedAt: policy.updatedAt,
  };
};

const serializeTenantAuthProvider = (
  provider: Awaited<ReturnType<typeof listTenantAuthProviders>>[number],
): Record<string, unknown> => {
  return {
    id: provider.id,
    tenantId: provider.tenantId,
    protocol: provider.protocol,
    label: provider.label,
    enabled: provider.enabled,
    isDefault: provider.isDefault,
    configJson: provider.configJson,
    createdAt: provider.createdAt,
    updatedAt: provider.updatedAt,
  };
};

export const registerTenantAuthManagementRoutes = (
  input: RegisterTenantAuthManagementRoutesInput,
): void => {
  const { app, resolveDatabase, requireEnterpriseTenant, requireTenantRole, ADMIN_ROLES } = input;

  app.get("/v1/tenants/:tenantId/auth-policy", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const policy = await resolveTenantAuthPolicy(db, pathParams.tenantId);
    return c.json(serializeTenantAuthPolicy(policy));
  });

  app.put("/v1/tenants/:tenantId/auth-policy", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantAuthPolicyRequest>;

    try {
      request = parseUpsertTenantAuthPolicyRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant auth policy payload",
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
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    if (request.defaultProviderId !== undefined && request.defaultProviderId !== null) {
      const provider = await findTenantAuthProviderById(
        db,
        pathParams.tenantId,
        request.defaultProviderId,
      );

      if (provider === null) {
        return c.json(
          {
            error: "Default auth provider not found",
          },
          400,
        );
      }
    }

    const policy = await upsertTenantAuthPolicy(db, {
      tenantId: pathParams.tenantId,
      loginMode: request.loginMode,
      breakGlassEnabled: request.breakGlassEnabled,
      localMfaRequired: request.localMfaRequired,
      defaultProviderId: request.defaultProviderId,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_policy_upserted",
      targetType: "tenant_auth_policy",
      targetId: pathParams.tenantId,
      metadata: {
        role: membershipRole,
        loginMode: policy.loginMode,
        breakGlassEnabled: policy.breakGlassEnabled,
        localMfaRequired: policy.localMfaRequired,
        defaultProviderId: policy.defaultProviderId,
        enforceForRoles: policy.enforceForRoles,
      },
    });

    return c.json(serializeTenantAuthPolicy(policy));
  });

  app.get("/v1/tenants/:tenantId/auth-providers", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const providers = await listTenantAuthProviders(db, pathParams.tenantId);
    return c.json(providers.map(serializeTenantAuthProvider));
  });

  app.post("/v1/tenants/:tenantId/auth-providers", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantAuthProviderRequest>;

    try {
      request = parseUpsertTenantAuthProviderRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant auth provider payload",
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
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const provider = await createTenantAuthProvider(db, {
      tenantId: pathParams.tenantId,
      protocol: request.protocol,
      label: request.label,
      enabled: request.enabled,
      isDefault: request.isDefault,
      configJson: request.configJson,
    });

    if (provider.isDefault) {
      const currentPolicy = await resolveTenantAuthPolicy(db, pathParams.tenantId);
      await upsertTenantAuthPolicy(db, {
        tenantId: pathParams.tenantId,
        loginMode: currentPolicy.loginMode,
        breakGlassEnabled: currentPolicy.breakGlassEnabled,
        localMfaRequired: currentPolicy.localMfaRequired,
        defaultProviderId: provider.id,
        enforceForRoles: currentPolicy.enforceForRoles,
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_provider_created",
      targetType: "tenant_auth_provider",
      targetId: provider.id,
      metadata: {
        role: membershipRole,
        protocol: provider.protocol,
        label: provider.label,
        enabled: provider.enabled,
        isDefault: provider.isDefault,
      },
    });

    return c.json(serializeTenantAuthProvider(provider), 201);
  });

  app.put("/v1/tenants/:tenantId/auth-providers/:providerId", async (c) => {
    const pathParams = parseTenantAuthProviderPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantAuthProviderRequest>;

    try {
      request = parseUpsertTenantAuthProviderRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant auth provider payload",
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
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const existingProvider = await findTenantAuthProviderById(
      db,
      pathParams.tenantId,
      pathParams.providerId,
    );

    if (existingProvider === null) {
      return c.json(
        {
          error: "Tenant auth provider not found",
        },
        404,
      );
    }

    const provider = await updateTenantAuthProvider(db, {
      tenantId: pathParams.tenantId,
      providerId: pathParams.providerId,
      protocol: request.protocol,
      label: request.label,
      enabled: request.enabled,
      isDefault: request.isDefault,
      configJson: request.configJson,
    });

    if (provider === null) {
      return c.json(
        {
          error: "Tenant auth provider not found",
        },
        404,
      );
    }

    const currentPolicy = await resolveTenantAuthPolicy(db, pathParams.tenantId);
    await upsertTenantAuthPolicy(db, {
      tenantId: pathParams.tenantId,
      loginMode: currentPolicy.loginMode,
      breakGlassEnabled: currentPolicy.breakGlassEnabled,
      localMfaRequired: currentPolicy.localMfaRequired,
      defaultProviderId: provider.isDefault
        ? provider.id
        : currentPolicy.defaultProviderId === provider.id
          ? null
          : currentPolicy.defaultProviderId,
      enforceForRoles: currentPolicy.enforceForRoles,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_provider_updated",
      targetType: "tenant_auth_provider",
      targetId: provider.id,
      metadata: {
        role: membershipRole,
        protocol: provider.protocol,
        label: provider.label,
        enabled: provider.enabled,
        isDefault: provider.isDefault,
      },
    });

    return c.json(serializeTenantAuthProvider(provider));
  });

  app.delete("/v1/tenants/:tenantId/auth-providers/:providerId", async (c) => {
    const pathParams = parseTenantAuthProviderPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const removed = await deleteTenantAuthProvider(db, pathParams.tenantId, pathParams.providerId);

    if (removed) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.auth_provider_deleted",
        targetType: "tenant_auth_provider",
        targetId: pathParams.providerId,
        metadata: {
          role: membershipRole,
        },
      });
    }

    return c.json({ removed });
  });
};
