import {
  createAuditLog,
  createTenantAuthProvider,
  deleteTenantAuthProvider,
  deleteTenantSsoSamlConfiguration,
  findTenantAuthProviderById,
  findTenantSsoSamlConfiguration,
  listTenantAuthProviders,
  resolveTenantAuthPolicy,
  updateTenantAuthProvider,
  upsertTenantAuthPolicy,
  HOSTED_ENTERPRISE_OIDC_ONLY_ERROR,
  isHostedEnterpriseAuthProviderSupported,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseTenantAuthProviderPathParams,
  parseTenantPathParams,
  parseUpsertTenantAuthPolicyRequest,
  parseUpsertTenantAuthProviderRequest,
  parseUpsertTenantSsoSamlConfigurationRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterTenantAuthManagementRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireEnterpriseTenant: (
    c: AppContext,
    tenantId: string,
    db: SqlDatabase,
  ) => Promise<Response | null>;
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
}

const LEGACY_SAML_DEPRECATED_ERROR =
  "Legacy SAML configuration is deprecated for hosted enterprise sign-in. Configure an OIDC provider instead.";
const LEGACY_SAML_COMPATIBILITY_NOTICE =
  "Legacy SAML compatibility remains visible for cleanup only. Configure an OIDC provider for hosted enterprise sign-in.";
const LEGACY_SAML_EDIT_BLOCKED_ERROR =
  "Legacy SAML compatibility entries are not editable from the supported enterprise auth workflow. Configure a new OIDC provider instead or delete the legacy entry.";
const LEGACY_SAML_DEFAULT_PROVIDER_ERROR =
  "Default enterprise provider must be an OIDC provider. Legacy SAML compatibility entries cannot be selected.";

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
  const compatibilityOnly = !isHostedEnterpriseAuthProviderSupported(provider);

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
    supportedInHostedRuntime: !compatibilityOnly,
    compatibilityOnly,
    ...(compatibilityOnly ? { notice: LEGACY_SAML_COMPATIBILITY_NOTICE } : {}),
  };
};

export const registerTenantAuthManagementRoutes = (
  input: RegisterTenantAuthManagementRoutesInput,
): void => {
  const { app, resolveDatabase, requireEnterpriseTenant, requireTenantRole, ADMIN_ROLES } = input;

  app.get("/v1/tenants/:tenantId/sso/saml", async (c) => {
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

    const configuration = await findTenantSsoSamlConfiguration(db, pathParams.tenantId);

    if (configuration === null) {
      return c.json(
        {
          error: "SAML SSO configuration not found",
        },
        404,
      );
    }

    return c.json({
      tenantId: pathParams.tenantId,
      deprecated: true,
      notice: LEGACY_SAML_COMPATIBILITY_NOTICE,
      configuration,
    });
  });

  app.put("/v1/tenants/:tenantId/sso/saml", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantSsoSamlConfigurationRequest>;

    try {
      request = parseUpsertTenantSsoSamlConfigurationRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid SAML SSO configuration payload",
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
    void request;
    void session;
    void membershipRole;

    return c.json(
      {
        error: LEGACY_SAML_DEPRECATED_ERROR,
      },
      410,
    );
  });

  app.delete("/v1/tenants/:tenantId/sso/saml", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
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

    const removed = await deleteTenantSsoSamlConfiguration(db, pathParams.tenantId);

    if (removed) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.sso_saml_configuration_deleted",
        targetType: "tenant_sso_saml_configuration",
        targetId: pathParams.tenantId,
        metadata: {
          role: membershipRole,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      removed,
    });
  });

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

      if (!isHostedEnterpriseAuthProviderSupported(provider)) {
        return c.json(
          {
            error: LEGACY_SAML_DEFAULT_PROVIDER_ERROR,
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

    if (request.protocol !== "oidc") {
      return c.json(
        {
          error: HOSTED_ENTERPRISE_OIDC_ONLY_ERROR,
        },
        400,
      );
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

    if (!isHostedEnterpriseAuthProviderSupported(existingProvider)) {
      return c.json(
        {
          error: LEGACY_SAML_EDIT_BLOCKED_ERROR,
        },
        400,
      );
    }

    if (request.protocol !== "oidc") {
      return c.json(
        {
          error: HOSTED_ENTERPRISE_OIDC_ONLY_ERROR,
        },
        400,
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
