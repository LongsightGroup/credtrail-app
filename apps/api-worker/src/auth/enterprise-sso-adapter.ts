import {
  createAuditLog,
  ensureTenantMembership,
  findTenantAuthProviderById,
  findTenantById,
  isHostedEnterpriseAuthProviderSupported,
  listTenantAuthProviders,
  resolveTenantAuthPolicy,
  type SqlDatabase,
  type TenantAuthPolicyRecord,
  type TenantAuthProviderProtocol,
  type TenantAuthProviderRecord,
} from "@credtrail/db";
import type { GenericOAuthConfig } from "better-auth/plugins/generic-oauth";
import { buildBetterAuthRouteResponse } from "./better-auth-bridge";
import type { BetterAuthRuntimeConfig } from "./better-auth-config";
import { buildLocalLoginPath } from "./break-glass-policy";
import { normalizeSafeRedirectPath } from "./redirect-paths";
import type { AuthenticatedPrincipal, RequestedTenantContext } from "./auth-context";

export interface EnterpriseSsoProviderOption {
  id: string;
  label: string;
  protocol: TenantAuthProviderProtocol;
  isDefault: boolean;
  startPath: string;
}

export interface EnterpriseLoginExperience {
  tenantId: string;
  loginMode: TenantAuthPolicyRecord["loginMode"];
  localLoginAllowed: boolean;
  explicitLocalLoginPath: string | null;
  enterpriseProviders: readonly EnterpriseSsoProviderOption[];
  autoStartPath: string | null;
  notice?: string | undefined;
}

export interface EnterpriseSsoAdapterContext<BindingsType> {
  env: BindingsType;
  req: {
    query: (name: string) => string | undefined;
    url: string;
  };
  json: (payload: unknown, status?: number) => Response;
}

interface BetterAuthRuntime {
  auth: {
    handler: (request: Request) => Promise<Response>;
  };
  runtimeConfig: BetterAuthRuntimeConfig;
}

export interface EnterpriseSsoAdapterInput<
  ContextType extends EnterpriseSsoAdapterContext<BindingsType>,
  BindingsType,
> {
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
  createBetterAuthRuntime: (
    context: ContextType,
    options?: {
      oauthProviders?: readonly GenericOAuthConfig[] | undefined;
    },
  ) => BetterAuthRuntime;
  createBetterAuthRequest: (context: ContextType, path: string, init?: RequestInit) => Request;
  resolveAuthenticatedPrincipal: (context: ContextType) => Promise<AuthenticatedPrincipal | null>;
  resolveRequestedTenantContext: (context: ContextType) => Promise<RequestedTenantContext | null>;
  rememberRequestedTenant: (context: ContextType, tenantId: string) => RequestedTenantContext;
}

export interface EnterpriseSsoAdapter<
  ContextType extends EnterpriseSsoAdapterContext<BindingsType>,
  BindingsType,
> {
  resolveLoginExperience: (
    context: ContextType,
    input: {
      tenantId: string;
      nextPath: string;
    },
  ) => Promise<EnterpriseLoginExperience>;
  enforceLocalMagicLinkRequest: (
    context: ContextType,
    input: {
      tenantId: string;
      nextPath?: string | undefined;
    },
  ) => Promise<Response | null>;
  start: (
    context: ContextType,
    input: {
      tenantId: string;
      providerId: string;
      nextPath: string;
    },
  ) => Promise<Response>;
  proxyCallback: (
    context: ContextType,
    input: {
      providerId: string;
    },
  ) => Promise<Response>;
  finalize: (
    context: ContextType,
    input: {
      tenantId: string;
      providerId: string | null;
      nextPath: string;
      status: string | null;
      error: string | null;
    },
  ) => Promise<Response>;
}

const redirectResponse = (location: string): Response => {
  return new Response(null, {
    status: 302,
    headers: {
      location,
    },
  });
};

const normalizeNextPath = (_tenantId: string, nextPath: string | undefined): string => {
  return normalizeSafeRedirectPath(nextPath, "/auth/resolve");
};

const buildTenantLoginPath = (input: {
  tenantId: string;
  nextPath?: string | undefined;
  reason?: string | undefined;
}): string => {
  const url = new URL("https://credtrail.local/login");
  url.searchParams.set("tenantId", input.tenantId);
  url.searchParams.set("next", normalizeNextPath(input.tenantId, input.nextPath));

  if (input.reason !== undefined && input.reason.trim().length > 0) {
    url.searchParams.set("reason", input.reason);
  }

  return `${url.pathname}${url.search}`;
};

const buildStartPath = (tenantId: string, providerId: string, nextPath: string): string => {
  const url = new URL(
    `/v1/auth/sso/${encodeURIComponent(providerId)}/start`,
    "https://credtrail.local",
  );
  url.searchParams.set("tenantId", tenantId);
  url.searchParams.set("next", normalizeNextPath(tenantId, nextPath));
  return `${url.pathname}${url.search}`;
};

const appendWellKnownDiscovery = (issuer: string): string => {
  const trimmedIssuer = issuer.trim().replace(/\/+$/, "");
  return `${trimmedIssuer}/.well-known/openid-configuration`;
};

const asString = (value: unknown): string | null => {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
};

const asBoolean = (value: unknown): boolean | undefined => {
  return typeof value === "boolean" ? value : undefined;
};

const asStringArray = (value: unknown): string[] | undefined => {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const output = value
    .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
    .filter((entry) => entry.length > 0);

  return output.length > 0 ? output : undefined;
};

const asStringRecord = (value: unknown): Record<string, string> | undefined => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => typeof entryValue === "string")
    .map(([entryKey, entryValue]) => [entryKey, (entryValue as string).trim()] as const)
    .filter(([, entryValue]) => entryValue.length > 0);

  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
};

const parseProviderConfigRecord = (configJson: string): Record<string, unknown> | null => {
  try {
    const parsed = JSON.parse(configJson) as unknown;

    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return null;
    }

    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
};

const toGenericOAuthConfig = (provider: TenantAuthProviderRecord): GenericOAuthConfig | null => {
  if (provider.protocol !== "oidc") {
    return null;
  }

  const parsed = parseProviderConfigRecord(provider.configJson);

  if (parsed === null) {
    return null;
  }

  const issuer = asString(parsed.issuer);
  const discoveryUrl =
    asString(parsed.discoveryUrl) ?? (issuer === null ? null : appendWellKnownDiscovery(issuer));
  const clientId = asString(parsed.clientId);
  const authorizationUrl = asString(parsed.authorizationUrl);
  const tokenUrl = asString(parsed.tokenUrl);

  if (clientId === null) {
    return null;
  }

  if (discoveryUrl === null && (authorizationUrl === null || tokenUrl === null)) {
    return null;
  }

  return {
    providerId: provider.id,
    clientId,
    ...(asString(parsed.clientSecret) === null
      ? {}
      : { clientSecret: asString(parsed.clientSecret) ?? undefined }),
    ...(discoveryUrl === null ? {} : { discoveryUrl }),
    ...(issuer === null ? {} : { issuer }),
    ...(authorizationUrl === null ? {} : { authorizationUrl }),
    ...(tokenUrl === null ? {} : { tokenUrl }),
    ...(asString(parsed.userInfoUrl) === null
      ? {}
      : { userInfoUrl: asString(parsed.userInfoUrl) ?? undefined }),
    ...(asStringArray(parsed.scopes) === undefined ? {} : { scopes: asStringArray(parsed.scopes) }),
    ...(asString(parsed.redirectURI) === null
      ? {}
      : { redirectURI: asString(parsed.redirectURI) ?? undefined }),
    ...(asString(parsed.responseType) === null
      ? {}
      : { responseType: asString(parsed.responseType) ?? undefined }),
    ...(asString(parsed.responseMode) === null
      ? {}
      : { responseMode: asString(parsed.responseMode) as "query" | "form_post" }),
    ...(asString(parsed.prompt) === null
      ? {}
      : {
          prompt: asString(parsed.prompt) as
            | "none"
            | "login"
            | "create"
            | "consent"
            | "select_account"
            | "select_account consent"
            | "login consent",
        }),
    ...(asBoolean(parsed.pkce) === undefined ? {} : { pkce: asBoolean(parsed.pkce) }),
    ...(asString(parsed.accessType) === null
      ? {}
      : { accessType: asString(parsed.accessType) ?? undefined }),
    ...(asStringRecord(parsed.authorizationUrlParams) === undefined
      ? {}
      : { authorizationUrlParams: asStringRecord(parsed.authorizationUrlParams) }),
    ...(asStringRecord(parsed.tokenUrlParams) === undefined
      ? {}
      : { tokenUrlParams: asStringRecord(parsed.tokenUrlParams) }),
    ...(asString(parsed.authentication) === null
      ? {}
      : { authentication: asString(parsed.authentication) as "basic" | "post" }),
    ...(asBoolean(parsed.requireIssuerValidation) === undefined
      ? {}
      : { requireIssuerValidation: asBoolean(parsed.requireIssuerValidation) }),
    ...(asStringRecord(parsed.discoveryHeaders) === undefined
      ? {}
      : { discoveryHeaders: asStringRecord(parsed.discoveryHeaders) }),
    ...(asStringRecord(parsed.authorizationHeaders) === undefined
      ? {}
      : { authorizationHeaders: asStringRecord(parsed.authorizationHeaders) }),
    ...(asBoolean(parsed.disableImplicitSignUp) === undefined
      ? {}
      : { disableImplicitSignUp: asBoolean(parsed.disableImplicitSignUp) }),
    ...(asBoolean(parsed.disableSignUp) === undefined
      ? {}
      : { disableSignUp: asBoolean(parsed.disableSignUp) }),
    ...(asBoolean(parsed.overrideUserInfo) === undefined
      ? {}
      : { overrideUserInfo: asBoolean(parsed.overrideUserInfo) }),
  };
};

const isRuntimeCapableEnterpriseProvider = (provider: TenantAuthProviderRecord): boolean => {
  if (!isHostedEnterpriseAuthProviderSupported(provider)) {
    return false;
  }

  return toGenericOAuthConfig(provider) !== null;
};

const resolveDefaultProvider = (
  policy: TenantAuthPolicyRecord,
  providers: readonly TenantAuthProviderRecord[],
): TenantAuthProviderRecord | null => {
  if (providers.length === 0) {
    return null;
  }

  const explicitDefault =
    policy.defaultProviderId === null
      ? null
      : (providers.find((provider) => provider.id === policy.defaultProviderId) ?? null);

  if (explicitDefault !== null) {
    return explicitDefault;
  }

  const providerMarkedDefault = providers.find((provider) => provider.isDefault) ?? null;

  if (providerMarkedDefault !== null) {
    return providerMarkedDefault;
  }

  return providers.length === 1 ? (providers[0] ?? null) : null;
};

const resolveTenantEnterpriseState = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<{
  tenant: Awaited<ReturnType<typeof findTenantById>>;
  policy: TenantAuthPolicyRecord | null;
  enabledProviders: TenantAuthProviderRecord[];
  supportedProviders: TenantAuthProviderRecord[];
  defaultProvider: TenantAuthProviderRecord | null;
}> => {
  const tenant = await findTenantById(db, tenantId);

  if (tenant?.planTier !== "enterprise") {
    return {
      tenant,
      policy: null,
      enabledProviders: [] as TenantAuthProviderRecord[],
      supportedProviders: [] as TenantAuthProviderRecord[],
      defaultProvider: null as TenantAuthProviderRecord | null,
    };
  }

  const policy = await resolveTenantAuthPolicy(db, tenantId);
  const enabledProviders = (await listTenantAuthProviders(db, tenantId)).filter(
    (provider) => provider.enabled,
  );
  const supportedProviders = enabledProviders.filter(isRuntimeCapableEnterpriseProvider);
  const defaultProvider = resolveDefaultProvider(policy, supportedProviders);

  return {
    tenant,
    policy,
    enabledProviders,
    supportedProviders,
    defaultProvider,
  };
};

const buildFinalizeUrl = (input: {
  baseURL: string;
  tenantId: string;
  providerId: string;
  nextPath: string;
  status?: string | undefined;
}): string => {
  const url = new URL("/auth/sso/finalize", input.baseURL);
  url.searchParams.set("tenantId", input.tenantId);
  url.searchParams.set("providerId", input.providerId);
  url.searchParams.set("next", normalizeNextPath(input.tenantId, input.nextPath));

  if (input.status !== undefined && input.status.trim().length > 0) {
    url.searchParams.set("status", input.status);
  }

  return url.toString();
};

export const createEnterpriseSsoAdapter = <
  ContextType extends EnterpriseSsoAdapterContext<BindingsType>,
  BindingsType,
>(
  input: EnterpriseSsoAdapterInput<ContextType, BindingsType>,
): EnterpriseSsoAdapter<ContextType, BindingsType> => {
  const resolveLoginExperience = async (
    context: ContextType,
    request: {
      tenantId: string;
      nextPath: string;
    },
  ): Promise<EnterpriseLoginExperience> => {
    const normalizedNextPath = normalizeNextPath(request.tenantId, request.nextPath);
    const state = await resolveTenantEnterpriseState(
      input.resolveDatabase(context.env),
      request.tenantId,
    );

    if (state.tenant?.planTier !== "enterprise" || state.policy === null) {
      return {
        tenantId: request.tenantId,
        loginMode: "local",
        localLoginAllowed: true,
        explicitLocalLoginPath: null,
        enterpriseProviders: [],
        autoStartPath: null,
      };
    }

    const enterpriseProviders = state.supportedProviders.map((provider) => ({
      id: provider.id,
      label: provider.label,
      protocol: provider.protocol,
      isDefault: state.defaultProvider?.id === provider.id,
      startPath: buildStartPath(request.tenantId, provider.id, normalizedNextPath),
    }));
    const autoStartPath =
      state.policy.loginMode === "sso_required" && state.defaultProvider !== null
        ? buildStartPath(request.tenantId, state.defaultProvider.id, normalizedNextPath)
        : null;

    return {
      tenantId: request.tenantId,
      loginMode: state.policy.loginMode,
      localLoginAllowed: state.policy.loginMode !== "sso_required",
      explicitLocalLoginPath:
        state.policy.loginMode === "sso_required" && state.policy.breakGlassEnabled
          ? buildLocalLoginPath({
              tenantId: request.tenantId,
              nextPath: normalizedNextPath,
            })
          : null,
      enterpriseProviders,
      autoStartPath,
      ...(state.policy.loginMode === "sso_required" && enterpriseProviders.length === 0
        ? {
            notice:
              "Institution sign-in is required for this tenant, but no supported hosted OIDC provider is currently available.",
          }
        : {}),
    };
  };

  const enforceLocalMagicLinkRequest = async (
    context: ContextType,
    request: {
      tenantId: string;
      nextPath?: string | undefined;
    },
  ): Promise<Response | null> => {
    const state = await resolveTenantEnterpriseState(
      input.resolveDatabase(context.env),
      request.tenantId,
    );

    if (state.tenant?.planTier !== "enterprise" || state.policy === null) {
      return null;
    }

    if (state.policy.loginMode !== "sso_required") {
      return null;
    }

    return context.json(
      {
        error: "Enterprise SSO is required for this tenant. Use institution sign-in instead.",
        loginPath: buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: request.nextPath,
          reason: "sso_required",
        }),
      },
      403,
    );
  };

  const start = async (
    context: ContextType,
    request: {
      tenantId: string;
      providerId: string;
      nextPath: string;
    },
  ): Promise<Response> => {
    const db = input.resolveDatabase(context.env);
    const normalizedNextPath = normalizeNextPath(request.tenantId, request.nextPath);
    const state = await resolveTenantEnterpriseState(db, request.tenantId);
    const provider =
      state.enabledProviders.find((entry) => entry.id === request.providerId) ?? null;

    if (state.tenant?.planTier !== "enterprise" || state.policy === null) {
      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
          reason: "sso_unavailable",
        }),
      );
    }

    if (state.policy.loginMode === "local") {
      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
        }),
      );
    }

    if (provider === null) {
      await createAuditLog(db, {
        tenantId: request.tenantId,
        action: "auth.sso_start_failed",
        targetType: "tenant_auth_provider",
        targetId: request.providerId,
        metadata: {
          reason: "provider_not_found_or_disabled",
          requestedProviderId: request.providerId,
        },
      });

      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
          reason: "sso_unavailable",
        }),
      );
    }

    if (!isHostedEnterpriseAuthProviderSupported(provider)) {
      await createAuditLog(db, {
        tenantId: request.tenantId,
        action: "auth.sso_start_failed",
        targetType: "tenant_auth_provider",
        targetId: provider.id,
        metadata: {
          reason: "protocol_not_supported_in_runtime",
          protocol: provider.protocol,
        },
      });

      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
          reason: "sso_unavailable",
        }),
      );
    }

    const oauthConfig = toGenericOAuthConfig(provider);

    if (oauthConfig === null) {
      await createAuditLog(db, {
        tenantId: request.tenantId,
        action: "auth.sso_start_failed",
        targetType: "tenant_auth_provider",
        targetId: provider.id,
        metadata: {
          reason: "invalid_provider_config",
          protocol: provider.protocol,
        },
      });

      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
          reason: "sso_unavailable",
        }),
      );
    }

    input.rememberRequestedTenant(context, request.tenantId);

    const { auth, runtimeConfig } = input.createBetterAuthRuntime(context, {
      oauthProviders: [oauthConfig],
    });
    const callbackURL = buildFinalizeUrl({
      baseURL: runtimeConfig.baseURL,
      tenantId: request.tenantId,
      providerId: provider.id,
      nextPath: normalizedNextPath,
    });
    const errorCallbackURL = buildFinalizeUrl({
      baseURL: runtimeConfig.baseURL,
      tenantId: request.tenantId,
      providerId: provider.id,
      nextPath: normalizedNextPath,
      status: "error",
    });
    const betterAuthResponse = await auth.handler(
      input.createBetterAuthRequest(context, "/sign-in/oauth2", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          providerId: provider.id,
          callbackURL,
          errorCallbackURL,
        }),
      }),
    );

    if (!betterAuthResponse.ok) {
      await createAuditLog(db, {
        tenantId: request.tenantId,
        action: "auth.sso_start_failed",
        targetType: "tenant_auth_provider",
        targetId: provider.id,
        metadata: {
          reason: "oauth_start_failed",
          status: betterAuthResponse.status,
        },
      });

      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
          reason: "sso_failed",
        }),
      );
    }

    const payload = await betterAuthResponse.json<{
      url?: string | undefined;
    }>();
    const authorizationUrl = payload.url?.trim();

    if (authorizationUrl === undefined || authorizationUrl.length === 0) {
      await createAuditLog(db, {
        tenantId: request.tenantId,
        action: "auth.sso_start_failed",
        targetType: "tenant_auth_provider",
        targetId: provider.id,
        metadata: {
          reason: "authorization_url_missing",
        },
      });

      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
          reason: "sso_failed",
        }),
      );
    }

    await createAuditLog(db, {
      tenantId: request.tenantId,
      action: "auth.sso_start_requested",
      targetType: "tenant_auth_provider",
      targetId: provider.id,
      metadata: {
        protocol: provider.protocol,
        nextPath: normalizedNextPath,
      },
    });

    return buildBetterAuthRouteResponse(betterAuthResponse, {
      status: 302,
      headers: {
        location: authorizationUrl,
      },
    });
  };

  const proxyCallback = async (
    context: ContextType,
    request: {
      providerId: string;
    },
  ): Promise<Response> => {
    const requestedTenant = await input.resolveRequestedTenantContext(context);

    if (requestedTenant === null) {
      return redirectResponse("/login?reason=sso_failed");
    }

    const provider = await findTenantAuthProviderById(
      input.resolveDatabase(context.env),
      requestedTenant.tenantId,
      request.providerId,
    );
    const oauthConfig =
      provider !== null && isHostedEnterpriseAuthProviderSupported(provider)
        ? toGenericOAuthConfig(provider)
        : null;

    if (provider === null || oauthConfig === null) {
      return redirectResponse(
        buildTenantLoginPath({
          tenantId: requestedTenant.tenantId,
          reason: "sso_unavailable",
        }),
      );
    }

    const { auth } = input.createBetterAuthRuntime(context, {
      oauthProviders: [oauthConfig],
    });
    const requestUrl = new URL(context.req.url);
    const betterAuthResponse = await auth.handler(
      input.createBetterAuthRequest(
        context,
        `/oauth2/callback/${encodeURIComponent(request.providerId)}${requestUrl.search}`,
        {
          method: "GET",
        },
      ),
    );
    const headers = new Headers();
    const location = betterAuthResponse.headers.get("location");

    if (location !== null) {
      headers.set("location", location);
    }

    return buildBetterAuthRouteResponse(betterAuthResponse, {
      status: betterAuthResponse.status,
      headers,
      body: betterAuthResponse.body,
    });
  };

  const finalize = async (
    context: ContextType,
    request: {
      tenantId: string;
      providerId: string | null;
      nextPath: string;
      status: string | null;
      error: string | null;
    },
  ): Promise<Response> => {
    const db = input.resolveDatabase(context.env);
    const normalizedNextPath = normalizeNextPath(request.tenantId, request.nextPath);

    if (request.status === "error" || (request.error !== null && request.error.trim().length > 0)) {
      await createAuditLog(db, {
        tenantId: request.tenantId,
        action: "auth.sso_sign_in_failed",
        targetType: "tenant_auth_provider",
        targetId: request.providerId ?? "unknown",
        metadata: {
          error: request.error ?? "sso_callback_failed",
          nextPath: normalizedNextPath,
        },
      });

      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
          reason: "sso_failed",
        }),
      );
    }

    input.rememberRequestedTenant(context, request.tenantId);

    const principal = await input.resolveAuthenticatedPrincipal(context);

    if (principal === null) {
      await createAuditLog(db, {
        tenantId: request.tenantId,
        action: "auth.sso_sign_in_failed",
        targetType: "tenant_auth_provider",
        targetId: request.providerId ?? "unknown",
        metadata: {
          error: "principal_not_resolved",
          nextPath: normalizedNextPath,
        },
      });

      return redirectResponse(
        buildTenantLoginPath({
          tenantId: request.tenantId,
          nextPath: normalizedNextPath,
          reason: "sso_failed",
        }),
      );
    }

    const membershipResult = await ensureTenantMembership(db, request.tenantId, principal.userId);

    if (membershipResult.created) {
      await createAuditLog(db, {
        tenantId: request.tenantId,
        actorUserId: principal.userId,
        action: "membership.role_assigned",
        targetType: "membership",
        targetId: `${request.tenantId}:${principal.userId}`,
        metadata: {
          userId: principal.userId,
          role: membershipResult.membership.role,
          source: "enterprise_sso",
        },
      });
    }

    await createAuditLog(db, {
      tenantId: request.tenantId,
      actorUserId: principal.userId,
      action: "auth.sso_sign_in_succeeded",
      targetType: "tenant_auth_provider",
      targetId: request.providerId ?? "unknown",
      metadata: {
        authMethod: principal.authMethod,
        nextPath: normalizedNextPath,
      },
    });

    return redirectResponse(normalizedNextPath);
  };

  return {
    resolveLoginExperience,
    enforceLocalMagicLinkRequest,
    start,
    proxyCallback,
    finalize,
  };
};
