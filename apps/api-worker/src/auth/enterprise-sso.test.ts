import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    createAuditLog: vi.fn(),
    ensureTenantMembership: vi.fn(),
    findTenantAuthProviderById: vi.fn(),
    findTenantById: vi.fn(),
    listTenantAuthProviders: vi.fn(),
    resolveTenantAuthPolicy: vi.fn(),
  };
});

import {
  createAuditLog,
  ensureTenantMembership,
  findTenantAuthProviderById,
  findTenantById,
  listTenantAuthProviders,
  resolveTenantAuthPolicy,
  type SqlDatabase,
  type TenantAuthProviderRecord,
} from "@credtrail/db";
import { createEnterpriseSsoAdapter } from "./enterprise-sso-adapter";

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedEnsureTenantMembership = vi.mocked(ensureTenantMembership);
const mockedFindTenantAuthProviderById = vi.mocked(findTenantAuthProviderById);
const mockedFindTenantById = vi.mocked(findTenantById);
const mockedListTenantAuthProviders = vi.mocked(listTenantAuthProviders);
const mockedResolveTenantAuthPolicy = vi.mocked(resolveTenantAuthPolicy);

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

interface FakeContext {
  env: {
    APP_ENV: string;
  };
  req: {
    url: string;
    query: (name: string) => string | undefined;
  };
  json: (payload: unknown, status?: number) => Response;
}

const createContext = (input?: { url?: string; query?: Record<string, string> }): FakeContext => {
  const query = input?.query ?? {};

  return {
    env: {
      APP_ENV: "test",
    },
    req: {
      url: input?.url ?? "https://credtrail.test/login",
      query: (name: string) => query[name],
    },
    json: (payload: unknown, status?: number) => {
      return Response.json(payload, {
        status: status ?? 200,
      });
    },
  };
};

const sampleTenant = () => {
  return {
    id: "tenant_123",
    slug: "tenant-123",
    displayName: "Tenant 123",
    planTier: "enterprise" as const,
    issuerDomain: "tenant-123.credtrail.test",
    didWeb: "did:web:credtrail.test:tenant_123",
    isActive: true,
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
  };
};

const samplePolicy = (
  overrides?: Record<string, unknown>,
): {
  tenantId: string;
  loginMode: "sso_required" | "hybrid" | "local";
  breakGlassEnabled: boolean;
  localMfaRequired: boolean;
  defaultProviderId: string | null;
  enforceForRoles: "all_users" | "admins_only";
  createdAt: string;
  updatedAt: string;
} => {
  return {
    tenantId: "tenant_123",
    loginMode: "sso_required" as const,
    breakGlassEnabled: false,
    localMfaRequired: false,
    defaultProviderId: "tap_oidc",
    enforceForRoles: "all_users" as const,
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
    ...overrides,
  };
};

const sampleProvider = (
  overrides?: Partial<TenantAuthProviderRecord>,
): TenantAuthProviderRecord => {
  return {
    id: "tap_oidc",
    tenantId: "tenant_123",
    protocol: "oidc" as const,
    label: "Campus OIDC",
    enabled: true,
    isDefault: true,
    configJson:
      '{"issuer":"https://idp.example.edu","clientId":"credtrail","clientSecret":"secret","scopes":["openid","email","profile"]}',
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue({
    id: "aud_123",
    tenantId: "tenant_123",
    actorUserId: null,
    action: "auth.sso_start_requested",
    targetType: "tenant_auth_provider",
    targetId: "tap_oidc",
    metadataJson: null,
    occurredAt: "2026-03-16T12:00:00.000Z",
    createdAt: "2026-03-16T12:00:00.000Z",
  });
  mockedEnsureTenantMembership.mockReset();
  mockedEnsureTenantMembership.mockResolvedValue({
    membership: {
      tenantId: "tenant_123",
      userId: "usr_123",
      role: "viewer",
      createdAt: "2026-03-16T12:00:00.000Z",
      updatedAt: "2026-03-16T12:00:00.000Z",
    },
    created: false,
  });
  mockedFindTenantById.mockReset();
  mockedFindTenantById.mockResolvedValue(sampleTenant());
  mockedResolveTenantAuthPolicy.mockReset();
  mockedResolveTenantAuthPolicy.mockResolvedValue(samplePolicy());
  mockedListTenantAuthProviders.mockReset();
  mockedListTenantAuthProviders.mockResolvedValue([sampleProvider()]);
  mockedFindTenantAuthProviderById.mockReset();
  mockedFindTenantAuthProviderById.mockResolvedValue(sampleProvider());
});

describe("enterprise SSO adapter", () => {
  it("resolves tenant login experience with SSO auto-start for sso_required tenants", async () => {
    const adapter = createEnterpriseSsoAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: vi.fn(),
      createBetterAuthRequest: vi.fn(),
      resolveAuthenticatedPrincipal: vi.fn(),
      resolveRequestedTenantContext: vi.fn(),
      rememberRequestedTenant: vi.fn(),
    });

    const result = await adapter.resolveLoginExperience(createContext(), {
      tenantId: "tenant_123",
      nextPath: "/tenants/tenant_123/admin",
    });

    expect(result.loginMode).toBe("sso_required");
    expect(result.localLoginAllowed).toBe(false);
    expect(result.autoStartPath).toBe(
      "/v1/auth/sso/tap_oidc/start?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
    );
    expect(result.enterpriseProviders).toEqual([
      expect.objectContaining({
        id: "tap_oidc",
        label: "Campus OIDC",
        protocol: "oidc",
      }),
    ]);
  });

  it("starts tenant-aware OIDC sign-in through Better Auth and preserves redirect state cookies", async () => {
    const rememberRequestedTenant = vi.fn();
    const createBetterAuthRequest = vi.fn((_: FakeContext, path: string, init?: RequestInit) => {
      return new Request(`https://credtrail.test/api/auth${path}`, init);
    });
    const authHandler = vi.fn(async (request: Request) => {
      const payload = (await request.json()) as {
        providerId: string;
        callbackURL: string;
        errorCallbackURL: string;
      };

      expect(payload).toMatchObject({
        providerId: "tap_oidc",
      });
      expect(String(payload.callbackURL)).toContain("/auth/sso/finalize");
      expect(String(payload.errorCallbackURL)).toContain("status=error");

      return new Response(
        JSON.stringify({
          url: "https://idp.example.edu/authorize?state=oauth-state",
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            "set-cookie": "better-auth.oauth_state=state123; Path=/; HttpOnly",
          },
        },
      );
    });
    const adapter = createEnterpriseSsoAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: vi.fn(() => ({
        runtimeConfig: {
          authSystem: "better_auth" as const,
          baseURL: "https://credtrail.test",
          trustedOrigins: ["https://credtrail.test"],
          secret: "secret",
          session: {
            cookieName: "better-auth.session_token" as const,
            expiresInSeconds: 604800,
            disableRefresh: true,
          },
          database: {
            schema: "auth" as const,
            searchPath: "auth,public",
          },
        },
        auth: {
          handler: authHandler,
        },
      })),
      createBetterAuthRequest,
      resolveAuthenticatedPrincipal: vi.fn(),
      resolveRequestedTenantContext: vi.fn(),
      rememberRequestedTenant,
    });

    const response = await adapter.start(createContext(), {
      tenantId: "tenant_123",
      providerId: "tap_oidc",
      nextPath: "/tenants/tenant_123/admin",
    });

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "https://idp.example.edu/authorize?state=oauth-state",
    );
    expect(response.headers.get("set-cookie")).toContain("better-auth.oauth_state=state123");
    expect(rememberRequestedTenant).toHaveBeenCalledWith(expect.any(Object), "tenant_123");
    expect(createBetterAuthRequest).toHaveBeenCalledWith(
      expect.any(Object),
      "/sign-in/oauth2",
      expect.objectContaining({
        method: "POST",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        action: "auth.sso_start_requested",
        targetId: "tap_oidc",
      }),
    );
  });

  it("audits malformed OIDC providers when SSO start cannot proceed", async () => {
    mockedListTenantAuthProviders.mockResolvedValue([
      sampleProvider({
        configJson: '{"issuer":"https://idp.example.edu"}',
      }),
    ]);
    const createBetterAuthRuntime = vi.fn();
    const adapter = createEnterpriseSsoAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime,
      createBetterAuthRequest: vi.fn(),
      resolveAuthenticatedPrincipal: vi.fn(),
      resolveRequestedTenantContext: vi.fn(),
      rememberRequestedTenant: vi.fn(),
    });

    const response = await adapter.start(createContext(), {
      tenantId: "tenant_123",
      providerId: "tap_oidc",
      nextPath: "/tenants/tenant_123/admin",
    });

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin&reason=sso_unavailable",
    );
    expect(createBetterAuthRuntime).not.toHaveBeenCalled();
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        action: "auth.sso_start_failed",
        targetId: "tap_oidc",
        metadata: expect.objectContaining({
          reason: "invalid_provider_config",
          protocol: "oidc",
        }),
      }),
    );
  });

  it("proxies the Better Auth enterprise callback through the requested tenant context", async () => {
    const createBetterAuthRequest = vi.fn((_: FakeContext, path: string, init?: RequestInit) => {
      return new Request(`https://credtrail.test/api/auth${path}`, init);
    });
    const adapter = createEnterpriseSsoAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: vi.fn(() => ({
        runtimeConfig: {
          authSystem: "better_auth" as const,
          baseURL: "https://credtrail.test",
          trustedOrigins: ["https://credtrail.test"],
          secret: "secret",
          session: {
            cookieName: "better-auth.session_token" as const,
            expiresInSeconds: 604800,
            disableRefresh: true,
          },
          database: {
            schema: "auth" as const,
            searchPath: "auth,public",
          },
        },
        auth: {
          handler: vi.fn(() =>
            Promise.resolve(
              new Response(null, {
                status: 302,
                headers: {
                  location:
                    "https://credtrail.test/auth/sso/finalize?tenantId=tenant_123&providerId=tap_oidc&next=%2Ftenants%2Ftenant_123%2Fadmin",
                  "set-cookie": "better-auth.session_token=session123; Path=/; HttpOnly",
                },
              }),
            ),
          ),
        },
      })),
      createBetterAuthRequest,
      resolveAuthenticatedPrincipal: vi.fn(),
      resolveRequestedTenantContext: vi.fn(() =>
        Promise.resolve({
          tenantId: "tenant_123",
        }),
      ),
      rememberRequestedTenant: vi.fn(),
    });

    const response = await adapter.proxyCallback(
      createContext({
        url: "https://credtrail.test/auth/sso/callback/tap_oidc?code=abc&state=xyz",
      }),
      {
        providerId: "tap_oidc",
      },
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toContain("/auth/sso/finalize");
    expect(response.headers.get("set-cookie")).toContain("better-auth.session_token=session123");
    expect(createBetterAuthRequest).toHaveBeenCalledWith(
      expect.any(Object),
      "/oauth2/callback/tap_oidc?code=abc&state=xyz",
      expect.objectContaining({
        method: "GET",
      }),
    );
  });

  it("finalizes enterprise sign-in by remembering tenant context, ensuring membership, and logging success", async () => {
    const rememberRequestedTenant = vi.fn();
    const adapter = createEnterpriseSsoAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: vi.fn(),
      createBetterAuthRequest: vi.fn(),
      resolveAuthenticatedPrincipal: vi.fn(() =>
        Promise.resolve({
          userId: "usr_123",
          authSessionId: "ba_ses_123",
          authMethod: "better_auth" as const,
          expiresAt: "2026-03-16T20:00:00.000Z",
        }),
      ),
      resolveRequestedTenantContext: vi.fn(),
      rememberRequestedTenant,
    });

    const response = await adapter.finalize(createContext(), {
      tenantId: "tenant_123",
      providerId: "tap_oidc",
      nextPath: "/tenants/tenant_123/admin",
      status: null,
      error: null,
    });

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin");
    expect(rememberRequestedTenant).toHaveBeenCalledWith(expect.any(Object), "tenant_123");
    expect(mockedEnsureTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_123");
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        actorUserId: "usr_123",
        action: "auth.sso_sign_in_succeeded",
        targetId: "tap_oidc",
      }),
    );
  });

  it("logs enterprise sign-in failures and returns the tenant login path", async () => {
    const adapter = createEnterpriseSsoAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: vi.fn(),
      createBetterAuthRequest: vi.fn(),
      resolveAuthenticatedPrincipal: vi.fn(),
      resolveRequestedTenantContext: vi.fn(),
      rememberRequestedTenant: vi.fn(),
    });

    const response = await adapter.finalize(createContext(), {
      tenantId: "tenant_123",
      providerId: "tap_oidc",
      nextPath: "/tenants/tenant_123/admin",
      status: "error",
      error: "access_denied",
    });

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin&reason=sso_failed",
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        action: "auth.sso_sign_in_failed",
        targetId: "tap_oidc",
      }),
    );
  });
});
