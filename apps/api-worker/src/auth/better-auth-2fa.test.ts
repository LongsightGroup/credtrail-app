import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedFindTenantById,
  mockedResolveTenantAuthPolicy,
  mockedFindActiveTenantBreakGlassAccountByEmail,
  mockedMarkTenantBreakGlassAccountUsed,
  mockedMarkTenantBreakGlassEnrollmentEmailSent,
  mockedResolveAuthenticatedPrincipalFromSession,
  mockedFindBetterAuthSessionByToken,
} = vi.hoisted(() => {
  return {
    mockedFindTenantById: vi.fn(),
    mockedResolveTenantAuthPolicy: vi.fn(),
    mockedFindActiveTenantBreakGlassAccountByEmail: vi.fn(),
    mockedMarkTenantBreakGlassAccountUsed: vi.fn(),
    mockedMarkTenantBreakGlassEnrollmentEmailSent: vi.fn(),
    mockedResolveAuthenticatedPrincipalFromSession: vi.fn(),
    mockedFindBetterAuthSessionByToken: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findTenantById: mockedFindTenantById,
    resolveTenantAuthPolicy: mockedResolveTenantAuthPolicy,
    findActiveTenantBreakGlassAccountByEmail: mockedFindActiveTenantBreakGlassAccountByEmail,
    markTenantBreakGlassAccountUsed: mockedMarkTenantBreakGlassAccountUsed,
    markTenantBreakGlassEnrollmentEmailSent: mockedMarkTenantBreakGlassEnrollmentEmailSent,
  };
});

vi.mock("./better-auth-adapter", async () => {
  const actual =
    await vi.importActual<typeof import("./better-auth-adapter")>("./better-auth-adapter");

  return {
    ...actual,
    resolveAuthenticatedPrincipalFromSession: mockedResolveAuthenticatedPrincipalFromSession,
  };
});

vi.mock("./better-auth-runtime", async () => {
  const actual =
    await vi.importActual<typeof import("./better-auth-runtime")>("./better-auth-runtime");

  return {
    ...actual,
    findBetterAuthSessionByToken: mockedFindBetterAuthSessionByToken,
  };
});

import type { SqlDatabase } from "@credtrail/db";
import { createBreakGlassPolicyAdapter } from "./break-glass-policy";

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

interface FakeContext {
  env: {
    APP_ENV: string;
  };
  req: {
    url: string;
  };
  header: ReturnType<typeof vi.fn>;
}

const createContext = (): FakeContext => {
  return {
    env: {
      APP_ENV: "test",
    },
    req: {
      url: "https://credtrail.test/login/local",
    },
    header: vi.fn(),
  };
};

beforeEach(() => {
  mockedFindTenantById.mockReset();
  mockedFindTenantById.mockResolvedValue({
    id: "tenant_123",
    slug: "tenant-123",
    displayName: "Tenant 123",
    planTier: "enterprise",
    issuerDomain: "tenant-123.credtrail.test",
    didWeb: "did:web:credtrail.test:tenant_123",
    isActive: true,
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
  });
  mockedResolveTenantAuthPolicy.mockReset();
  mockedResolveTenantAuthPolicy.mockResolvedValue({
    tenantId: "tenant_123",
    loginMode: "sso_required",
    breakGlassEnabled: true,
    localMfaRequired: true,
    defaultProviderId: "tap_oidc",
    enforceForRoles: "all_users",
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
  });
  mockedFindActiveTenantBreakGlassAccountByEmail.mockReset();
  mockedFindActiveTenantBreakGlassAccountByEmail.mockResolvedValue({
    tenantId: "tenant_123",
    userId: "usr_break_glass",
    email: "admin@example.edu",
    createdByUserId: "usr_admin",
    lastUsedAt: null,
    lastEnrollmentEmailSentAt: null,
    revokedAt: null,
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
    betterAuthUserId: "ba_usr_break_glass",
    localCredentialEnabled: true,
    twoFactorEnabled: true,
  });
  mockedMarkTenantBreakGlassAccountUsed.mockReset();
  mockedMarkTenantBreakGlassAccountUsed.mockResolvedValue(undefined);
  mockedMarkTenantBreakGlassEnrollmentEmailSent.mockReset();
  mockedMarkTenantBreakGlassEnrollmentEmailSent.mockResolvedValue(undefined);
  mockedResolveAuthenticatedPrincipalFromSession.mockReset();
  mockedResolveAuthenticatedPrincipalFromSession.mockResolvedValue({
    userId: "usr_break_glass",
    authSessionId: "ba_session_123",
    authMethod: "better_auth",
    expiresAt: "2026-03-16T13:00:00.000Z",
  });
  mockedFindBetterAuthSessionByToken.mockReset();
  mockedFindBetterAuthSessionByToken.mockResolvedValue({
    sessionId: "ba_session_123",
    sessionToken: "token_123",
    userId: "ba_usr_break_glass",
    expiresAt: "2026-03-16T13:00:00.000Z",
    userEmail: "admin@example.edu",
    userEmailVerified: true,
  });
});

describe("break-glass policy adapter", () => {
  it("returns two-factor-required when Better Auth elevates the local sign-in challenge", async () => {
    const rememberRequestedTenant = vi.fn();
    const authHandler = vi.fn(async () => {
      return new Response(JSON.stringify({ twoFactorRedirect: true }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "set-cookie": "better-auth.two_factor=challenge; Path=/; HttpOnly",
        },
      });
    });
    const adapter = createBreakGlassPolicyAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: () => ({
        runtimeConfig: {
          authSystem: "better_auth",
          baseURL: "https://credtrail.test",
          trustedOrigins: ["https://credtrail.test"],
          secret: "secret",
          session: {
            cookieName: "better-auth.session_token",
            expiresInSeconds: 604800,
            disableRefresh: true,
          },
          database: {
            schema: "auth",
            searchPath: "auth,public",
          },
        },
        auth: {
          handler: authHandler,
        },
      }),
      createBetterAuthRequest: (_context, path, init) =>
        new Request(`https://credtrail.test/api/auth${path}`, init),
      resolveCurrentSession: vi.fn(),
      rememberRequestedTenant,
    });

    const result = await adapter.signIn(createContext(), {
      tenantId: "tenant_123",
      email: "admin@example.edu",
      password: "password-123",
      nextPath: "/tenants/tenant_123/admin",
    });

    expect(result).toEqual({
      status: "two_factor_required",
    });
    expect(rememberRequestedTenant).toHaveBeenCalledWith(expect.anything(), "tenant_123");
  });

  it("does not mark password-reset enrollment sent without recorded provider acceptance", async () => {
    const authHandler = vi.fn(async () => {
      return new Response(JSON.stringify({ status: true }), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      });
    });
    const adapter = createBreakGlassPolicyAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: () => ({
        runtimeConfig: {
          authSystem: "better_auth",
          baseURL: "https://credtrail.test",
          trustedOrigins: ["https://credtrail.test"],
          secret: "secret",
          session: {
            cookieName: "better-auth.session_token",
            expiresInSeconds: 604800,
            disableRefresh: true,
          },
          database: {
            schema: "auth",
            searchPath: "auth,public",
          },
        },
        auth: {
          handler: authHandler,
        },
      }),
      createBetterAuthRequest: (_context, path, init) =>
        new Request(`https://credtrail.test/api/auth${path}`, init),
      resolveCurrentSession: vi.fn(),
      rememberRequestedTenant: vi.fn(),
    });

    const result = await adapter.requestPasswordReset(createContext(), {
      tenantId: "tenant_123",
      email: "admin@example.edu",
      nextPath: "/tenants/tenant_123/admin",
    });

    expect(result).toBe("unavailable");
    expect(mockedMarkTenantBreakGlassEnrollmentEmailSent).not.toHaveBeenCalled();
  });

  it("routes signed-in local users without TOTP into setup flow", async () => {
    const authHandler = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          token: "token_123",
          user: {
            email: "admin@example.edu",
            twoFactorEnabled: false,
          },
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            "set-cookie": "better-auth.session_token=session; Path=/; HttpOnly",
          },
        },
      );
    });
    const adapter = createBreakGlassPolicyAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: () => ({
        runtimeConfig: {
          authSystem: "better_auth",
          baseURL: "https://credtrail.test",
          trustedOrigins: ["https://credtrail.test"],
          secret: "secret",
          session: {
            cookieName: "better-auth.session_token",
            expiresInSeconds: 604800,
            disableRefresh: true,
          },
          database: {
            schema: "auth",
            searchPath: "auth,public",
          },
        },
        auth: {
          handler: authHandler,
        },
      }),
      createBetterAuthRequest: (_context, path, init) =>
        new Request(`https://credtrail.test/api/auth${path}`, init),
      resolveCurrentSession: vi.fn(),
      rememberRequestedTenant: vi.fn(),
    });

    const result = await adapter.signIn(createContext(), {
      tenantId: "tenant_123",
      email: "admin@example.edu",
      password: "password-123",
      nextPath: "/tenants/tenant_123/admin",
    });

    expect(result).toEqual({
      status: "setup_required",
    });
  });

  it("verifies TOTP, resolves the principal, and records break-glass usage", async () => {
    const authHandler = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          token: "token_123",
          user: {
            email: "admin@example.edu",
          },
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            "set-cookie": "better-auth.session_token=session; Path=/; HttpOnly",
          },
        },
      );
    });
    const adapter = createBreakGlassPolicyAdapter({
      resolveDatabase: () => fakeDb,
      createBetterAuthRuntime: () => ({
        runtimeConfig: {
          authSystem: "better_auth",
          baseURL: "https://credtrail.test",
          trustedOrigins: ["https://credtrail.test"],
          secret: "secret",
          session: {
            cookieName: "better-auth.session_token",
            expiresInSeconds: 604800,
            disableRefresh: true,
          },
          database: {
            schema: "auth",
            searchPath: "auth,public",
          },
        },
        auth: {
          handler: authHandler,
        },
      }),
      createBetterAuthRequest: (_context, path, init) =>
        new Request(`https://credtrail.test/api/auth${path}`, init),
      resolveCurrentSession: vi.fn(),
      rememberRequestedTenant: vi.fn(),
    });

    const result = await adapter.verifyTwoFactor(createContext(), {
      tenantId: "tenant_123",
      code: "123456",
    });

    expect(result).toEqual({
      status: "authenticated",
      principal: {
        userId: "usr_break_glass",
        authSessionId: "ba_session_123",
        authMethod: "better_auth",
        expiresAt: "2026-03-16T13:00:00.000Z",
      },
    });
    expect(mockedMarkTenantBreakGlassAccountUsed).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_break_glass",
      usedAt: expect.any(String),
    });
  });
});
