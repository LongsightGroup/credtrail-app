import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deleteCookie, setCookie } from "hono/cookie";

const {
  mockedResolveEnterpriseLoginExperience,
  mockedEnforceLocalMagicLinkRequest,
  mockedStartEnterpriseSso,
  mockedProxyEnterpriseSsoCallback,
  mockedFinalizeEnterpriseSso,
  mockedBreakGlassRequestPasswordReset,
  mockedBreakGlassSignIn,
  mockedBreakGlassEnrollTwoFactor,
  mockedBreakGlassVerifyTwoFactor,
  mockedBreakGlassResetPassword,
  mockedListAccessibleTenantContextsForUserFn,
  mockedCreateLocalDevelopmentSessionForCredtrailUser,
} = vi.hoisted(() => {
  return {
    mockedResolveEnterpriseLoginExperience: vi.fn(),
    mockedEnforceLocalMagicLinkRequest: vi.fn(),
    mockedStartEnterpriseSso: vi.fn(),
    mockedProxyEnterpriseSsoCallback: vi.fn(),
    mockedFinalizeEnterpriseSso: vi.fn(),
    mockedBreakGlassRequestPasswordReset: vi.fn(),
    mockedBreakGlassSignIn: vi.fn(),
    mockedBreakGlassEnrollTwoFactor: vi.fn(),
    mockedBreakGlassVerifyTwoFactor: vi.fn(),
    mockedBreakGlassResetPassword: vi.fn(),
    mockedListAccessibleTenantContextsForUserFn: vi.fn(),
    mockedCreateLocalDevelopmentSessionForCredtrailUser: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    countAuthMagicLinkRateLimitAttempts: vi.fn(),
    findTenantMembership: vi.fn(),
    findUserByEmail: vi.fn(),
    listAccessibleTenantContextsForUser: mockedListAccessibleTenantContextsForUserFn,
    pruneAuthMagicLinkRateLimitAttempts: vi.fn(),
    recordAuthMagicLinkRateLimitAttempt: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./auth/enterprise-sso-adapter", () => {
  return {
    createEnterpriseSsoAdapter: vi.fn(() => ({
      resolveLoginExperience: mockedResolveEnterpriseLoginExperience,
      enforceLocalMagicLinkRequest: mockedEnforceLocalMagicLinkRequest,
      start: mockedStartEnterpriseSso,
      proxyCallback: mockedProxyEnterpriseSsoCallback,
      finalize: mockedFinalizeEnterpriseSso,
    })),
  };
});

vi.mock("./auth/break-glass-policy", async () => {
  const actual = await vi.importActual<typeof import("./auth/break-glass-policy")>(
    "./auth/break-glass-policy",
  );

  return {
    ...actual,
    createBreakGlassPolicyAdapter: vi.fn(() => ({
      requestPasswordReset: mockedBreakGlassRequestPasswordReset,
      signIn: mockedBreakGlassSignIn,
      enrollTwoFactor: mockedBreakGlassEnrollTwoFactor,
      verifyTwoFactor: mockedBreakGlassVerifyTwoFactor,
      resetPassword: mockedBreakGlassResetPassword,
    })),
  };
});

import {
  countAuthMagicLinkRateLimitAttempts,
  findTenantMembership,
  findUserByEmail,
  listAccessibleTenantContextsForUser,
  pruneAuthMagicLinkRateLimitAttempts,
  recordAuthMagicLinkRateLimitAttempt,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import type { TurnstileVerifier, VerifyTurnstileTokenInput } from "./auth/turnstile";

const mockedCountAuthMagicLinkRateLimitAttempts = vi.mocked(countAuthMagicLinkRateLimitAttempts);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindUserByEmail = vi.mocked(findUserByEmail);
const mockedListAccessibleTenantContextsForUser = vi.mocked(listAccessibleTenantContextsForUser);
const mockedPruneAuthMagicLinkRateLimitAttempts = vi.mocked(pruneAuthMagicLinkRateLimitAttempts);
const mockedRecordAuthMagicLinkRateLimitAttempt = vi.mocked(recordAuthMagicLinkRateLimitAttempt);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (
  appEnv: string,
  overrides?: Partial<{
    BADGE_OBJECTS: R2Bucket;
  }>,
): {
  APP_ENV: string;
  DATABASE_URL: string;
  HYPERDRIVE?: Hyperdrive;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  GOOGLE_OAUTH_CLIENT_ID?: string;
  GOOGLE_OAUTH_CLIENT_SECRET?: string;
} => {
  return {
    APP_ENV: appEnv,
    DATABASE_URL: "postgres://credtrail-test.local/db",
    ...(appEnv === "production"
      ? { HYPERDRIVE: { connectionString: "postgres://hyperdrive-test.local/db" } as Hyperdrive }
      : {}),
    BADGE_OBJECTS: overrides?.BADGE_OBJECTS ?? ({} as R2Bucket),
    PLATFORM_DOMAIN: "localhost",
    PUBLIC_APP_ORIGIN: "http://localhost",
  };
};

interface MockedInternalAuthProvider {
  requestMagicLink: ReturnType<typeof vi.fn>;
  createMagicLinkSession: ReturnType<typeof vi.fn>;
  createLtiSession: ReturnType<typeof vi.fn>;
  resolveAuthenticatedPrincipal: ReturnType<typeof vi.fn>;
  resolveRequestedTenantContext: ReturnType<typeof vi.fn>;
  revokeCurrentSession: ReturnType<typeof vi.fn>;
}

const loadAppWithMockedHostedAuthProviders = async (options?: {
  requestMagicLinkResult?: {
    tenantId: string;
    email: string;
    deliveryStatus: "sent" | "skipped" | "failed";
    expiresAt?: string | undefined;
    debugMagicLinkToken?: string | undefined;
    debugMagicLinkUrl?: string | undefined;
  };
  betterAuthInitiallyAuthenticated?: boolean;
  betterAuthPrincipal?: {
    userId: string;
    authSessionId: string;
    authMethod: "better_auth";
    expiresAt: string;
  };
  betterAuthRequestedTenant?: {
    tenantId: string;
  } | null;
}): Promise<{
  app: typeof app;
  betterAuthProvider: MockedInternalAuthProvider;
}> => {
  vi.resetModules();

  const betterAuthPrincipal = options?.betterAuthPrincipal ?? {
    userId: "usr_better",
    authSessionId: "ba_ses_123",
    authMethod: "better_auth" as const,
    expiresAt: "2026-02-18T22:00:00.000Z",
  };
  const betterAuthRequestedTenant =
    options?.betterAuthRequestedTenant === undefined
      ? {
          tenantId: "tenant_123",
        }
      : options.betterAuthRequestedTenant;
  let betterAuthAuthenticated = options?.betterAuthInitiallyAuthenticated ?? false;

  const betterAuthProvider: MockedInternalAuthProvider = {
    requestMagicLink: vi.fn(() =>
      Promise.resolve(
        options?.requestMagicLinkResult ?? {
          tenantId: "tenant_123",
          email: "learner@example.edu",
          deliveryStatus: "sent" as const,
          expiresAt: "2026-02-18T12:10:00.000Z",
          debugMagicLinkToken: "better-token-1234567890",
          debugMagicLinkUrl:
            "http://localhost/auth/magic-link/verify?token=better-token-1234567890&next=%2Fauth%2Fresolve",
        },
      ),
    ),
    createMagicLinkSession: vi.fn((context: Parameters<typeof setCookie>[0]) => {
      betterAuthAuthenticated = true;
      setCookie(context, "better-auth.session_token", "better-session", {
        httpOnly: true,
        sameSite: "Lax",
        path: "/",
      });
      return Promise.resolve(betterAuthPrincipal);
    }),
    createLtiSession: vi.fn(),
    resolveAuthenticatedPrincipal: vi.fn(() =>
      Promise.resolve(betterAuthAuthenticated ? betterAuthPrincipal : null),
    ),
    resolveRequestedTenantContext: vi.fn(() =>
      Promise.resolve(betterAuthAuthenticated ? betterAuthRequestedTenant : null),
    ),
    revokeCurrentSession: vi.fn((context: Parameters<typeof deleteCookie>[0]) => {
      betterAuthAuthenticated = false;
      deleteCookie(context, "better-auth.session_token", {
        path: "/",
      });
      return Promise.resolve();
    }),
  };

  vi.doMock("./auth/better-auth-adapter", async () => {
    const actual = await vi.importActual<typeof import("./auth/better-auth-adapter")>(
      "./auth/better-auth-adapter",
    );

    return {
      ...actual,
      createBetterAuthProvider: vi.fn(() => betterAuthProvider),
    };
  });

  vi.doMock("./app/auth-runtime", async () => {
    const actual = await vi.importActual<typeof import("./app/auth-runtime")>("./app/auth-runtime");

    return {
      ...actual,
      createLocalDevelopmentSessionForCredtrailUser:
        mockedCreateLocalDevelopmentSessionForCredtrailUser,
    };
  });

  const { app: isolatedApp } = await import("./index");

  return {
    app: isolatedApp,
    betterAuthProvider,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedCountAuthMagicLinkRateLimitAttempts.mockReset();
  mockedCountAuthMagicLinkRateLimitAttempts.mockResolvedValue(0);
  mockedFindUserByEmail.mockReset();
  mockedFindUserByEmail.mockResolvedValue({
    id: "usr_123",
    email: "learner@example.edu",
  });
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue({
    tenantId: "tenant_123",
    userId: "usr_123",
    role: "viewer",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedPruneAuthMagicLinkRateLimitAttempts.mockReset();
  mockedPruneAuthMagicLinkRateLimitAttempts.mockResolvedValue();
  mockedRecordAuthMagicLinkRateLimitAttempt.mockReset();
  mockedRecordAuthMagicLinkRateLimitAttempt.mockResolvedValue();
  mockedListAccessibleTenantContextsForUser.mockReset();
  mockedListAccessibleTenantContextsForUser.mockResolvedValue([
    {
      tenantId: "tenant_123",
      tenantSlug: "tenant-123",
      tenantDisplayName: "Tenant 123",
      tenantPlanTier: "team",
      membershipRole: "viewer",
    },
  ]);
  mockedBreakGlassRequestPasswordReset.mockReset();
  mockedBreakGlassRequestPasswordReset.mockResolvedValue("sent");
  mockedBreakGlassSignIn.mockReset();
  mockedBreakGlassSignIn.mockResolvedValue({
    status: "rejected",
    reason: "break_glass_invalid_credentials",
  });
  mockedBreakGlassEnrollTwoFactor.mockReset();
  mockedBreakGlassEnrollTwoFactor.mockResolvedValue({
    status: "rejected",
    reason: "break_glass_enrollment_failed",
  });
  mockedBreakGlassVerifyTwoFactor.mockReset();
  mockedBreakGlassVerifyTwoFactor.mockResolvedValue({
    status: "rejected",
    reason: "break_glass_invalid_code",
  });
  mockedBreakGlassResetPassword.mockReset();
  mockedBreakGlassResetPassword.mockResolvedValue("rejected");
  mockedResolveEnterpriseLoginExperience.mockReset();
  mockedResolveEnterpriseLoginExperience.mockResolvedValue({
    tenantId: "tenant_123",
    loginMode: "local",
    localLoginAllowed: true,
    enterpriseProviders: [],
    autoStartPath: null,
  });
  mockedEnforceLocalMagicLinkRequest.mockReset();
  mockedEnforceLocalMagicLinkRequest.mockResolvedValue(null);
  mockedStartEnterpriseSso.mockReset();
  mockedStartEnterpriseSso.mockResolvedValue(
    new Response(null, {
      status: 302,
      headers: {
        location: "/login?reason=sso_unavailable",
      },
    }),
  );
  mockedProxyEnterpriseSsoCallback.mockReset();
  mockedProxyEnterpriseSsoCallback.mockResolvedValue(
    new Response(null, {
      status: 302,
      headers: {
        location: "/login?reason=sso_failed",
      },
    }),
  );
  mockedFinalizeEnterpriseSso.mockReset();
  mockedFinalizeEnterpriseSso.mockResolvedValue(
    new Response(null, {
      status: 302,
      headers: {
        location: "/login?reason=sso_failed",
      },
    }),
  );
  mockedCreateLocalDevelopmentSessionForCredtrailUser.mockReset();
  mockedCreateLocalDevelopmentSessionForCredtrailUser.mockImplementation(
    (context: Parameters<typeof setCookie>[0]) => {
      setCookie(context, "better-auth.session_token", "better-session", {
        httpOnly: true,
        sameSite: "Lax",
        path: "/",
      });

      return Promise.resolve({
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-02-18T22:00:00.000Z",
      });
    },
  );
});

afterEach(() => {
  vi.doUnmock("./auth/better-auth-adapter");
  vi.doUnmock("./app/auth-runtime");
  vi.restoreAllMocks();
});

describe("magic-link auth routes", () => {
  it("renders login page with magic-link form and linked page assets", async () => {
    const env = createEnv("production");
    const response = await app.request(
      "/login?tenantId=sakai&next=%2Ftenants%2Fsakai%2Fadmin",
      undefined,
      env,
    );
    const body = await response.text();
    const stylesheetMatch =
      /<link rel="stylesheet" href="([^"]*\/assets\/ui\/auth-login\.[^"]+\.css)"/.exec(body);
    const scriptMatch =
      /<script[^>]*src="([^"]*\/assets\/ui\/auth-login\.[^"]+\.js)"[^>]*><\/script>/.exec(body);
    const stylesheetPath = stylesheetMatch?.[1] ?? null;
    const scriptPath = scriptMatch?.[1] ?? null;

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(body).toContain("Sign in with your institution email");
    expect(body).toContain("Email sign-in");
    expect(body).toContain("Sign-in links expire in 10 minutes.");
    expect(body).toContain('id="magic-link-login-form"');
    expect(body).toContain('name="tenantId"');
    expect(body).toContain('value="sakai"');
    expect(body).not.toContain("Tenant ID");
    expect(body).toContain("ct-login__context");
    expect(body).toContain("/assets/ui/foundation.");
    expect(body).not.toContain(".ct-login__hero {");
    expect(stylesheetPath).not.toBeNull();
    expect(scriptPath).not.toBeNull();

    expect(stylesheetPath).toMatch(/^\/assets\/ui\/auth-login\.[a-f0-9]{10}\.css$/);
    expect(scriptPath).toMatch(/^\/assets\/ui\/auth-login\.[a-f0-9]{10}\.js$/);
  });

  it("renders email-first login without a visible tenant field", async () => {
    const response = await app.request("/login", undefined, createEnv("production"));
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Sign in with your institution email");
    expect(body).toContain('id="magic-link-login-tenant"');
    expect(body).toContain('type="hidden"');
    expect(body).not.toContain("Tenant ID");
    expect(body).not.toContain('placeholder="sakai"');
  });

  it("renders Google sign-in when OAuth credentials are configured", async () => {
    const env = {
      ...createEnv("production"),
      GOOGLE_OAUTH_CLIENT_ID: "google-client-id",
      GOOGLE_OAUTH_CLIENT_SECRET: "google-client-secret",
    };
    const response = await app.request("/login", undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Continue with Google");
    expect(body).toContain("/auth/google/start");
    expect(body).toContain("ct-login__google-mark");
    expect(body).toContain("ct-login__submit--google");
  });

  it("redirects sso_required tenant login pages into the default enterprise provider flow", async () => {
    mockedResolveEnterpriseLoginExperience.mockResolvedValue({
      tenantId: "tenant_123",
      loginMode: "sso_required",
      localLoginAllowed: false,
      enterpriseProviders: [
        {
          id: "tap_oidc",
          label: "Campus OIDC",
          protocol: "oidc",
          isDefault: true,
          startPath:
            "/v1/auth/sso/tap_oidc/start?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
        },
      ],
      autoStartPath:
        "/v1/auth/sso/tap_oidc/start?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
    });

    const response = await app.request(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
      undefined,
      createEnv("production"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/v1/auth/sso/tap_oidc/start?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
    );
  });

  it("renders a truthful notice instead of auto-starting when no supported hosted enterprise provider is available", async () => {
    mockedResolveEnterpriseLoginExperience.mockResolvedValue({
      tenantId: "tenant_123",
      loginMode: "sso_required",
      localLoginAllowed: false,
      enterpriseProviders: [],
      autoStartPath: null,
      notice:
        "Institution sign-in is required for this tenant, but no supported hosted OIDC provider is currently available.",
    });

    const response = await app.request(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
      undefined,
      createEnv("production"),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("no supported hosted OIDC provider is currently available");
    expect(body).not.toContain("Continue with Campus OIDC");
  });

  it("renders a truthful hosted enterprise unavailability notice after an unsupported SSO start redirect", async () => {
    const response = await app.request(
      "/login?tenantId=tenant_123&reason=sso_unavailable",
      undefined,
      createEnv("production"),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(
      "Hosted institution sign-in is not available for this tenant right now.",
    );
  });

  it("renders hybrid tenant login pages with both local and enterprise options", async () => {
    mockedResolveEnterpriseLoginExperience.mockResolvedValue({
      tenantId: "tenant_123",
      loginMode: "hybrid",
      localLoginAllowed: true,
      explicitLocalLoginPath: null,
      enterpriseProviders: [
        {
          id: "tap_oidc",
          label: "Campus OIDC",
          protocol: "oidc",
          isDefault: true,
          startPath:
            "/v1/auth/sso/tap_oidc/start?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
        },
      ],
      autoStartPath: null,
    });

    const response = await app.request(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
      undefined,
      createEnv("production"),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Institution sign-in");
    expect(body).toContain("Continue with Campus OIDC");
    expect(body).not.toContain("OIDC or SAML");
    expect(body).toContain('id="magic-link-login-form"');
  });

  it("renders explicit break-glass local sign-in link when SSO-required tenant enables fallback accounts", async () => {
    mockedResolveEnterpriseLoginExperience.mockResolvedValue({
      tenantId: "tenant_123",
      loginMode: "sso_required",
      localLoginAllowed: false,
      explicitLocalLoginPath:
        "/login/local?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
      enterpriseProviders: [
        {
          id: "tap_oidc",
          label: "Campus OIDC",
          protocol: "oidc",
          isDefault: false,
          startPath:
            "/v1/auth/sso/tap_oidc/start?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
        },
      ],
      autoStartPath: null,
    });

    const response = await app.request(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
      undefined,
      createEnv("production"),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("break-glass local sign-in");
    expect(body).toContain(
      "/login/local?tenantId=tenant_123&amp;next=%2Ftenants%2Ftenant_123%2Fadmin",
    );
  });

  it("renders explicit break-glass local login page", async () => {
    const response = await app.request(
      "/login/local?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
      undefined,
      createEnv("production"),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Break-glass local sign-in");
    expect(body).toContain('action="/auth/local/sign-in"');
    expect(body).toContain('action="/auth/local/reset-password/request"');
  });

  it("redirects local break-glass sign-in into MFA setup when Better Auth account exists without TOTP", async () => {
    mockedBreakGlassSignIn.mockResolvedValue({
      status: "setup_required",
    });

    const response = await app.request(
      "/auth/local/sign-in",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          tenantId: "tenant_123",
          next: "/tenants/tenant_123/admin",
          email: "admin@example.edu",
          password: "test-password",
        }).toString(),
      },
      createEnv("production"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/auth/local/two-factor/setup?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin",
    );
    expect(response.headers.get("set-cookie")).toContain("credtrail_break_glass_pending_mfa=");
  });

  it("redirects local break-glass verification into the requested tenant path on success", async () => {
    mockedBreakGlassVerifyTwoFactor.mockResolvedValue({
      status: "authenticated",
      principal: {
        userId: "usr_break_glass",
        authSessionId: "ba_session_123",
        authMethod: "better_auth",
        expiresAt: "2026-03-17T01:00:00.000Z",
      },
    });

    const response = await app.request(
      "/auth/local/two-factor/verify",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          tenantId: "tenant_123",
          next: "/tenants/tenant_123/admin",
          code: "123456",
        }).toString(),
      },
      createEnv("production"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin");
  });

  it("returns token + url in development mode for magic-link request", async () => {
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          email: "learner@example.edu",
          preferredLocale: "en-US",
          preferredTimeZone: "America/New_York",
        }),
      },
      createEnv("development"),
    );
    const body = await response.json<{
      status: string;
      deliveryStatus: string;
      magicLinkToken: string;
      magicLinkUrl: string;
    }>();

    expect(response.status).toBe(202);
    expect(body.status).toBe("sent");
    expect(typeof body.magicLinkToken).toBe("string");
    expect(body.magicLinkToken.length).toBeGreaterThan(0);
    expect(body.magicLinkUrl).toContain("/auth/magic-link/verify?token=");
    expect(body.magicLinkUrl).toContain("next=");
  });

  it("logs in a seeded local user through a development-only API without rate limiting", async () => {
    mockedCountAuthMagicLinkRateLimitAttempts.mockResolvedValue(3);
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/dev/auth/login-as?tenantId=tenant_123&email=learner%40example.edu&next=%2Ftenants%2Ftenant_123%2Fadmin",
      {
        method: "GET",
      },
      createEnv("development"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin");
    expect(response.headers.get("set-cookie")).toContain("better-auth.session_token=");
    expect(mockedPruneAuthMagicLinkRateLimitAttempts).not.toHaveBeenCalled();
    expect(mockedCountAuthMagicLinkRateLimitAttempts).not.toHaveBeenCalled();
    expect(mockedRecordAuthMagicLinkRateLimitAttempt).not.toHaveBeenCalled();
    expect(mockedCreateLocalDevelopmentSessionForCredtrailUser).toHaveBeenCalledWith(
      expect.anything(),
      {
        tenantId: "tenant_123",
        userId: "usr_123",
      },
    );
    expect(betterAuthProvider.requestMagicLink).not.toHaveBeenCalled();
  });

  it("does not redirect local development login-as to protocol-relative next paths", async () => {
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/dev/auth/login-as?tenantId=tenant_123&email=learner%40example.edu&next=%2F%2Fevil.example%2Fpath",
      {
        method: "GET",
      },
      createEnv("development"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin");
  });

  it("seeds the trusted demo credential through the development-only R2 binding route", async () => {
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders();
    const put = vi.fn<R2Bucket["put"]>(async () => ({ key: "seeded" }) as R2Object);

    const response = await isolatedApp.request(
      "/v1/dev/storage/seed-trusted-demo-credential",
      {
        method: "POST",
      },
      createEnv("development", {
        BADGE_OBJECTS: {
          put,
        } as unknown as R2Bucket,
      }),
    );
    const body = await response.json<{
      status: string;
      key: string;
    }>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("seeded");
    expect(body.key).toBe(
      "tenants/tenant_123/assertions/tenant_123%3Aassertion_trusted_demo.jsonld",
    );
    expect(put).toHaveBeenCalledWith(
      body.key,
      expect.stringContaining("Applied Analytics TrustEd Credential"),
      {
        httpMetadata: {
          contentType: "application/ld+json",
          cacheControl: "public, max-age=31536000, immutable",
        },
      },
    );
  });

  it("does not expose the local CLI login-as API outside development", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/dev/auth/login-as?tenantId=tenant_123&email=learner%40example.edu",
      {
        method: "GET",
      },
      createEnv("production"),
    );

    expect(response.status).toBe(404);
    expect(mockedFindUserByEmail).not.toHaveBeenCalled();
    expect(betterAuthProvider.requestMagicLink).not.toHaveBeenCalled();
  });

  it("does not expose the local trusted demo storage seed route outside development", async () => {
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders();
    const put = vi.fn<R2Bucket["put"]>(async () => ({ key: "seeded" }) as R2Object);

    const response = await isolatedApp.request(
      "/v1/dev/storage/seed-trusted-demo-credential",
      {
        method: "POST",
      },
      createEnv("production", {
        BADGE_OBJECTS: {
          put,
        } as unknown as R2Bucket,
      }),
    );

    expect(response.status).toBe(404);
    expect(put).not.toHaveBeenCalled();
  });

  it("rejects local hosted magic-link requests when enterprise SSO is required", async () => {
    mockedEnforceLocalMagicLinkRequest.mockResolvedValue(
      Response.json(
        {
          error: "Enterprise SSO is required for this tenant. Use institution sign-in instead.",
        },
        {
          status: 403,
        },
      ),
    );

    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();
    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          email: "learner@example.edu",
          preferredLocale: "en-US",
          preferredTimeZone: "America/New_York",
        }),
      },
      createEnv("production"),
    );
    const body = await response.json<{
      error: string;
    }>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("Enterprise SSO is required");
    expect(mockedFindUserByEmail).not.toHaveBeenCalled();
    expect(betterAuthProvider.requestMagicLink).not.toHaveBeenCalled();
  });

  it("delegates hosted magic-link requests to Better Auth for existing tenant members", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const requestBody = {
      tenantId: "tenant_123",
      email: "learner@example.edu",
      preferredLocale: "en-US",
      preferredTimeZone: "America/New_York",
    };
    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(requestBody),
      },
      createEnv("development"),
    );
    const body = await response.json<{
      status: string;
      deliveryStatus: string;
      tenantId: string;
      email: string;
      expiresAt: string;
      magicLinkToken: string;
      magicLinkUrl: string;
    }>();

    expect(response.status).toBe(202);
    expect(body).toEqual({
      status: "sent",
      deliveryStatus: "sent",
      tenantId: "tenant_123",
      email: "learner@example.edu",
      expiresAt: "2026-02-18T12:10:00.000Z",
      magicLinkToken: "better-token-1234567890",
      magicLinkUrl:
        "http://localhost/auth/magic-link/verify?token=better-token-1234567890&next=%2Fauth%2Fresolve",
    });
    expect(mockedFindUserByEmail).toHaveBeenCalledWith(fakeDb, "learner@example.edu");
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_123");
    expect(betterAuthProvider.requestMagicLink).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        tenantId: "tenant_123",
        email: "learner@example.edu",
        preferredLocale: "en-US",
        preferredTimeZone: "America/New_York",
      }),
    );
  });

  it("infers the organization for email-only magic-link requests when the user has one membership", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: "learner@example.edu",
          nextPath: "/auth/resolve",
        }),
      },
      createEnv("development"),
    );
    const body = await response.json<{
      status: string;
      tenantId: string;
      email: string;
    }>();

    expect(response.status).toBe(202);
    expect(body.status).toBe("sent");
    expect(body.tenantId).toBe("tenant_123");
    expect(body.email).toBe("learner@example.edu");
    expect(mockedFindTenantMembership).not.toHaveBeenCalled();
    expect(mockedListAccessibleTenantContextsForUser).toHaveBeenCalledWith(fakeDb, "usr_123");
    expect(betterAuthProvider.requestMagicLink).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        tenantId: "tenant_123",
        email: "learner@example.edu",
        nextPath: "/auth/resolve",
      }),
    );
  });

  it("sends an unscoped link without exposing organizations when multiple memberships exist", async () => {
    mockedListAccessibleTenantContextsForUser.mockResolvedValue([
      {
        tenantId: "tenant_123",
        tenantSlug: "tenant-123",
        tenantDisplayName: "Tenant 123",
        tenantPlanTier: "team",
        membershipRole: "viewer",
      },
      {
        tenantId: "tenant_456",
        tenantSlug: "tenant-456",
        tenantDisplayName: "Tenant 456",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
    ]);
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: "learner@example.edu",
        }),
      },
      createEnv("production"),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body).toEqual({
      status: "sent",
      deliveryStatus: "sent",
      email: "learner@example.edu",
    });
    expect(body).not.toHaveProperty("organizations");
    expect(body).not.toHaveProperty("tenantId");
    expect(betterAuthProvider.requestMagicLink).toHaveBeenCalledWith(expect.anything(), {
      email: "learner@example.edu",
    });
  });

  it("keeps email-only SSO membership policy out of the response", async () => {
    mockedEnforceLocalMagicLinkRequest.mockResolvedValue(
      Response.json({ error: "Enterprise SSO is required" }, { status: 403 }),
    );
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "learner@example.edu" }),
      },
      createEnv("production"),
    );

    await expect(response.json()).resolves.toEqual({
      status: "sent",
      deliveryStatus: "sent",
      email: "learner@example.edu",
    });
    expect(response.status).toBe(202);
    expect(betterAuthProvider.requestMagicLink).not.toHaveBeenCalled();
  });

  it("accepts unknown magic-link emails without sending or creating accounts", async () => {
    mockedFindUserByEmail.mockResolvedValue(null);
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          email: "stranger@example.edu",
        }),
      },
      createEnv("production"),
    );
    const body = await response.json<{
      status: string;
      deliveryStatus: string;
      tenantId: string;
      email: string;
    }>();

    expect(response.status).toBe(202);
    expect(body).toEqual({
      status: "sent",
      deliveryStatus: "sent",
      tenantId: "tenant_123",
      email: "stranger@example.edu",
    });
    expect(mockedFindTenantMembership).not.toHaveBeenCalled();
    expect(betterAuthProvider.requestMagicLink).not.toHaveBeenCalled();
  });

  it("accepts non-member magic-link requests without sending", async () => {
    mockedFindTenantMembership.mockResolvedValue(null);
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          email: "learner@example.edu",
        }),
      },
      createEnv("production"),
    );
    const body = await response.json<{
      status: string;
      deliveryStatus: string;
      tenantId: string;
      email: string;
    }>();

    expect(response.status).toBe(202);
    expect(body).toEqual({
      status: "sent",
      deliveryStatus: "sent",
      tenantId: "tenant_123",
      email: "learner@example.edu",
    });
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_123");
    expect(betterAuthProvider.requestMagicLink).not.toHaveBeenCalled();
  });

  it("requires Turnstile after low magic-link rate thresholds", async () => {
    mockedCountAuthMagicLinkRateLimitAttempts.mockResolvedValue(3);
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "cf-connecting-ip": "203.0.113.10",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          email: "learner@example.edu",
        }),
      },
      {
        ...createEnv("production"),
        TURNSTILE_SITE_KEY: "turnstile-site-key",
        TURNSTILE_SECRET_KEY: "turnstile-secret-key",
      },
    );
    const body = await response.json<{
      error: string;
      turnstileRequired: boolean;
      turnstileSiteKey: string;
    }>();

    expect(response.status).toBe(428);
    expect(body).toMatchObject({
      turnstileRequired: true,
      turnstileSiteKey: "turnstile-site-key",
    });
    expect(body.error).toContain("Human verification");
    expect(mockedRecordAuthMagicLinkRateLimitAttempt).toHaveBeenCalledTimes(4);
    expect(betterAuthProvider.requestMagicLink).not.toHaveBeenCalled();
  });

  it("accepts valid Turnstile tokens after rate thresholds are exceeded", async () => {
    mockedCountAuthMagicLinkRateLimitAttempts.mockResolvedValue(3);
    const verifiedInputs: VerifyTurnstileTokenInput[] = [];
    const turnstileVerifier: TurnstileVerifier = {
      verify: (input) => {
        verifiedInputs.push(input);
        return Promise.resolve(true);
      },
    };
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/request",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "cf-connecting-ip": "203.0.113.10",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          email: "learner@example.edu",
          turnstileToken: "valid-turnstile-token",
        }),
      },
      {
        ...createEnv("production"),
        TURNSTILE_SITE_KEY: "turnstile-site-key",
        TURNSTILE_SECRET_KEY: "turnstile-secret-key",
        TURNSTILE_VERIFIER: turnstileVerifier,
      },
    );

    expect(response.status).toBe(202);
    expect(verifiedInputs).toEqual([
      expect.objectContaining({
        secretKey: "turnstile-secret-key",
        token: "valid-turnstile-token",
        remoteIp: "203.0.113.10",
      }),
    ]);
    expect(mockedRecordAuthMagicLinkRateLimitAttempt).toHaveBeenCalledTimes(4);
    expect(betterAuthProvider.requestMagicLink).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        tenantId: "tenant_123",
        email: "learner@example.edu",
      }),
    );
  });

  it("delegates JSON verify to Better Auth-backed session creation instead of legacy token tables", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders();

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/verify",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          token: "better-token-1234567890",
        }),
      },
      createEnv("production"),
    );
    const body = await response.json<{
      status: string;
      tenantId: string;
      userId: string;
      expiresAt: string;
    }>();

    expect(response.status).toBe(200);
    expect(body).toEqual({
      status: "authenticated",
      tenantId: "tenant_123",
      userId: "usr_better",
      expiresAt: "2026-02-18T22:00:00.000Z",
    });
    expect(response.headers.get("set-cookie")).toContain(
      "better-auth.session_token=better-session",
    );
    expect(betterAuthProvider.createMagicLinkSession).toHaveBeenCalledTimes(1);
  });

  it("authenticates an unscoped JSON magic link before organization selection", async () => {
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders({
      betterAuthRequestedTenant: null,
    });

    const response = await isolatedApp.request(
      "/v1/auth/magic-link/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: "better-token-1234567890" }),
      },
      createEnv("production"),
    );

    await expect(response.json()).resolves.toEqual({
      status: "authenticated",
      userId: "usr_better",
      expiresAt: "2026-02-18T22:00:00.000Z",
    });
    expect(response.status).toBe(200);
  });

  it("reports an authenticated session before organization selection", async () => {
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders({
      betterAuthInitiallyAuthenticated: true,
      betterAuthRequestedTenant: null,
    });

    const response = await isolatedApp.request(
      "/v1/auth/session",
      {
        headers: { Cookie: "better-auth.session_token=better-session" },
      },
      createEnv("production"),
    );

    await expect(response.json()).resolves.toEqual({
      status: "authenticated",
      userId: "usr_better",
      expiresAt: "2026-02-18T22:00:00.000Z",
    });
    expect(response.status).toBe(200);
  });

  it("uses Better Auth-backed session inspection without falling back to legacy session tables", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedHostedAuthProviders({
      betterAuthInitiallyAuthenticated: true,
    });

    const sessionResponse = await isolatedApp.request(
      "/v1/auth/session",
      {
        headers: {
          Cookie: "better-auth.session_token=better-session",
        },
      },
      createEnv("production"),
    );
    const sessionBody = await sessionResponse.json<{
      status: string;
      tenantId: string;
      userId: string;
      expiresAt: string;
    }>();

    expect(sessionResponse.status).toBe(200);
    expect(sessionBody).toEqual({
      status: "authenticated",
      tenantId: "tenant_123",
      userId: "usr_better",
      expiresAt: "2026-02-18T22:00:00.000Z",
    });
    expect(betterAuthProvider.resolveAuthenticatedPrincipal).toHaveBeenCalled();
  });

  it("redirects single-tenant authenticated users from /auth/resolve into their preferred tenant path", async () => {
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders({
      betterAuthInitiallyAuthenticated: true,
    });

    const response = await isolatedApp.request(
      "/auth/resolve",
      {
        headers: {
          Cookie: "better-auth.session_token=better-session",
        },
      },
      createEnv("production"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/learner/dashboard");
    expect(response.headers.get("set-cookie")).toContain("credtrail_requested_tenant=tenant_123");
    expect(mockedListAccessibleTenantContextsForUser).toHaveBeenCalledWith(fakeDb, "usr_better");
  });

  it("redirects multi-tenant authenticated users from /auth/resolve into the chooser flow", async () => {
    mockedListAccessibleTenantContextsForUser.mockResolvedValue([
      {
        tenantId: "tenant_123",
        tenantSlug: "tenant-123",
        tenantDisplayName: "Tenant 123",
        tenantPlanTier: "team",
        membershipRole: "viewer",
      },
      {
        tenantId: "tenant_456",
        tenantSlug: "tenant-456",
        tenantDisplayName: "Tenant 456",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
    ]);
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders({
      betterAuthInitiallyAuthenticated: true,
      betterAuthRequestedTenant: null,
    });

    const response = await isolatedApp.request(
      "/auth/resolve",
      {
        headers: {
          Cookie: "better-auth.session_token=better-session",
        },
      },
      createEnv("production"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/account/organizations");
  });

  it("renders the organization chooser for multi-tenant authenticated users", async () => {
    mockedListAccessibleTenantContextsForUser.mockResolvedValue([
      {
        tenantId: "tenant_123",
        tenantSlug: "tenant-123",
        tenantDisplayName: "Tenant 123",
        tenantPlanTier: "team",
        membershipRole: "viewer",
      },
      {
        tenantId: "tenant_456",
        tenantSlug: "tenant-456",
        tenantDisplayName: "Tenant 456",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
    ]);
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders({
      betterAuthInitiallyAuthenticated: true,
      betterAuthRequestedTenant: {
        tenantId: "tenant_456",
      },
    });

    const response = await isolatedApp.request(
      "/account/organizations",
      {
        headers: {
          Cookie: "better-auth.session_token=better-session",
        },
      },
      createEnv("production"),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Choose your institution");
    expect(body).toContain("Tenant 123");
    expect(body).toContain("Tenant 456");
    expect(body).toContain("Current");
    expect(body).toContain('action="/account/organizations/select"');
  });

  it("remembers the explicit organization selection and redirects into the chosen tenant path", async () => {
    mockedListAccessibleTenantContextsForUser.mockResolvedValue([
      {
        tenantId: "tenant_123",
        tenantSlug: "tenant-123",
        tenantDisplayName: "Tenant 123",
        tenantPlanTier: "team",
        membershipRole: "viewer",
      },
      {
        tenantId: "tenant_456",
        tenantSlug: "tenant-456",
        tenantDisplayName: "Tenant 456",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
    ]);
    const { app: isolatedApp } = await loadAppWithMockedHostedAuthProviders({
      betterAuthInitiallyAuthenticated: true,
      betterAuthRequestedTenant: null,
    });

    const response = await isolatedApp.request(
      "/account/organizations/select",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=better-session",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          tenantId: "tenant_456",
          next: "",
        }).toString(),
      },
      createEnv("production"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/tenants/tenant_456/admin");
    expect(response.headers.get("set-cookie")).toContain("credtrail_requested_tenant=tenant_456");
  });

  it("does not rely on credtrail_session for hosted auth session inspection", async () => {
    const response = await app.request(
      "/v1/auth/session",
      {
        headers: {
          Cookie: "credtrail_session=session-token",
        },
      },
      createEnv("production"),
    );
    const body = await response.json<{
      error: string;
    }>();

    expect(response.status).toBe(401);
    expect(body).toEqual({
      error: "Not authenticated",
    });
  });
});
