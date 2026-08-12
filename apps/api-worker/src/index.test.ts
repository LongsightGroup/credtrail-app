import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import type { SqlDatabase } from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

interface MockedInternalAuthProvider {
  requestMagicLink: ReturnType<typeof vi.fn>;
  createMagicLinkSession: ReturnType<typeof vi.fn>;
  createLtiSession: ReturnType<typeof vi.fn>;
  resolveAuthenticatedPrincipal: ReturnType<typeof vi.fn>;
  resolveRequestedTenantContext: ReturnType<typeof vi.fn>;
  revokeCurrentSession: ReturnType<typeof vi.fn>;
}

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  JOB_PROCESSOR_TOKEN?: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

afterEach(() => {
  vi.doUnmock("./auth/better-auth-adapter");
});

const loadAppWithMockedAuthFactories = async (input?: {
  betterAuthPrincipal?: {
    userId: string;
    authSessionId: string;
    authMethod: "better_auth";
    expiresAt: string;
  } | null;
  betterAuthRequestedTenant?: {
    tenantId: string;
    source: "route" | "legacy_session";
    authoritative: boolean;
  } | null;
}) => {
  vi.resetModules();

  const betterAuthProvider: MockedInternalAuthProvider = {
    requestMagicLink: vi.fn(),
    createMagicLinkSession: vi.fn(),
    createLtiSession: vi.fn(),
    resolveAuthenticatedPrincipal: vi.fn(() => Promise.resolve(input?.betterAuthPrincipal ?? null)),
    resolveRequestedTenantContext: vi.fn(() =>
      Promise.resolve(input?.betterAuthRequestedTenant ?? null),
    ),
    revokeCurrentSession: vi.fn(() => Promise.resolve()),
  };
  const createBetterAuthProvider = vi.fn(() => betterAuthProvider);

  vi.doMock("./auth/better-auth-adapter", async () => {
    const actual = await vi.importActual<typeof import("./auth/better-auth-adapter")>(
      "./auth/better-auth-adapter",
    );

    return {
      ...actual,
      createBetterAuthProvider,
    };
  });

  const { app: isolatedApp } = await import("./index");

  return {
    app: isolatedApp,
    betterAuthProvider,
    createBetterAuthProvider,
  };
};

const loadAppWithMockedAuthProviders = async (input: {
  betterAuthPrincipal?: {
    userId: string;
    authSessionId: string;
    authMethod: "better_auth";
    expiresAt: string;
  } | null;
  betterAuthRequestedTenant?: {
    tenantId: string;
    source: "route" | "legacy_session";
    authoritative: boolean;
  } | null;
}): Promise<{
  app: typeof app;
  betterAuthProvider: MockedInternalAuthProvider;
}> => {
  vi.resetModules();

  const betterAuthProvider: MockedInternalAuthProvider = {
    requestMagicLink: vi.fn(),
    createMagicLinkSession: vi.fn(),
    createLtiSession: vi.fn(),
    resolveAuthenticatedPrincipal: vi.fn(() => Promise.resolve(input.betterAuthPrincipal ?? null)),
    resolveRequestedTenantContext: vi.fn(() =>
      Promise.resolve(input.betterAuthRequestedTenant ?? null),
    ),
    revokeCurrentSession: vi.fn(() => Promise.resolve()),
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

  const { app: isolatedApp } = await import("./index");

  return {
    app: isolatedApp,
    betterAuthProvider,
  };
};

describe("GET /", () => {
  it("redirects to /login", async () => {
    const response = await app.request("/", undefined, createEnv());

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/login");
  });

  it("instantiates the Better Auth provider in the composition root", async () => {
    const { createBetterAuthProvider } = await loadAppWithMockedAuthFactories();

    expect(createBetterAuthProvider).toHaveBeenCalledTimes(1);
  });

  it("resolves hosted auth sessions through Better Auth in the composition root", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: {
        userId: "usr_better",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth",
        expiresAt: "2026-03-17T22:00:00.000Z",
      },
      betterAuthRequestedTenant: {
        tenantId: "tenant_better",
        source: "route",
        authoritative: true,
      },
    });

    const response = await isolatedApp.request("/v1/auth/session", undefined, createEnv());
    const body = await response.json<{
      status: string;
      tenantId: string;
      userId: string;
      expiresAt: string;
    }>();

    expect(response.status).toBe(200);
    expect(body).toEqual({
      status: "authenticated",
      tenantId: "tenant_better",
      userId: "usr_better",
      expiresAt: "2026-03-17T22:00:00.000Z",
    });
    expect(betterAuthProvider.resolveAuthenticatedPrincipal).toHaveBeenCalled();
  });

  it("keeps hosted auth routes Better Auth-only when no Better Auth session is present", async () => {
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: null,
      betterAuthRequestedTenant: null,
    });

    const response = await isolatedApp.request("/v1/auth/session", undefined, createEnv());
    const body = await response.json<{
      error: string;
    }>();

    expect(response.status).toBe(401);
    expect(body).toEqual({
      error: "Not authenticated",
    });
  });

  it("registers the reporting routes in the composition root", async () => {
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: null,
      betterAuthRequestedTenant: null,
    });

    const overviewResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/reporting/overview",
      undefined,
      createEnv(),
    );
    const engagementResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/reporting/engagement",
      undefined,
      createEnv(),
    );
    const trendsResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/reporting/trends",
      undefined,
      createEnv(),
    );
    const comparisonsResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/reporting/comparisons",
      undefined,
      createEnv(),
    );
    const hierarchyResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/reporting/hierarchy",
      undefined,
      createEnv(),
    );

    expect(overviewResponse.status).toBe(401);
    expect(engagementResponse.status).toBe(401);
    expect(trendsResponse.status).toBe(401);
    expect(comparisonsResponse.status).toBe(401);
    expect(hierarchyResponse.status).toBe(401);
  });

  it("registers the learner-record management routes in the composition root", async () => {
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: null,
      betterAuthRequestedTenant: null,
    });

    const listResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/learner-record-entries?learnerProfileId=lpr_123",
      undefined,
      createEnv(),
    );
    const createResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/learner-record-entries",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          learnerProfileId: "lpr_123",
          trustLevel: "issuer_verified",
          recordType: "course",
          title: "Clinical Placement Seminar",
          provenance: {
            issuerName: "CredTrail University",
            sourceSystem: "credtrail_admin",
            issuedAt: "2026-03-24T15:00:00.000Z",
            evidenceLinks: [],
          },
        }),
      },
      createEnv(),
    );

    expect(listResponse.status).toBe(401);
    expect(createResponse.status).toBe(401);
  });

  it("registers the learner-record export routes in the composition root", async () => {
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: null,
      betterAuthRequestedTenant: null,
    });

    const exportResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/learner-records/lpr_123/export",
      undefined,
      createEnv(),
    );
    const mappingResponse = await isolatedApp.request(
      "/v1/tenants/tenant_123/learner-records/lpr_123/standards-mapping",
      undefined,
      createEnv(),
    );

    expect(exportResponse.status).toBe(401);
    expect(mappingResponse.status).toBe(401);
  });
});
