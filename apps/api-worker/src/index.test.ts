import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    createAuditLog: vi.fn(),
    upsertBadgeTemplateById: vi.fn(),
    upsertTenant: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  type AuditLogRecord,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantRecord,
  createAuditLog,
  upsertBadgeTemplateById,
  upsertTenant,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

interface ErrorResponse {
  error: string;
}

const mockedUpsertTenant = vi.mocked(upsertTenant);
const mockedUpsertBadgeTemplateById = vi.mocked(upsertBadgeTemplateById);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
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
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  JOB_PROCESSOR_TOKEN?: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleBadgeTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript-foundations",
    title: "TypeScript Foundations",
    description: "Awarded for completing TS basics.",
    criteriaUri: null,
    imageUri: null,
    createdByUserId: "usr_issuer",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: '{"stability":"institution_registry"}',
    isArchived: false,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleTenant = (overrides?: Partial<TenantRecord>): TenantRecord => {
  return {
    id: "sakai",
    slug: "sakai",
    displayName: "Sakai Project",
    planTier: "team",
    issuerDomain: "sakai.credtrail.test",
    didWeb: "did:web:credtrail.test:sakai",
    isActive: true,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: "aud_123",
    tenantId: "sakai",
    actorUserId: null,
    action: "tenant.updated",
    targetType: "tenant",
    targetId: "sakai",
    metadataJson: null,
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
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

describe("PUT /v1/admin/tenants/:tenantId", () => {
  beforeEach(() => {
    mockedUpsertTenant.mockReset();
  });

  it("returns 503 when bootstrap admin token is not configured", async () => {
    const response = await app.request(
      "/v1/admin/tenants/sakai",
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer any-token",
        },
        body: JSON.stringify({
          slug: "sakai",
          displayName: "Sakai Project",
        }),
      },
      createEnv(),
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(503);
    expect(body.error).toBe("Bootstrap admin API is not configured");
    expect(mockedUpsertTenant).not.toHaveBeenCalled();
  });

  it("returns 401 when bootstrap bearer token does not match", async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
    };
    const response = await app.request(
      "/v1/admin/tenants/sakai",
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer wrong-secret",
        },
        body: JSON.stringify({
          slug: "sakai",
          displayName: "Sakai Project",
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe("Unauthorized");
    expect(mockedUpsertTenant).not.toHaveBeenCalled();
  });

  it("upserts tenant metadata through the admin API", async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
    };
    mockedUpsertTenant.mockResolvedValue(sampleTenant());

    const response = await app.request(
      "/v1/admin/tenants/sakai",
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer bootstrap-secret",
        },
        body: JSON.stringify({
          slug: "sakai",
          displayName: "Sakai Project",
        }),
      },
      env,
    );
    const body = await response.json<{ tenant: TenantRecord }>();

    expect(response.status).toBe(201);
    expect(body.tenant.id).toBe("sakai");
    expect(body.tenant.didWeb).toBe("did:web:credtrail.test:sakai");
    expect(mockedUpsertTenant).toHaveBeenCalledWith(fakeDb, {
      id: "sakai",
      slug: "sakai",
      displayName: "Sakai Project",
      planTier: "team",
      issuerDomain: "sakai.credtrail.test",
      didWeb: "did:web:credtrail.test:sakai",
      isActive: undefined,
    });
  });

  it("returns 409 when tenant URL key/domain uniqueness is violated", async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
    };
    mockedUpsertTenant.mockRejectedValue(
      new Error('duplicate key value violates unique constraint "tenants_slug_key"'),
    );

    const response = await app.request(
      "/v1/admin/tenants/sakai",
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer bootstrap-secret",
        },
        body: JSON.stringify({
          slug: "sakai",
          displayName: "Sakai Project",
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(409);
    expect(body.error).toBe("Tenant URL key or issuer domain is already in use.");
  });
});

describe("PUT /v1/admin/tenants/:tenantId/badge-templates/:badgeTemplateId", () => {
  beforeEach(() => {
    mockedUpsertBadgeTemplateById.mockReset();
  });

  it("upserts a template through the admin API", async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
    };
    mockedUpsertBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({
        id: "badge_template_sakai_1000",
        tenantId: "sakai",
        slug: "sakai-1000-commits-contributor",
      }),
    );

    const response = await app.request(
      "/v1/admin/tenants/sakai/badge-templates/badge_template_sakai_1000",
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer bootstrap-secret",
        },
        body: JSON.stringify({
          slug: "sakai-1000-commits-contributor",
          title: "Sakai 1000+ Commits Contributor",
          description: "Awarded for contributing 1000+ commits to Sakai.",
          criteriaUri: "https://github.com/sakaiproject/sakai",
          imageUri: "https://avatars.githubusercontent.com/u/429529?s=200&v=4",
        }),
      },
      env,
    );
    const body = await response.json<{ tenantId: string; template: BadgeTemplateRecord }>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe("sakai");
    expect(body.template.id).toBe("badge_template_sakai_1000");
    expect(mockedUpsertBadgeTemplateById).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        id: "badge_template_sakai_1000",
        tenantId: "sakai",
        slug: "sakai-1000-commits-contributor",
        title: "Sakai 1000+ Commits Contributor",
        description: "Awarded for contributing 1000+ commits to Sakai.",
        criteriaUri: "https://github.com/sakaiproject/sakai",
        imageUri: "https://avatars.githubusercontent.com/u/429529?s=200&v=4",
      }),
    );
  });
});
