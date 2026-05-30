import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedFindTenantAuthProviderById,
  mockedFindTenantAuthPolicy,
  mockedUpsertTenantAuthPolicy,
  mockedResolveTenantAuthPolicy,
  mockedListTenantAuthProviders,
  mockedCreateTenantAuthProvider,
  mockedUpdateTenantAuthProvider,
  mockedDeleteTenantAuthProvider,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} = vi.hoisted(() => {
  return {
    mockedFindTenantAuthProviderById: vi.fn(),
    mockedFindTenantAuthPolicy: vi.fn(),
    mockedUpsertTenantAuthPolicy: vi.fn(),
    mockedResolveTenantAuthPolicy: vi.fn(),
    mockedListTenantAuthProviders: vi.fn(),
    mockedCreateTenantAuthProvider: vi.fn(),
    mockedUpdateTenantAuthProvider: vi.fn(),
    mockedDeleteTenantAuthProvider: vi.fn(),
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    createAuditLog: vi.fn(),
    findTenantAuthProviderById: mockedFindTenantAuthProviderById,
    findTenantMembership: vi.fn(),
    findTenantById: vi.fn(),
    findTenantAuthPolicy: mockedFindTenantAuthPolicy,
    resolveTenantAuthPolicy: mockedResolveTenantAuthPolicy,
    upsertTenantAuthPolicy: mockedUpsertTenantAuthPolicy,
    listTenantAuthProviders: mockedListTenantAuthProviders,
    createTenantAuthProvider: mockedCreateTenantAuthProvider,
    updateTenantAuthProvider: mockedUpdateTenantAuthProvider,
    deleteTenantAuthProvider: mockedDeleteTenantAuthProvider,
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./auth/better-auth-adapter", async () => {
  const actual = await vi.importActual<typeof import("./auth/better-auth-adapter")>(
    "./auth/better-auth-adapter",
  );

  return {
    ...actual,
    createBetterAuthProvider: vi.fn(() => ({
      requestMagicLink: vi.fn(),
      createMagicLinkSession: vi.fn(),
      createLtiSession: vi.fn(),
      resolveAuthenticatedPrincipal: mockedResolveBetterAuthPrincipal,
      resolveRequestedTenantContext: mockedResolveBetterAuthRequestedTenant,
      revokeCurrentSession: vi.fn(async () => {}),
    })),
  };
});

import {
  createAuditLog,
  findTenantMembership,
  findTenantById,
  type AuditLogRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
  type TenantRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

interface ErrorResponse {
  error: string;
}

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindTenantById = vi.mocked(findTenantById);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleMembership = (role: TenantMembershipRecord["role"]): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_admin",
    role,
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
  };
};

const sampleTenant = (overrides?: Partial<TenantRecord>): TenantRecord => {
  return {
    id: "tenant_123",
    slug: "tenant-123",
    displayName: "Tenant 123",
    planTier: "enterprise",
    issuerDomain: "tenant-123.credtrail.test",
    didWeb: "did:web:credtrail.test:tenant_123",
    isActive: true,
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
    ...overrides,
  };
};

const sampleAuditLog = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: "aud_123",
    tenantId: "tenant_123",
    actorUserId: "usr_admin",
    action: "tenant.auth_policy_upserted",
    targetType: "tenant_auth_policy",
    targetId: "tenant_123",
    metadataJson: null,
    occurredAt: "2026-03-16T12:00:00.000Z",
    createdAt: "2026-03-16T12:00:00.000Z",
    ...overrides,
  };
};

const sampleAuthPolicy = (overrides?: Record<string, unknown>): Record<string, unknown> => {
  return {
    tenantId: "tenant_123",
    loginMode: "hybrid",
    breakGlassEnabled: true,
    localMfaRequired: true,
    defaultProviderId: "tap_oidc",
    enforceForRoles: "all_users",
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
    ...overrides,
  };
};

const sampleAuthProvider = (overrides?: Record<string, unknown>): Record<string, unknown> => {
  return {
    id: "tap_oidc",
    tenantId: "tenant_123",
    protocol: "oidc",
    label: "Campus OIDC",
    enabled: true,
    isDefault: true,
    configJson:
      '{"issuer":"https://idp.example.edu","clientId":"credtrail","clientSecret":"secret"}',
    createdAt: "2026-03-16T12:00:00.000Z",
    updatedAt: "2026-03-16T12:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleMembership("admin"));
  mockedFindTenantById.mockReset();
  mockedFindTenantById.mockResolvedValue(sampleTenant());
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLog());
  mockedFindTenantAuthProviderById.mockReset();
  mockedFindTenantAuthProviderById.mockResolvedValue(sampleAuthProvider());
  mockedFindTenantAuthPolicy.mockReset();
  mockedFindTenantAuthPolicy.mockResolvedValue(sampleAuthPolicy());
  mockedResolveTenantAuthPolicy.mockReset();
  mockedResolveTenantAuthPolicy.mockResolvedValue(sampleAuthPolicy());
  mockedUpsertTenantAuthPolicy.mockReset();
  mockedUpsertTenantAuthPolicy.mockResolvedValue(sampleAuthPolicy({ loginMode: "sso_required" }));
  mockedListTenantAuthProviders.mockReset();
  mockedListTenantAuthProviders.mockResolvedValue([
    sampleAuthProvider(),
    sampleAuthProvider({
      id: "tap_saml",
      protocol: "saml",
      label: "Campus SAML",
      isDefault: false,
      configJson:
        '{"ssoLoginUrl":"https://idp.example.edu/sso","idpEntityId":"https://idp.example.edu/entity"}',
    }),
  ]);
  mockedCreateTenantAuthProvider.mockReset();
  mockedCreateTenantAuthProvider.mockResolvedValue(sampleAuthProvider());
  mockedUpdateTenantAuthProvider.mockReset();
  mockedUpdateTenantAuthProvider.mockResolvedValue(
    sampleAuthProvider({
      id: "tap_saml",
      protocol: "saml",
      label: "Campus SAML",
      enabled: false,
      isDefault: false,
    }),
  );
  mockedDeleteTenantAuthProvider.mockReset();
  mockedDeleteTenantAuthProvider.mockResolvedValue(true);
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockImplementation(
    async (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return null;
      }

      return {
        userId: "usr_admin",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-03-16T23:00:00.000Z",
      };
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
});

describe("enterprise auth policy governance", () => {
  it("reads and updates enterprise tenant auth policy with audit logging", async () => {
    const env = createEnv();
    mockedResolveTenantAuthPolicy.mockResolvedValue(
      sampleAuthPolicy({
        enforceForRoles: "admins_only",
      }),
    );
    mockedUpsertTenantAuthPolicy.mockResolvedValue(
      sampleAuthPolicy({
        loginMode: "sso_required",
        enforceForRoles: "all_users",
      }),
    );

    const getResponse = await app.request(
      "/v1/tenants/tenant_123/auth-policy",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(getResponse.status).toBe(200);
    const getBody = await getResponse.json<Record<string, unknown>>();
    expect(getBody.loginMode).toBe("hybrid");
    expect(getBody.defaultProviderId).toBe("tap_oidc");
    expect(getBody.enforceForRoles).toBeUndefined();

    const putResponse = await app.request(
      "/v1/tenants/tenant_123/auth-policy",
      {
        method: "PUT",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          loginMode: "sso_required",
          breakGlassEnabled: true,
          localMfaRequired: true,
          defaultProviderId: "tap_oidc",
          enforceForRoles: "admins_only",
        }),
      },
      env,
    );

    expect(putResponse.status).toBe(200);
    const putBody = await putResponse.json<Record<string, unknown>>();
    expect(putBody.loginMode).toBe("sso_required");
    expect(putBody.enforceForRoles).toBeUndefined();
    expect(mockedUpsertTenantAuthPolicy).toHaveBeenCalledWith(
      fakeDb,
      expect.not.objectContaining({
        enforceForRoles: expect.anything(),
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        actorUserId: "usr_admin",
        action: "tenant.auth_policy_upserted",
        targetType: "tenant_auth_policy",
        targetId: "tenant_123",
      }),
    );
  });

  it("keeps enterprise auth provider management OIDC-only while exposing legacy SAML as compatibility-only", async () => {
    const env = createEnv();

    const listResponse = await app.request(
      "/v1/tenants/tenant_123/auth-providers",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(listResponse.status).toBe(200);
    const listBody = await listResponse.json<Array<Record<string, unknown>>>();
    expect(listBody).toHaveLength(2);
    expect(listBody[0]?.protocol).toBe("oidc");
    expect(listBody[1]?.protocol).toBe("saml");
    expect(listBody[0]?.compatibilityOnly).toBe(false);
    expect(listBody[1]?.compatibilityOnly).toBe(true);
    expect(listBody[1]?.notice).toContain("Legacy SAML compatibility");

    const createResponse = await app.request(
      "/v1/tenants/tenant_123/auth-providers",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          protocol: "oidc",
          label: "Campus OIDC",
          enabled: true,
          isDefault: true,
          configJson:
            '{"issuer":"https://idp.example.edu","clientId":"credtrail","clientSecret":"secret"}',
        }),
      },
      env,
    );

    expect(createResponse.status).toBe(201);
    const createBody = await createResponse.json<Record<string, unknown>>();
    expect(createBody.label).toBe("Campus OIDC");
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "tenant.auth_provider_created",
        targetType: "tenant_auth_provider",
      }),
    );

    const createLegacySamlResponse = await app.request(
      "/v1/tenants/tenant_123/auth-providers",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          protocol: "saml",
          label: "Campus SAML",
          enabled: true,
          isDefault: false,
          configJson:
            '{"ssoLoginUrl":"https://idp.example.edu/sso","idpEntityId":"https://idp.example.edu/entity"}',
        }),
      },
      env,
    );
    const createLegacySamlBody = await createLegacySamlResponse.json<ErrorResponse>();

    expect(createLegacySamlResponse.status).toBe(400);
    expect(createLegacySamlBody.error).toContain("OIDC providers only");

    mockedFindTenantAuthProviderById.mockResolvedValueOnce(
      sampleAuthProvider({
        id: "tap_saml",
        protocol: "saml",
        label: "Campus SAML",
        isDefault: false,
        configJson:
          '{"ssoLoginUrl":"https://idp.example.edu/sso","idpEntityId":"https://idp.example.edu/entity"}',
      }),
    );

    const updateResponse = await app.request(
      "/v1/tenants/tenant_123/auth-providers/tap_saml",
      {
        method: "PUT",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          protocol: "saml",
          label: "Campus SAML",
          enabled: false,
          isDefault: false,
          configJson:
            '{"ssoLoginUrl":"https://idp.example.edu/sso","idpEntityId":"https://idp.example.edu/entity"}',
        }),
      },
      env,
    );
    const updateBody = await updateResponse.json<ErrorResponse>();

    expect(updateResponse.status).toBe(400);
    expect(updateBody.error).toContain("Legacy SAML compatibility entries are not editable");

    const deleteResponse = await app.request(
      "/v1/tenants/tenant_123/auth-providers/tap_saml",
      {
        method: "DELETE",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(deleteResponse.status).toBe(200);
    const deleteBody = await deleteResponse.json<Record<string, unknown>>();
    expect(deleteBody.removed).toBe(true);
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "tenant.auth_provider_deleted",
        targetType: "tenant_auth_provider",
        targetId: "tap_saml",
      }),
    );
  });

  it("treats legacy SAML write endpoints as deprecated compatibility-only surfaces", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/sso/saml",
      {
        method: "PUT",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          idpEntityId: "https://idp.example.edu/entity",
          ssoLoginUrl: "https://idp.example.edu/sso",
          idpCertificatePem: "-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----",
          spEntityId: "https://credtrail.test/saml/sp",
          assertionConsumerServiceUrl: "https://credtrail.test/saml/acs",
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(410);
    expect(body.error).toContain("deprecated");
  });

  it("keeps enterprise auth governance gated behind enterprise plan checks", async () => {
    const env = createEnv();
    mockedFindTenantById.mockResolvedValue(sampleTenant({ planTier: "team" }));

    const response = await app.request(
      "/v1/tenants/tenant_123/auth-providers",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(403);
    const body = await response.json<ErrorResponse>();
    expect(body.error).toContain("enterprise");
  });
});
