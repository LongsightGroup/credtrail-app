import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
  mockedFindActiveSessionByHash,
  mockedTouchSession,
} = vi.hoisted(() => {
  return {
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
    mockedFindActiveSessionByHash: vi.fn(),
    mockedTouchSession: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    createAuditLog: vi.fn(),
    findActiveSessionByHash: mockedFindActiveSessionByHash,
    findAssertionById: vi.fn(),
    findAssertionIssuanceProvenanceByAssertionId: vi.fn(),
    findAssertionReportingAttributionByAssertionId: vi.fn(),
    findBadgeIssuanceRuleById: vi.fn(),
    findBadgeIssuanceRuleEvaluationByAssertionId: vi.fn(),
    findBadgeIssuanceRuleVersionById: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findTenantMembership: vi.fn(),
    findTenantOrgUnitById: vi.fn(),
    findUsersByIds: vi.fn(),
    listAssertionLifecycleEvents: vi.fn(),
    listAuditLogsForAssertion: vi.fn(),
    listBadgeIssuanceRuleVersionApprovalEvents: vi.fn(),
    listBadgeIssuanceRuleVersionApprovalSteps: vi.fn(),
    resolveAssertionLifecycleState: vi.fn(),
    touchSession: mockedTouchSession,
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
      revokeCurrentSession: vi.fn().mockResolvedValue(undefined),
    })),
  };
});

import {
  findAssertionById,
  findAssertionIssuanceProvenanceByAssertionId,
  findAssertionReportingAttributionByAssertionId,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleEvaluationByAssertionId,
  findBadgeIssuanceRuleVersionById,
  findBadgeTemplateById,
  findTenantMembership,
  findUsersByIds,
  listAssertionLifecycleEvents,
  listAuditLogsForAssertion,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  resolveAssertionLifecycleState,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { app } from "./index";

const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
const mockedListAssertionLifecycleEvents = vi.mocked(listAssertionLifecycleEvents);
const mockedListAuditLogsForAssertion = vi.mocked(listAuditLogsForAssertion);
const mockedFindAssertionReportingAttributionByAssertionId = vi.mocked(
  findAssertionReportingAttributionByAssertionId,
);
const mockedFindAssertionIssuanceProvenanceByAssertionId = vi.mocked(
  findAssertionIssuanceProvenanceByAssertionId,
);
const mockedFindBadgeIssuanceRuleEvaluationByAssertionId = vi.mocked(
  findBadgeIssuanceRuleEvaluationByAssertionId,
);
const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
const mockedFindBadgeIssuanceRuleVersionById = vi.mocked(findBadgeIssuanceRuleVersionById);
const mockedListBadgeIssuanceRuleVersionApprovalEvents = vi.mocked(
  listBadgeIssuanceRuleVersionApprovalEvents,
);
const mockedListBadgeIssuanceRuleVersionApprovalSteps = vi.mocked(
  listBadgeIssuanceRuleVersionApprovalSteps,
);
const mockedFindUsersByIds = vi.mocked(findUsersByIds);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);

const fakeDb = { prepare: vi.fn() };

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  BETTER_AUTH_SECRET: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    BETTER_AUTH_SECRET: "test-better-auth-secret",
  };
};

const sampleSession = (): {
  id: string;
  userId: string;
  expiresAt: Date;
} => {
  return {
    id: "session_123",
    userId: "usr_admin",
    expiresAt: new Date("2099-01-01T00:00:00.000Z"),
  };
};

describe("GET /v1/tenants/:tenantId/assertions/:assertionId/evidence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedCreatePostgresDatabase.mockReturnValue(fakeDb as never);
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedResolveBetterAuthPrincipal.mockResolvedValue({
      userId: "usr_admin",
      email: "admin@tenant-123.edu",
    });
    mockedResolveBetterAuthRequestedTenant.mockResolvedValue({
      tenantId: "tenant_123",
      membershipRole: "admin",
    });
    mockedFindTenantMembership.mockResolvedValue({
      tenantId: "tenant_123",
      userId: "usr_admin",
      role: "issuer",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });
    mockedFindAssertionById.mockResolvedValue(null);
    mockedFindBadgeTemplateById.mockResolvedValue(null);
    mockedResolveAssertionLifecycleState.mockResolvedValue(null);
    mockedListAssertionLifecycleEvents.mockResolvedValue([]);
    mockedListAuditLogsForAssertion.mockResolvedValue([]);
    mockedFindAssertionReportingAttributionByAssertionId.mockResolvedValue(null);
    mockedFindAssertionIssuanceProvenanceByAssertionId.mockResolvedValue(null);
    mockedFindBadgeIssuanceRuleEvaluationByAssertionId.mockResolvedValue(null);
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(null);
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue(null);
    mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([]);
    mockedListBadgeIssuanceRuleVersionApprovalSteps.mockResolvedValue([]);
    mockedFindUsersByIds.mockResolvedValue(new Map());
  });

  it("returns 404 when the assertion does not exist", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_123:assertion_missing/evidence",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(404);
  });

  it("returns 422 when assertionId is not tenant-scoped", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_999:assertion_456/evidence",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(422);
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });

  it("returns structured evidence JSON for issuer-role members", async () => {
    const env = createEnv();

    mockedFindAssertionById.mockResolvedValue({
      id: "tenant_123:assertion_456",
      tenantId: "tenant_123",
      publicId: "cred-abc123",
      learnerProfileId: null,
      badgeTemplateId: "tenant_123:badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      vcR2Key: "tenants/tenant_123/assertions/tenant_123:assertion_456.jsonld",
      statusListIndex: null,
      idempotencyKey: "manual:tenant_123:assertion_456",
      issuedAt: "2026-03-24T15:00:00.000Z",
      issuedByUserId: "usr_admin",
      revokedAt: null,
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });
    mockedFindBadgeTemplateById.mockResolvedValue({
      id: "tenant_123:badge_template_001",
      tenantId: "tenant_123",
      slug: "applied-analytics",
      title: "Applied Analytics",
      description: "Awarded for analytics coursework.",
      criteriaUri: "https://example.edu/criteria",
      imageUri: "https://example.edu/badges/analytics.png",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });
    mockedResolveAssertionLifecycleState.mockResolvedValue({
      state: "active",
      source: "default_active",
      reasonCode: null,
      reason: null,
      transitionedAt: null,
      revokedAt: null,
    });
    mockedFindUsersByIds.mockResolvedValue(
      new Map([
        [
          "usr_admin",
          {
            id: "usr_admin",
            email: "admin@tenant-123.edu",
          },
        ],
      ]),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_123:assertion_456/evidence",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const payload: unknown = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(payload).toMatchObject({
      assertionId: "tenant_123:assertion_456",
      tenantId: "tenant_123",
      summary: {
        badgeTitle: "Applied Analytics",
        recipientIdentity: "learner@example.edu",
      },
      issuance: {
        source: "manual",
      },
    });
  });

  it("denies access when the user is not a tenant issuer", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue({
      tenantId: "tenant_123",
      userId: "usr_learner",
      role: "viewer",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_123:assertion_456/evidence",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(403);
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });
});
