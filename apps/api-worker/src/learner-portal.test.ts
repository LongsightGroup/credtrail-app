import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockedResolveBetterAuthPrincipal, mockedResolveBetterAuthRequestedTenant } = vi.hoisted(
  () => {
    return {
      mockedResolveBetterAuthPrincipal: vi.fn(),
      mockedResolveBetterAuthRequestedTenant: vi.fn(),
    };
  },
);

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    addLearnerIdentityAlias: vi.fn(),
    findLearnerProfileById: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findTenantMembership: vi.fn(),
    findUserById: vi.fn(),
    listAssertionEngagementEvents: vi.fn(),
    listAccessibleTenantContextsForUser: vi.fn(),
    listLearnerBadgeSummaries: vi.fn(),
    listLearnerRecordAssertionExports: vi.fn(),
    listLearnerRecordEntries: vi.fn(),
    listLearnerIdentitiesByProfile: vi.fn(),
    recordAssertionEngagementEvent: vi.fn(),
    removeLearnerIdentityAliasesByType: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
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
  addLearnerIdentityAlias,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findTenantMembership,
  findUserById,
  listAssertionEngagementEvents,
  listAccessibleTenantContextsForUser,
  listLearnerBadgeSummaries,
  listLearnerRecordAssertionExports,
  listLearnerRecordEntries,
  listLearnerIdentitiesByProfile,
  recordAssertionEngagementEvent,
  removeLearnerIdentityAliasesByType,
  resolveLearnerProfileForIdentity,
  type AssertionEngagementEventRecord,
  type LearnerBadgeSummaryRecord,
  type LearnerProfileRecord,
  type LearnerRecordAssertionExportRecord,
  type LearnerRecordEntryRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { getSeededDemoLearnerRecordFixture } from "./learner-record/seeded-demo-learner-record-fixture";

interface ErrorResponse {
  error: string;
}

const mockedAddLearnerIdentityAlias = vi.mocked(addLearnerIdentityAlias);
const mockedFindLearnerProfileById = vi.mocked(findLearnerProfileById);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindUserById = vi.mocked(findUserById);
const mockedListAssertionEngagementEvents = vi.mocked(listAssertionEngagementEvents);
const mockedListAccessibleTenantContextsForUser = vi.mocked(listAccessibleTenantContextsForUser);
const mockedListLearnerBadgeSummaries = vi.mocked(listLearnerBadgeSummaries);
const mockedListLearnerRecordAssertionExports = vi.mocked(listLearnerRecordAssertionExports);
const mockedListLearnerRecordEntries = vi.mocked(listLearnerRecordEntries);
const mockedListLearnerIdentitiesByProfile = vi.mocked(listLearnerIdentitiesByProfile);
const mockedRecordAssertionEngagementEvent = vi.mocked(recordAssertionEngagementEvent);
const mockedRemoveLearnerIdentityAliasesByType = vi.mocked(removeLearnerIdentityAliasesByType);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
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
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
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

const sampleUserRecord = (overrides?: {
  id?: string;
  email?: string;
}): { id: string; email: string } => {
  return {
    id: overrides?.id ?? "usr_123",
    email: overrides?.email ?? "learner@example.edu",
  };
};

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleLearnerBadge = (
  overrides?: Partial<LearnerBadgeSummaryRecord>,
): LearnerBadgeSummaryRecord => {
  return {
    assertionId: "tenant_123:assertion_456",
    assertionPublicId: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "TypeScript Foundations",
    badgeDescription: "Awarded for completing TS basics.",
    issuedAt: "2026-02-10T22:00:00.000Z",
    revokedAt: null,
    ...overrides,
  };
};

const sampleAssertionEngagementEvent = (
  overrides?: Partial<AssertionEngagementEventRecord>,
): AssertionEngagementEventRecord => {
  return {
    id: "aee_claim_123",
    tenantId: "tenant_123",
    assertionId: "tenant_123:assertion_456",
    eventType: "learner_claim",
    actorType: "learner",
    channel: "learner_dashboard",
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleLearnerRecordAssertionExport = (
  overrides?: Partial<LearnerRecordAssertionExportRecord>,
): LearnerRecordAssertionExportRecord => {
  return {
    assertionId: "tenant_123:assertion_456",
    assertionPublicId: "public_assertion_456",
    tenantId: "tenant_123",
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "Applied Analytics Badge",
    badgeDescription: "Awarded for applied analytics work.",
    badgeCriteriaUri: "https://credtrail.example.edu/badges/applied-analytics/criteria",
    badgeImageUri: "https://credtrail.example.edu/badges/applied-analytics/image.png",
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "tenants/tenant_123/assertions/assertion_456.jsonld",
    statusListIndex: 12,
    idempotencyKey: "idem_123",
    issuedAt: "2026-03-24T15:00:00.000Z",
    issuedByUserId: "usr_admin",
    revokedAt: null,
    issuerName: "CredTrail University",
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
    ...overrides,
  };
};

const sampleLearnerRecordEntry = (
  overrides?: Partial<LearnerRecordEntryRecord>,
): LearnerRecordEntryRecord => {
  return {
    id: "lre_123",
    tenantId: "tenant_123",
    learnerProfileId: "lpr_123",
    trustLevel: "issuer_verified",
    recordType: "course",
    status: "active",
    title: "Clinical Placement Seminar",
    description: "Completed with distinction.",
    issuerName: "CredTrail University",
    issuerUserId: "usr_admin",
    sourceSystem: "credtrail_admin",
    sourceRecordId: null,
    issuedAt: "2026-03-23T15:00:00.000Z",
    revisedAt: null,
    revokedAt: null,
    evidenceLinksJson: '["https://credtrail.example.edu/evidence/clinical-placement-seminar"]',
    detailsJson: '{"grade":"A"}',
    createdAt: "2026-03-23T15:00:00.000Z",
    updatedAt: "2026-03-23T15:00:00.000Z",
    ...overrides,
  };
};

const sampleTenantMembership = (
  overrides?: Partial<TenantMembershipRecord>,
): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_123",
    role: "viewer",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindLearnerProfileById.mockReset();
  mockedFindLearnerProfileById.mockResolvedValue(sampleLearnerProfile());
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
  mockedListAssertionEngagementEvents.mockReset();
  mockedListAssertionEngagementEvents.mockResolvedValue([]);
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
  mockedListLearnerRecordAssertionExports.mockReset();
  mockedListLearnerRecordAssertionExports.mockResolvedValue([sampleLearnerRecordAssertionExport()]);
  mockedListLearnerRecordEntries.mockReset();
  mockedListLearnerRecordEntries.mockResolvedValue([sampleLearnerRecordEntry()]);
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockImplementation(
    async (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return null;
      }

      return {
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-03-17T22:00:00.000Z",
      };
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
  mockedRecordAssertionEngagementEvent.mockReset();
  mockedRecordAssertionEngagementEvent.mockResolvedValue({
    status: "recorded",
    event: sampleAssertionEngagementEvent(),
  });
});

afterEach(() => {
  vi.doUnmock("./auth/better-auth-adapter");
});

describe("GET /tenants/:tenantId/learner/dashboard", () => {
  beforeEach(() => {
    mockedFindUserById.mockReset();
    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedListLearnerIdentitiesByProfile.mockReset();
    mockedListLearnerIdentitiesByProfile.mockResolvedValue([]);
    mockedListLearnerBadgeSummaries.mockReset();
  });

  it("returns 401 when no learner session is present", async () => {
    const env = createEnv();
    const response = await app.request("/tenants/tenant_123/learner/dashboard", undefined, env);
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe("Not authenticated");
  });

  it("authorizes learner dashboard from requested tenant membership even when session tenant differs", async () => {
    const env = createEnv();

    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const response = await app.request(
      "/tenants/tenant_123/learner/dashboard",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Your credential collection");
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_123");
  });

  it("authorizes learner dashboard from Better Auth without a legacy session cookie", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: {
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth",
        expiresAt: "2026-03-17T22:00:00.000Z",
      },
    });
    const env = createEnv();

    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const response = await isolatedApp.request(
      "/tenants/tenant_123/learner/dashboard",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Your credential collection");
    expect(betterAuthProvider.resolveAuthenticatedPrincipal).toHaveBeenCalled();
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_123");
  });

  it("returns 403 when the authenticated user lacks membership for the requested tenant", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(null);

    const response = await app.request(
      "/tenants/tenant_123/learner/dashboard",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toBe("Membership not found for requested tenant");
    expect(mockedListLearnerBadgeSummaries).not.toHaveBeenCalled();
  });

  it("renders learner badge list with share links", async () => {
    const env = createEnv();

    mockedListLearnerBadgeSummaries.mockResolvedValue([
      sampleLearnerBadge(),
      sampleLearnerBadge({
        assertionId: "tenant_123:assertion_999",
        assertionPublicId: "public_assertion_999",
        badgeTitle: "Advanced TypeScript",
        revokedAt: "2026-02-11T01:00:00.000Z",
      }),
    ]);

    const response = await app.request(
      "/tenants/tenant_123/learner/dashboard",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Your credential collection");
    expect(body).toContain("Your badges");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Advanced TypeScript");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22");
    expect(body).toContain("/badges/public_assertion_999");
    expect(body).toContain("View public badge");
    expect(body).toContain("Claim from dashboard");
    expect(body).toContain("Verified");
    expect(body).toContain("Revoked");
    expect(body).toContain("Profile settings");
    expect(body).toContain("Manage learner DID");
    expect(body).toContain("No learner DID is currently configured.");
    expect(body).toContain("/tenants/tenant_123/learner/record");
    expect(body).toContain("Open full learner record");
    expect(body).not.toContain("Switch organization");
    expect(mockedListLearnerIdentitiesByProfile).toHaveBeenCalledWith(
      fakeDb,
      "tenant_123",
      "lpr_123",
    );
    expect(mockedListLearnerBadgeSummaries).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_123",
    });
  });

  it("renders persistent claim and wallet-accept states when engagement was already recorded", async () => {
    const env = createEnv();

    mockedListLearnerBadgeSummaries.mockResolvedValue([
      sampleLearnerBadge(),
      sampleLearnerBadge({
        assertionId: "tenant_123:assertion_999",
        assertionPublicId: "public_assertion_999",
        badgeTitle: "Advanced TypeScript",
      }),
    ]);
    mockedListAssertionEngagementEvents.mockImplementation(async (_db, input) => {
      if (input.assertionId === "tenant_123:assertion_456") {
        return [
          sampleAssertionEngagementEvent({
            assertionId: "tenant_123:assertion_456",
            eventType: "learner_claim",
          }),
        ];
      }

      return [
        sampleAssertionEngagementEvent({
          id: "aee_wallet_123",
          assertionId: "tenant_123:assertion_999",
          eventType: "wallet_accept",
          actorType: "wallet",
          channel: "oid4vci",
        }),
      ];
    });

    const response = await app.request(
      "/tenants/tenant_123/learner/dashboard?claimStatus=recorded",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Credential claim recorded from your dashboard.");
    expect(body).toContain("Claim recorded in CredTrail");
    expect(body).toContain("Accepted in wallet");
  });

  it("renders configured learner DID and status notice", async () => {
    const env = createEnv();

    mockedListLearnerIdentitiesByProfile.mockResolvedValue([
      {
        id: "lid_did_123",
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        identityType: "did",
        identityValue: "did:key:z6MkhLearnerDidExample",
        isPrimary: false,
        isVerified: true,
        createdAt: "2026-02-10T22:00:00.000Z",
        updatedAt: "2026-02-10T22:00:00.000Z",
      },
    ]);
    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const response = await app.request(
      "/tenants/tenant_123/learner/dashboard?didStatus=updated",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(
      "Learner DID updated. Newly issued badges will use this DID as credentialSubject.id.",
    );
    expect(body).toContain('<details class="learner-dashboard__profile-details" open');
    expect(body).toContain("Current DID:");
    expect(body).toContain("did:key:z6MkhLearnerDidExample");
  });

  it("shows an explicit switch-organization link only when the learner can access more than one tenant", async () => {
    const env = createEnv();

    mockedListLearnerBadgeSummaries.mockResolvedValue([]);
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
        membershipRole: "viewer",
      },
    ]);

    const response = await app.request(
      "/tenants/tenant_123/learner/dashboard",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Switch organization");
    expect(body).toContain(
      "/account/organizations?next=%2Ftenants%2Ftenant_123%2Flearner%2Fdashboard",
    );
  });

  it("lets one authenticated learner session open more than one tenant-scoped dashboard", async () => {
    mockedFindTenantMembership.mockImplementation(async (_db, tenantId) => {
      if (tenantId === "tenant_123" || tenantId === "tenant_456") {
        return sampleTenantMembership({
          tenantId,
        });
      }

      return null;
    });
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
        membershipRole: "viewer",
      },
    ]);
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: {
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth",
        expiresAt: "2026-03-17T22:00:00.000Z",
      },
    });
    const env = createEnv();

    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const firstResponse = await isolatedApp.request(
      "/tenants/tenant_123/learner/dashboard",
      undefined,
      env,
    );
    const secondResponse = await isolatedApp.request(
      "/tenants/tenant_456/learner/dashboard",
      undefined,
      env,
    );
    const secondBody = await secondResponse.text();

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(200);
    expect(secondBody).toContain("Tenant record");
    expect(secondBody).toContain("tenant_456");
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_123");
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_456", "usr_123");
  });

  it("renders empty state when learner has no earned badges yet", async () => {
    const env = createEnv();

    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const response = await app.request(
      "/tenants/tenant_123/learner/dashboard",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Your credential collection is ready for its first published badge.");
    expect(body).toContain("No badges have been issued to this learner account yet.");
  });
});

describe("GET /tenants/:tenantId/learner/record", () => {
  beforeEach(() => {
    mockedFindUserById.mockReset();
    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileById.mockReset();
    mockedFindLearnerProfileById.mockResolvedValue(sampleLearnerProfile());
    mockedListLearnerRecordAssertionExports.mockReset();
    mockedListLearnerRecordAssertionExports.mockResolvedValue([
      sampleLearnerRecordAssertionExport(),
    ]);
    mockedListLearnerRecordEntries.mockReset();
    mockedListLearnerRecordEntries.mockResolvedValue([
      sampleLearnerRecordEntry(),
      sampleLearnerRecordEntry({
        id: "lre_supp_001",
        trustLevel: "learner_supplemental",
        recordType: "supplemental_artifact",
        title: "Portfolio Reflection",
        description: "Learner-supplied capstone reflection.",
        issuerName: "Learner self report",
        issuerUserId: null,
        sourceSystem: "learner_self_reported",
        sourceRecordId: null,
        evidenceLinksJson: '["https://portfolio.example.edu/learner-one"]',
        detailsJson: '{"portfolioUrl":"https://portfolio.example.edu/learner-one"}',
      }),
      sampleLearnerRecordEntry({
        id: "lre_revoked_001",
        recordType: "membership",
        title: "Membership Standing",
        status: "revoked",
        sourceSystem: "csv_import",
        sourceRecordId: "legacy:membership:001",
        revokedAt: "2026-03-22T15:00:00.000Z",
      }),
    ]);
  });

  it("renders a unified learner record page on the normal learner route family", async () => {
    const response = await app.request(
      "/tenants/tenant_123/learner/record",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Unified learner record");
    expect(body).toContain("Institution-verified record");
    expect(body).toContain("Learner-supplemental record");
    expect(body).toContain("Historical record");
    expect(body).toContain("Applied Analytics Badge");
    expect(body).toContain("Clinical Placement Seminar");
    expect(body).toContain("Portfolio Reflection");
    expect(body).toContain("Membership Standing");
    expect(body).toContain("/badges/public_assertion_456");
    expect(body).not.toContain("standards mapping");
    expect(body).not.toContain("Download export");
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      identityType: "email",
      identityValue: "learner@example.edu",
    });
    expect(mockedFindLearnerProfileById).toHaveBeenCalledWith(fakeDb, "tenant_123", "lpr_123");
  });

  it("can verify a seeded-demo learner-record slice on the normal learner route from the canonical fixture", async () => {
    const seededDemo = getSeededDemoLearnerRecordFixture();

    mockedResolveLearnerProfileForIdentity.mockResolvedValueOnce(seededDemo.learnerProfile);
    mockedFindLearnerProfileById.mockResolvedValueOnce(seededDemo.learnerProfile);
    mockedListLearnerRecordAssertionExports.mockResolvedValueOnce([...seededDemo.assertionExports]);
    mockedListLearnerRecordEntries.mockResolvedValueOnce([...seededDemo.recordEntries]);

    const response = await app.request(
      seededDemo.routeFamily.learnerRecord,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Unified learner record");
    expect(body).toContain("Applied Analytics Badge");
    expect(body).toContain("Clinical Placement Seminar");
    expect(body).toContain("Portfolio Reflection");
    expect(body).toContain("Leadership Society Membership");
    expect(body).toContain("Issuer verified");
    expect(body).toContain("Learner supplemental");
    expect(body).not.toContain("Download export");
  });
});

describe("POST /tenants/:tenantId/learner/settings/did", () => {
  beforeEach(() => {
    mockedFindUserById.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedFindLearnerProfileByIdentity.mockReset();
    mockedRemoveLearnerIdentityAliasesByType.mockReset();
    mockedAddLearnerIdentityAlias.mockReset();
  });

  it("returns 401 when no learner session is present", async () => {
    const env = createEnv();
    const response = await app.request(
      "/tenants/tenant_123/learner/settings/did",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          did: "did:key:z6MkhLearnerDidExample",
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe("Not authenticated");
  });

  it("saves learner DID and redirects with updated status", async () => {
    const env = createEnv();

    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileByIdentity.mockResolvedValue(null);
    mockedRemoveLearnerIdentityAliasesByType.mockResolvedValue(0);

    const response = await app.request(
      "/tenants/tenant_123/learner/settings/did",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "content-type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          did: "did:key:z6MkhLearnerDidExample",
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "", "http://localhost");
    expect(redirectUrl.pathname).toBe("/tenants/tenant_123/learner/dashboard");
    expect(redirectUrl.searchParams.get("didStatus")).toBe("updated");
    expect(mockedRemoveLearnerIdentityAliasesByType).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      identityType: "did",
    });
    expect(mockedAddLearnerIdentityAlias).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      identityType: "did",
      identityValue: "did:key:z6MkhLearnerDidExample",
      isPrimary: false,
      isVerified: true,
    });
  });

  it("clears learner DID and redirects with cleared status", async () => {
    const env = createEnv();

    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedRemoveLearnerIdentityAliasesByType.mockResolvedValue(1);

    const response = await app.request(
      "/tenants/tenant_123/learner/settings/did",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "content-type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          did: "",
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "", "http://localhost");
    expect(redirectUrl.pathname).toBe("/tenants/tenant_123/learner/dashboard");
    expect(redirectUrl.searchParams.get("didStatus")).toBe("cleared");
    expect(mockedRemoveLearnerIdentityAliasesByType).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      identityType: "did",
    });
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
    expect(mockedFindLearnerProfileByIdentity).not.toHaveBeenCalled();
  });

  it("rejects DID already linked to another learner profile", async () => {
    const env = createEnv();

    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileByIdentity.mockResolvedValue(
      sampleLearnerProfile({
        id: "lpr_other",
      }),
    );

    const response = await app.request(
      "/tenants/tenant_123/learner/settings/did",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "content-type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          did: "did:key:z6MkhConflictingDid",
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "", "http://localhost");
    expect(redirectUrl.pathname).toBe("/tenants/tenant_123/learner/dashboard");
    expect(redirectUrl.searchParams.get("didStatus")).toBe("conflict");
    expect(mockedRemoveLearnerIdentityAliasesByType).not.toHaveBeenCalled();
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
  });

  it("rejects invalid DID values and redirects with invalid status", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/learner/settings/did",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "content-type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          did: "did:example:unsupported",
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "", "http://localhost");
    expect(redirectUrl.pathname).toBe("/tenants/tenant_123/learner/dashboard");
    expect(redirectUrl.searchParams.get("didStatus")).toBe("invalid");
    expect(mockedFindUserById).not.toHaveBeenCalled();
    expect(mockedRemoveLearnerIdentityAliasesByType).not.toHaveBeenCalled();
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
  });
});

describe("POST /tenants/:tenantId/learner/badges/:assertionId/claim", () => {
  beforeEach(() => {
    mockedFindUserById.mockReset();
    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedListLearnerBadgeSummaries.mockReset();
    mockedListLearnerBadgeSummaries.mockResolvedValue([sampleLearnerBadge()]);
  });

  it("records an explicit learner claim and redirects back to the dashboard", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_456/claim",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    const redirectUrl = new URL(response.headers.get("location") ?? "", "http://localhost");

    expect(response.status).toBe(303);
    expect(redirectUrl.pathname).toBe("/tenants/tenant_123/learner/dashboard");
    expect(redirectUrl.searchParams.get("claimStatus")).toBe("recorded");
    expect(mockedRecordAssertionEngagementEvent).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        assertionId: "tenant_123:assertion_456",
        eventType: "learner_claim",
        actorType: "learner",
        channel: "learner_dashboard",
        occurredAt: expect.stringMatching(/^20/),
      }),
    );
  });

  it("keeps the claim flow idempotent when the learner already claimed the credential", async () => {
    const env = createEnv();

    mockedRecordAssertionEngagementEvent.mockResolvedValueOnce({
      status: "already_recorded",
      event: sampleAssertionEngagementEvent(),
    });

    const response = await app.request(
      "/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_456/claim",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    const redirectUrl = new URL(response.headers.get("location") ?? "", "http://localhost");

    expect(response.status).toBe(303);
    expect(redirectUrl.searchParams.get("claimStatus")).toBe("already_recorded");
  });
});
