import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedGetTenantReportingComparisons,
  mockedGetTenantReportingEngagementCounts,
  mockedGetTenantReportingOverview,
  mockedGetTenantReportingTrends,
  mockedListTenantMembershipOrgUnitScopes,
  mockedListTenantOrgUnits,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} = vi.hoisted(() => {
  return {
    mockedGetTenantReportingComparisons: vi.fn(),
    mockedGetTenantReportingEngagementCounts: vi.fn(),
    mockedGetTenantReportingOverview: vi.fn(),
    mockedGetTenantReportingTrends: vi.fn(),
    mockedListTenantMembershipOrgUnitScopes: vi.fn(),
    mockedListTenantOrgUnits: vi.fn(),
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findTenantMembership: vi.fn(),
    getTenantReportingEngagementCounts: mockedGetTenantReportingEngagementCounts,
    getTenantReportingOverview: mockedGetTenantReportingOverview,
    getTenantReportingTrends: mockedGetTenantReportingTrends,
    listTenantMembershipOrgUnitScopes: mockedListTenantMembershipOrgUnitScopes,
    listTenantOrgUnits: mockedListTenantOrgUnits,
    listTenantReportingComparisons: mockedGetTenantReportingComparisons,
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
      revokeCurrentSession: vi.fn(() => Promise.resolve()),
    })),
  };
});

import {
  findTenantMembership,
  getTenantReportingEngagementCounts,
  getTenantReportingTrends,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  listTenantReportingComparisons,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRecord,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedGetTenantReportingComparisonsDb = vi.mocked(listTenantReportingComparisons);
const mockedGetTenantReportingEngagementCountsDb = vi.mocked(getTenantReportingEngagementCounts);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const mockedGetTenantReportingTrendsDb = vi.mocked(getTenantReportingTrends);
const mockedListTenantMembershipOrgUnitScopesDb = vi.mocked(listTenantMembershipOrgUnitScopes);
const mockedListTenantOrgUnitsDb = vi.mocked(listTenantOrgUnits);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = () => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

const stripBom = (value: string): string => {
  return value.replace(/^\uFEFF/, "");
};

const sampleReportingOrgUnits = (): TenantOrgUnitRecord[] => {
  return [
    {
      id: "tenant_123:org:institution",
      tenantId: "tenant_123",
      unitType: "institution",
      slug: "institution",
      displayName: "Tenant 123 Institution",
      parentOrgUnitId: null,
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:college-eng",
      tenantId: "tenant_123",
      unitType: "college",
      slug: "college-eng",
      displayName: "College of Engineering",
      parentOrgUnitId: "tenant_123:org:institution",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:college-arts",
      tenantId: "tenant_123",
      unitType: "college",
      slug: "college-arts",
      displayName: "College of Arts",
      parentOrgUnitId: "tenant_123:org:institution",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-cs",
      tenantId: "tenant_123",
      unitType: "department",
      slug: "department-cs",
      displayName: "Computer Science",
      parentOrgUnitId: "tenant_123:org:college-eng",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-math",
      tenantId: "tenant_123",
      unitType: "department",
      slug: "department-math",
      displayName: "Mathematics",
      parentOrgUnitId: "tenant_123:org:college-eng",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-history",
      tenantId: "tenant_123",
      unitType: "department",
      slug: "department-history",
      displayName: "History",
      parentOrgUnitId: "tenant_123:org:college-arts",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:program-cs",
      tenantId: "tenant_123",
      unitType: "program",
      slug: "program-cs",
      displayName: "Computer Science Program",
      parentOrgUnitId: "tenant_123:org:department-cs",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    },
  ];
};

const sampleScopedReportingScope = (
  overrides?: Partial<TenantMembershipOrgUnitScopeRecord>,
): TenantMembershipOrgUnitScopeRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_admin",
    orgUnitId: "tenant_123:org:college-eng",
    role: "issuer",
    createdByUserId: "usr_owner",
    createdAt: "2026-03-21T12:00:00.000Z",
    updatedAt: "2026-03-21T12:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue({
    tenantId: "tenant_123",
    userId: "usr_admin",
    role: "admin",
    createdAt: "2026-03-21T12:00:00.000Z",
    updatedAt: "2026-03-21T12:00:00.000Z",
  });
  mockedGetTenantReportingOverview.mockReset();
  mockedGetTenantReportingOverview.mockResolvedValue({
    tenantId: "tenant_123",
    filters: {
      issuedFrom: "2026-03-01",
      issuedTo: "2026-03-31",
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
    },
    counts: {
      issued: 14,
      active: 12,
      suspended: 1,
      revoked: 1,
      pendingReview: 1,
    },
    generatedAt: "2026-03-21T12:00:00.000Z",
  });
  mockedGetTenantReportingEngagementCountsDb.mockReset();
  mockedGetTenantReportingEngagementCountsDb.mockResolvedValue({
    issuedCount: 14,
    publicBadgeViewCount: 41,
    verificationViewCount: 16,
    shareClickCount: 7,
    learnerClaimCount: 5,
    walletAcceptCount: 4,
    claimRate: 35.7,
    shareRate: 28.6,
  });
  mockedGetTenantReportingTrendsDb.mockReset();
  mockedGetTenantReportingTrendsDb.mockResolvedValue({
    tenantId: "tenant_123",
    filters: {
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
    },
    bucket: "day",
    series: [
      {
        bucketStart: "2026-03-01",
        issuedCount: 3,
        publicBadgeViewCount: 8,
        verificationViewCount: 2,
        shareClickCount: 1,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
      },
      {
        bucketStart: "2026-03-02",
        issuedCount: 2,
        publicBadgeViewCount: 5,
        verificationViewCount: 3,
        shareClickCount: 2,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
      },
    ],
    generatedAt: "2026-03-21T12:00:00.000Z",
  });
  mockedGetTenantReportingComparisonsDb.mockReset();
  mockedGetTenantReportingComparisonsDb.mockImplementation(
    async (_db, input: { groupBy: "badgeTemplate" | "orgUnit" }) => {
      if (input.groupBy === "orgUnit") {
        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:institution",
            issuedCount: 14,
            publicBadgeViewCount: 41,
            verificationViewCount: 16,
            shareClickCount: 7,
            learnerClaimCount: 5,
            walletAcceptCount: 4,
            claimRate: 35.7,
            shareRate: 28.6,
          },
        ];
      }

      return [
        {
          groupBy: "badgeTemplate",
          groupId: "badge_template_001",
          issuedCount: 9,
          publicBadgeViewCount: 28,
          verificationViewCount: 11,
          shareClickCount: 5,
          learnerClaimCount: 4,
          walletAcceptCount: 3,
          claimRate: 44.4,
          shareRate: 33.3,
        },
      ];
    },
  );
  mockedListTenantMembershipOrgUnitScopesDb.mockReset();
  mockedListTenantMembershipOrgUnitScopesDb.mockResolvedValue([]);
  mockedListTenantOrgUnitsDb.mockReset();
  mockedListTenantOrgUnitsDb.mockResolvedValue(sampleReportingOrgUnits());
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockResolvedValue({
    userId: "usr_admin",
    authSessionId: "ba_ses_123",
    authMethod: "better_auth",
    expiresAt: "2026-03-21T23:00:00.000Z",
  });
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
});

describe("GET /v1/tenants/:tenantId/reporting/overview", () => {
  it("returns reporting overview counts and metric definitions for tenant admins", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/overview?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.json<{
      status: string;
      counts: {
        issued: number;
        pendingReview: number;
      };
      metrics: Array<{
        key: string;
        available: boolean;
        value: number | null;
      }>;
    }>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.counts).toEqual(
      expect.objectContaining({
        issued: 14,
        pendingReview: 1,
      }),
    );
    expect(body.metrics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          key: "issued",
          available: true,
          value: 14,
        }),
        expect.objectContaining({
          key: "claimRate",
          available: true,
          value: null,
        }),
      ]),
    );
    expect(mockedGetTenantReportingOverview).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      issuedFrom: "2026-03-01",
      issuedTo: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      state: undefined,
    });
  });

  it("returns 400 when the reporting query is invalid", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/overview?issuedFrom=2026-03-31&issuedTo=2026-03-01",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid reporting overview query");
  });

  it("returns 403 when the authenticated user is not a tenant admin", async () => {
    mockedFindTenantMembership.mockResolvedValue({
      tenantId: "tenant_123",
      userId: "usr_admin",
      role: "viewer",
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/overview",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(403);
  });
});

describe("GET /v1/tenants/:tenantId/reporting/hierarchy", () => {
  it("returns hierarchy rollups for the requested focus org and level", async () => {
    mockedGetTenantReportingComparisonsDb.mockImplementation(
      async (_db, input: { groupBy: "badgeTemplate" | "orgUnit" }) => {
        if (input.groupBy !== "orgUnit") {
          return [];
        }

        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-cs",
            issuedCount: 8,
            publicBadgeViewCount: 24,
            verificationViewCount: 9,
            shareClickCount: 5,
            learnerClaimCount: 4,
            walletAcceptCount: 2,
            claimRate: 50,
            shareRate: 37.5,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-math",
            issuedCount: 4,
            publicBadgeViewCount: 10,
            verificationViewCount: 3,
            shareClickCount: 1,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 50,
            shareRate: 25,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-history",
            issuedCount: 6,
            publicBadgeViewCount: 14,
            verificationViewCount: 5,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 33.3,
            shareRate: 16.7,
          },
        ];
      },
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/hierarchy?from=2026-03-01&to=2026-03-31&focusOrgUnitId=tenant_123:org:college-eng&level=department",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.json<{
      status: string;
      filters: {
        focusOrgUnitId: string | null;
        level: string;
      };
      rows: Array<{
        orgUnitId: string;
        level: string;
        issuedCount: number;
      }>;
    }>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.filters).toEqual({
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
      focusOrgUnitId: "tenant_123:org:college-eng",
      level: "department",
    });
    expect(body.rows).toEqual([
      expect.objectContaining({
        orgUnitId: "tenant_123:org:department-cs",
        level: "department",
        issuedCount: 8,
      }),
      expect.objectContaining({
        orgUnitId: "tenant_123:org:department-math",
        level: "department",
        issuedCount: 4,
      }),
    ]);
  });
});

describe("GET /v1/tenants/:tenantId/reporting/engagement", () => {
  it("returns raw engagement counts separately from rate metrics", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/engagement?from=2026-03-01&to=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.json<{
      status: string;
      counts: {
        publicBadgeViewCount: number;
      };
      rates: {
        claimRate: number;
        shareRate: number;
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.counts).toEqual(
      expect.objectContaining({
        publicBadgeViewCount: 41,
      }),
    );
    expect(body.rates).toEqual({
      claimRate: 35.7,
      shareRate: 28.6,
    });
    expect(mockedGetTenantReportingEngagementCountsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      state: undefined,
    });
  });
});

describe("GET /v1/tenants/:tenantId/reporting/trends", () => {
  it("returns time-bucketed issuance and engagement series for the selected filters", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/trends?from=2026-03-01&to=2026-03-31&bucket=day",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.json<{
      status: string;
      bucket: string;
      series: Array<{
        bucketStart: string;
        issuedCount: number;
        learnerClaimCount: number;
      }>;
    }>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.bucket).toBe("day");
    expect(body.series).toEqual([
      expect.objectContaining({
        bucketStart: "2026-03-01",
        issuedCount: 3,
        learnerClaimCount: 1,
      }),
      expect.objectContaining({
        bucketStart: "2026-03-02",
        issuedCount: 2,
        learnerClaimCount: 1,
      }),
    ]);
    expect(mockedGetTenantReportingTrendsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      bucket: "day",
    });
  });
});

describe("GET /v1/tenants/:tenantId/reporting/comparisons", () => {
  it("returns comparison rows for the requested grouping", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/comparisons?from=2026-03-01&to=2026-03-31&groupBy=badgeTemplate",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.json<{
      status: string;
      rows: Array<{
        groupBy: string;
        groupId: string;
        counts: {
          issuedCount: number;
        };
        rates: {
          shareRate: number;
        };
      }>;
    }>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.rows).toEqual([
      expect.objectContaining({
        groupBy: "badgeTemplate",
        groupId: "badge_template_001",
        counts: expect.objectContaining({
          issuedCount: 9,
        }),
        rates: expect.objectContaining({
          shareRate: 33.3,
        }),
      }),
    ]);
    expect(mockedGetTenantReportingComparisonsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      groupBy: "badgeTemplate",
    });
  });

  it("allows scoped issuers to read in-scope comparisons and rejects out-of-scope hierarchy focus", async () => {
    mockedFindTenantMembership.mockResolvedValue({
      tenantId: "tenant_123",
      userId: "usr_admin",
      role: "issuer",
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedListTenantMembershipOrgUnitScopesDb.mockResolvedValue([sampleScopedReportingScope()]);
    mockedGetTenantReportingComparisonsDb.mockImplementation(
      async (_db, input: { groupBy: "badgeTemplate" | "orgUnit" }) => {
        if (input.groupBy !== "orgUnit") {
          return [];
        }

        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-cs",
            issuedCount: 7,
            publicBadgeViewCount: 18,
            verificationViewCount: 7,
            shareClickCount: 3,
            learnerClaimCount: 3,
            walletAcceptCount: 2,
            claimRate: 42.9,
            shareRate: 28.6,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-history",
            issuedCount: 5,
            publicBadgeViewCount: 11,
            verificationViewCount: 4,
            shareClickCount: 2,
            learnerClaimCount: 1,
            walletAcceptCount: 1,
            claimRate: 20,
            shareRate: 20,
          },
        ];
      },
    );

    const inScopeResponse = await app.request(
      "/v1/tenants/tenant_123/reporting/comparisons?groupBy=orgUnit",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const inScopeBody = await inScopeResponse.json<{
      rows: Array<{
        groupId: string;
      }>;
    }>();

    expect(inScopeResponse.status).toBe(200);
    expect(inScopeBody.rows).toEqual([
      expect.objectContaining({
        groupId: "tenant_123:org:department-cs",
      }),
    ]);
    expect(mockedGetTenantReportingComparisonsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: undefined,
      to: undefined,
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      groupBy: "orgUnit",
    });

    const outOfScopeResponse = await app.request(
      "/v1/tenants/tenant_123/reporting/hierarchy?focusOrgUnitId=tenant_123:org:college-arts&level=department",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const outOfScopeBody = await outOfScopeResponse.json<{ error: string }>();

    expect(outOfScopeResponse.status).toBe(403);
    expect(outOfScopeBody.error).toBe("Requested org unit is outside reporting scope");
  });
});

describe("GET /v1/tenants/:tenantId/reporting/*.csv", () => {
  it("returns CSV attachments for scoped overview exports and preserves reporting scope checks", async () => {
    mockedFindTenantMembership.mockResolvedValue({
      tenantId: "tenant_123",
      userId: "usr_admin",
      role: "issuer",
      createdAt: "2026-03-21T12:00:00.000Z",
      updatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedListTenantMembershipOrgUnitScopesDb.mockResolvedValue([sampleScopedReportingScope()]);

    const inScopeResponse = await app.request(
      "/v1/tenants/tenant_123/reporting/overview/export.csv?issuedFrom=2026-03-01&issuedTo=2026-03-31&orgUnitId=tenant_123:org:department-cs",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const inScopeBody = await inScopeResponse.text();

    expect(inScopeResponse.status).toBe(200);
    expect(inScopeResponse.headers.get("cache-control")).toBe("no-store");
    expect(inScopeResponse.headers.get("content-type")).toBe("text/csv; charset=utf-8");
    expect(inScopeResponse.headers.get("content-disposition")).toContain('attachment; filename="');
    expect(stripBom(inScopeBody).startsWith("Tenant ID,")).toBe(true);
    expect(stripBom(inScopeBody)).toContain("Issued");
    expect(mockedGetTenantReportingOverview).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      issuedFrom: "2026-03-01",
      issuedTo: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: "tenant_123:org:department-cs",
      state: undefined,
    });

    const outOfScopeResponse = await app.request(
      "/v1/tenants/tenant_123/reporting/overview/export.csv?orgUnitId=tenant_123:org:department-history",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const outOfScopeBody = await outOfScopeResponse.json<{ error: string }>();

    expect(outOfScopeResponse.status).toBe(403);
    expect(outOfScopeBody.error).toBe("Requested org unit is outside reporting scope");
  });

  it("preserves exact-match orgUnitId filters for comparison exports", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/comparisons/export.csv?issuedFrom=2026-03-01&issuedTo=2026-03-31&groupBy=badgeTemplate&orgUnitId=tenant_123:org:department-cs",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/csv; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(stripBom(body)).toContain("Group ID");
    expect(mockedGetTenantReportingComparisonsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: "tenant_123:org:department-cs",
      groupBy: "badgeTemplate",
    });
  });

  it("preserves explicit focusOrgUnitId and level hierarchy drilldown semantics for exports", async () => {
    mockedGetTenantReportingComparisonsDb.mockImplementation(
      async (_db, input: { groupBy: "badgeTemplate" | "orgUnit" }) => {
        if (input.groupBy !== "orgUnit") {
          return [];
        }

        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-cs",
            issuedCount: 8,
            publicBadgeViewCount: 24,
            verificationViewCount: 9,
            shareClickCount: 5,
            learnerClaimCount: 4,
            walletAcceptCount: 2,
            claimRate: 50,
            shareRate: 37.5,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-history",
            issuedCount: 6,
            publicBadgeViewCount: 14,
            verificationViewCount: 5,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 33.3,
            shareRate: 16.7,
          },
        ];
      },
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/reporting/hierarchy/export.csv?issuedFrom=2026-03-01&issuedTo=2026-03-31&badgeTemplateId=badge_template_001&orgUnitId=tenant_123%3Aorg%3Adepartment-cs&state=active&focusOrgUnitId=tenant_123:org:college-eng&level=department",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = stripBom(await response.text());

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/csv; charset=utf-8");
    expect(mockedGetTenantReportingComparisonsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:department-cs",
      state: "active",
      groupBy: "orgUnit",
    });
    expect(body).toContain("Badge Template ID");
    expect(body).toContain("Lifecycle State");
    expect(body).toContain("Computer Science");
    expect(body).not.toContain("History");
  });
});
