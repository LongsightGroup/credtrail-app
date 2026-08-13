import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedFindLearnerProfileById,
  mockedListLearnerRecordAssertionExports,
  mockedListLearnerRecordEntries,
  mockedFindTenantMembership,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} = vi.hoisted(() => {
  return {
    mockedFindLearnerProfileById: vi.fn(),
    mockedListLearnerRecordAssertionExports: vi.fn(),
    mockedListLearnerRecordEntries: vi.fn(),
    mockedFindTenantMembership: vi.fn(),
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findLearnerProfileById: mockedFindLearnerProfileById,
    listLearnerRecordAssertionExports: mockedListLearnerRecordAssertionExports,
    listLearnerRecordEntries: mockedListLearnerRecordEntries,
    findTenantMembership: mockedFindTenantMembership,
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(() => ({
      prepare: vi.fn(),
    })),
  };
});

vi.mock("../auth/better-auth-adapter", async () => {
  const actual = await vi.importActual<typeof import("../auth/better-auth-adapter")>(
    "../auth/better-auth-adapter",
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

import type {
  LearnerProfileRecord,
  LearnerRecordAssertionExportRecord,
  LearnerRecordEntryRecord,
} from "@credtrail/db";

import { app } from "../index";
import { getSeededDemoLearnerRecordFixture } from "../learner-record/seeded-demo-learner-record-fixture";

const createEnv = () => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: "Learner One",
    createdAt: "2026-03-25T12:00:00.000Z",
    updatedAt: "2026-03-25T12:00:00.000Z",
    ...overrides,
  };
};

const sampleAssertionExport = (
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

beforeEach(() => {
  mockedFindLearnerProfileById.mockReset();
  mockedListLearnerRecordAssertionExports.mockReset();
  mockedListLearnerRecordEntries.mockReset();
  mockedFindTenantMembership.mockReset();
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockReset();

  mockedFindTenantMembership.mockResolvedValue({
    tenantId: "tenant_123",
    userId: "usr_admin",
    role: "admin",
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
  });
  mockedResolveBetterAuthPrincipal.mockResolvedValue({
    userId: "usr_admin",
    authSessionId: "ses_admin",
    authMethod: "better_auth",
    expiresAt: "2026-03-26T15:00:00.000Z",
  });
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue({
    tenantId: "tenant_123",
  });
  mockedFindLearnerProfileById.mockResolvedValue(sampleLearnerProfile());
  mockedListLearnerRecordAssertionExports.mockResolvedValue([sampleAssertionExport()]);
  mockedListLearnerRecordEntries.mockResolvedValue([sampleLearnerRecordEntry()]);
});

describe("learner-record export routes", () => {
  it("returns a tenant-scoped learner-record export bundle for admins", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/learner-records/lpr_123/export?profile=native_portable_json",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toEqual(
      expect.objectContaining({
        schemaVersion: "credtrail-learner-record-export/v1",
        profile: "native_portable_json",
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        counts: {
          totalItems: 2,
          badgeAssertions: 1,
          recordEntries: 1,
          issuerVerified: 2,
          learnerSupplemental: 0,
        },
      }),
    );
    expect(Array.isArray(body.items)).toBe(true);
    expect(mockedListLearnerRecordAssertionExports).toHaveBeenCalledWith(expect.any(Object), {
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
    });
  });

  it("can verify the seeded-demo learner-record export bundle on the normal route", async () => {
    const seededDemo = getSeededDemoLearnerRecordFixture();
    mockedFindLearnerProfileById.mockResolvedValueOnce(seededDemo.learnerProfile);
    mockedListLearnerRecordAssertionExports.mockResolvedValueOnce([...seededDemo.assertionExports]);
    mockedListLearnerRecordEntries.mockResolvedValueOnce([...seededDemo.recordEntries]);

    const response = await app.request(
      seededDemo.routeFamily.nativeExport,
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body).toEqual(
      expect.objectContaining({
        profile: "native_portable_json",
        learnerProfileId: seededDemo.learnerProfileId,
        counts: seededDemo.nativePortableExport.counts,
      }),
    );
    expect(Array.isArray(body.items)).toBe(true);
  });

  it("returns standards mapping output with native, mapped, and unavailable support states", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/learner-records/lpr_123/standards-mapping",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();
    const standardsMapping =
      body.standardsMapping && typeof body.standardsMapping === "object"
        ? (body.standardsMapping as Record<string, unknown>)
        : null;
    const frameworks = Array.isArray(standardsMapping?.frameworks)
      ? (standardsMapping?.frameworks as Array<Record<string, unknown>>)
      : [];
    const ob3 = frameworks.find((framework) => framework.framework === "ob3");

    expect(response.status).toBe(200);
    expect(body.profile).toBe("clr_alignment_json");
    expect(body.itemCounts).toEqual({
      totalItems: 2,
      badgeAssertions: 1,
      recordEntries: 1,
      issuerVerified: 2,
      learnerSupplemental: 0,
    });
    expect(ob3).toEqual(
      expect.objectContaining({
        framework: "ob3",
      }),
    );
    expect(Array.isArray((ob3 as { fields?: unknown[] } | undefined)?.fields)).toBe(true);
  });

  it("can verify the seeded-demo standards-mapping output on the normal route", async () => {
    const seededDemo = getSeededDemoLearnerRecordFixture();
    mockedFindLearnerProfileById.mockResolvedValueOnce(seededDemo.learnerProfile);
    mockedListLearnerRecordAssertionExports.mockResolvedValueOnce([...seededDemo.assertionExports]);
    mockedListLearnerRecordEntries.mockResolvedValueOnce([...seededDemo.recordEntries]);

    const response = await app.request(
      seededDemo.routeFamily.standardsMapping,
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.profile).toBe("clr_alignment_json");
    expect(body.itemCounts).toEqual(seededDemo.standardsMappingResponse.itemCounts);
  });

  it("rejects non-admin access to learner-record export routes", async () => {
    mockedFindTenantMembership.mockResolvedValueOnce({
      tenantId: "tenant_123",
      userId: "usr_viewer",
      role: "viewer",
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/learner-records/lpr_123/export",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(403);
  });

  it("returns 404 when the learner profile does not exist", async () => {
    mockedFindLearnerProfileById.mockResolvedValueOnce(null);

    const response = await app.request(
      "/v1/tenants/tenant_123/learner-records/lpr_missing/export",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(404);
    expect(body.error).toBe("Learner profile not found");
  });
});
