import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  hoistedFindLearnerProfileById,
  hoistedFindLearnerProfileByIdentity,
  hoistedListLearnerProfilesForRecordLookup,
  hoistedListLearnerRecordAssertionExports,
  hoistedListLearnerRecordEntries,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
  mockedFindActiveSessionByHash,
  mockedTouchSession,
} = vi.hoisted(() => {
  return {
    hoistedFindLearnerProfileById: vi.fn(),
    hoistedFindLearnerProfileByIdentity: vi.fn(),
    hoistedListLearnerProfilesForRecordLookup: vi.fn(),
    hoistedListLearnerRecordAssertionExports: vi.fn(),
    hoistedListLearnerRecordEntries: vi.fn(),
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
    mockedFindActiveSessionByHash: vi.fn(),
    mockedTouchSession: vi.fn(),
  };
});

describe("admin learner-record review route", () => {
  it("renders the bounded learner-record review route for admins", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?learner=learner-123",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner Records");
    expect(body).toContain("Load learner record");
    expect(body).toContain("Download native portable export");
    expect(body).toContain("Open standards mapping");
    expect(mockedListLearnerProfilesForRecordLookup).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      lookupValue: "learner-123",
    });
  });

  it("can verify the canonical seeded-demo learner-record review route for admins", async () => {
    const env = createEnv();
    const seededDemo = getSeededDemoLearnerRecordFixture();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedListLearnerProfilesForRecordLookup.mockResolvedValueOnce([seededDemo.learnerProfile]);
    mockedListLearnerRecordAssertionExports.mockResolvedValueOnce([...seededDemo.assertionExports]);
    mockedListLearnerRecordEntries.mockResolvedValueOnce([...seededDemo.recordEntries]);

    const response = await app.request(
      seededDemo.routeFamily.adminReview,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner Records");
    expect(body).toContain("Portfolio Reflection");
    expect(body).toContain("Leadership Society Membership");
    expect(body).toContain(`href="${seededDemo.routeFamily.nativeExport}"`);
    expect(body).toContain(`href="${seededDemo.routeFamily.standardsMapping}"`);
  });

  it("rejects overlong learner-record review queries", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));

    const response = await app.request(
      `/tenants/tenant_123/admin/operations/learner-records?learner=${"x".repeat(321)}`,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid learner-record review query");
  });
});

describe("admin learner-record import route", () => {
  it("renders the dedicated learner-record import route for admins", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-record-imports",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner Record Imports");
    expect(body).toContain("Download CSV template");
    expect(body).toContain("Current import progress");
  });

  it("keeps learner-record import preview inside the admin operations route family", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    const formData = new FormData();
    formData.set(
      "file",
      new File(
        [
          [
            "learnerEmail,title,recordType,issuedAt,badgeTemplateUrlKey,pathwayLabel",
            "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z,migration-foundations,Clinical readiness",
          ].join("\n"),
        ],
        "learner-records.csv",
        {
          type: "text/csv",
        },
      ),
    );

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-record-imports/preview",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner-record import preview ready");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/operations/learner-record-imports/preview"',
    );
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/operations/learner-record-imports/apply"',
    );
    expect(body).toContain("Queue reviewed import");
    expect(body).not.toContain("/v1/tenants/tenant_123/learner-record-imports/csv");
  });
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    countTenantMembershipsByRole: vi.fn(),
    createAuditLog: vi.fn(),
    createLearnerRecordImportPreview: vi.fn(),
    createDelegatedIssuingAuthorityGrant: vi.fn(),
    createTenantApiKey: vi.fn(),
    createTenantOrgUnit: vi.fn(),
    enqueueJobQueueMessageOnce: vi.fn(),
    findActiveDelegatedIssuingAuthorityGrantForAction: vi.fn(),
    findActiveLearnerRecordImportPreview: vi.fn(),
    findActiveSessionByHash: mockedFindActiveSessionByHash,
    findBadgeTemplateById: vi.fn(),
    findDelegatedIssuingAuthorityGrantById: vi.fn(),
    findActiveTenantBreakGlassAccountByUserId: vi.fn(),
    findLearnerProfileById: hoistedFindLearnerProfileById,
    findLearnerProfileByIdentity: hoistedFindLearnerProfileByIdentity,
    listLearnerProfilesForRecordLookup: hoistedListLearnerProfilesForRecordLookup,
    findTenantAuthPolicy: vi.fn(),
    findTenantMembership: vi.fn(),
    findTenantById: vi.fn(),
    findUserById: vi.fn(),
    findUsersByIds: vi.fn(),
    getTenantReportingEngagementCounts: vi.fn(),
    getTenantReportingOverview: vi.fn(),
    getTenantReportingTrends: vi.fn(),
    hasTenantMembershipOrgUnitAccess: vi.fn(),
    hasTenantMembershipOrgUnitScopeAssignments: vi.fn(),
    listAccessibleTenantContextsForUser: vi.fn(),
    listBadgeIssuanceRules: vi.fn(),
    listBadgeIssuanceRuleVersions: vi.fn(),
    listBadgeIssuanceRuleVersionsForRules: vi.fn(),
    findTenantOrgUnitById: vi.fn(),
    listAuditLogs: vi.fn(),
    listBadgeTemplates: vi.fn(),
    countBadgeTemplateImageRevisions: vi.fn(),
    listBadgeTemplateImageRevisionCountsByTenant: vi.fn(),
    listBadgeTemplateOwnershipEvents: vi.fn(),
    listDelegatedIssuingAuthorityGrantEvents: vi.fn(),
    listDelegatedIssuingAuthorityGrants: vi.fn(),
    listImportLearnerRecordBatchQueueMessages: vi.fn(),
    listLearnerRecordAssertionExports: hoistedListLearnerRecordAssertionExports,
    listLearnerRecordEntries: hoistedListLearnerRecordEntries,
    listTenantAuthProviders: vi.fn(),
    listTenantMembershipOrgUnitScopes: vi.fn(),
    listTenantOrgUnits: vi.fn(),
    listTenantApiKeys: vi.fn(),
    listTenantBreakGlassAccounts: vi.fn(),
    listTenantLmsConnections: vi.fn(),
    listTenantMembers: vi.fn(),
    listTenantReportingComparisons: vi.fn(),
    markLearnerRecordImportPreviewQueued: vi.fn(),
    removeTenantMembership: vi.fn(),
    removeTenantMembershipOrgUnitScope: vi.fn(),
    revokeTenantApiKey: vi.fn(),
    revokeTenantBreakGlassAccount: vi.fn(),
    revokeDelegatedIssuingAuthorityGrant: vi.fn(),
    touchSession: mockedTouchSession,
    transferBadgeTemplateOwnership: vi.fn(),
    updateBadgeTemplate: vi.fn(),
    upsertTenantMembershipRole: vi.fn(),
    upsertTenantMembershipOrgUnitScope: vi.fn(),
    upsertUserByEmail: vi.fn(),
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
  countTenantMembershipsByRole,
  createAuditLog,
  createLearnerRecordImportPreview,
  createDelegatedIssuingAuthorityGrant,
  createTenantApiKey,
  createTenantOrgUnit,
  enqueueJobQueueMessageOnce,
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findActiveLearnerRecordImportPreview,
  findActiveTenantBreakGlassAccountByUserId,
  findBadgeTemplateById,
  findDelegatedIssuingAuthorityGrantById,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  listLearnerProfilesForRecordLookup,
  findTenantAuthPolicy,
  findTenantMembership,
  findTenantById,
  findTenantOrgUnitById,
  findUserById,
  findUsersByIds,
  getTenantReportingEngagementCounts,
  getTenantReportingOverview,
  getTenantReportingTrends,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listAccessibleTenantContextsForUser,
  listBadgeIssuanceRules,
  listAuditLogs,
  listBadgeIssuanceRuleVersions,
  listBadgeIssuanceRuleVersionsForRules,
  listBadgeTemplates,
  listBadgeTemplateImageRevisionCountsByTenant,
  listBadgeTemplateOwnershipEvents,
  listDelegatedIssuingAuthorityGrantEvents,
  listDelegatedIssuingAuthorityGrants,
  listImportLearnerRecordBatchQueueMessages,
  listLearnerRecordAssertionExports,
  listLearnerRecordEntries,
  listTenantAuthProviders,
  listTenantApiKeys,
  listTenantBreakGlassAccounts,
  listTenantLmsConnections,
  listTenantMembers,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  listTenantReportingComparisons,
  markLearnerRecordImportPreviewQueued,
  removeTenantMembership,
  removeTenantMembershipOrgUnitScope,
  revokeTenantApiKey,
  revokeTenantBreakGlassAccount,
  revokeDelegatedIssuingAuthorityGrant,
  transferBadgeTemplateOwnership,
  updateBadgeTemplate,
  upsertTenantMembershipRole,
  upsertTenantMembershipOrgUnitScope,
  upsertUserByEmail,
  type TenantApiKeyRecord,
  type AuditLogRecord,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityGrantEventRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantRecord,
  type TenantMembershipOrgUnitScopeRecord,
  type TenantMembershipRecord,
  type TenantMemberRecord,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { getSeededDemoLearnerRecordFixture } from "./learner-record/seeded-demo-learner-record-fixture";
import { getSeededDemoReportingRouteFixture } from "./reporting/seeded-demo-reporting-fixture";

interface ErrorResponse {
  error: string;
}

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedListAuditLogs = vi.mocked(listAuditLogs);
const mockedUpdateBadgeTemplate = vi.mocked(updateBadgeTemplate);
const mockedCountTenantMembershipsByRole = vi.mocked(countTenantMembershipsByRole);
const mockedCreateLearnerRecordImportPreview = vi.mocked(createLearnerRecordImportPreview);
const mockedCreateDelegatedIssuingAuthorityGrant = vi.mocked(createDelegatedIssuingAuthorityGrant);
const mockedCreateTenantApiKey = vi.mocked(createTenantApiKey);
const mockedCreateTenantOrgUnit = vi.mocked(createTenantOrgUnit);
const mockedFindActiveDelegatedIssuingAuthorityGrantForAction = vi.mocked(
  findActiveDelegatedIssuingAuthorityGrantForAction,
);
const mockedFindActiveLearnerRecordImportPreview = vi.mocked(findActiveLearnerRecordImportPreview);
const mockedFindActiveTenantBreakGlassAccountByUserId = vi.mocked(
  findActiveTenantBreakGlassAccountByUserId,
);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindDelegatedIssuingAuthorityGrantById = vi.mocked(
  findDelegatedIssuingAuthorityGrantById,
);
const mockedFindLearnerProfileById = vi.mocked(findLearnerProfileById);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedListLearnerProfilesForRecordLookup = vi.mocked(listLearnerProfilesForRecordLookup);
const mockedFindTenantAuthPolicy = vi.mocked(findTenantAuthPolicy);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindTenantById = vi.mocked(findTenantById);
const mockedFindTenantOrgUnitById = vi.mocked(findTenantOrgUnitById);
const mockedFindUserById = vi.mocked(findUserById);
const mockedFindUsersByIds = vi.mocked(findUsersByIds);
const mockedGetTenantReportingEngagementCounts = vi.mocked(getTenantReportingEngagementCounts);
const mockedGetTenantReportingOverview = vi.mocked(getTenantReportingOverview);
const mockedGetTenantReportingTrends = vi.mocked(getTenantReportingTrends);
const mockedEnqueueJobQueueMessageOnce = vi.mocked(enqueueJobQueueMessageOnce);
const mockedHasTenantMembershipOrgUnitAccess = vi.mocked(hasTenantMembershipOrgUnitAccess);
const mockedHasTenantMembershipOrgUnitScopeAssignments = vi.mocked(
  hasTenantMembershipOrgUnitScopeAssignments,
);
const mockedListAccessibleTenantContextsForUser = vi.mocked(listAccessibleTenantContextsForUser);
const mockedListBadgeIssuanceRules = vi.mocked(listBadgeIssuanceRules);
const mockedListBadgeIssuanceRuleVersions = vi.mocked(listBadgeIssuanceRuleVersions);
const mockedListBadgeIssuanceRuleVersionsForRules = vi.mocked(
  listBadgeIssuanceRuleVersionsForRules,
);
const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
const mockedListBadgeTemplateImageRevisionCountsByTenant = vi.mocked(
  listBadgeTemplateImageRevisionCountsByTenant,
);
const mockedListBadgeTemplateOwnershipEvents = vi.mocked(listBadgeTemplateOwnershipEvents);
const mockedListDelegatedIssuingAuthorityGrantEvents = vi.mocked(
  listDelegatedIssuingAuthorityGrantEvents,
);
const mockedListDelegatedIssuingAuthorityGrants = vi.mocked(listDelegatedIssuingAuthorityGrants);
const mockedListImportLearnerRecordBatchQueueMessages = vi.mocked(
  listImportLearnerRecordBatchQueueMessages,
);
const mockedListLearnerRecordAssertionExports = vi.mocked(listLearnerRecordAssertionExports);
const mockedListLearnerRecordEntries = vi.mocked(listLearnerRecordEntries);
const mockedListTenantAuthProviders = vi.mocked(listTenantAuthProviders);
const mockedListTenantApiKeys = vi.mocked(listTenantApiKeys);
const mockedListTenantBreakGlassAccounts = vi.mocked(listTenantBreakGlassAccounts);
const mockedListTenantLmsConnections = vi.mocked(listTenantLmsConnections);
const mockedListTenantMembers = vi.mocked(listTenantMembers);
const mockedListTenantMembershipOrgUnitScopes = vi.mocked(listTenantMembershipOrgUnitScopes);
const mockedListTenantOrgUnits = vi.mocked(listTenantOrgUnits);
const mockedListTenantReportingComparisons = vi.mocked(listTenantReportingComparisons);
const mockedMarkLearnerRecordImportPreviewQueued = vi.mocked(markLearnerRecordImportPreviewQueued);
const mockedRemoveTenantMembership = vi.mocked(removeTenantMembership);
const mockedRemoveTenantMembershipOrgUnitScope = vi.mocked(removeTenantMembershipOrgUnitScope);
const mockedRevokeTenantApiKey = vi.mocked(revokeTenantApiKey);
const mockedRevokeTenantBreakGlassAccount = vi.mocked(revokeTenantBreakGlassAccount);
const mockedRevokeDelegatedIssuingAuthorityGrant = vi.mocked(revokeDelegatedIssuingAuthorityGrant);
const mockedTransferBadgeTemplateOwnership = vi.mocked(transferBadgeTemplateOwnership);
const mockedUpsertTenantMembershipRole = vi.mocked(upsertTenantMembershipRole);
const mockedUpsertTenantMembershipOrgUnitScope = vi.mocked(upsertTenantMembershipOrgUnitScope);
const mockedUpsertUserByEmail = vi.mocked(upsertUserByEmail);
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

const getReportingPanelArticleMarkup = (html: string, heading: string): string => {
  const headingMarkup = `<h2>${heading}</h2>`;
  const headingIndex = html.indexOf(headingMarkup);

  expect(headingIndex).toBeGreaterThan(-1);

  const start = html.lastIndexOf("<article", headingIndex);

  expect(start).toBeGreaterThan(-1);

  const end = html.indexOf("</article>", headingIndex);

  expect(end).toBeGreaterThan(start);

  return html.slice(start, end);
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

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
  mockedFindTenantById.mockReset();
  mockedFindTenantById.mockResolvedValue(sampleTenant());
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: "usr_123",
    email: "learner@example.edu",
  });
  mockedFindUsersByIds.mockReset();
  mockedFindUsersByIds.mockImplementation(async (_db, userIds) => {
    const usersById = new Map<string, { id: string; email: string }>();

    for (const userId of userIds) {
      const user = await mockedFindUserById(_db, userId);

      if (user !== null) {
        usersById.set(userId, user);
      }
    }

    return usersById;
  });
  mockedFindDelegatedIssuingAuthorityGrantById.mockReset();
  mockedFindDelegatedIssuingAuthorityGrantById.mockResolvedValue(null);
  mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
  mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
  mockedFindActiveTenantBreakGlassAccountByUserId.mockReset();
  mockedFindActiveTenantBreakGlassAccountByUserId.mockResolvedValue(null);
  mockedHasTenantMembershipOrgUnitAccess.mockReset();
  mockedHasTenantMembershipOrgUnitAccess.mockResolvedValue(false);
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockReset();
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockResolvedValue(false);
  mockedListAccessibleTenantContextsForUser.mockReset();
  mockedListAccessibleTenantContextsForUser.mockResolvedValue([]);
  mockedFindLearnerProfileById.mockReset();
  mockedFindLearnerProfileById.mockResolvedValue({
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: "Learner One",
    createdAt: "2026-03-25T12:00:00.000Z",
    updatedAt: "2026-03-25T12:00:00.000Z",
  });
  mockedFindLearnerProfileByIdentity.mockReset();
  mockedFindLearnerProfileByIdentity.mockResolvedValue({
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: "Learner One",
    createdAt: "2026-03-25T12:00:00.000Z",
    updatedAt: "2026-03-25T12:00:00.000Z",
  });
  mockedListLearnerProfilesForRecordLookup.mockReset();
  mockedListLearnerProfilesForRecordLookup.mockResolvedValue([
    {
      id: "lpr_123",
      tenantId: "tenant_123",
      subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
      displayName: "Learner One",
      createdAt: "2026-03-25T12:00:00.000Z",
      updatedAt: "2026-03-25T12:00:00.000Z",
    },
  ]);
  mockedListLearnerRecordAssertionExports.mockReset();
  mockedListLearnerRecordAssertionExports.mockResolvedValue([
    {
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
    },
  ]);
  mockedListLearnerRecordEntries.mockReset();
  mockedListLearnerRecordEntries.mockResolvedValue([
    {
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
    },
  ]);
  mockedListBadgeIssuanceRules.mockReset();
  mockedListBadgeIssuanceRules.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleVersions.mockReset();
  mockedListBadgeIssuanceRuleVersions.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleVersionsForRules.mockReset();
  mockedListBadgeIssuanceRuleVersionsForRules.mockResolvedValue([]);
  mockedFindTenantOrgUnitById.mockReset();
  mockedFindTenantOrgUnitById.mockResolvedValue(null);
  mockedListBadgeTemplates.mockReset();
  mockedListBadgeTemplates.mockResolvedValue([sampleBadgeTemplate()]);
  mockedListBadgeTemplateImageRevisionCountsByTenant.mockReset();
  mockedListBadgeTemplateImageRevisionCountsByTenant.mockResolvedValue([]);
  mockedListBadgeTemplateOwnershipEvents.mockReset();
  mockedListBadgeTemplateOwnershipEvents.mockResolvedValue([]);
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
  mockedListDelegatedIssuingAuthorityGrantEvents.mockReset();
  mockedListDelegatedIssuingAuthorityGrantEvents.mockResolvedValue([]);
  mockedListDelegatedIssuingAuthorityGrants.mockReset();
  mockedListDelegatedIssuingAuthorityGrants.mockResolvedValue([]);
  mockedListImportLearnerRecordBatchQueueMessages.mockReset();
  mockedListImportLearnerRecordBatchQueueMessages.mockResolvedValue([]);
  mockedCreateLearnerRecordImportPreview.mockReset();
  mockedCreateLearnerRecordImportPreview.mockImplementation(async (_db, input) => ({
    tenantId: input.tenantId,
    batchId: input.batchId,
    fileName: input.fileName,
    format: input.format,
    defaultsJson: input.defaultsJson,
    reportsJson: input.reportsJson,
    queuePayloadsJson: input.queuePayloadsJson,
    createdByUserId: input.createdByUserId ?? null,
    createdAt: input.createdAt,
    expiresAt: input.expiresAt,
    queuedAt: null,
  }));
  mockedFindActiveLearnerRecordImportPreview.mockReset();
  mockedFindActiveLearnerRecordImportPreview.mockResolvedValue(null);
  mockedMarkLearnerRecordImportPreviewQueued.mockReset();
  mockedMarkLearnerRecordImportPreviewQueued.mockResolvedValue(true);
  mockedEnqueueJobQueueMessageOnce.mockReset();
  mockedEnqueueJobQueueMessageOnce.mockResolvedValue(true);
  mockedFindTenantAuthPolicy.mockReset();
  mockedFindTenantAuthPolicy.mockResolvedValue(null);
  mockedGetTenantReportingEngagementCounts.mockReset();
  mockedGetTenantReportingEngagementCounts.mockResolvedValue({
    issuedCount: 5,
    publicBadgeViewCount: 14,
    verificationViewCount: 5,
    shareClickCount: 2,
    learnerClaimCount: 2,
    walletAcceptCount: 1,
    claimRate: 40,
    shareRate: 20,
  });
  mockedGetTenantReportingOverview.mockReset();
  mockedGetTenantReportingOverview.mockResolvedValue({
    tenantId: "tenant_123",
    filters: {
      issuedFrom: null,
      issuedTo: null,
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
    },
    counts: {
      issued: 5,
      active: 5,
      suspended: 0,
      revoked: 0,
      pendingReview: 0,
      claimRate: 40,
      shareRate: 20,
    },
    generatedAt: "2026-03-21T12:00:00.000Z",
  });
  mockedGetTenantReportingTrends.mockReset();
  mockedGetTenantReportingTrends.mockResolvedValue({
    tenantId: "tenant_123",
    filters: {
      from: null,
      to: null,
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
    },
    bucket: "day",
    series: [
      {
        bucketStart: "2026-03-01",
        issuedCount: 5,
        publicBadgeViewCount: 14,
        verificationViewCount: 5,
        shareClickCount: 2,
        learnerClaimCount: 2,
        walletAcceptCount: 1,
      },
    ],
    generatedAt: "2026-03-21T12:00:00.000Z",
  });
  mockedListTenantAuthProviders.mockReset();
  mockedListTenantAuthProviders.mockResolvedValue([]);
  mockedListTenantApiKeys.mockReset();
  mockedListTenantApiKeys.mockResolvedValue([]);
  mockedListTenantBreakGlassAccounts.mockReset();
  mockedListTenantBreakGlassAccounts.mockResolvedValue([]);
  mockedListTenantLmsConnections.mockReset();
  mockedListTenantLmsConnections.mockResolvedValue([]);
  mockedListTenantMembers.mockReset();
  mockedListTenantMembers.mockResolvedValue([
    sampleTenantMember({
      userId: "usr_123",
      email: "learner@example.edu",
      role: "admin",
    }),
  ]);
  mockedListTenantMembershipOrgUnitScopes.mockReset();
  mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([]);
  mockedListTenantOrgUnits.mockReset();
  mockedListTenantOrgUnits.mockResolvedValue([]);
  mockedListTenantReportingComparisons.mockReset();
  mockedListTenantReportingComparisons.mockImplementation(
    async (_db, input: { groupBy: "badgeTemplate" | "orgUnit" }) => {
      if (input.groupBy === "badgeTemplate") {
        return [
          {
            groupBy: "badgeTemplate",
            groupId: "badge_template_001",
            issuedCount: 5,
            publicBadgeViewCount: 14,
            verificationViewCount: 5,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 40,
            shareRate: 20,
          },
        ];
      }

      return [
        {
          groupBy: "orgUnit",
          groupId: "tenant_123:org:institution",
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
          claimRate: 40,
          shareRate: 20,
        },
      ];
    },
  );
  mockedCreateTenantOrgUnit.mockReset();
  mockedCreateTenantApiKey.mockReset();
  mockedCreateTenantApiKey.mockResolvedValue(sampleTenantApiKey());
  mockedTransferBadgeTemplateOwnership.mockReset();
  mockedUpsertTenantMembershipOrgUnitScope.mockReset();
  mockedRemoveTenantMembershipOrgUnitScope.mockReset();
  mockedRemoveTenantMembershipOrgUnitScope.mockResolvedValue(false);
  mockedRemoveTenantMembership.mockReset();
  mockedRemoveTenantMembership.mockResolvedValue(true);
  mockedRevokeTenantApiKey.mockReset();
  mockedRevokeTenantApiKey.mockResolvedValue(false);
  mockedRevokeTenantBreakGlassAccount.mockReset();
  mockedRevokeTenantBreakGlassAccount.mockResolvedValue(false);
  mockedCreateDelegatedIssuingAuthorityGrant.mockReset();
  mockedRevokeDelegatedIssuingAuthorityGrant.mockReset();
  mockedCountTenantMembershipsByRole.mockReset();
  mockedCountTenantMembershipsByRole.mockResolvedValue({
    owner: 1,
    admin: 1,
    issuer: 0,
    approver: 0,
    viewer: 0,
  });
  mockedUpsertTenantMembershipRole.mockReset();
  mockedUpsertTenantMembershipRole.mockImplementation(async (_db, input) => {
    return {
      membership: sampleTenantMembership({
        tenantId: input.tenantId,
        userId: input.userId,
        role: input.role,
      }),
      previousRole: null,
      changed: true,
    };
  });
  mockedUpsertUserByEmail.mockReset();
  mockedUpsertUserByEmail.mockResolvedValue({
    id: "usr_colleague",
    email: "colleague@example.edu",
  });
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  mockedListAuditLogs.mockReset();
  mockedListAuditLogs.mockResolvedValue([]);
  mockedUpdateBadgeTemplate.mockReset();
  mockedUpdateBadgeTemplate.mockResolvedValue(sampleBadgeTemplate());
});

afterEach(() => {
  vi.doUnmock("./auth/better-auth-adapter");
});

const sampleSession = (overrides?: { tenantId?: string; userId?: string }): SessionRecord => {
  return {
    id: "ses_123",
    tenantId: overrides?.tenantId ?? "tenant_123",
    userId: overrides?.userId ?? "usr_123",
    sessionTokenHash: "session-hash",
    expiresAt: "2026-02-11T22:00:00.000Z",
    lastSeenAt: "2026-02-10T22:00:00.000Z",
    revokedAt: null,
    createdAt: "2026-02-10T22:00:00.000Z",
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
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleTenantApiKey = (overrides?: Partial<TenantApiKeyRecord>): TenantApiKeyRecord => {
  return {
    id: "tak_123",
    tenantId: "tenant_123",
    label: "Integration key",
    keyPrefix: "ctak_abc12345",
    keyHash: "hash_123",
    scopesJson: '["queue.issue","queue.revoke"]',
    createdByUserId: "usr_123",
    expiresAt: null,
    lastUsedAt: null,
    revokedAt: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
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

const sampleTenantOrgUnit = (overrides?: Partial<TenantOrgUnitRecord>): TenantOrgUnitRecord => {
  return {
    id: "tenant_123:org:institution",
    tenantId: "tenant_123",
    unitType: "institution",
    slug: "institution",
    displayName: "Tenant 123 Institution",
    parentOrgUnitId: null,
    createdByUserId: "usr_123",
    isActive: true,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleTenantMembershipOrgUnitScope = (
  overrides?: Partial<TenantMembershipOrgUnitScopeRecord>,
): TenantMembershipOrgUnitScopeRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_123",
    orgUnitId: "tenant_123:org:department-math",
    role: "issuer",
    createdByUserId: "usr_admin",
    createdAt: "2026-02-13T00:00:00.000Z",
    updatedAt: "2026-02-13T00:00:00.000Z",
    ...overrides,
  };
};

const sampleDelegatedIssuingAuthorityGrant = (
  overrides?: Partial<DelegatedIssuingAuthorityGrantRecord>,
): DelegatedIssuingAuthorityGrantRecord => {
  return {
    id: "dag_123",
    tenantId: "tenant_123",
    delegateUserId: "usr_delegate",
    delegatedByUserId: "usr_admin",
    orgUnitId: "tenant_123:org:department-math",
    allowedActions: ["issue_badge"],
    badgeTemplateIds: ["badge_template_001"],
    startsAt: "2026-02-13T00:00:00.000Z",
    endsAt: "2026-03-13T00:00:00.000Z",
    revokedAt: null,
    revokedByUserId: null,
    revokedReason: null,
    status: "active",
    createdAt: "2026-02-13T00:00:00.000Z",
    updatedAt: "2026-02-13T00:00:00.000Z",
    ...overrides,
  };
};

const sampleDelegatedIssuingAuthorityGrantEvent = (
  overrides?: Partial<DelegatedIssuingAuthorityGrantEventRecord>,
): DelegatedIssuingAuthorityGrantEventRecord => {
  return {
    id: "dage_123",
    tenantId: "tenant_123",
    grantId: "dag_123",
    eventType: "granted",
    actorUserId: "usr_admin",
    detailsJson: '{"reason":"Spring delegation"}',
    occurredAt: "2026-02-13T00:00:00.000Z",
    createdAt: "2026-02-13T00:00:00.000Z",
    ...overrides,
  };
};

const sampleTenantMembership = (
  overrides?: Partial<TenantMembershipRecord>,
): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_123",
    role: "issuer",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleTenantMember = (overrides?: Partial<TenantMemberRecord>): TenantMemberRecord => {
  return {
    ...sampleTenantMembership(),
    email: "member@example.edu",
    ...overrides,
  };
};

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: "aud_123",
    tenantId: "tenant_123",
    actorUserId: "usr_123",
    action: "assertion.issued",
    targetType: "assertion",
    targetId: "tenant_123:assertion_456",
    metadataJson: null,
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

describe("tenant member management endpoints", () => {
  const cookieHeaders = {
    Origin: "http://localhost",
    Cookie: "better-auth.session_token=session-token",
  };

  const mockTenantMembershipLookup = (
    actorRole: TenantMembershipRecord["role"],
    targetMembership: TenantMembershipRecord | null,
  ): void => {
    mockedFindTenantMembership.mockImplementation(async (_db, tenantId, userId) => {
      if (userId === "usr_123") {
        return sampleTenantMembership({
          tenantId,
          userId,
          role: actorRole,
        });
      }

      return targetMembership === null
        ? null
        : sampleTenantMembership({
            ...targetMembership,
            tenantId,
            userId,
          });
    });
  };

  it("lets an admin add a new colleague by email as admin", async () => {
    const env = createEnv();
    mockTenantMembershipLookup("admin", null);
    mockedUpsertTenantMembershipRole.mockResolvedValueOnce({
      membership: sampleTenantMembership({
        userId: "usr_colleague",
        role: "admin",
      }),
      previousRole: null,
      changed: true,
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/members",
      {
        method: "POST",
        headers: {
          ...cookieHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: "colleague@example.edu",
          role: "admin",
          sendInvite: false,
        }),
      },
      env,
    );
    const body = await response.json<{
      member: { userId: string; email: string; role: string };
      invite: { deliveryStatus: string };
    }>();

    expect(response.status).toBe(201);
    expect(body.member).toEqual(
      expect.objectContaining({
        userId: "usr_colleague",
        email: "colleague@example.edu",
        role: "admin",
      }),
    );
    expect(body.invite.deliveryStatus).toBe("skipped");
    expect(mockedUpsertUserByEmail).toHaveBeenCalledWith(fakeDb, "colleague@example.edu");
    expect(mockedUpsertTenantMembershipRole).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_colleague",
      role: "admin",
    });
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "membership.role_assigned",
        targetId: "tenant_123:usr_colleague",
      }),
    );
  });

  it.each(["issuer", "viewer", "admin"] as const)(
    "lets an admin update an existing member role to %s",
    async (nextRole) => {
      const env = createEnv();
      const previousRole = nextRole === "admin" ? "viewer" : "admin";
      mockTenantMembershipLookup(
        "admin",
        sampleTenantMembership({
          userId: "usr_colleague",
          role: previousRole,
        }),
      );
      mockedUpsertTenantMembershipRole.mockResolvedValueOnce({
        membership: sampleTenantMembership({
          userId: "usr_colleague",
          role: nextRole,
        }),
        previousRole,
        changed: true,
      });
      mockedFindUserById.mockResolvedValueOnce({
        id: "usr_colleague",
        email: "colleague@example.edu",
      });

      const response = await app.request(
        "/v1/tenants/tenant_123/members/usr_colleague/role",
        {
          method: "PATCH",
          headers: {
            ...cookieHeaders,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            role: nextRole,
          }),
        },
        env,
      );
      const body = await response.json<{ member: { role: string }; previousRole: string }>();

      expect(response.status).toBe(200);
      expect(body.member.role).toBe(nextRole);
      expect(body.previousRole).toBe(previousRole);
      expect(mockedCreateAuditLog).toHaveBeenCalledWith(
        fakeDb,
        expect.objectContaining({
          action: "membership.role_changed",
        }),
      );
    },
  );

  it("rejects admin attempts to assign owner", async () => {
    const env = createEnv();
    mockTenantMembershipLookup("admin", null);

    const response = await app.request(
      "/v1/tenants/tenant_123/members",
      {
        method: "POST",
        headers: {
          ...cookieHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: "owner@example.edu",
          role: "owner",
          sendInvite: false,
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toBe("Only tenant owners can assign the owner role.");
    expect(mockedUpsertTenantMembershipRole).not.toHaveBeenCalled();
  });

  it("lets an owner assign owner", async () => {
    const env = createEnv();
    mockTenantMembershipLookup("owner", null);
    mockedUpsertTenantMembershipRole.mockResolvedValueOnce({
      membership: sampleTenantMembership({
        userId: "usr_colleague",
        role: "owner",
      }),
      previousRole: null,
      changed: true,
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/members",
      {
        method: "POST",
        headers: {
          ...cookieHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: "colleague@example.edu",
          role: "owner",
          sendInvite: false,
        }),
      },
      env,
    );

    expect(response.status).toBe(201);
    expect(mockedUpsertTenantMembershipRole).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_colleague",
      role: "owner",
    });
  });

  it("blocks demoting the last owner", async () => {
    const env = createEnv();
    mockTenantMembershipLookup(
      "owner",
      sampleTenantMembership({
        userId: "usr_owner_target",
        role: "owner",
      }),
    );
    mockedCountTenantMembershipsByRole.mockResolvedValueOnce({
      owner: 1,
      admin: 1,
      issuer: 0,
      approver: 0,
      viewer: 0,
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/members/usr_owner_target/role",
      {
        method: "PATCH",
        headers: {
          ...cookieHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          role: "admin",
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(409);
    expect(body.error).toBe("At least one tenant owner must remain.");
    expect(mockedUpsertTenantMembershipRole).not.toHaveBeenCalled();
  });

  it("rejects self-removal and self-demotion", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        userId: "usr_123",
        role: "admin",
      }),
    );

    const demoteResponse = await app.request(
      "/v1/tenants/tenant_123/members/usr_123/role",
      {
        method: "PATCH",
        headers: {
          ...cookieHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          role: "viewer",
        }),
      },
      env,
    );
    const removeResponse = await app.request(
      "/v1/tenants/tenant_123/members/usr_123",
      {
        method: "DELETE",
        headers: cookieHeaders,
      },
      env,
    );

    expect(demoteResponse.status).toBe(409);
    expect(removeResponse.status).toBe(409);
    expect(mockedUpsertTenantMembershipRole).not.toHaveBeenCalled();
    expect(mockedRemoveTenantMembership).not.toHaveBeenCalled();
  });

  it("removes tenant membership and revokes active break-glass access", async () => {
    const env = createEnv();
    mockTenantMembershipLookup(
      "admin",
      sampleTenantMembership({
        userId: "usr_colleague",
        role: "issuer",
      }),
    );
    mockedFindUserById.mockResolvedValueOnce({
      id: "usr_colleague",
      email: "colleague@example.edu",
    });
    mockedRevokeTenantBreakGlassAccount.mockResolvedValueOnce(true);

    const response = await app.request(
      "/v1/tenants/tenant_123/members/usr_colleague",
      {
        method: "DELETE",
        headers: cookieHeaders,
      },
      env,
    );
    const body = await response.json<{ removed: boolean; revokedBreakGlass: boolean }>();

    expect(response.status).toBe(200);
    expect(body.removed).toBe(true);
    expect(body.revokedBreakGlass).toBe(true);
    expect(mockedRemoveTenantMembership).toHaveBeenCalledWith(
      fakeDb,
      "tenant_123",
      "usr_colleague",
    );
    expect(mockedRevokeTenantBreakGlassAccount).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: "usr_colleague",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "membership.removed",
      }),
    );
  });

  it("blocks unauthorized roles from the workflow", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        userId: "usr_123",
        role: "viewer",
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/members",
      {
        headers: cookieHeaders,
      },
      env,
    );

    expect(response.status).toBe(403);
  });

  it("delivers member invites through magic links for local and hybrid tenants", async () => {
    const env = createEnv();
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: {
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth",
        expiresAt: "2026-03-17T22:00:00.000Z",
      },
    });
    betterAuthProvider.requestMagicLink.mockResolvedValue({
      deliveryStatus: "sent",
    });
    mockTenantMembershipLookup(
      "admin",
      sampleTenantMembership({
        userId: "usr_colleague",
        role: "admin",
      }),
    );
    mockedFindUserById.mockResolvedValueOnce({
      id: "usr_colleague",
      email: "colleague@example.edu",
    });
    mockedFindTenantById.mockResolvedValue(sampleTenant({ planTier: "team" }));
    mockedFindTenantAuthPolicy.mockResolvedValue(null);

    const response = await isolatedApp.request(
      "/v1/tenants/tenant_123/members/usr_colleague/invite",
      {
        method: "POST",
        headers: cookieHeaders,
      },
      env,
    );
    const body = await response.json<{
      invite: { deliveryStatus: string; inviteKind: string };
    }>();

    expect(response.status).toBe(200);
    expect(body.invite).toEqual({
      deliveryStatus: "sent",
      inviteKind: "magic_link",
    });
    expect(betterAuthProvider.requestMagicLink).toHaveBeenCalledWith(expect.anything(), {
      tenantId: "tenant_123",
      email: "colleague@example.edu",
      nextPath: "/auth/resolve",
    });
  });

  it("delivers member invites through SSO sign-in notices for SSO-required tenants", async () => {
    const env = createEnv();
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: {
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth",
        expiresAt: "2026-03-17T22:00:00.000Z",
      },
    });
    mockTenantMembershipLookup(
      "admin",
      sampleTenantMembership({
        userId: "usr_colleague",
        role: "admin",
      }),
    );
    mockedFindUserById.mockResolvedValueOnce({
      id: "usr_colleague",
      email: "colleague@example.edu",
    });
    mockedFindTenantById.mockResolvedValue(
      sampleTenant({
        planTier: "enterprise",
        displayName: "Sakai University",
      }),
    );
    mockedFindTenantAuthPolicy.mockResolvedValue({
      tenantId: "tenant_123",
      loginMode: "sso_required",
      breakGlassEnabled: false,
      localMfaRequired: false,
      defaultProviderId: "tap_oidc",
      enforceForRoles: "all_users",
      createdAt: "2026-03-17T22:00:00.000Z",
      updatedAt: "2026-03-17T22:00:00.000Z",
    });

    const response = await isolatedApp.request(
      "/v1/tenants/tenant_123/members/usr_colleague/invite",
      {
        method: "POST",
        headers: cookieHeaders,
      },
      env,
    );
    const body = await response.json<{
      invite: { deliveryStatus: string; inviteKind: string };
    }>();

    expect(response.status).toBe(200);
    expect(body.invite).toEqual({
      deliveryStatus: "sent",
      inviteKind: "sso_notice",
    });
    expect(betterAuthProvider.requestMagicLink).not.toHaveBeenCalled();
  });
});

describe("org unit and badge ownership governance endpoints", () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedCreateTenantOrgUnit.mockReset();
    mockedListTenantOrgUnits.mockReset();
    mockedListTenantOrgUnits.mockResolvedValue([]);
    mockedListBadgeTemplateImageRevisionCountsByTenant.mockReset();
    mockedListBadgeTemplateImageRevisionCountsByTenant.mockResolvedValue([]);
    mockedListBadgeTemplateOwnershipEvents.mockReset();
    mockedListBadgeTemplateOwnershipEvents.mockResolvedValue([]);
    mockedTransferBadgeTemplateOwnership.mockReset();
    mockedFindBadgeTemplateById.mockReset();
    mockedFindDelegatedIssuingAuthorityGrantById.mockReset();
    mockedFindDelegatedIssuingAuthorityGrantById.mockResolvedValue(null);
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
    mockedCreateAuditLog.mockClear();
  });

  it("loads scoped reporting with a narrow page-data path and keeps badge-template comparisons available", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "issuer" }));
    mockedListTenantMembershipOrgUnitScopes.mockImplementation(
      async (_db, input: { tenantId: string; userId?: string | undefined }) => {
        if (input.userId === "usr_123") {
          return [
            sampleTenantMembershipOrgUnitScope({
              userId: "usr_123",
              orgUnitId: "tenant_123:org:college-eng",
              role: "issuer",
            }),
          ];
        }

        return [];
      },
    );
    mockedListTenantOrgUnits.mockResolvedValue([
      sampleTenantOrgUnit(),
      sampleTenantOrgUnit({
        id: "tenant_123:org:college-eng",
        unitType: "college",
        slug: "college-eng",
        displayName: "College of Engineering",
        parentOrgUnitId: "tenant_123:org:institution",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:college-arts",
        unitType: "college",
        slug: "college-arts",
        displayName: "College of Arts",
        parentOrgUnitId: "tenant_123:org:institution",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:department-cs",
        unitType: "department",
        slug: "department-cs",
        displayName: "Computer Science",
        parentOrgUnitId: "tenant_123:org:college-eng",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:department-math",
        unitType: "department",
        slug: "department-math",
        displayName: "Mathematics",
        parentOrgUnitId: "tenant_123:org:college-eng",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:program-cs",
        unitType: "program",
        slug: "program-cs",
        displayName: "Computer Science Program",
        parentOrgUnitId: "tenant_123:org:department-cs",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:department-history",
        unitType: "department",
        slug: "department-history",
        displayName: "History",
        parentOrgUnitId: "tenant_123:org:college-arts",
      }),
    ]);
    mockedListBadgeTemplates.mockResolvedValue([
      sampleBadgeTemplate(),
      sampleBadgeTemplate({
        id: "badge_template_chem",
        slug: "chemistry-lab",
        title: "Chemistry Lab",
        ownerOrgUnitId: "tenant_123:org:department-history",
      }),
    ]);
    mockedGetTenantReportingOverview.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === "tenant_123:org:program-cs") {
        return {
          tenantId: "tenant_123",
          filters: {
            issuedFrom: input.issuedFrom ?? null,
            issuedTo: input.issuedTo ?? null,
            badgeTemplateId: input.badgeTemplateId ?? null,
            orgUnitId: input.orgUnitId,
            state: input.state ?? null,
          },
          counts: {
            issued: 5,
            active: 5,
            suspended: 0,
            revoked: 0,
            pendingReview: 0,
            claimRate: 40,
            shareRate: 20,
          },
          generatedAt: "2026-03-21T12:00:00.000Z",
        };
      }

      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 0,
          active: 0,
          suspended: 0,
          revoked: 0,
          pendingReview: 0,
          claimRate: 0,
          shareRate: 0,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });
    mockedGetTenantReportingEngagementCounts.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === "tenant_123:org:program-cs") {
        return {
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
          claimRate: 40,
          shareRate: 20,
        };
      }

      return {
        issuedCount: 0,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 0,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        claimRate: 0,
        shareRate: 0,
      };
    });
    mockedGetTenantReportingTrends.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === "tenant_123:org:program-cs") {
        return {
          tenantId: "tenant_123",
          filters: {
            from: input.from ?? null,
            to: input.to ?? null,
            badgeTemplateId: input.badgeTemplateId ?? null,
            orgUnitId: input.orgUnitId ?? null,
            state: input.state ?? null,
          },
          bucket: "day",
          series: [
            {
              bucketStart: "2026-03-01",
              issuedCount: 5,
              publicBadgeViewCount: 14,
              verificationViewCount: 5,
              shareClickCount: 2,
              learnerClaimCount: 2,
              walletAcceptCount: 1,
            },
          ],
          generatedAt: "2026-03-21T12:00:00.000Z",
        };
      }

      return {
        tenantId: "tenant_123",
        filters: {
          from: input.from ?? null,
          to: input.to ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        bucket: "day",
        series: [],
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });
    mockedListTenantReportingComparisons.mockImplementation(async (_db, input) => {
      if (input.groupBy === "orgUnit") {
        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-cs",
            issuedCount: 5,
            publicBadgeViewCount: 14,
            verificationViewCount: 5,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 40,
            shareRate: 20,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-math",
            issuedCount: 4,
            publicBadgeViewCount: 8,
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
            issuedCount: 3,
            publicBadgeViewCount: 6,
            verificationViewCount: 2,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 33.3,
            shareRate: 16.7,
          },
        ];
      }

      if (input.orgUnitId === "tenant_123:org:program-cs") {
        return [
          {
            groupBy: "badgeTemplate",
            groupId: "badge_template_001",
            issuedCount: 5,
            publicBadgeViewCount: 14,
            verificationViewCount: 5,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 40,
            shareRate: 20,
          },
        ];
      }

      if (input.orgUnitId === "tenant_123:org:department-history") {
        return [
          {
            groupBy: "badgeTemplate",
            groupId: "badge_template_chem",
            issuedCount: 3,
            publicBadgeViewCount: 6,
            verificationViewCount: 2,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 33.3,
            shareRate: 16.7,
          },
        ];
      }

      return [];
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore?orgUnitId=tenant_123%3Aorg%3Aprogram-cs",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(html).toContain("Reporting Explore");
    expect(html).not.toContain("Executive Summary");
    expect(html).not.toContain('class="ct-admin__reporting-summary-band"');
    expect(html).not.toContain('class="ct-admin__reporting-supporting-grid"');
    expect(html).toContain('class="ct-admin__reporting-slice-strip"');
    expect(html).toContain('data-reporting-slice-metric="issued"');
    expect(html).toContain('class="ct-admin__reporting-state-summary"');
    expect(html).not.toContain('class="ct-admin__reporting-supporting-rail"');
    expect(html).toContain("Current view");
    expect(html).toContain("Compare by badge template");
    expect(html).toContain("Hierarchy drilldown");
    expect(html).toContain("College of Engineering");
    expect(html).toContain("Computer Science");
    expect(html).toContain("Mathematics");
    expect(html).toContain("Computer Science Program");
    expect(html).toContain('aria-label="Reporting hierarchy breadcrumb"');
    expect(html).toContain("ct-admin__reporting-focus-summary");
    expect(html).toContain("Reporting workspace");
    expect(html).toContain("data-reporting-root-link");
    expect(html).toContain(
      'data-reporting-focus-target="reporting-hierarchy-focus-tenant_123%3Aorg%3Acollege-eng"',
    );
    expect(html).toContain(
      'data-reporting-focus-root="reporting-hierarchy-focus-tenant_123%3Aorg%3Acollege-eng"',
    );
    expect(html).toContain(
      'href="/tenants/tenant_123/admin/reporting/explore#reporting-hierarchy-focus-tenant_123%3Aorg%3Acollege-eng"',
    );
    expect(html).toContain('aria-current="page">Computer Science</span>');
    expect(html).toContain('class="ct-admin__reporting-lower-story"');
    expect(html).toContain("Performer panels");
    expect(html).toContain("Volume rankings");
    expect(html).toContain("Rate rankings");
    expect(html).toContain("Compare level: department rows in the current visible hierarchy.");
    expect(html).toContain("Highest issuance volume");
    expect(html).toContain("Highest claim rate");
    expect(html).toContain(
      "Rate rankings require at least 5 issued badges so issued totals stay visible beside every rate callout.",
    );
    expect(html).toContain("Comparing department rows by claim rate.");
    expect(html).toContain("Issued totals stay visible beside each ranked rate row.");
    expect(html).toContain('class="ct-reporting-visual"');
    expect(html).toContain('data-reporting-visual-kind="comparison-bars"');
    expect(
      (html.match(/data-reporting-visual-kind="comparison-ranked"/g) ?? []).length,
    ).toBeGreaterThanOrEqual(2);
    expect(html).toContain('class="ct-reporting-visual__comparison-ranked-list"');
    expect(html).toContain('class="ct-reporting-visual__legend"');
    expect(html).not.toContain('data-reporting-visual-kind="stacked-summary"');
    expect(html).toContain("Current badge state mix");
    expect(html).toContain("TypeScript Foundations");
    expect(html).toContain("14 public views · 40.0% claim · 20.0% share");
    expect(html).toContain(
      "One badge template matches these filters. Open the exact row only when you need every event column.",
    );
    expect(html).toContain("Exact badge-template row");
    expect(html).toContain("Show all event columns");
    expect(html).not.toContain(
      "The table below keeps the full row set with exact counts and rate definitions.",
    );
    expect(html).toContain("Advanced hierarchy drilldowns");
    expect(html).toContain(
      "Open org-unit drilldowns and performer rankings when you need structural detail.",
    );
    expect(html).toContain('data-reporting-bar-group="template-comparisons"');
    expect(html).toContain('data-reporting-bar-group="org-comparisons"');
    expect(html).toContain('href="/tenants/tenant_123/admin/reporting/reports?');
    expect(html).toContain("orgUnitId=tenant_123%3Aorg%3Aprogram-cs");
    expect(html).not.toContain("<h2>Export CSV</h2>");
    expect(html.indexOf("Compare by badge template")).toBeLessThan(
      html.indexOf("Compare by org unit"),
    );
    expect(html.indexOf("Compare by org unit")).toBeLessThan(
      html.indexOf("Advanced hierarchy drilldowns"),
    );
    expect(html.indexOf("Advanced hierarchy drilldowns")).toBeLessThan(
      html.indexOf("Hierarchy drilldown"),
    );
    expect(html.indexOf("Hierarchy drilldown")).toBeLessThan(html.indexOf("Performer panels"));
    expect(html).not.toContain("Phase 10 product data");
    expect(html).not.toContain("Phase 11 Scope");
    expect(html).not.toContain('href="/v1/tenants/tenant_123/assertions/ledger-export.csv"');
    expect(html).not.toContain('id="issued-badges-export-form"');
    expect(html).not.toContain("Chemistry Lab");
    expect(html).not.toContain("College of Arts");
    expect(html).not.toContain("History");
    expect(html).not.toContain("6 public views · 33.3% claim · 16.7% share");
    expect(html).not.toContain('aria-current="page">History</span>');
    expect(html).not.toContain(
      'href="/tenants/tenant_123/admin/reporting/explore#reporting-hierarchy-focus-tenant_123%3Aorg%3Adepartment-history"',
    );
    expect(mockedListDelegatedIssuingAuthorityGrants).not.toHaveBeenCalled();
    expect(mockedListTenantApiKeys).not.toHaveBeenCalled();
    expect(mockedListBadgeIssuanceRules).not.toHaveBeenCalled();
    expect(mockedFindTenantAuthPolicy).not.toHaveBeenCalled();
    expect(mockedListTenantAuthProviders).not.toHaveBeenCalled();
    expect(mockedListTenantBreakGlassAccounts).not.toHaveBeenCalled();
  });

  it("keeps sparse reporting states scoped to already-visible rows", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "issuer" }));
    mockedListTenantMembershipOrgUnitScopes.mockImplementation(
      async (_db, input: { tenantId: string; userId?: string | undefined }) => {
        if (input.userId === "usr_123") {
          return [
            sampleTenantMembershipOrgUnitScope({
              userId: "usr_123",
              orgUnitId: "tenant_123:org:college-eng",
              role: "issuer",
            }),
          ];
        }

        return [];
      },
    );
    mockedListTenantOrgUnits.mockResolvedValue([
      sampleTenantOrgUnit(),
      sampleTenantOrgUnit({
        id: "tenant_123:org:college-eng",
        unitType: "college",
        slug: "college-eng",
        displayName: "College of Engineering",
        parentOrgUnitId: "tenant_123:org:institution",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:college-arts",
        unitType: "college",
        slug: "college-arts",
        displayName: "College of Arts",
        parentOrgUnitId: "tenant_123:org:institution",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:department-cs",
        unitType: "department",
        slug: "department-cs",
        displayName: "Computer Science",
        parentOrgUnitId: "tenant_123:org:college-eng",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:program-cs",
        unitType: "program",
        slug: "program-cs",
        displayName: "Computer Science Program",
        parentOrgUnitId: "tenant_123:org:department-cs",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:department-history",
        unitType: "department",
        slug: "department-history",
        displayName: "History",
        parentOrgUnitId: "tenant_123:org:college-arts",
      }),
    ]);
    mockedListBadgeTemplates.mockResolvedValue([
      sampleBadgeTemplate(),
      sampleBadgeTemplate({
        id: "badge_template_chem",
        slug: "chemistry-lab",
        title: "Chemistry Lab",
        ownerOrgUnitId: "tenant_123:org:department-history",
      }),
    ]);
    mockedGetTenantReportingOverview.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === "tenant_123:org:program-cs") {
        return {
          tenantId: "tenant_123",
          filters: {
            issuedFrom: input.issuedFrom ?? null,
            issuedTo: input.issuedTo ?? null,
            badgeTemplateId: input.badgeTemplateId ?? null,
            orgUnitId: input.orgUnitId,
            state: input.state ?? null,
          },
          counts: {
            issued: 5,
            active: 5,
            suspended: 0,
            revoked: 0,
            pendingReview: 0,
            claimRate: 40,
            shareRate: 20,
          },
          generatedAt: "2026-03-21T12:00:00.000Z",
        };
      }

      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 0,
          active: 0,
          suspended: 0,
          revoked: 0,
          pendingReview: 0,
          claimRate: 0,
          shareRate: 0,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });
    mockedGetTenantReportingEngagementCounts.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === "tenant_123:org:program-cs") {
        return {
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
          claimRate: 40,
          shareRate: 20,
        };
      }

      return {
        issuedCount: 0,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 0,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        claimRate: 0,
        shareRate: 0,
      };
    });
    mockedGetTenantReportingTrends.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === "tenant_123:org:program-cs") {
        return {
          tenantId: "tenant_123",
          filters: {
            from: input.from ?? null,
            to: input.to ?? null,
            badgeTemplateId: input.badgeTemplateId ?? null,
            orgUnitId: input.orgUnitId ?? null,
            state: input.state ?? null,
          },
          bucket: "day",
          series: [
            {
              bucketStart: "2026-03-01",
              issuedCount: 5,
              publicBadgeViewCount: 14,
              verificationViewCount: 5,
              shareClickCount: 2,
              learnerClaimCount: 2,
              walletAcceptCount: 1,
            },
          ],
          generatedAt: "2026-03-21T12:00:00.000Z",
        };
      }

      return {
        tenantId: "tenant_123",
        filters: {
          from: input.from ?? null,
          to: input.to ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        bucket: "day",
        series: [],
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });
    mockedListTenantReportingComparisons.mockImplementation(async (_db, input) => {
      if (input.groupBy === "orgUnit") {
        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-cs",
            issuedCount: 5,
            publicBadgeViewCount: 14,
            verificationViewCount: 5,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 40,
            shareRate: 20,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-history",
            issuedCount: 3,
            publicBadgeViewCount: 6,
            verificationViewCount: 2,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 33.3,
            shareRate: 16.7,
          },
        ];
      }

      if (input.orgUnitId === "tenant_123:org:program-cs") {
        return [
          {
            groupBy: "badgeTemplate",
            groupId: "badge_template_001",
            issuedCount: 5,
            publicBadgeViewCount: 14,
            verificationViewCount: 5,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 40,
            shareRate: 20,
          },
        ];
      }

      if (input.orgUnitId === "tenant_123:org:department-history") {
        return [
          {
            groupBy: "badgeTemplate",
            groupId: "badge_template_chem",
            issuedCount: 3,
            publicBadgeViewCount: 6,
            verificationViewCount: 2,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 33.3,
            shareRate: 16.7,
          },
        ];
      }

      return [];
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore?orgUnitId=tenant_123%3Aorg%3Aprogram-cs",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const html = await response.text();
    const trendPanel = getReportingPanelArticleMarkup(html, "Trend lines");
    const templatePanel = getReportingPanelArticleMarkup(html, "Compare by badge template");
    const orgUnitPanel = getReportingPanelArticleMarkup(html, "Compare by org unit");
    const hierarchyPanel = getReportingPanelArticleMarkup(html, "Hierarchy drilldown");
    const performerPanel = getReportingPanelArticleMarkup(html, "Performer panels");

    expect(response.status).toBe(200);
    expect(trendPanel).toContain('data-reporting-state="sparse"');
    expect(templatePanel).toContain('data-reporting-state="sparse"');
    expect(orgUnitPanel).toContain('data-reporting-state="sparse"');
    expect(hierarchyPanel).toContain('data-reporting-state="sparse"');
    expect(performerPanel).toContain('data-reporting-state="sparse"');
    expect(html).toContain(
      "One badge template matches these filters. Open the exact row only when you need every event column.",
    );
    expect(html).toContain(
      "One org unit matches these filters. Open the exact row only when you need every event column.",
    );
    expect(html).toContain("Exact badge-template row");
    expect(html).toContain("Exact org-unit row");
    expect(html).toContain("Show all event columns");
    expect(html).toContain("Your filters currently show one visible reporting path.");
    expect(html).toContain(
      "Rankings stay paused until this view has more than one comparable hierarchy row.",
    );
    expect(html).toContain("Computer Science Program");
    expect(html).not.toContain("Chemistry Lab");
    expect(html).not.toContain("History");
    expect(html).not.toContain("College of Arts");
  });

  it("can verify scoped seeded-demo reporting from the canonical fixture on the normal route", async () => {
    const env = createEnv();
    const seededDemo = getSeededDemoReportingRouteFixture();
    const scopedSlice = seededDemo.scopedOrgContext;

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "issuer" }));
    mockedListTenantMembershipOrgUnitScopes.mockImplementation(
      async (_db, input: { tenantId: string; userId?: string | undefined }) => {
        if (input.userId === "usr_123") {
          return [
            sampleTenantMembershipOrgUnitScope({
              userId: "usr_123",
              orgUnitId: scopedSlice.rootOrgUnitId,
              role: "issuer",
            }),
          ];
        }

        return [];
      },
    );
    mockedListTenantOrgUnits.mockResolvedValue([...seededDemo.orgUnits]);
    mockedListBadgeTemplates.mockResolvedValue([...seededDemo.badgeTemplates]);
    mockedGetTenantReportingOverview.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === scopedSlice.orgUnitId) {
        return scopedSlice.overview;
      }

      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 0,
          active: 0,
          suspended: 0,
          revoked: 0,
          pendingReview: 0,
          claimRate: 0,
          shareRate: 0,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });
    mockedGetTenantReportingEngagementCounts.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === scopedSlice.orgUnitId) {
        return scopedSlice.engagementCounts;
      }

      return {
        issuedCount: 0,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 0,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        claimRate: 0,
        shareRate: 0,
      };
    });
    mockedGetTenantReportingTrends.mockImplementation(async (_db, input) => {
      if (input.orgUnitId === scopedSlice.orgUnitId) {
        return scopedSlice.trends;
      }

      return {
        tenantId: "tenant_123",
        filters: {
          from: input.from ?? null,
          to: input.to ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        bucket: "day",
        series: [],
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });
    mockedListTenantReportingComparisons.mockImplementation(async (_db, input) => {
      if (input.groupBy === "orgUnit") {
        return [...scopedSlice.rawOrgUnitComparisons];
      }

      if (input.orgUnitId === scopedSlice.orgUnitId) {
        return [...scopedSlice.templateComparisons];
      }

      return [];
    });

    const response = await app.request(
      `${seededDemo.routePath}?orgUnitId=${encodeURIComponent(scopedSlice.orgUnitId)}`,
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(html).not.toContain('class="ct-admin__reporting-presentation-note');
    expect(html).not.toContain("Smart defaults active.");
    expect(html).toContain("At a glance");
    expect(html).toContain('class="ct-admin__reporting-primary-story');
    expect(html).toContain('class="ct-admin__reporting-highlight-grid');
    expect(html).toContain("Ranked charts");
    expect(html).toContain('class="ct-admin__reporting-deep-links');
    expect(html).toContain("Where to look next");
    expect(html).not.toContain("Scoped drilldowns");
    expect(html.indexOf("At a glance")).toBeLessThan(html.indexOf("Where to look next"));
    expect(html.indexOf("Where to look next")).toBeLessThan(html.indexOf("Ranked charts"));
    expect(html).toContain("Computer Science Program");
    expect(html).toContain("TypeScript Foundations");
    expect(html).toContain("14 public views · 40.0% claim · 20.0% share");
    expect(html).toContain("Org unit to notice");
    expect(html).toContain("Template to notice");
    expect(html).toContain("Open in Explore");
    expect(html).not.toContain("data-reporting-root-link");
    expect(html).not.toContain("#reporting-hierarchy-focus");
    expect(html).not.toContain("Chemistry Lab");
    expect(html).not.toContain("History");
    expect(html).not.toContain("demo mode");
    expect(html).not.toContain("presentation-only");
  });

  it("keeps empty reporting states scoped to already-visible rows", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "issuer" }));
    mockedListTenantMembershipOrgUnitScopes.mockImplementation(
      async (_db, input: { tenantId: string; userId?: string | undefined }) => {
        if (input.userId === "usr_123") {
          return [
            sampleTenantMembershipOrgUnitScope({
              userId: "usr_123",
              orgUnitId: "tenant_123:org:college-eng",
              role: "issuer",
            }),
          ];
        }

        return [];
      },
    );
    mockedListTenantOrgUnits.mockResolvedValue([
      sampleTenantOrgUnit(),
      sampleTenantOrgUnit({
        id: "tenant_123:org:college-eng",
        unitType: "college",
        slug: "college-eng",
        displayName: "College of Engineering",
        parentOrgUnitId: "tenant_123:org:institution",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:college-arts",
        unitType: "college",
        slug: "college-arts",
        displayName: "College of Arts",
        parentOrgUnitId: "tenant_123:org:institution",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:department-cs",
        unitType: "department",
        slug: "department-cs",
        displayName: "Computer Science",
        parentOrgUnitId: "tenant_123:org:college-eng",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:program-cs",
        unitType: "program",
        slug: "program-cs",
        displayName: "Computer Science Program",
        parentOrgUnitId: "tenant_123:org:department-cs",
      }),
      sampleTenantOrgUnit({
        id: "tenant_123:org:department-history",
        unitType: "department",
        slug: "department-history",
        displayName: "History",
        parentOrgUnitId: "tenant_123:org:college-arts",
      }),
    ]);
    mockedListBadgeTemplates.mockResolvedValue([
      sampleBadgeTemplate(),
      sampleBadgeTemplate({
        id: "badge_template_chem",
        slug: "chemistry-lab",
        title: "Chemistry Lab",
        ownerOrgUnitId: "tenant_123:org:department-history",
      }),
    ]);
    mockedGetTenantReportingOverview.mockResolvedValue({
      tenantId: "tenant_123",
      filters: {
        issuedFrom: null,
        issuedTo: null,
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      counts: {
        issued: 0,
        active: 0,
        suspended: 0,
        revoked: 0,
        pendingReview: 0,
        claimRate: 0,
        shareRate: 0,
      },
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingEngagementCounts.mockResolvedValue({
      issuedCount: 0,
      publicBadgeViewCount: 0,
      verificationViewCount: 0,
      shareClickCount: 0,
      learnerClaimCount: 0,
      walletAcceptCount: 0,
      claimRate: 0,
      shareRate: 0,
    });
    mockedGetTenantReportingTrends.mockResolvedValue({
      tenantId: "tenant_123",
      filters: {
        from: null,
        to: null,
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      bucket: "day",
      series: [],
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedListTenantReportingComparisons.mockImplementation(async (_db, input) => {
      if (input.groupBy === "orgUnit") {
        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-history",
            issuedCount: 3,
            publicBadgeViewCount: 6,
            verificationViewCount: 2,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 33.3,
            shareRate: 16.7,
          },
        ];
      }

      if (input.orgUnitId === "tenant_123:org:department-history") {
        return [
          {
            groupBy: "badgeTemplate",
            groupId: "badge_template_chem",
            issuedCount: 3,
            publicBadgeViewCount: 6,
            verificationViewCount: 2,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 33.3,
            shareRate: 16.7,
          },
        ];
      }

      return [];
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const html = await response.text();
    const trendPanel = getReportingPanelArticleMarkup(html, "Trend lines");
    const templatePanel = getReportingPanelArticleMarkup(html, "Compare by badge template");
    const orgUnitPanel = getReportingPanelArticleMarkup(html, "Compare by org unit");
    const hierarchyPanel = getReportingPanelArticleMarkup(html, "Hierarchy drilldown");
    const performerPanel = getReportingPanelArticleMarkup(html, "Performer panels");

    expect(response.status).toBe(200);
    expect(trendPanel).toContain('data-reporting-state="empty"');
    expect(templatePanel).toContain('data-reporting-state="empty"');
    expect(orgUnitPanel).toContain('data-reporting-state="empty"');
    expect(hierarchyPanel).toContain('data-reporting-state="empty"');
    expect(performerPanel).toContain('data-reporting-state="empty"');
    expect(html).toContain("The selected filters do not have enough activity to chart yet.");
    expect(html).toContain("No badge-template rows are visible for this view yet.");
    expect(html).toContain("No org-unit rows are visible for this view yet.");
    expect(html).toContain(
      "Hierarchy drilldowns appear here once visible org-unit rows exist for this view.",
    );
    expect(html).toContain(
      "Performer rankings appear once this view includes comparable hierarchy rows.",
    );
    expect(html).not.toContain("Chemistry Lab");
    expect(html).not.toContain("History");
    expect(html).not.toContain("College of Arts");
  });

  it("lists tenant org units for issuer roles", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedListTenantOrgUnits.mockResolvedValue([
      sampleTenantOrgUnit(),
      sampleTenantOrgUnit({
        id: "tenant_123:org:department-math",
        unitType: "department",
        slug: "math",
        displayName: "Department of Mathematics",
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/org-units",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.tenantId).toBe("tenant_123");
    expect(Array.isArray(body.orgUnits)).toBe(true);
    expect(mockedListTenantOrgUnits).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      includeInactive: false,
    });
  });

  it("authorizes requested tenant governance routes even when the legacy session tenant differs", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "issuer" }));
    mockedFindActiveSessionByHash.mockResolvedValue(
      sampleSession({
        tenantId: "tenant_other",
      }),
    );
    mockedTouchSession.mockResolvedValue(undefined);
    mockedListTenantOrgUnits.mockResolvedValue([sampleTenantOrgUnit()]);

    const response = await app.request(
      "/v1/tenants/tenant_123/org-units",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.tenantId).toBe("tenant_123");
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_123");
  });

  it("authorizes requested tenant governance routes from Better Auth without a legacy session cookie", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedAuthProviders({
      betterAuthPrincipal: {
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth",
        expiresAt: "2026-03-17T22:00:00.000Z",
      },
    });
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "issuer" }));
    mockedListTenantOrgUnits.mockResolvedValue([sampleTenantOrgUnit()]);

    const response = await isolatedApp.request(
      "/v1/tenants/tenant_123/org-units",
      {
        method: "GET",
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.tenantId).toBe("tenant_123");
    expect(betterAuthProvider.resolveAuthenticatedPrincipal).toHaveBeenCalled();
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_123");
    expect(mockedFindActiveSessionByHash).not.toHaveBeenCalled();
  });

  it("creates a tenant org unit for admin roles and writes audit log", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedCreateTenantOrgUnit.mockResolvedValue(
      sampleTenantOrgUnit({
        id: "ou_department_math",
        unitType: "department",
        slug: "math",
        displayName: "Department of Mathematics",
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/org-units",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          unitType: "department",
          displayName: "Department of Mathematics",
          parentOrgUnitId: "tenant_123:org:institution",
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe("tenant_123");
    expect(mockedCreateTenantOrgUnit).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        unitType: "department",
        slug: "department-of-mathematics",
        displayName: "Department of Mathematics",
        parentOrgUnitId: "tenant_123:org:institution",
        createdByUserId: "usr_123",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        action: "tenant.org_unit_created",
        targetType: "org_unit",
      }),
    );
  });

  it("creates tenant API keys for admin roles and writes audit log", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedCreateTenantApiKey.mockResolvedValue(sampleTenantApiKey());

    const response = await app.request(
      "/v1/tenants/tenant_123/api-keys",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          label: "Integration key",
          scopes: ["queue.issue", "queue.revoke"],
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe("tenant_123");
    expect(typeof body.apiKey).toBe("string");
    expect(mockedCreateTenantApiKey).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        label: "Integration key",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "tenant.api_key_created",
      }),
    );
  });

  it("lists and revokes tenant API keys for admin roles", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedListTenantApiKeys.mockResolvedValue([sampleTenantApiKey()]);
    mockedRevokeTenantApiKey.mockResolvedValue(true);

    const listResponse = await app.request(
      "/v1/tenants/tenant_123/api-keys?includeRevoked=true",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const listBody = await listResponse.json<Record<string, unknown>>();

    expect(listResponse.status).toBe(200);
    expect(Array.isArray(listBody.keys)).toBe(true);
    expect(mockedListTenantApiKeys).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      includeRevoked: true,
    });

    const revokeResponse = await app.request(
      "/v1/tenants/tenant_123/api-keys/tak_123/revoke",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          revokedAt: "2026-02-20T00:00:00.000Z",
        }),
      },
      env,
    );
    const revokeBody = await revokeResponse.json<Record<string, unknown>>();

    expect(revokeResponse.status).toBe(200);
    expect(revokeBody.revoked).toBe(true);
    expect(mockedRevokeTenantApiKey).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      apiKeyId: "tak_123",
      revokedAt: "2026-02-20T00:00:00.000Z",
    });
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "tenant.api_key_revoked",
      }),
    );
  });

  it("lists scoped org-unit grants for a tenant user", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([
      sampleTenantMembershipOrgUnitScope({ userId: "usr_issuer" }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/users/usr_issuer/org-unit-scopes",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.userId).toBe("usr_issuer");
    expect(Array.isArray(body.scopes)).toBe(true);
    expect(mockedListTenantMembershipOrgUnitScopes).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_issuer",
    });
  });

  it("upserts scoped org-unit grants for a tenant user", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedUpsertTenantMembershipOrgUnitScope.mockResolvedValue({
      scope: sampleTenantMembershipOrgUnitScope({
        userId: "usr_issuer",
        orgUnitId: "tenant_123:org:department-math",
        role: "issuer",
      }),
      previousRole: null,
      changed: true,
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/users/usr_issuer/org-unit-scopes/tenant_123:org:department-math",
      {
        method: "PUT",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          role: "issuer",
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.changed).toBe(true);
    expect(mockedUpsertTenantMembershipOrgUnitScope).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: "usr_issuer",
        orgUnitId: "tenant_123:org:department-math",
        role: "issuer",
        createdByUserId: "usr_123",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "membership.org_scope_assigned",
        targetType: "membership_org_scope",
      }),
    );
  });

  it("deletes scoped org-unit grants for a tenant user", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedRemoveTenantMembershipOrgUnitScope.mockResolvedValue(true);

    const response = await app.request(
      "/v1/tenants/tenant_123/users/usr_issuer/org-unit-scopes/tenant_123:org:department-math",
      {
        method: "DELETE",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.removed).toBe(true);
    expect(mockedRemoveTenantMembershipOrgUnitScope).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_issuer",
      orgUnitId: "tenant_123:org:department-math",
    });
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "membership.org_scope_removed",
        targetType: "membership_org_scope",
      }),
    );
  });

  it("lists delegated issuing authority grants for a tenant user", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedListDelegatedIssuingAuthorityGrants.mockResolvedValue([
      sampleDelegatedIssuingAuthorityGrant({ delegateUserId: "usr_issuer" }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/users/usr_issuer/issuing-authority-grants?includeRevoked=true",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.userId).toBe("usr_issuer");
    expect(Array.isArray(body.grants)).toBe(true);
    expect(mockedListDelegatedIssuingAuthorityGrants).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      delegateUserId: "usr_issuer",
      includeRevoked: true,
      includeExpired: false,
    });
  });

  it("creates delegated issuing authority grants and writes audit logs", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedCreateDelegatedIssuingAuthorityGrant.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        id: "dag_new",
        delegateUserId: "usr_issuer",
        allowedActions: ["issue_badge", "revoke_badge"],
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/users/usr_issuer/issuing-authority-grants",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          orgUnitId: "tenant_123:org:department-math",
          badgeTemplateIds: ["badge_template_001"],
          allowedActions: ["issue_badge", "revoke_badge"],
          endsAt: "2026-03-13T00:00:00.000Z",
          reason: "Spring term authority",
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.userId).toBe("usr_issuer");
    expect(mockedCreateDelegatedIssuingAuthorityGrant).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        delegateUserId: "usr_issuer",
        delegatedByUserId: "usr_123",
        orgUnitId: "tenant_123:org:department-math",
        allowedActions: ["issue_badge", "revoke_badge"],
        badgeTemplateIds: ["badge_template_001"],
        endsAt: "2026-03-13T00:00:00.000Z",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "delegated_issuing_authority.granted",
        targetType: "delegated_issuing_authority_grant",
      }),
    );
  });

  it("revokes delegated issuing authority grants and writes audit logs", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindDelegatedIssuingAuthorityGrantById.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        id: "dag_123",
        delegateUserId: "usr_issuer",
      }),
    );
    mockedRevokeDelegatedIssuingAuthorityGrant.mockResolvedValue({
      status: "revoked",
      grant: sampleDelegatedIssuingAuthorityGrant({
        id: "dag_123",
        delegateUserId: "usr_issuer",
        revokedAt: "2026-02-20T00:00:00.000Z",
        revokedByUserId: "usr_123",
        revokedReason: "Policy update",
        status: "revoked",
      }),
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/users/usr_issuer/issuing-authority-grants/dag_123/revoke",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          reason: "Policy update",
          revokedAt: "2026-02-20T00:00:00.000Z",
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("revoked");
    expect(mockedRevokeDelegatedIssuingAuthorityGrant).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        grantId: "dag_123",
        revokedByUserId: "usr_123",
        revokedReason: "Policy update",
        revokedAt: "2026-02-20T00:00:00.000Z",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "delegated_issuing_authority.revoked",
        targetType: "delegated_issuing_authority_grant",
      }),
    );
  });

  it("returns delegated issuing authority grant lifecycle events", async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: "admin" }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindDelegatedIssuingAuthorityGrantById.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        id: "dag_123",
        delegateUserId: "usr_issuer",
      }),
    );
    mockedListDelegatedIssuingAuthorityGrantEvents.mockResolvedValue([
      sampleDelegatedIssuingAuthorityGrantEvent({
        grantId: "dag_123",
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/users/usr_issuer/issuing-authority-grants/dag_123/events?limit=25",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(Array.isArray(body.events)).toBe(true);
    expect(mockedListDelegatedIssuingAuthorityGrantEvents).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      grantId: "dag_123",
      limit: 25,
    });
  });
});
