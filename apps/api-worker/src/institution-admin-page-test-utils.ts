import { beforeEach, expect, vi } from "vitest";

const {
  mockedFindLearnerProfileById,
  mockedFindLearnerProfileByIdentity,
  mockedFindTenantAuthPolicy,
  mockedGetTenantReportingComparisons,
  mockedGetTenantReportingEngagementCounts,
  mockedListTenantAuthProviders,
  mockedListTenantBreakGlassAccounts,
  mockedFindTenantLmsConnectionById,
  mockedListTenantLmsConnections,
  mockedListTenantMembers,
  mockedListImportLearnerRecordBatchQueueMessages,
  mockedCreateLearnerRecordImportPreview,
  mockedEnqueueJobQueueMessageOnce,
  mockedFindActiveLearnerRecordImportPreview,
  mockedMarkLearnerRecordImportPreviewQueued,
  mockedListAccessibleTenantContextsForUser,
  mockedListLearnerRecordAssertionExports,
  mockedListLearnerRecordEntries,
  mockedGetTenantReportingOverview,
  mockedGetTenantReportingTrends,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} = vi.hoisted(() => {
  return {
    mockedFindLearnerProfileById: vi.fn(),
    mockedFindLearnerProfileByIdentity: vi.fn(),
    mockedFindTenantAuthPolicy: vi.fn(),
    mockedGetTenantReportingComparisons: vi.fn(),
    mockedGetTenantReportingEngagementCounts: vi.fn(),
    mockedListTenantAuthProviders: vi.fn(),
    mockedListTenantBreakGlassAccounts: vi.fn(),
    mockedFindTenantLmsConnectionById: vi.fn(),
    mockedListTenantLmsConnections: vi.fn(),
    mockedListTenantMembers: vi.fn(),
    mockedListImportLearnerRecordBatchQueueMessages: vi.fn(),
    mockedCreateLearnerRecordImportPreview: vi.fn(),
    mockedEnqueueJobQueueMessageOnce: vi.fn(),
    mockedFindActiveLearnerRecordImportPreview: vi.fn(),
    mockedMarkLearnerRecordImportPreviewQueued: vi.fn(),
    mockedListAccessibleTenantContextsForUser: vi.fn(),
    mockedListLearnerRecordAssertionExports: vi.fn(),
    mockedListLearnerRecordEntries: vi.fn(),
    mockedGetTenantReportingOverview: vi.fn(),
    mockedGetTenantReportingTrends: vi.fn(),
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
  };
});

export {
  mockedCreateLearnerRecordImportPreview,
  mockedEnqueueJobQueueMessageOnce,
  mockedFindActiveLearnerRecordImportPreview,
  mockedFindLearnerProfileById,
  mockedFindLearnerProfileByIdentity,
  mockedFindTenantAuthPolicy,
  mockedFindTenantLmsConnectionById,
  mockedGetTenantReportingComparisons,
  mockedGetTenantReportingEngagementCounts,
  mockedGetTenantReportingOverview,
  mockedGetTenantReportingTrends,
  mockedListAccessibleTenantContextsForUser,
  mockedListImportLearnerRecordBatchQueueMessages,
  mockedListLearnerRecordAssertionExports,
  mockedListLearnerRecordEntries,
  mockedListTenantAuthProviders,
  mockedListTenantBreakGlassAccounts,
  mockedListTenantLmsConnections,
  mockedListTenantMembers,
  mockedMarkLearnerRecordImportPreviewQueued,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
};

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findLearnerProfileById: mockedFindLearnerProfileById,
    findLearnerProfileByIdentity: mockedFindLearnerProfileByIdentity,
    createLearnerRecordImportPreview: mockedCreateLearnerRecordImportPreview,
    enqueueJobQueueMessageOnce: mockedEnqueueJobQueueMessageOnce,
    findActiveLearnerRecordImportPreview: mockedFindActiveLearnerRecordImportPreview,
    findTenantAuthPolicy: mockedFindTenantAuthPolicy,
    findTenantById: vi.fn(),
    findTenantMembership: vi.fn(),
    findUserById: vi.fn(),
    getTenantReportingEngagementCounts: mockedGetTenantReportingEngagementCounts,
    getTenantReportingOverview: mockedGetTenantReportingOverview,
    getTenantReportingTrends: mockedGetTenantReportingTrends,
    listImportLearnerRecordBatchQueueMessages: mockedListImportLearnerRecordBatchQueueMessages,
    listDelegatedIssuingAuthorityGrants: vi.fn(),
    listAccessibleTenantContextsForUser: mockedListAccessibleTenantContextsForUser,
    listLearnerRecordAssertionExports: mockedListLearnerRecordAssertionExports,
    listLearnerRecordEntries: mockedListLearnerRecordEntries,
    listBadgeIssuanceRules: vi.fn(),
    listBadgeIssuanceRuleVersions: vi.fn(),
    listBadgeIssuanceRuleEvaluations: vi.fn().mockResolvedValue([]),
    listBadgeIssuanceRuleValueLists: vi.fn().mockResolvedValue([]),
    createBadgeIssuanceRuleValueList: vi.fn(),
    findBadgeIssuanceRuleEvaluationById: vi.fn(),
    resolveBadgeIssuanceRuleEvaluationReview: vi.fn(),
    findBadgeIssuanceRuleById: vi.fn().mockResolvedValue(null),
    listTenantReportingComparisons: mockedGetTenantReportingComparisons,
    listTenantBreakGlassAccounts: mockedListTenantBreakGlassAccounts,
    listTenantMembers: mockedListTenantMembers,
    listTenantMembershipOrgUnitScopes: vi.fn(),
    listTenantAuthProviders: mockedListTenantAuthProviders,
    findTenantLmsConnectionById: mockedFindTenantLmsConnectionById,
    listTenantLmsConnections: mockedListTenantLmsConnections,
    createAuditLog: vi.fn(),
    createBadgeTemplate: vi.fn(),
    createBadgeTemplateImageRevision: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findBadgeTemplateImageRevisionById: vi.fn(),
    setBadgeTemplateArchivedState: vi.fn(),
    updateBadgeTemplate: vi.fn(),
    listAuditLogs: vi.fn(),
    listBadgeTemplateImageRevisions: vi.fn(),
    listBadgeTemplateOwnershipEvents: vi.fn(),
    countBadgeTemplateImageRevisions: vi.fn(),
    listBadgeTemplateImageRevisionCountsByTenant: vi.fn(),
    listBadgeTemplates: vi.fn(),
    listTenantApiKeys: vi.fn(),
    listTenantAssertions: vi.fn(),
    findAssertionById: vi.fn(),
    recordAssertionLifecycleTransition: vi.fn(),
    createTenantApiKey: vi.fn(),
    revokeTenantApiKey: vi.fn(),
    upsertTenantLmsConnection: vi.fn(),
    listTenantOrgUnits: vi.fn(),
    markLearnerRecordImportPreviewQueued: mockedMarkLearnerRecordImportPreviewQueued,
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
  createLearnerRecordImportPreview,
  countBadgeTemplateImageRevisions,
  createAuditLog,
  createBadgeTemplate,
  createBadgeTemplateImageRevision,
  findBadgeTemplateById,
  findBadgeTemplateImageRevisionById,
  setBadgeTemplateArchivedState,
  updateBadgeTemplate,
  findActiveLearnerRecordImportPreview,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findTenantById,
  findTenantMembership,
  findUserById,
  getTenantReportingEngagementCounts,
  listDelegatedIssuingAuthorityGrants,
  listAuditLogs,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  listBadgeIssuanceRuleEvaluations,
  listBadgeIssuanceRuleValueLists,
  createBadgeIssuanceRuleValueList,
  findBadgeIssuanceRuleEvaluationById,
  resolveBadgeIssuanceRuleEvaluationReview,
  findBadgeIssuanceRuleById,
  listBadgeTemplateImageRevisions,
  listBadgeTemplateImageRevisionCountsByTenant,
  listBadgeTemplateOwnershipEvents,
  listBadgeTemplates,
  listImportLearnerRecordBatchQueueMessages,
  listTenantApiKeys,
  listTenantAssertions,
  findAssertionById,
  recordAssertionLifecycleTransition,
  createTenantApiKey,
  revokeTenantApiKey,
  upsertTenantLmsConnection,
  findTenantLmsConnectionById,
  listTenantLmsConnections,
  listTenantMembers,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  markLearnerRecordImportPreviewQueued,
  getTenantReportingOverview,
  getTenantReportingTrends,
  listLearnerRecordAssertionExports,
  listLearnerRecordEntries,
  listTenantReportingComparisons,
  type LearnerProfileRecord,
  type LearnerRecordAssertionExportRecord,
  type LearnerRecordEntryRecord,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
  type TenantMembershipRecord,
  type TenantMemberRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

export const mockedCountBadgeTemplateImageRevisions = vi.mocked(countBadgeTemplateImageRevisions);
export const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
export const mockedFindBadgeTemplateImageRevisionById = vi.mocked(
  findBadgeTemplateImageRevisionById,
);
export const mockedSetBadgeTemplateArchivedState = vi.mocked(setBadgeTemplateArchivedState);
export const mockedCreateBadgeTemplate = vi.mocked(createBadgeTemplate);
export const mockedUpdateBadgeTemplate = vi.mocked(updateBadgeTemplate);
export const mockedListAuditLogs = vi.mocked(listAuditLogs);
export const mockedListBadgeTemplateImageRevisions = vi.mocked(listBadgeTemplateImageRevisions);
export const mockedListBadgeTemplateOwnershipEvents = vi.mocked(listBadgeTemplateOwnershipEvents);
export const mockedCreateLearnerRecordImportPreviewDb = vi.mocked(createLearnerRecordImportPreview);
export const mockedFindActiveLearnerRecordImportPreviewDb = vi.mocked(
  findActiveLearnerRecordImportPreview,
);
export const mockedFindLearnerProfileByIdDb = vi.mocked(findLearnerProfileById);
export const mockedFindLearnerProfileByIdentityDb = vi.mocked(findLearnerProfileByIdentity);
export const mockedFindTenantMembership = vi.mocked(findTenantMembership);
export const mockedFindTenantById = vi.mocked(findTenantById);
export const mockedFindUserById = vi.mocked(findUserById);
export const mockedListDelegatedIssuingAuthorityGrants = vi.mocked(
  listDelegatedIssuingAuthorityGrants,
);
export const mockedListBadgeIssuanceRules = vi.mocked(listBadgeIssuanceRules);
export const mockedListBadgeIssuanceRuleVersions = vi.mocked(listBadgeIssuanceRuleVersions);
export const mockedListBadgeIssuanceRuleEvaluations = vi.mocked(listBadgeIssuanceRuleEvaluations);
export const mockedListBadgeIssuanceRuleValueLists = vi.mocked(listBadgeIssuanceRuleValueLists);
export const mockedCreateBadgeIssuanceRuleValueList = vi.mocked(createBadgeIssuanceRuleValueList);
export const mockedFindBadgeIssuanceRuleEvaluationById = vi.mocked(
  findBadgeIssuanceRuleEvaluationById,
);
export const mockedResolveBadgeIssuanceRuleEvaluationReview = vi.mocked(
  resolveBadgeIssuanceRuleEvaluationReview,
);
export const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
export const mockedListBadgeTemplateImageRevisionCountsByTenant = vi.mocked(
  listBadgeTemplateImageRevisionCountsByTenant,
);
export const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
export const mockedListImportLearnerRecordBatchQueueMessagesDb = vi.mocked(
  listImportLearnerRecordBatchQueueMessages,
);
export const mockedListTenantOrgUnits = vi.mocked(listTenantOrgUnits);
export const mockedListTenantApiKeys = vi.mocked(listTenantApiKeys);
export const mockedListTenantAssertions = vi.mocked(listTenantAssertions);
export const mockedFindAssertionById = vi.mocked(findAssertionById);
export const mockedRecordAssertionLifecycleTransition = vi.mocked(
  recordAssertionLifecycleTransition,
);
export const mockedCreateTenantApiKey = vi.mocked(createTenantApiKey);
export const mockedRevokeTenantApiKey = vi.mocked(revokeTenantApiKey);
export const mockedUpsertTenantLmsConnection = vi.mocked(upsertTenantLmsConnection);
export const mockedFindTenantLmsConnectionByIdDb = vi.mocked(findTenantLmsConnectionById);
export const mockedListTenantLmsConnectionsDb = vi.mocked(listTenantLmsConnections);
export const mockedListTenantMembersDb = vi.mocked(listTenantMembers);
export const mockedListTenantMembershipOrgUnitScopes = vi.mocked(listTenantMembershipOrgUnitScopes);
export const mockedMarkLearnerRecordImportPreviewQueuedDb = vi.mocked(
  markLearnerRecordImportPreviewQueued,
);
export const mockedGetTenantReportingComparisonsDb = vi.mocked(listTenantReportingComparisons);
export const mockedGetTenantReportingEngagementCountsDb = vi.mocked(
  getTenantReportingEngagementCounts,
);
export const mockedGetTenantReportingOverviewDb = vi.mocked(getTenantReportingOverview);
export const mockedGetTenantReportingTrendsDb = vi.mocked(getTenantReportingTrends);
export const mockedListLearnerRecordAssertionExportsDb = vi.mocked(
  listLearnerRecordAssertionExports,
);
export const mockedListLearnerRecordEntriesDb = vi.mocked(listLearnerRecordEntries);
export const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
export const fakeDbPrepare = vi.fn();
export const fakeDb = {
  prepare: fakeDbPrepare,
} as unknown as SqlDatabase;

export const createEnv = (): {
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

export const sampleMembership = (role: TenantMembershipRecord["role"]): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_admin",
    role,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  };
};

export const sampleTenantMember = (overrides?: Partial<TenantMemberRecord>): TenantMemberRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_member",
    email: "member@tenant-123.edu",
    role: "issuer",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:30:00.000Z",
    ...overrides,
  };
};

export const sampleLearnerProfile = (
  overrides?: Partial<LearnerProfileRecord>,
): LearnerProfileRecord => {
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

export const sampleLearnerRecordAssertionExport = (
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

export const sampleLearnerRecordEntry = (
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

export const sampleTenantLmsConnection = (
  overrides?: Partial<TenantLmsConnectionRecord>,
): TenantLmsConnectionRecord => {
  return {
    id: "lms_123",
    tenantId: "tenant_123",
    displayName: "TrySakai",
    providerKind: "sakai",
    apiBaseUrl: "https://trysakai.example.edu",
    authorizationEndpoint: null,
    tokenEndpoint: null,
    clientId: null,
    clientSecret: null,
    scope: null,
    accessToken: "sakai-token",
    refreshToken: null,
    accessTokenExpiresAt: null,
    refreshTokenExpiresAt: null,
    connectedAt: "2026-02-18T12:00:00.000Z",
    ltiIssuer: "https://trysakai.example.edu",
    ltiClientId: "sakai-client",
    ltiDeploymentId: "deployment-123",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
    ...overrides,
  };
};

export const sampleReportingOrgUnits = () => {
  return [
    {
      id: "tenant_123:org:institution",
      tenantId: "tenant_123",
      unitType: "institution" as const,
      slug: "institution",
      displayName: "Institution",
      parentOrgUnitId: null,
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:college-eng",
      tenantId: "tenant_123",
      unitType: "college" as const,
      slug: "college-eng",
      displayName: "College of Engineering",
      parentOrgUnitId: "tenant_123:org:institution",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:college-arts",
      tenantId: "tenant_123",
      unitType: "college" as const,
      slug: "college-arts",
      displayName: "College of Arts",
      parentOrgUnitId: "tenant_123:org:institution",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-cs",
      tenantId: "tenant_123",
      unitType: "department" as const,
      slug: "department-cs",
      displayName: "Computer Science",
      parentOrgUnitId: "tenant_123:org:college-eng",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-math",
      tenantId: "tenant_123",
      unitType: "department" as const,
      slug: "department-math",
      displayName: "Mathematics",
      parentOrgUnitId: "tenant_123:org:college-eng",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-history",
      tenantId: "tenant_123",
      unitType: "department" as const,
      slug: "department-history",
      displayName: "History",
      parentOrgUnitId: "tenant_123:org:college-arts",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-design",
      tenantId: "tenant_123",
      unitType: "department" as const,
      slug: "department-design",
      displayName: "Design",
      parentOrgUnitId: "tenant_123:org:college-arts",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:program-cs",
      tenantId: "tenant_123",
      unitType: "program" as const,
      slug: "program-cs",
      displayName: "Computer Science Program",
      parentOrgUnitId: "tenant_123:org:department-cs",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:program-design",
      tenantId: "tenant_123",
      unitType: "program" as const,
      slug: "program-design",
      displayName: "Design Foundations",
      parentOrgUnitId: "tenant_123:org:department-design",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ];
};

export const getReportingPanelMarkup = (html: string, heading: string): string => {
  const headingMarkup = `<h2>${heading}</h2>`;
  const start = html.indexOf(headingMarkup);

  expect(start).toBeGreaterThan(-1);

  const end = html.indexOf("</article>", start);

  expect(end).toBeGreaterThan(start);

  return html.slice(start, end);
};

export const getReportingPanelArticleMarkup = (html: string, heading: string): string => {
  const headingMarkup = `<h2>${heading}</h2>`;
  const headingIndex = html.indexOf(headingMarkup);

  expect(headingIndex).toBeGreaterThan(-1);

  const start = html.lastIndexOf("<article", headingIndex);

  expect(start).toBeGreaterThan(-1);

  const end = html.indexOf("</article>", headingIndex);

  expect(end).toBeGreaterThan(start);

  return html.slice(start, end);
};

beforeEach(() => {
  fakeDbPrepare.mockReset();
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleMembership("admin"));
  mockedFindTenantById.mockReset();
  mockedFindTenantById.mockResolvedValue({
    id: "tenant_123",
    slug: "tenant-123",
    displayName: "Tenant 123",
    planTier: "team",
    issuerDomain: "tenant-123.credtrail.test",
    didWeb: "did:web:credtrail.test:tenant_123",
    isActive: true,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedFindBadgeTemplateById.mockReset();
  mockedFindBadgeTemplateById.mockResolvedValue(null);
  mockedFindBadgeTemplateImageRevisionById.mockReset();
  mockedFindBadgeTemplateImageRevisionById.mockResolvedValue(null);
  mockedSetBadgeTemplateArchivedState.mockReset();
  mockedSetBadgeTemplateArchivedState.mockResolvedValue(null);
  mockedCreateBadgeTemplate.mockReset();
  mockedCreateBadgeTemplate.mockResolvedValue({
    id: "badge_template_created",
    tenantId: "tenant_123",
    slug: "created-template",
    title: "Created Template",
    description: null,
    criteriaUri: null,
    imageUri: null,
    createdByUserId: "usr_admin",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedUpdateBadgeTemplate.mockReset();
  mockedUpdateBadgeTemplate.mockResolvedValue(null);
  mockedListAuditLogs.mockReset();
  mockedListAuditLogs.mockResolvedValue([]);
  mockedListBadgeTemplateOwnershipEvents.mockReset();
  mockedListBadgeTemplateOwnershipEvents.mockResolvedValue([]);
  mockedListBadgeTemplateImageRevisions.mockReset();
  mockedListBadgeTemplateImageRevisions.mockResolvedValue([]);
  mockedCountBadgeTemplateImageRevisions.mockReset();
  mockedCountBadgeTemplateImageRevisions.mockResolvedValue(0);
  vi.mocked(createAuditLog).mockReset();
  vi.mocked(createAuditLog).mockResolvedValue({
    id: "aud_test",
    tenantId: "tenant_123",
    actorUserId: "usr_admin",
    action: "badge_template.image_restored",
    targetType: "badge_template",
    targetId: "badge_template_001",
    metadataJson: null,
    occurredAt: "2026-02-18T12:00:00.000Z",
    createdAt: "2026-02-18T12:00:00.000Z",
  });
  vi.mocked(createBadgeTemplateImageRevision).mockReset();
  vi.mocked(createBadgeTemplateImageRevision).mockResolvedValue({
    id: "btir_test",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    previousImageUri: "https://example.edu/new.png",
    newImageUri: "https://example.edu/old.png",
    sourceType: "restore",
    promptText: null,
    provider: null,
    model: null,
    metadataJson: null,
    createdByUserId: "usr_admin",
    createdAt: "2026-02-18T12:00:00.000Z",
  });
  mockedFindTenantAuthPolicy.mockReset();
  mockedFindTenantAuthPolicy.mockResolvedValue({
    tenantId: "tenant_123",
    loginMode: "hybrid",
    breakGlassEnabled: true,
    localMfaRequired: true,
    defaultProviderId: "tap_oidc",
    enforceForRoles: "all_users",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: "usr_admin",
    email: "admin@tenant-123.edu",
  });
  mockedListBadgeTemplateImageRevisionCountsByTenant.mockReset();
  mockedListBadgeTemplateImageRevisionCountsByTenant.mockResolvedValue([
    {
      badgeTemplateId: "badge_template_001",
      revisionCount: 3,
    },
  ]);
  mockedListBadgeTemplates.mockReset();
  mockedListBadgeTemplates.mockResolvedValue([
    {
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "typescript-foundations",
      title: "TypeScript Foundations",
      description: "Awarded for TypeScript basics.",
      criteriaUri: "https://example.edu/criteria",
      imageUri: "https://example.edu/badges/typescript.png",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedListBadgeIssuanceRules.mockReset();
  mockedListBadgeIssuanceRules.mockResolvedValue([
    {
      id: "brl_123",
      tenantId: "tenant_123",
      name: "CS101 Excellence Rule",
      description: "Issue badge for CS101 completion and grade threshold.",
      badgeTemplateId: "badge_template_001",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: "brv_123",
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedListBadgeIssuanceRuleVersions.mockReset();
  mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
    {
      id: "brv_123",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 1,
      status: "draft",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"CS101","minScore":80}}',
      changeSummary: "Initial draft",
      createdByUserId: "usr_admin",
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedListBadgeIssuanceRuleEvaluations.mockReset();
  mockedListBadgeIssuanceRuleEvaluations.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleValueLists.mockReset();
  mockedListBadgeIssuanceRuleValueLists.mockResolvedValue([]);
  mockedCreateBadgeIssuanceRuleValueList.mockReset();
  mockedCreateBadgeIssuanceRuleValueList.mockResolvedValue({
    id: "brvl_123",
    tenantId: "tenant_123",
    label: "Core CS sequence",
    kind: "course_ids",
    values: ["CS101", "CS102"],
    createdByUserId: "usr_admin",
    archivedAt: null,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedFindBadgeIssuanceRuleEvaluationById.mockReset();
  mockedFindBadgeIssuanceRuleEvaluationById.mockResolvedValue(null);
  mockedResolveBadgeIssuanceRuleEvaluationReview.mockReset();
  mockedResolveBadgeIssuanceRuleEvaluationReview.mockResolvedValue(null);
  mockedFindBadgeIssuanceRuleById.mockReset();
  mockedFindBadgeIssuanceRuleById.mockResolvedValue(null);
  mockedListTenantOrgUnits.mockReset();
  mockedListTenantOrgUnits.mockResolvedValue(sampleReportingOrgUnits());
  mockedListTenantMembershipOrgUnitScopes.mockReset();
  mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([
    {
      tenantId: "tenant_123",
      userId: "usr_issuer",
      orgUnitId: "tenant_123:org:institution",
      role: "issuer",
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:30:00.000Z",
    },
  ]);
  mockedListTenantAssertions.mockReset();
  mockedListTenantAssertions.mockResolvedValue([]);
  mockedFindAssertionById.mockReset();
  mockedFindAssertionById.mockResolvedValue(null);
  mockedRecordAssertionLifecycleTransition.mockReset();
  mockedRecordAssertionLifecycleTransition.mockResolvedValue({
    status: "transitioned",
    fromState: "active",
    toState: "revoked",
    currentState: "revoked",
    event: null,
    message: null,
  });
  mockedUpsertTenantLmsConnection.mockReset();
  mockedUpsertTenantLmsConnection.mockResolvedValue(
    sampleTenantLmsConnection({
      id: "lms_new",
      displayName: "New LMS",
    }),
  );
  mockedCreateTenantApiKey.mockReset();
  mockedCreateTenantApiKey.mockResolvedValue({
    id: "tak_new",
    tenantId: "tenant_123",
    label: "Integration key",
    keyPrefix: "ctak_newkey",
    keyHash: "hash_new",
    scopesJson: '["queue.issue","queue.revoke"]',
    createdByUserId: "usr_admin",
    expiresAt: null,
    lastUsedAt: null,
    revokedAt: null,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedRevokeTenantApiKey.mockReset();
  mockedRevokeTenantApiKey.mockResolvedValue(true);
  mockedListTenantApiKeys.mockReset();
  mockedListTenantApiKeys.mockResolvedValue([
    {
      id: "tak_active",
      tenantId: "tenant_123",
      label: "Issuer integration",
      keyPrefix: "ctak_abc123",
      keyHash: "hash_active",
      scopesJson: '["queue.issue","queue.revoke"]',
      createdByUserId: "usr_admin",
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tak_revoked",
      tenantId: "tenant_123",
      label: "Old key",
      keyPrefix: "ctak_old123",
      keyHash: "hash_revoked",
      scopesJson: '["queue.issue"]',
      createdByUserId: "usr_admin",
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: "2026-02-18T12:30:00.000Z",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:30:00.000Z",
    },
  ]);
  mockedListTenantLmsConnectionsDb.mockReset();
  const lmsConnections = [
    sampleTenantLmsConnection({
      id: "lms_canvas",
      displayName: "Canvas Test",
      providerKind: "canvas",
      apiBaseUrl: "https://canvas.example.edu",
      accessToken: "canvas-token",
      ltiIssuer: "https://canvas.example.edu",
      ltiClientId: "canvas-client",
      ltiDeploymentId: "canvas-deployment",
    }),
  ];
  mockedListTenantLmsConnectionsDb.mockResolvedValue(lmsConnections);
  mockedFindTenantLmsConnectionByIdDb.mockReset();
  mockedFindTenantLmsConnectionByIdDb.mockImplementation(async (_db, input) => {
    return lmsConnections.find((connection) => connection.id === input.connectionId) ?? null;
  });
  mockedListDelegatedIssuingAuthorityGrants.mockReset();
  mockedListDelegatedIssuingAuthorityGrants.mockResolvedValue([
    {
      id: "dag_123",
      tenantId: "tenant_123",
      delegateUserId: "usr_delegate",
      delegatedByUserId: "usr_admin",
      orgUnitId: "tenant_123:org:institution",
      allowedActions: ["issue_badge"],
      badgeTemplateIds: [],
      startsAt: "2026-02-18T12:00:00.000Z",
      endsAt: "2026-05-18T12:00:00.000Z",
      revokedAt: null,
      revokedByUserId: null,
      revokedReason: null,
      status: "active",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedListTenantAuthProviders.mockReset();
  mockedListTenantAuthProviders.mockResolvedValue([
    {
      id: "tap_oidc",
      tenantId: "tenant_123",
      protocol: "oidc",
      label: "Campus OIDC",
      enabled: true,
      isDefault: true,
      configJson:
        '{"issuer":"https://idp.example.edu","clientId":"credtrail","clientSecret":"secret"}',
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tap_saml",
      tenantId: "tenant_123",
      protocol: "saml",
      label: "Legacy SAML",
      enabled: true,
      isDefault: false,
      configJson:
        '{"ssoLoginUrl":"https://idp.example.edu/sso","idpEntityId":"https://idp.example.edu/entity"}',
      createdAt: "2026-02-18T12:05:00.000Z",
      updatedAt: "2026-02-18T12:05:00.000Z",
    },
  ]);
  mockedListTenantBreakGlassAccounts.mockReset();
  mockedListTenantBreakGlassAccounts.mockResolvedValue([
    {
      tenantId: "tenant_123",
      userId: "usr_break_glass",
      email: "admin@tenant-123.edu",
      createdByUserId: "usr_admin",
      lastUsedAt: null,
      lastEnrollmentEmailSentAt: "2026-02-18T12:05:00.000Z",
      revokedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:05:00.000Z",
      betterAuthUserId: "ba_usr_break_glass",
      localCredentialEnabled: true,
      twoFactorEnabled: true,
    },
  ]);
  mockedListTenantMembersDb.mockReset();
  mockedListTenantMembersDb.mockResolvedValue([
    sampleTenantMember({
      userId: "usr_admin",
      email: "admin@tenant-123.edu",
      role: "admin",
    }),
    sampleTenantMember({
      userId: "usr_issuer",
      email: "issuer@tenant-123.edu",
      role: "issuer",
    }),
  ]);
  mockedListAccessibleTenantContextsForUser.mockReset();
  mockedListAccessibleTenantContextsForUser.mockResolvedValue([
    {
      tenantId: "tenant_123",
      tenantSlug: "tenant-123",
      tenantDisplayName: "Tenant 123",
      tenantPlanTier: "team",
      membershipRole: "admin",
    },
  ]);
  mockedListImportLearnerRecordBatchQueueMessagesDb.mockReset();
  mockedListImportLearnerRecordBatchQueueMessagesDb.mockResolvedValue([]);
  mockedCreateLearnerRecordImportPreviewDb.mockReset();
  mockedCreateLearnerRecordImportPreviewDb.mockImplementation(async (_db, input) => ({
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
  mockedEnqueueJobQueueMessageOnce.mockReset();
  mockedEnqueueJobQueueMessageOnce.mockResolvedValue(true);
  mockedFindActiveLearnerRecordImportPreviewDb.mockReset();
  mockedFindActiveLearnerRecordImportPreviewDb.mockResolvedValue(null);
  mockedMarkLearnerRecordImportPreviewQueuedDb.mockReset();
  mockedMarkLearnerRecordImportPreviewQueuedDb.mockResolvedValue(true);
  mockedFindLearnerProfileByIdDb.mockReset();
  mockedFindLearnerProfileByIdDb.mockResolvedValue(sampleLearnerProfile());
  mockedFindLearnerProfileByIdentityDb.mockReset();
  mockedFindLearnerProfileByIdentityDb.mockResolvedValue(sampleLearnerProfile());
  mockedListLearnerRecordAssertionExportsDb.mockReset();
  mockedListLearnerRecordAssertionExportsDb.mockResolvedValue([
    sampleLearnerRecordAssertionExport(),
  ]);
  mockedListLearnerRecordEntriesDb.mockReset();
  mockedListLearnerRecordEntriesDb.mockResolvedValue([
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
  mockedGetTenantReportingOverviewDb.mockReset();
  mockedGetTenantReportingOverviewDb.mockResolvedValue({
    tenantId: "tenant_123",
    filters: {
      issuedFrom: null,
      issuedTo: null,
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
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-design",
            issuedCount: 1,
            publicBadgeViewCount: 3,
            verificationViewCount: 1,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 100,
            shareRate: 100,
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
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockImplementation(
    (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return null;
      }

      return {
        userId: "usr_admin",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-02-18T23:00:00.000Z",
      };
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
});
